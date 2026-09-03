//! Deliver over VOT QUIC: a manifest per grant, the servers a fetch is
//! answered from, admission of a fetch session, and the capability mint.
//!
//! Serving is off unless `VOTPORT_SERVE_BIND` is set. A grant's manifest is
//! built the first time a fetch capability is minted for it, from the same
//! files the HTTP path serves, and written under `data/outbound.manifests`.
//! A package root is a function of the files, so two grants over one file
//! set share a root and a server; what names a grant at admission is the
//! ticket recorded at mint, keyed by the capability's token id. A ticket
//! reserves one delivery against `max_downloads` until it is delivered or
//! expires, taken in one statement so two mints cannot both take the last
//! one, and a restart warms a server for every unexpired ticket, so a
//! minted capability stays good for its hour.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::{Path as AxumPath, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine as _;
use serde::Deserialize;
use serde_json::json;
use vot_sdk::object::{proof_leaves_at, ObjectId, Suite, PROOF_LEAF_SIZE};
use vot_sdk::package::{PackageBuilder, PackageEntry};

use super::outbound::{
    active_grant, begin_outbound_operation, require_grant_access, source_info_indexed_with_file,
    ActiveDownload,
};
use super::{ApiError, ApiResult};
use crate::app::App;
use crate::store::{now_unix, FetchTicket, OutboundGrant};

/// vot-cli's bundle layout, which `BundleServer::assemble` reads and which
/// upstream keeps crate-private: the manifest directory, its seal, and its
/// zero-padded page names.
const MANIFEST_DIRECTORY: &str = "manifest";
const MANIFEST_SEAL: &str = "seal.cbor";
const MANIFESTS_DIRECTORY: &str = "outbound.manifests";

/// A minted capability lives this long at most; the grant's own expiry
/// caps it lower.
const CAPABILITY_TTL_SECS: u64 = 3600;

/// Expired tickets are kept this long for the operator, then dropped.
const TICKET_RETENTION_SECS: u64 = 86_400;

/// Manifest builds and server assembly run one at a time: a build replaces
/// a directory another build may be reading. With a warm leaf cache the
/// critical section is a sample and a few milliseconds; the first mint of a
/// grant reads its files under this lock to compute the leaves.
/// ponytail: one process-wide lock; shard per grant if cold first mints
/// queue behind each other.
static BUILDS: Mutex<()> = Mutex::new(());

fn page_name(index: u64) -> String {
    format!("{index:016}.cbor")
}

/// Why a fetch session was refused, as a fixed metrics series.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ServeRefusalReason {
    Rate,
    Capability,
    Unknown,
    Closed,
    Busy,
}

impl ServeRefusalReason {
    pub(crate) const ALL: [Self; 5] = [
        Self::Rate,
        Self::Capability,
        Self::Unknown,
        Self::Closed,
        Self::Busy,
    ];

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Rate => "rate",
            Self::Capability => "capability",
            Self::Unknown => "unknown",
            Self::Closed => "closed",
            Self::Busy => "busy",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Rate => 0,
            Self::Capability => 1,
            Self::Unknown => 2,
            Self::Closed => 3,
            Self::Busy => 4,
        }
    }
}

/// Serve counters, on `App` so `/metrics` reads them whether or not the
/// listener is bound.
#[derive(Default)]
pub(crate) struct ServeMetrics {
    bytes_total: AtomicU64,
    deliveries_total: AtomicU64,
    refused: [AtomicU64; 5],
}

impl ServeMetrics {
    fn refuse(&self, reason: ServeRefusalReason) {
        self.refused[reason.index()].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn bytes(&self) -> u64 {
        self.bytes_total.load(Ordering::Relaxed)
    }

    pub(crate) fn deliveries(&self) -> u64 {
        self.deliveries_total.load(Ordering::Relaxed)
    }

    pub(crate) fn refusals(&self, reason: ServeRefusalReason) -> u64 {
        self.refused[reason.index()].load(Ordering::Relaxed)
    }
}

/// One fetch's hold on the download slot set: a slot per capability, not
/// per rail, released when its last session ends.
struct FetchSlot {
    #[allow(dead_code)]
    guard: ActiveDownload,
    sessions: usize,
}

/// One admitted session's hold on its fetch's slot, released on drop: the
/// seam may discard an admission after the policy returned (its deadline,
/// a refused scope, a failed grant), never running the observer, and the
/// slot must not outlive that.
struct SessionHold {
    registry: Arc<ServeRegistry>,
    token: [u8; 16],
}

impl Drop for SessionHold {
    fn drop(&mut self) {
        self.registry.release_slot(self.token);
    }
}

/// The servers assembled this process by package root and the slots fetches
/// hold.
#[derive(Default)]
pub(crate) struct ServeRegistry {
    servers: Mutex<HashMap<[u8; 32], Arc<vot_cli::BundleServer>>>,
    slots: Mutex<HashMap<[u8; 16], FetchSlot>>,
}

impl ServeRegistry {
    fn server(&self, root: [u8; 32]) -> Option<Arc<vot_cli::BundleServer>> {
        self.servers
            .lock()
            .expect("serve registry poisoned")
            .get(&root)
            .cloned()
    }

    /// Takes the fetch's slot on its first session, counts every later one.
    fn claim_slot(&self, app: &Arc<App>, token: [u8; 16], token_hash: &str) -> Result<(), ()> {
        let mut slots = self.slots.lock().expect("serve registry poisoned");
        if let Some(slot) = slots.get_mut(&token) {
            slot.sessions += 1;
            return Ok(());
        }
        let key = format!("{token_hash}:quic:{}", hex::encode(token));
        let guard =
            ActiveDownload::claim_with_grant(Arc::clone(app), &key, token_hash).map_err(|_| ())?;
        slots.insert(token, FetchSlot { guard, sessions: 1 });
        Ok(())
    }

    /// Releases one session of a fetch; the last one returns the slot, so a
    /// later fetch on the same token starts fresh.
    fn release_slot(&self, token: [u8; 16]) {
        let mut slots = self.slots.lock().expect("serve registry poisoned");
        if let Some(slot) = slots.get_mut(&token) {
            slot.sessions = slot.sessions.saturating_sub(1);
            if slot.sessions == 0 {
                slots.remove(&token);
            }
        }
    }

    /// Sessions of admitted fetches now running.
    pub(crate) fn active_sessions(&self) -> usize {
        self.slots
            .lock()
            .expect("serve registry poisoned")
            .values()
            .map(|slot| slot.sessions)
            .sum()
    }

    /// Keeps servers for `roots`. Slots are released by their sessions, never
    /// here.
    fn retain(&self, roots: &HashSet<[u8; 32]>) {
        self.servers
            .lock()
            .expect("serve registry poisoned")
            .retain(|root, _| roots.contains(root));
    }
}

/// Everything the serve listener retains for the process lifetime.
pub struct ServeState {
    pub(crate) listener: Mutex<vot_cli::Listener>,
    pub(crate) issuer: ed25519_dalek::SigningKey,
    pub(crate) address: String,
    pub(crate) audience: String,
    pub(crate) certificate_digest: [u8; 32],
    pub(crate) registry: Arc<ServeRegistry>,
}

/// One grant file as a package entry and the file that backs it.
pub(crate) struct GrantEntry {
    pub(crate) components: Vec<String>,
    pub(crate) object: ObjectId,
    pub(crate) path: PathBuf,
}

/// The grant's files in package order, resolved the way a download resolves
/// them.
pub(crate) fn grant_entries(app: &App, grant: &OutboundGrant) -> ApiResult<Vec<GrantEntry>> {
    let count = grant.files.len().max(1);
    let mut entries = Vec::with_capacity(count);
    for index in 0..count {
        let source = source_info_indexed_with_file(app, grant, index, grant.files.get(index))?;
        entries.push(GrantEntry {
            components: source
                .name
                .split('/')
                .filter(|part| !part.is_empty())
                .map(str::to_owned)
                .collect(),
            object: source.object,
            path: source.path,
        });
    }
    Ok(entries)
}

/// Sorts entries into manifest order and refuses two that fold to one key,
/// as the browser sender does before it builds a package.
fn ordered(entries: &[GrantEntry]) -> Result<Vec<(Vec<u8>, &GrantEntry)>, String> {
    let mut keyed = Vec::with_capacity(entries.len());
    for entry in entries {
        let path = vot_manifest::PackagePath::portable(entry.components.iter().cloned())
            .map_err(|error| format!("package path {:?}: {error:?}", entry.components))?;
        let key = vot_manifest::canonical_path_key(&path, vot_manifest::PathProfile::Portable)
            .map_err(|error| format!("package path key {:?}: {error:?}", entry.components))?;
        keyed.push((key, entry));
    }
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    for pair in keyed.windows(2) {
        if pair[0].0 == pair[1].0 {
            return Err(format!(
                "\"{}\" and \"{}\" collide once case is folded",
                pair[0].1.components.join("/"),
                pair[1].1.components.join("/")
            ));
        }
    }
    Ok(keyed)
}

/// A built package: its root, its encoded pages, and its seal.
struct BuiltPackage {
    root: [u8; 32],
    pages: Vec<Vec<u8>>,
    seal: Vec<u8>,
}

fn build_package(entries: &[GrantEntry]) -> Result<BuiltPackage, String> {
    let ordered = ordered(entries)?;
    let mut builder = PackageBuilder::new().map_err(|error| format!("package: {error:?}"))?;
    let mut drafts = Vec::new();
    for (_, entry) in &ordered {
        let package_entry = PackageEntry::direct(entry.components.clone(), &entry.object)
            .map_err(|error| format!("package entry {:?}: {error:?}", entry.components))?;
        if let Some(draft) = builder
            .push(&package_entry)
            .map_err(|error| format!("package push {:?}: {error:?}", entry.components))?
        {
            drafts.push(draft);
        }
    }
    let assembly = builder
        .finish()
        .map_err(|error| format!("package finish: {error:?}"))?;
    let (summary, last, mut finalizer) = assembly.into_parts();
    drafts.push(last);
    let mut pages = Vec::with_capacity(drafts.len());
    for draft in drafts {
        pages.push(
            finalizer
                .push(draft)
                .map_err(|error| format!("manifest page: {error:?}"))?
                .into_bytes(),
        );
    }
    let seal = finalizer
        .finish()
        .map_err(|error| format!("manifest seal: {error:?}"))?
        .into_bytes();
    Ok(BuiltPackage {
        root: summary.root(),
        pages,
        seal,
    })
}

/// Builds the package over `entries` and writes its pages and seal under
/// `<directory>/manifest/`, replacing whatever was there. Returns the
/// package root. Written whole into a stage directory and renamed into
/// place, so a reader never sees a manifest with pages missing; the stage
/// is removed on any failure.
pub(crate) fn write_manifest(directory: &Path, entries: &[GrantEntry]) -> Result<[u8; 32], String> {
    let BuiltPackage { root, pages, seal } = build_package(entries)?;
    let stage = directory.with_file_name(format!(
        ".{}.stage-{}",
        directory
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("manifest"),
        crate::auth::random_token()
    ));
    let written = write_stage(&stage, &pages, &seal).and_then(|()| {
        if directory.exists() {
            std::fs::remove_dir_all(directory)
                .map_err(|error| format!("replace {}: {error}", directory.display()))?;
        }
        std::fs::rename(&stage, directory)
            .map_err(|error| format!("publish {}: {error}", directory.display()))
    });
    if written.is_err() {
        let _ = std::fs::remove_dir_all(&stage);
    }
    written.map(|()| root)
}

fn write_stage(stage: &Path, pages: &[Vec<u8>], seal: &[u8]) -> Result<(), String> {
    let manifest = stage.join(MANIFEST_DIRECTORY);
    std::fs::create_dir_all(&manifest)
        .map_err(|error| format!("create {}: {error}", manifest.display()))?;
    let write = |name: &str, bytes: &[u8]| -> Result<(), String> {
        let path = manifest.join(name);
        std::fs::write(&path, bytes)
            .map_err(|error| format!("write {}: {error}", path.display()))?;
        std::fs::File::open(&path)
            .and_then(|file| file.sync_all())
            .map_err(|error| format!("sync {}: {error}", path.display()))
    };
    for (index, page) in pages.iter().enumerate() {
        write(&page_name(index as u64), page)?;
    }
    write(MANIFEST_SEAL, seal)
}

/// Where a grant's manifest lives.
pub(crate) fn manifest_directory(app: &App, grant_id: &str) -> PathBuf {
    app.config.data_dir.join(MANIFESTS_DIRECTORY).join(grant_id)
}

/// The proof directory a grant's leaves are cached in, beside its catalogs.
fn proof_root(app: &App) -> PathBuf {
    app.config.data_dir.join("outbound.proofs")
}

/// Where an object's proof leaves are cached, named as its catalog is.
fn leaf_cache_path(proof_root: &Path, object: &ObjectId) -> PathBuf {
    proof_root.join(format!(
        "{}-{}-{}.leaves",
        object.suite,
        hex::encode(object.root),
        object.length
    ))
}

/// Reads an object's cached leaves, or `None` for anything a serve will not
/// prepare from: no cache, a header that names another object, or a count
/// that cannot describe the object. Never an error; the object is read
/// instead. The `VOTLEAF` layout upstream keeps crate-private, so the
/// cache interoperates if that writer is ever exposed.
fn read_leaves(proof_root: &Path, object: &ObjectId) -> Option<Vec<[u8; 32]>> {
    let bytes = std::fs::read(leaf_cache_path(proof_root, object)).ok()?;
    let header = 8 + 1 + 8 + 8;
    if bytes.len() < header
        || &bytes[..8] != b"VOTLEAF\x01"
        || bytes[8] != u8::try_from(object.suite).ok()?
    {
        return None;
    }
    let length = u64::from_le_bytes(bytes[9..17].try_into().ok()?);
    let count = u64::from_le_bytes(bytes[17..25].try_into().ok()?);
    if length != object.length || count != object.length.div_ceil(PROOF_LEAF_SIZE) {
        return None;
    }
    let count = usize::try_from(count).ok()?;
    if bytes.len() != header + count * 32 {
        return None;
    }
    Some(
        bytes[header..]
            .chunks_exact(32)
            .map(|leaf| leaf.try_into().expect("32 bytes"))
            .collect(),
    )
}

/// Writes an object's leaves to the cache, staged and renamed so a reader
/// never sees a short file. Best effort: a serve without the cache still
/// works by reading the object.
fn write_leaves(proof_root: &Path, object: &ObjectId, leaves: &[[u8; 32]]) {
    let destination = leaf_cache_path(proof_root, object);
    let stage = destination.with_file_name(format!(
        ".{}.stage-{}",
        destination
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("leaves"),
        crate::auth::random_token()
    ));
    let mut bytes = Vec::with_capacity(25 + leaves.len() * 32);
    bytes.extend_from_slice(b"VOTLEAF\x01");
    bytes.push(u8::try_from(object.suite).unwrap_or(0));
    bytes.extend_from_slice(&object.length.to_le_bytes());
    bytes.extend_from_slice(&(leaves.len() as u64).to_le_bytes());
    for leaf in leaves {
        bytes.extend_from_slice(leaf);
    }
    let written = std::fs::create_dir_all(proof_root)
        .and_then(|()| std::fs::write(&stage, &bytes))
        .and_then(|()| std::fs::File::open(&stage).and_then(|file| file.sync_all()))
        .and_then(|()| std::fs::rename(&stage, &destination));
    if written.is_err() {
        let _ = std::fs::remove_file(&stage);
    }
}

/// Computes an object's proof leaves by reading the file across the pool.
/// A serve otherwise reads every byte on one thread (about 1.4 s per GiB);
/// this reads leaf-aligned ranges in parallel, which is what makes the
/// first fetch of a large grant fast. Returns `None` on any read failure,
/// which leaves the serve to read the object and say why.
fn compute_leaves(path: &Path, suite: Suite, length: u64) -> Option<Vec<[u8; 32]>> {
    use std::io::{Read as _, Seek as _, SeekFrom};
    let leaf = PROOF_LEAF_SIZE;
    let total = length.div_ceil(leaf);
    let workers = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1)
        .min(8)
        .min(usize::try_from(total).unwrap_or(1))
        .max(1);
    let per = total.div_ceil(workers as u64);
    let ranges: Vec<(u64, u64)> = (0..workers as u64)
        .map(|w| {
            let start = (w * per).min(total) * leaf;
            let end = (((w + 1) * per).min(total) * leaf).min(length);
            (start, end)
        })
        .filter(|(start, end)| start < end)
        .collect();
    let parts: Vec<Option<Vec<[u8; 32]>>> = std::thread::scope(|scope| {
        let handles: Vec<_> = ranges
            .iter()
            .map(|&(start, end)| {
                scope.spawn(move || -> Option<Vec<[u8; 32]>> {
                    // Streamed in 16-leaf steps so memory stays bounded
                    // however large the object, never the whole range.
                    let step = 16 * leaf;
                    let mut file = std::fs::File::open(path).ok()?;
                    file.seek(SeekFrom::Start(start)).ok()?;
                    let mut leaves = Vec::new();
                    let mut offset = start;
                    let mut buf = vec![0u8; usize::try_from(step).ok()?];
                    while offset < end {
                        let take = usize::try_from((end - offset).min(step)).ok()?;
                        file.read_exact(&mut buf[..take]).ok()?;
                        leaves.extend(proof_leaves_at(suite, offset, &buf[..take], length).ok()?);
                        offset += take as u64;
                    }
                    Some(leaves)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().ok()?)
            .collect()
    });
    let mut leaves = Vec::with_capacity(total as usize);
    for part in parts {
        leaves.extend(part?);
    }
    (leaves.len() as u64 == total).then_some(leaves)
}

/// An object's leaves for `assemble`: from the cache, or computed in
/// parallel and cached. `None` for an object of one leaf or less, which
/// `assemble` reads whatever leaves accompany it.
fn ensure_leaves(proof_root: &Path, object: &ObjectId, path: &Path) -> Option<Vec<[u8; 32]>> {
    if object.length <= PROOF_LEAF_SIZE {
        return None;
    }
    if let Some(leaves) = read_leaves(proof_root, object) {
        return Some(leaves);
    }
    let suite = Suite::try_from(object.suite).ok()?;
    let leaves = compute_leaves(path, suite, object.length)?;
    write_leaves(proof_root, object, &leaves);
    Some(leaves)
}

/// The grant's manifest root and its server, building either that is
/// missing. Runs on the blocking pool: assembling reads every byte of a
/// file it has no leaves for.
pub(crate) fn ensure_server(
    app: &Arc<App>,
    serve: &ServeState,
    grant: &OutboundGrant,
) -> ApiResult<([u8; 32], Arc<vot_cli::BundleServer>)> {
    let _building = BUILDS.lock().expect("manifest builds poisoned");
    let entries = grant_entries(app, grant)?;
    let directory = manifest_directory(app, &grant.id);
    let recorded = app
        .store
        .outbound_grant_manifest_root(&grant.id)
        .map_err(super::store_unavailable)?
        .and_then(|hex| hex::decode(hex).ok())
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok());
    let root = match recorded {
        Some(root)
            if directory
                .join(MANIFEST_DIRECTORY)
                .join(MANIFEST_SEAL)
                .is_file() =>
        {
            root
        }
        _ => {
            let root = write_manifest(&directory, &entries)
                .map_err(|error| ApiError::internal(format!("grant manifest: {error}")))?;
            app.store
                .put_outbound_grant_manifest(&grant.id, &hex::encode(root), now_unix())
                .map_err(super::store_unavailable)?;
            root
        }
    };
    if let Some(server) = serve.registry.server(root) {
        return Ok((root, server));
    }
    let proofs = proof_root(app);
    let mut sources = BTreeMap::new();
    for entry in &entries {
        // From the cache or computed in parallel and cached, so the first
        // fetch of a large grant samples the files instead of reading them.
        sources.insert(
            entry.object.root,
            vot_cli::ServedSource {
                path: entry.path.clone(),
                leaves: ensure_leaves(&proofs, &entry.object, &entry.path),
            },
        );
    }
    let server = match vot_cli::BundleServer::assemble(&directory, sources) {
        Ok(server) => Arc::new(server),
        Err(error) => {
            // A leaf cache that no longer describes its object (bit rot the
            // length and count checks miss) fails assembly with a root
            // mismatch. Drop the caches so the next mint recomputes them
            // rather than failing forever on the same bad bytes.
            for entry in &entries {
                let _ = std::fs::remove_file(leaf_cache_path(&proofs, &entry.object));
            }
            return Err(ApiError::internal(format!(
                "assemble grant server: {error:?}"
            )));
        }
    };
    serve
        .registry
        .servers
        .lock()
        .expect("serve registry poisoned")
        .insert(root, Arc::clone(&server));
    Ok((root, server))
}

/// Assembles a server for every unexpired ticket, so capabilities minted
/// before a restart are honoured after it. Runs off the accept thread so a
/// cold grant's read does not delay the listener; a fetch that arrives
/// before its grant is warmed is refused unknown until its server lands. A
/// grant that fails to build is logged and its tickets refuse.
pub(crate) fn warm(app: &Arc<App>, serve: &ServeState) {
    let tickets = match app.store.unexpired_fetch_tickets(now_unix()) {
        Ok(tickets) => tickets,
        Err(error) => {
            tracing::error!(%error, "live fetch tickets unavailable; nothing warmed");
            return;
        }
    };
    let mut warmed: HashSet<String> = HashSet::new();
    for ticket in tickets {
        if !warmed.insert(ticket.grant_id.clone()) {
            continue;
        }
        let grant = match app.store.outbound_grant_by_id(&ticket.grant_id) {
            Ok(Some(grant)) if grant_open(&grant, now_unix()) => grant,
            Ok(_) => continue,
            Err(error) => {
                tracing::warn!(grant_id = %ticket.grant_id, %error, "grant unavailable while warming");
                continue;
            }
        };
        if let Err(error) = ensure_server(app, serve, &grant) {
            tracing::warn!(grant_id = %grant.id, error = %error.message, "grant server not warmed");
        }
    }
}

/// Drops servers of grants no longer open and tickets long expired. Called
/// from the session sweeper. Servers are kept by the grant's state rather than
/// by tickets, so a server built at mint survives the moment before its ticket
/// is written and a delivered token can fetch again inside its window.
pub(crate) fn prune(app: &App) {
    let Some(serve) = app.serve.as_ref() else {
        return;
    };
    let now = now_unix();
    let servable = match app.store.servable_manifest_roots(now) {
        Ok(servable) => servable,
        Err(error) => {
            tracing::warn!(%error, "servable roots unavailable; registry kept");
            return;
        }
    };
    let roots: HashSet<[u8; 32]> = servable
        .iter()
        .filter_map(|root| decode_root(root))
        .collect();
    serve.registry.retain(&roots);
    if let Err(error) = app
        .store
        .prune_fetch_tickets(now.saturating_sub(TICKET_RETENTION_SECS))
    {
        tracing::warn!(%error, "fetch ticket prune failed");
    }
}

fn decode_root(hex: &str) -> Option<[u8; 32]> {
    hex::decode(hex).ok()?.try_into().ok()
}

#[derive(Deserialize)]
pub struct FetchRequest {
    holder_key: String,
}

/// `POST /api/s/{token}/fetch`: mints a capability for the grant's package,
/// bound to the recipient's holder key, and says where to dial.
pub async fn mint_fetch(
    State(app): State<Arc<App>>,
    AxumPath(token): AxumPath<String>,
    headers: HeaderMap,
    Json(request): Json<FetchRequest>,
) -> ApiResult<Response> {
    let Some(serve) = app.serve.as_ref() else {
        return Err(ApiError::not_found());
    };
    let grant = active_grant(&app, &token)?;
    let _operation = begin_outbound_operation(&app, &grant.tenant)?;
    require_grant_access(&app, &grant, &headers)?;
    if !app.outbound_rate.allow(&grant.token_hash) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many requests for this delivery",
        ));
    }
    let holder = hex::decode(&request.holder_key)
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .filter(|bytes| ed25519_dalek::VerifyingKey::from_bytes(bytes).is_ok())
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "holder_key must be 32 hex bytes of an ed25519 public key",
            )
        })?;
    let now = now_unix();
    let remaining = grant.expires_at.saturating_sub(now);
    if remaining == 0 {
        return Err(ApiError::not_found());
    }
    let seconds = remaining.min(CAPABILITY_TTL_SECS);
    let (root, _server) = {
        let app = Arc::clone(&app);
        let grant = grant.clone();
        tokio::task::spawn_blocking(move || {
            let serve = app.serve.as_ref().expect("serve state disappeared");
            ensure_server(&app, serve, &grant)
        })
        .await
        .map_err(|_| ApiError::internal("grant server build failed"))??
    };
    let capability = vot_cli::authz::issue(
        "votport",
        &serve.audience,
        &serve.issuer,
        holder,
        root,
        now,
        seconds,
    )
    .map_err(|error| ApiError::internal(format!("issue fetch capability: {error:?}")))?;
    let token_id = vot_capability::decode(&capability)
        .ok()
        .and_then(|signed| {
            vot_capability::Capability::from_canonical_bytes(&signed.capability).ok()
        })
        .map(|capability| capability.token_id)
        .ok_or_else(|| ApiError::internal("issued capability does not decode"))?;
    let expires_at = now + seconds;
    // The reservation against max_downloads is taken here, in the insert
    // itself, after the build so a refused mint costs no ticket.
    let reserved = app
        .store
        .put_fetch_ticket(
            &FetchTicket {
                token_id: hex::encode(token_id),
                grant_id: grant.id.clone(),
                manifest_root: hex::encode(root),
                expires_at,
                delivered_at: None,
            },
            grant.downloads,
            grant.max_downloads,
            now,
        )
        .map_err(super::store_unavailable)?;
    if !reserved {
        return Err(ApiError::not_found());
    }
    tracing::info!(
        target: "audit", event = "outbound_fetch_minted", grant_id = %grant.id,
        expires_at, "fetch capability minted"
    );
    app.store.audit(
        &grant.tenant,
        "",
        "outbound_fetch_minted",
        &grant.id,
        &json!({ "expires_at": expires_at, "package_root": hex::encode(root) }),
    );
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({
            "capability": base64::prelude::BASE64_STANDARD.encode(&capability),
            "address": serve.address,
            "certificate_digest": hex::encode(serve.certificate_digest),
            "package_root": hex::encode(root),
            "expires_at": expires_at,
        })),
    )
        .into_response())
}

fn refuse(
    app: &App,
    reason: ServeRefusalReason,
    peer: std::net::SocketAddr,
) -> Option<vot_cli::ServeAdmission> {
    app.serve_metrics.refuse(reason);
    tracing::warn!(
        target: "audit", event = "serve_refused", %peer, reason = reason.label(),
        "fetch session refused"
    );
    None
}

/// Whether a grant may still be fetched: not revoked, not expired, and not
/// exhausted. `max_downloads` counts client deliveries, which is what a
/// fetch session is.
pub(crate) fn grant_open(grant: &OutboundGrant, now: u64) -> bool {
    grant.revoked_at.is_none()
        && grant.expires_at > now
        && !grant
            .max_downloads
            .is_some_and(|max| grant.downloads >= max)
}

/// The admission policy the serve listener runs for every session.
pub(crate) fn admit_fetch(
    app: &Arc<App>,
    presentation: vot_cli::ServePresentation<'_>,
    runtime: &tokio::runtime::Handle,
) -> Option<vot_cli::ServeAdmission> {
    let serve = app.serve.as_ref()?;
    let peer = presentation.peer;
    if !app.serve_rate.allow(&peer.ip().to_string()) {
        return refuse(app, ServeRefusalReason::Rate, peer);
    }
    // The token id and root are read before authentication only to find
    // the ticket and pick the requirement that then authenticates the
    // token; the seam re-checks the granted scope against the server it
    // is answered from.
    let capability = vot_capability::decode(&presentation.open.capability)
        .ok()
        .and_then(|signed| {
            vot_capability::Capability::from_canonical_bytes(&signed.capability).ok()
        });
    let Some(capability) = capability else {
        return refuse(app, ServeRefusalReason::Capability, peer);
    };
    let token = capability.token_id;
    let root = capability.scope.root;
    let ticket = match app.store.fetch_ticket(&hex::encode(token)) {
        Ok(Some(ticket)) => ticket,
        Ok(None) => return refuse(app, ServeRefusalReason::Unknown, peer),
        Err(error) => {
            tracing::error!(%error, "fetch ticket lookup failed during admission");
            return refuse(app, ServeRefusalReason::Unknown, peer);
        }
    };
    if decode_root(&ticket.manifest_root) != Some(root) {
        return refuse(app, ServeRefusalReason::Capability, peer);
    }
    let grant = match app.store.outbound_grant_by_id(&ticket.grant_id) {
        Ok(Some(grant)) => grant,
        Ok(None) => return refuse(app, ServeRefusalReason::Unknown, peer),
        Err(error) => {
            tracing::error!(%error, "grant lookup failed during fetch admission");
            return refuse(app, ServeRefusalReason::Unknown, peer);
        }
    };
    if !grant_open(&grant, presentation.now) {
        return refuse(app, ServeRefusalReason::Closed, peer);
    }
    let Some(server) = serve.registry.server(root) else {
        // Built at mint and warmed off-thread after a restart, so a server
        // can be briefly absent for a valid ticket while warming, or absent
        // because a build failed; both refuse unknown, both are in the log.
        return refuse(app, ServeRefusalReason::Unknown, peer);
    };
    let verifying_key = serve.issuer.verifying_key();
    let requirement = vot_cli::authz::Requirement::new(
        "votport",
        vot_cli::authz::key_id_of(&verifying_key),
        verifying_key,
        &serve.audience,
        root,
    );
    let Some(scope) = requirement.decide(
        presentation.challenge,
        presentation.open,
        presentation.channel_binding,
        presentation.now,
    ) else {
        return refuse(app, ServeRefusalReason::Capability, peer);
    };
    if serve
        .registry
        .claim_slot(app, token, &grant.token_hash)
        .is_err()
    {
        return refuse(app, ServeRefusalReason::Busy, peer);
    }
    tracing::info!(
        target: "audit", event = "serve_admitted", grant_id = %grant.id, %peer,
        "fetch session admitted"
    );
    app.store.audit(
        &grant.tenant,
        "",
        "serve_admitted",
        &grant.id,
        &json!({ "peer": peer.to_string() }),
    );
    let observer = {
        let hold = SessionHold {
            registry: Arc::clone(&serve.registry),
            token,
        };
        let app = Arc::clone(app);
        let runtime = runtime.clone();
        let grant_id = grant.id.clone();
        let tenant = grant.tenant.clone();
        let token_hash = grant.token_hash.clone();
        let notify = grant.notify_on_download;
        let file_count = grant.files.len().max(1);
        Box::new(move |report: vot_cli::ServeReport| {
            // Runs on the session's own thread: bookkeeping only, the store
            // write goes to the blocking pool. A final-cursor report is the
            // fetch's completion acknowledgement; the primary session carries
            // it and the rails do not, so exactly one report records delivery.
            let delivered = report.objects != 0 && report.cursor == Some(report.objects);
            drop(hold);
            app.serve_metrics
                .bytes_total
                .fetch_add(report.served_bytes, Ordering::Relaxed);
            let status = match &report.status {
                Ok(status) => format!("{status:?}"),
                Err(error) => format!("{error:?}"),
            };
            tracing::info!(
                target: "audit", event = "serve_session_ended", grant_id = %grant_id, %peer,
                served_bytes = report.served_bytes, cursor = ?report.cursor, status = %status,
                "fetch session ended"
            );
            if !delivered {
                return;
            }
            let store = Arc::clone(&app.store);
            let notifier = Arc::clone(&app);
            let spawner = runtime.clone();
            runtime.spawn_blocking(move || {
                let now = now_unix();
                let indexes: Vec<usize> = (0..file_count).collect();
                let recorded = store.record_outbound_download(&grant_id, &indexes, now);
                // The reservation closes only with a recorded delivery; a
                // failed record leaves it standing, which errs the safe way.
                if recorded.is_ok() {
                    if let Err(error) = store.mark_fetch_delivered(&hex::encode(token), now) {
                        tracing::warn!(grant_id = %grant_id, %error, "fetch ticket not marked delivered");
                    }
                }
                tracing::info!(
                    target: "audit", event = "serve_completed", grant_id = %grant_id, %peer,
                    recorded = recorded.is_ok(), "fetch delivered"
                );
                store.audit(
                    &tenant,
                    "",
                    "serve_completed",
                    &grant_id,
                    &json!({ "peer": peer.to_string(), "recorded": recorded.is_ok() }),
                );
                match recorded {
                    Ok(result) => {
                        notifier
                            .serve_metrics
                            .deliveries_total
                            .fetch_add(1, Ordering::Relaxed);
                        if notify && (result.first_download || result.completed_delivery) {
                            match store.outbound_grant_by_token_hash(&token_hash) {
                                Ok(Some(full)) => {
                                    spawner.spawn(crate::notify::outbound_downloaded(
                                        Arc::clone(&notifier),
                                        full,
                                        result,
                                    ));
                                }
                                other => {
                                    tracing::warn!(grant_id = %grant_id, ?other, "fetch delivery notification reload failed");
                                }
                            }
                        }
                    }
                    Err(error) => {
                        tracing::warn!(grant_id = %grant_id, %error, "fetch delivery record refused");
                    }
                }
            });
        }) as Box<dyn FnOnce(vot_cli::ServeReport) + Send>
    };
    Some(vot_cli::ServeAdmission {
        server,
        scope,
        observer: Some(observer),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "timing, run with --ignored --nocapture"]
    fn bench_parallel_vs_serial_leaves() {
        use std::io::Read as _;
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("big.bin");
        let length = 512 * PROOF_LEAF_SIZE * 16; // 512 MiB
        let bytes: Vec<u8> = (0..length).map(|index| (index % 251) as u8).collect();
        std::fs::write(&source, &bytes).unwrap();
        drop(bytes);

        let serial_start = std::time::Instant::now();
        let mut builder =
            vot_sdk::object::InMemoryObjectBuilder::new(Suite::Blake3Bao64, Some(length), length)
                .unwrap();
        let mut file = std::fs::File::open(&source).unwrap();
        let mut buf = vec![0u8; 1 << 20];
        loop {
            let read = file.read(&mut buf).unwrap();
            if read == 0 {
                break;
            }
            builder.update(&buf[..read]).unwrap();
        }
        let _ = builder.finish().unwrap();
        let serial = serial_start.elapsed();

        let parallel_start = std::time::Instant::now();
        let leaves = compute_leaves(&source, Suite::Blake3Bao64, length).unwrap();
        let parallel = parallel_start.elapsed();
        assert_eq!(leaves.len() as u64, length.div_ceil(PROOF_LEAF_SIZE));

        let gib = length as f64 / (1024.0 * 1024.0 * 1024.0);
        eprintln!(
            "leaves for {gib:.2} GiB: serial {:.3}s ({:.0} ms/GiB), parallel {:.3}s ({:.0} ms/GiB), {:.1}x",
            serial.as_secs_f64(),
            serial.as_secs_f64() / gib * 1000.0,
            parallel.as_secs_f64(),
            parallel.as_secs_f64() / gib * 1000.0,
            serial.as_secs_f64() / parallel.as_secs_f64(),
        );
    }

    #[test]
    fn leaves_computed_in_parallel_match_the_cache_and_serve_after_the_object_moves() {
        // A file over one leaf, not a multiple of the leaf size, so the last
        // segment is a partial leaf and the parallel split is exercised.
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("reel.bin");
        let length = PROOF_LEAF_SIZE * 3 + 1234;
        let bytes: Vec<u8> = (0..length).map(|index| (index % 251) as u8).collect();
        std::fs::write(&source, &bytes).unwrap();
        let object = {
            let mut builder = vot_sdk::object::InMemoryObjectBuilder::new(
                Suite::Blake3Bao64,
                Some(length),
                length,
            )
            .unwrap();
            builder.update(&bytes).unwrap();
            builder.finish().unwrap().object_id().clone()
        };
        let computed = compute_leaves(&source, Suite::Blake3Bao64, length).unwrap();
        assert_eq!(computed.len() as u64, length.div_ceil(PROOF_LEAF_SIZE));

        let proofs = directory.path().join("outbound.proofs");
        // First call computes and caches; a truncated source afterward still
        // serves, because the cache carries the leaves.
        let first = ensure_leaves(&proofs, &object, &source).unwrap();
        assert_eq!(first, computed);
        assert!(read_leaves(&proofs, &object).is_some());
        std::fs::write(&source, b"gone").unwrap();
        assert_eq!(
            ensure_leaves(&proofs, &object, &source),
            Some(computed.clone())
        );

        // A cache present but naming another length is ignored: write the
        // computed leaves under the object's name but with a header claiming
        // one more leaf, and read_leaves refuses it.
        let mut corrupt = std::fs::read(leaf_cache_path(&proofs, &object)).unwrap();
        corrupt[17..25].copy_from_slice(&(computed.len() as u64 + 1).to_le_bytes());
        std::fs::write(leaf_cache_path(&proofs, &object), &corrupt).unwrap();
        assert!(read_leaves(&proofs, &object).is_none());
        // Restore the good cache for later reads.
        write_leaves(&proofs, &object, &computed);
        // One leaf or less has no tree to hand in.
        let small = ObjectId {
            suite: 1,
            root: [0; 32],
            length: PROOF_LEAF_SIZE,
        };
        assert!(ensure_leaves(&proofs, &small, &source).is_none());
    }

    #[test]
    fn a_grant_is_open_only_while_live_and_unexhausted() {
        let grant = |revoked: Option<u64>, expires_at: u64, downloads: u64, max: Option<u64>| {
            OutboundGrant {
                id: "g".to_owned(),
                token_hash: "h".to_owned(),
                password_hash: None,
                tenant: String::new(),
                link_id: String::new(),
                upload_id: String::new(),
                package_root: String::new(),
                name: "a.bin".to_owned(),
                suite: "blake3".to_owned(),
                root: "00".repeat(32),
                file_index: 0,
                bytes: 1,
                label: "l".to_owned(),
                created_at: 1,
                expires_at,
                revoked_at: revoked,
                downloads,
                max_downloads: max,
                notify_on_download: false,
                first_download_at: None,
                last_download_at: None,
                files: Vec::new(),
            }
        };
        assert!(grant_open(&grant(None, 100, 0, None), 50));
        assert!(!grant_open(&grant(Some(10), 100, 0, None), 50));
        assert!(!grant_open(&grant(None, 50, 0, None), 50));
        assert!(!grant_open(&grant(None, 100, 2, Some(2)), 50));
        assert!(grant_open(&grant(None, 100, 1, Some(2)), 50));
    }

    #[test]
    fn refusal_reasons_are_a_fixed_series() {
        let metrics = ServeMetrics::default();
        for reason in ServeRefusalReason::ALL {
            metrics.refuse(reason);
        }
        assert!(ServeRefusalReason::ALL
            .iter()
            .all(|reason| metrics.refusals(*reason) == 1));
        assert_eq!(
            ServeRefusalReason::ALL
                .iter()
                .map(|reason| reason.label())
                .collect::<Vec<_>>(),
            ["rate", "capability", "unknown", "closed", "busy"]
        );
    }

    #[test]
    fn a_manifest_is_deterministic_ordered_and_refuses_folded_collisions() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("a.bin");
        std::fs::write(&file, b"payload").unwrap();
        let object = |root: u8| ObjectId {
            suite: 1,
            root: [root; 32],
            length: 7,
        };
        let entry = |components: &[&str], root: u8| GrantEntry {
            components: components.iter().map(|part| (*part).to_owned()).collect(),
            object: object(root),
            path: file.clone(),
        };
        let forward = [entry(&["b.txt"], 1), entry(&["sub", "a.txt"], 2)];
        let backward = [entry(&["sub", "a.txt"], 2), entry(&["b.txt"], 1)];
        let first = write_manifest(&directory.path().join("one"), &forward).unwrap();
        let second = write_manifest(&directory.path().join("two"), &backward).unwrap();
        assert_eq!(first, second, "order of input must not change the root");
        assert!(directory
            .path()
            .join("one")
            .join(MANIFEST_DIRECTORY)
            .join(MANIFEST_SEAL)
            .is_file());
        assert!(directory
            .path()
            .join("one")
            .join(MANIFEST_DIRECTORY)
            .join(page_name(0))
            .is_file());
        let different = write_manifest(
            &directory.path().join("three"),
            &[entry(&["b.txt"], 1), entry(&["sub", "a.txt"], 3)],
        )
        .unwrap();
        assert_ne!(first, different, "a different object must change the root");

        let collision = write_manifest(
            &directory.path().join("four"),
            &[entry(&["Report.pdf"], 1), entry(&["report.pdf"], 2)],
        )
        .unwrap_err();
        assert!(
            collision.contains("collide once case is folded"),
            "{collision}"
        );
        let nested = write_manifest(
            &directory.path().join("five"),
            &[entry(&["a"], 1), entry(&["a", "b"], 2)],
        )
        .unwrap_err();
        assert!(nested.contains("package push"), "{nested}");
    }

    #[test]
    fn a_manifest_that_cannot_be_published_leaves_no_stage_behind() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("a.bin");
        std::fs::write(&file, b"payload").unwrap();
        let entries = [GrantEntry {
            components: vec!["a.bin".to_owned()],
            object: ObjectId {
                suite: 1,
                root: [1; 32],
                length: 7,
            },
            path: file,
        }];
        // The target is a file: the stage is written beside it, replacing
        // the target fails, and the stage must go.
        let parent = directory.path().join("grants");
        std::fs::create_dir(&parent).unwrap();
        let target = parent.join("grant");
        std::fs::write(&target, b"in the way").unwrap();
        let error = write_manifest(&target, &entries).unwrap_err();
        assert!(error.contains("replace "), "{error}");
        let leftovers = std::fs::read_dir(&parent)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".stage-"))
            .count();
        assert_eq!(leftovers, 0);
    }

    #[test]
    fn a_running_fetch_keeps_its_slot_past_its_ticket() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let registry = Arc::new(ServeRegistry::default());
        registry.claim_slot(&app, [1; 16], "hash").unwrap();
        registry.claim_slot(&app, [1; 16], "hash").unwrap();
        assert_eq!(registry.active_sessions(), 2);
        // No ticket names the token, but a session still runs: the sweep
        // evicts servers, never slots.
        registry.retain(&HashSet::new());
        assert_eq!(registry.active_sessions(), 2);
        registry.release_slot([1; 16]);
        assert_eq!(registry.active_sessions(), 1);
        registry.release_slot([1; 16]);
        assert_eq!(registry.active_sessions(), 0);
        assert!(
            app.outbound_active.lock().unwrap().is_empty(),
            "the download slot returned with the last session"
        );
        // Admitted but never served (the seam discards the admission and
        // its observer): the hold the observer owns releases on drop.
        registry.claim_slot(&app, [2; 16], "hash").unwrap();
        assert_eq!(registry.active_sessions(), 1);
        drop(SessionHold {
            registry: Arc::clone(&registry),
            token: [2; 16],
        });
        assert_eq!(registry.active_sessions(), 0);
        assert!(app.outbound_active.lock().unwrap().is_empty());
    }
}
