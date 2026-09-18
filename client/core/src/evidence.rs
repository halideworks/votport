//! Verification statements have their own outbox; retrying them never downloads files.

use crate::api::{Client, OutboundMetadata};
use crate::delivery_protocol::{manifest_digest, Evidence, EvidenceKind, SignedChallenge};
use crate::error::{Error, Result};
use crate::identity::{self, Device};
use crate::progress::{Event, Observer};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, Once};
use std::time::Duration;

pub struct Prepared {
    authorization: SignedChallenge,
    key: ed25519_dalek::SigningKey,
}

#[derive(Serialize, Deserialize)]
struct Pending {
    base: String,
    evidence: Evidence,
    /// The share link token the delivery arrived from, kept so acceptance
    /// can request a fresh challenge when the cached one nears expiry.
    /// Older outbox entries predate it and only keep their expired error.
    #[serde(default)]
    token: Option<String>,
}

#[derive(Default, Debug, Clone, uniffi::Record)]
pub struct OutboxStatus {
    pub pending: u64,
    pub recorded: u64,
    pub failed: u64,
}

#[derive(Clone, Debug, Serialize, uniffi::Record)]
pub struct VerificationRecord {
    pub id: String,
    pub server: String,
    pub grant_id: String,
    pub manifest: String,
    pub expires_at: u64,
    pub verification_status: String,
    pub acceptance_status: String,
}

fn prepare(
    client: &Client,
    metadata: &OutboundMetadata,
    device: &Device,
) -> Result<Option<Prepared>> {
    let Some(manifest) = &metadata.delivery_manifest else {
        return Ok(None);
    };
    let base = client.base();
    let authorization = metadata
        .evidence_authorization
        .clone()
        .ok_or_else(|| Error::Other("delivery acknowledgement authorization is missing".into()))?;
    if !authorization.verify(metadata.receipt_key.as_deref().unwrap_or_default())
        || &authorization.challenge.manifest != manifest
        || Some(&authorization.challenge.grant_id) != metadata.grant_id.as_ref()
        || authorization.challenge.holder != device.holder_key_hex()
        || authorization.challenge.origin.trim_end_matches('/') != base.trim_end_matches('/')
    {
        return Err(Error::Other(
            "delivery acknowledgement authorization does not match".into(),
        ));
    }
    Ok(Some(Prepared {
        authorization,
        key: device.signing_key(),
    }))
}

pub fn prepare_receive(
    client: &Client,
    metadata: &OutboundMetadata,
    device: Option<&Device>,
    observer: &mut dyn Observer,
) -> Result<Option<Prepared>> {
    let Some(manifest) = &metadata.delivery_manifest else {
        return Ok(None);
    };
    if *manifest
        != manifest_digest(
            metadata
                .files
                .iter()
                .map(|f| (&*f.name, &*f.suite, &*f.root, f.bytes)),
        )
    {
        return Err(Error::Other(
            "delivery manifest does not match the announced files".into(),
        ));
    }
    if let Some(device) = device {
        if let Ok(prepared) = prepare(client, metadata, device) {
            return Ok(prepared);
        }
    }
    observer.event(Event::Evidence {
        status: "unavailable".into(),
    });
    Ok(None)
}

pub fn complete(
    base: &str,
    prepared: Option<Prepared>,
    token: Option<&str>,
    observer: &mut dyn Observer,
) {
    let Some(prepared) = prepared else {
        return;
    };
    let evidence = Evidence::sign(
        prepared.authorization,
        EvidenceKind::Verified,
        &prepared.key,
    );
    let directory = outbox();
    match enqueue(base, evidence, token.map(str::to_owned), &directory) {
        Ok(_) => {
            observer.event(Event::Evidence {
                status: "pending".into(),
            });
            start_retry_worker();
        }
        Err(_) => observer.event(Event::Evidence {
            status: "unavailable".into(),
        }),
    }
}

fn outbox() -> PathBuf {
    identity::state_dir().join("evidence")
}

fn create_directory(directory: &Path) -> std::io::Result<()> {
    if directory.is_dir() {
        return Ok(());
    }
    if let Some(parent) = directory.parent().filter(|p| !p.as_os_str().is_empty()) {
        create_directory(parent)?;
    }
    match std::fs::create_dir(directory) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && directory.is_dir() => {}
        Err(error) => return Err(error),
    }
    #[cfg(unix)]
    if let Some(parent) = directory.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn enqueue(
    base: &str,
    evidence: Evidence,
    token: Option<String>,
    directory: &Path,
) -> Result<PathBuf> {
    create_directory(directory)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
    }
    let path = directory.join(format!("{}.json", evidence.id()));
    let pending = Pending {
        base: base.into(),
        evidence,
        token,
    };
    let bytes = serde_json::to_vec(&pending).map_err(|e| Error::Other(e.to_string()))?;
    identity::write_private(&path, &bytes)?;
    Ok(path)
}

fn cache(directory: &Path, id: &str, base: &str, evidence: &Evidence) -> Result<()> {
    create_directory(directory)?;
    let bytes = serde_json::to_vec(&Pending {
        base: base.into(),
        evidence: evidence.clone(),
        // Cached copies (accepted statements, retry sources) are never
        // refreshed, so they carry no share token.
        token: None,
    })
    .map_err(|e| Error::Other(e.to_string()))?;
    identity::write_private(&directory.join(format!("{id}.json")), &bytes)
}

fn read_pending(path: &Path) -> Result<Pending> {
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 16384 {
        return Err(Error::Other("invalid acknowledgement outbox entry".into()));
    }
    serde_json::from_slice(&std::fs::read(path)?).map_err(|e| Error::Other(e.to_string()))
}

fn send_pending(path: &Path) -> Result<()> {
    let pending = read_pending(path)?;
    let client = Client::with_timeout(&pending.base, Some(Duration::from_secs(5)))?;
    client.submit_evidence(&pending.evidence)?;
    let directory = path
        .parent()
        .ok_or_else(|| Error::Other("invalid outbox path".into()))?;
    if pending.evidence.kind == EvidenceKind::Verified {
        cache(
            &directory.join("verified"),
            &pending.evidence.id(),
            &pending.base,
            &pending.evidence,
        )?;
    }
    let recorded = directory.join("recorded");
    create_directory(&recorded)?;
    identity::write_private(&recorded.join(pending.evidence.id()), b"recorded")?;
    std::fs::remove_file(path)?;
    #[cfg(unix)]
    std::fs::File::open(directory)?.sync_all()?;
    Ok(())
}

fn report_status(directory: &Path, id: &str) -> String {
    if directory.join("recorded").join(id).is_file() {
        "recorded"
    } else if directory.join(format!("{id}.json")).is_file() {
        "pending"
    } else if directory
        .join("failed")
        .join(format!("{id}.json"))
        .is_file()
    {
        "expired"
    } else {
        "unavailable"
    }
    .into()
}

#[uniffi::export]
pub fn delivery_verifications() -> Vec<VerificationRecord> {
    let directory = outbox();
    let entries = std::fs::read_dir(&directory)
        .into_iter()
        .flatten()
        .chain(
            std::fs::read_dir(directory.join("verified"))
                .into_iter()
                .flatten(),
        )
        .chain(
            std::fs::read_dir(directory.join("failed"))
                .into_iter()
                .flatten(),
        );
    let mut records = vec![];
    let mut seen = std::collections::HashSet::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(pending) = read_pending(&path)
            .or_else(|_| read_pending(&directory.join("verified").join(entry.file_name())))
            .or_else(|_| read_pending(&directory.join("failed").join(entry.file_name())))
        else {
            continue;
        };
        let id = pending.evidence.id();
        if pending.evidence.kind != EvidenceKind::Verified || !seen.insert(id.clone()) {
            continue;
        }
        let challenge = &pending.evidence.authorization.challenge;
        let accepted = read_pending(&directory.join("accepted").join(format!("{id}.json"))).ok();
        records.push(VerificationRecord {
            verification_status: report_status(&directory, &id),
            acceptance_status: accepted.as_ref().map_or_else(
                || "not_accepted".into(),
                |pending| report_status(&directory, &pending.evidence.id()),
            ),
            id,
            server: pending.base,
            grant_id: challenge.grant_id.clone(),
            manifest: challenge.manifest.clone(),
            expires_at: challenge.expires_at,
        });
    }
    records.sort_by(|a, b| {
        b.expires_at
            .cmp(&a.expires_at)
            .then_with(|| a.id.cmp(&b.id))
    });
    records
}

#[uniffi::export]
pub fn accept_delivery(verification_id: String) -> Result<String> {
    accept_in(&outbox(), &verification_id, &Device::load_or_create()?)
}

fn accept_in(directory: &Path, id: &str, device: &Device) -> Result<String> {
    if id.len() != 64 || !id.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::Other("invalid verification ID".into()));
    }
    let mut pending = read_pending(&directory.join(format!("{id}.json")))
        .or_else(|_| read_pending(&directory.join("verified").join(format!("{id}.json"))))?;
    if pending.evidence.id() != id
        || pending.evidence.kind != EvidenceKind::Verified
        || pending.evidence.authorization.challenge.holder != device.holder_key_hex()
        || !pending
            .evidence
            .verify(&pending.evidence.authorization.issuer)
    {
        return Err(Error::Other(
            "this device does not hold the original verification record".into(),
        ));
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // An authorization near or past its expiry is replaced from a fresh
    // challenge when the share token is still held, so a delivery verified
    // early in its window stays acceptable to the end of that window.
    // Best effort: a password-protected delivery needs the grant cookie
    // the original verification used, so a failed refresh keeps the cached
    // authorization and its expired error below.
    if pending.evidence.authorization.challenge.expires_at <= now + ACCEPTANCE_REFRESH_WINDOW {
        let _ = refresh_authorization(&mut pending, device);
    }
    if pending.evidence.authorization.challenge.expires_at <= now {
        return Err(Error::Other(
            "the acceptance authorization has expired; verify the saved delivery files again to request a fresh one".into(),
        ));
    }
    let evidence = Evidence::sign(
        pending.evidence.authorization,
        EvidenceKind::Accepted,
        &device.signing_key(),
    );
    cache(&directory.join("accepted"), id, &pending.base, &evidence)?;
    let path = enqueue(&pending.base, evidence, pending.token, directory)?;
    let status = if send_pending(&path).is_ok() {
        "recorded"
    } else {
        "pending"
    };
    start_retry_worker();
    Ok(status.into())
}

/// How long before an acceptance authorization's expiry acceptance
/// refreshes it from a fresh challenge.
const ACCEPTANCE_REFRESH_WINDOW: u64 = 86_400;

/// Swaps a near-expiry authorization for a fresh challenge from the same
/// server, requiring the same issuer, grant, manifest, and holder so the
/// accepted evidence still attests the original verification.
fn refresh_authorization(pending: &mut Pending, device: &Device) -> Result<()> {
    let token = pending
        .token
        .as_deref()
        .ok_or_else(|| Error::Other("no share link token for a fresh challenge".into()))?;
    let client = Client::with_timeout(&pending.base, Some(Duration::from_secs(5)))?;
    let fresh = client.evidence_challenge(token, None, &device.holder_key_hex())?;
    let original = &pending.evidence.authorization;
    let challenge = &fresh.challenge;
    let unchanged = challenge.grant_id == original.challenge.grant_id
        && challenge.manifest == original.challenge.manifest
        && challenge.holder == original.challenge.holder
        && challenge.origin == original.challenge.origin
        && fresh.issuer == original.issuer
        && fresh.verify(&original.issuer);
    if !unchanged {
        return Err(Error::Other(
            "the fresh acceptance authorization does not match the verified delivery".into(),
        ));
    }
    pending.evidence.authorization = fresh;
    Ok(())
}

#[uniffi::export]
pub fn recipient_device_key() -> Result<String> {
    Ok(Device::load_or_create()?.holder_key_hex())
}

fn retry_in(directory: &Path) -> OutboxStatus {
    for kind in ["verified", "accepted"] {
        for entry in std::fs::read_dir(directory.join(kind))
            .into_iter()
            .flatten()
            .flatten()
        {
            let Ok(pending) = read_pending(&entry.path()) else {
                continue;
            };
            if report_status(directory, &pending.evidence.id()) == "unavailable" {
                let _ = enqueue(&pending.base, pending.evidence, pending.token, directory);
            }
        }
    }
    let mut result = OutboxStatus::default();
    let Ok(entries) = std::fs::read_dir(directory) else {
        return result;
    };
    // ponytail: list the outbox for fair batches; use an indexed queue if it reaches millions of reports.
    let mut paths: Vec<_> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    paths.sort();
    result.pending = paths.len() as u64;
    let cursor = std::fs::read_to_string(directory.join("cursor")).unwrap_or_default();
    let start = paths.partition_point(|p| {
        p.file_name().unwrap_or_default().to_string_lossy().as_ref() <= cursor.as_str()
    });
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    for path in paths[start..].iter().chain(&paths[..start]).take(16) {
        let expired = std::fs::read(path)
            .ok()
            .filter(|bytes| bytes.len() <= 16384)
            .and_then(|bytes| serde_json::from_slice::<Pending>(&bytes).ok())
            .is_some_and(|pending| pending.evidence.authorization.challenge.expires_at <= now);
        let sent = send_pending(path);
        if sent.is_ok() {
            result.recorded += 1;
            result.pending -= 1;
        } else if expired && matches!(sent, Err(Error::Server { status: 401, .. })) {
            let failed = directory.join("failed");
            if std::fs::create_dir_all(&failed)
                .and_then(|()| {
                    std::fs::rename(path, failed.join(path.file_name().unwrap_or_default()))
                })
                .is_ok()
            {
                result.pending -= 1;
            }
        }
        let _ = identity::write_private(
            &directory.join("cursor"),
            path.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .as_bytes(),
        );
    }
    result.failed = std::fs::read_dir(directory.join("failed"))
        .map(|entries| entries.flatten().count() as u64)
        .unwrap_or(0);
    result
}

fn outbox_status(directory: &Path) -> OutboxStatus {
    OutboxStatus {
        pending: std::fs::read_dir(directory)
            .map(|entries| {
                entries
                    .flatten()
                    .filter(|entry| {
                        entry
                            .path()
                            .extension()
                            .is_some_and(|extension| extension == "json")
                    })
                    .count() as u64
            })
            .unwrap_or(0),
        recorded: 0,
        failed: std::fs::read_dir(directory.join("failed"))
            .map(|entries| entries.flatten().count() as u64)
            .unwrap_or(0),
    }
}

#[uniffi::export]
pub fn retry_evidence() -> OutboxStatus {
    static RETRY: Mutex<()> = Mutex::new(());
    // One pass holds this lock across its network round trips, seconds per
    // report. A second caller never queues behind it: it reports the outbox
    // as it stands instead, so a slow retry path cannot stall the FFI.
    match RETRY.try_lock() {
        Ok(_pass) => retry_in(&outbox()),
        Err(std::sync::TryLockError::Poisoned(pass)) => {
            let _pass = pass.into_inner();
            retry_in(&outbox())
        }
        Err(std::sync::TryLockError::WouldBlock) => outbox_status(&outbox()),
    }
}

pub fn start_retry_worker() {
    static START: Once = Once::new();
    START.call_once(|| {
        std::thread::spawn(|| loop {
            retry_evidence();
            std::thread::sleep(Duration::from_secs(60));
        });
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery_protocol::Challenge;

    #[test]
    fn canonical_client_origins_preserve_signed_evidence() {
        let directory = tempfile::tempdir().unwrap();
        let device = Device::load_or_create_in(directory.path()).unwrap();
        let signer = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        let root = "12".repeat(32);
        let manifest = manifest_digest([("file.bin", "blake3", root.as_str(), 8)]);
        for (base, origin) in [
            ("https://DROP.EXAMPLE.com:443/", "https://drop.example.com"),
            ("http://LOCALHOST:80/", "http://localhost"),
            ("http://[::1]:80/", "http://[::1]"),
        ] {
            let authorization = SignedChallenge::issue(
                Challenge {
                    origin: origin.into(),
                    grant_id: "grant".into(),
                    manifest: manifest.clone(),
                    holder: device.holder_key_hex(),
                    nonce: "nonce".into(),
                    issued_at: 1,
                    expires_at: u64::MAX,
                },
                &signer,
            );
            let metadata: OutboundMetadata = serde_json::from_value(serde_json::json!({
                "grant_id": "grant", "delivery_manifest": manifest,
                "evidence_authorization": authorization,
                "receipt_key": hex::encode(signer.verifying_key().to_bytes()),
                "has_password": false,
                "files": [{"name":"file.bin","suite":"blake3","root":root,"bytes":8,"download_url":"/file"}],
            })).unwrap();
            let client = Client::new(base).unwrap();
            let prepared = prepare_receive(
                &client,
                &metadata,
                Some(&device),
                &mut crate::progress::Silent,
            )
            .unwrap()
            .expect("equivalent origin spellings must retain signed evidence");
            assert_eq!(prepared.authorization, authorization);
            assert!(prepared.authorization.verify(&authorization.issuer));
            for other in [
                "https://other.example.com",
                "http://drop.example.com",
                "https://drop.example.com:444",
            ] {
                assert!(prepare_receive(
                    &Client::new(other).unwrap(),
                    &metadata,
                    Some(&device),
                    &mut crate::progress::Silent,
                )
                .unwrap()
                .is_none());
            }
        }
    }

    fn report(base: &str, nonce: &str, expires_at: u64, kind: EvidenceKind) -> Evidence {
        let server = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        let key = ed25519_dalek::SigningKey::from_bytes(&[2; 32]);
        Evidence::sign(
            SignedChallenge::issue(
                Challenge {
                    origin: base.into(),
                    grant_id: "grant".into(),
                    manifest: "manifest".into(),
                    holder: hex::encode(key.verifying_key().to_bytes()),
                    nonce: nonce.into(),
                    issued_at: 1,
                    expires_at,
                },
                &server,
            ),
            kind,
            &key,
        )
    }

    fn respond(
        listener: std::net::TcpListener,
        status: u16,
        body: String,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            use std::io::{BufRead, Read, Write};
            listener.set_nonblocking(true).unwrap();
            for _ in 0..400 {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        stream
                            .set_write_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let mut reader = std::io::BufReader::new(&stream);
                        let mut length = 0;
                        for _ in 0..64 {
                            let mut line = String::new();
                            assert!(reader.read_line(&mut line).unwrap() > 0);
                            if line == "\r\n" {
                                break;
                            }
                            if let Some(value) =
                                line.to_ascii_lowercase().strip_prefix("content-length:")
                            {
                                length = value.trim().parse::<usize>().unwrap();
                            }
                        }
                        assert!(length < 16384);
                        reader.read_exact(&mut vec![0; length]).unwrap();
                        write!(stream,"HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
                        return;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(error) => panic!("{error}"),
                }
            }
            panic!("evidence client did not connect");
        })
    }

    #[test]
    fn only_exact_successful_acknowledgements_remove_reports() {
        for (status, body, recorded) in [
            (302, "valid", false),
            (200, "{}", false),
            (200, "wrong", false),
            (200, "false", false),
            (200, "valid", true),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let evidence = report(&base, "test", u64::MAX, EvidenceKind::Verified);
            let body = match body {
                "valid" => serde_json::json!({"id":evidence.id(),"recorded":true}).to_string(),
                "false" => serde_json::json!({"id":evidence.id(),"recorded":false}).to_string(),
                "wrong" => serde_json::json!({"id":"wrong","recorded":true}).to_string(),
                other => other.into(),
            };
            let path = enqueue(&base, evidence.clone(), None, dir.path()).unwrap();
            let server = respond(listener, status, body);
            let result = retry_in(dir.path());
            server.join().unwrap();
            assert_eq!(result.recorded, u64::from(recorded));
            assert_eq!(path.exists(), !recorded);
            assert_eq!(
                report_status(dir.path(), &evidence.id()),
                if recorded { "recorded" } else { "pending" }
            );
            if recorded {
                assert_eq!(
                    read_pending(
                        &dir.path()
                            .join("verified")
                            .join(format!("{}.json", evidence.id()))
                    )
                    .unwrap()
                    .evidence,
                    evidence
                );
            }
        }
    }

    #[test]
    fn expired_transport_failures_are_retained_and_fair_batches_reach_later_reports() {
        let dir = tempfile::tempdir().unwrap();
        let base = "http://127.0.0.1:1";
        for index in 0..17 {
            enqueue(
                base,
                report(base, &index.to_string(), 1, EvidenceKind::Verified),
                None,
                dir.path(),
            )
            .unwrap();
        }
        let mut paths: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        paths.sort();
        let result = retry_in(dir.path());
        assert_eq!((result.pending, result.failed), (17, 0));
        assert_eq!(
            std::fs::read_to_string(dir.path().join("cursor")).unwrap(),
            paths[15].to_str().unwrap()
        );
        let result = retry_in(dir.path());
        assert_eq!((result.pending, result.failed), (17, 0));
        assert_eq!(
            std::fs::read_to_string(dir.path().join("cursor")).unwrap(),
            paths[14].to_str().unwrap()
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let expired = report(&base, "expired", 1, EvidenceKind::Verified);
        let separate = tempfile::tempdir().unwrap();
        enqueue(&base, expired.clone(), None, separate.path()).unwrap();
        let server = respond(listener, 401, "{}".into());
        let result = retry_in(separate.path());
        server.join().unwrap();
        assert_eq!((result.pending, result.failed), (0, 1));
        assert_eq!(report_status(separate.path(), &expired.id()), "expired");
    }

    #[test]
    fn cached_acceptance_recovers_a_missing_outbox_without_changing_signed_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let base = "http://127.0.0.1:1";
        let verified = report(base, "test", u64::MAX, EvidenceKind::Verified);
        let accepted = report(base, "test", u64::MAX, EvidenceKind::Accepted);
        cache(
            &dir.path().join("verified"),
            &verified.id(),
            base,
            &verified,
        )
        .unwrap();
        cache(
            &dir.path().join("accepted"),
            &verified.id(),
            base,
            &accepted,
        )
        .unwrap();
        assert_eq!(report_status(dir.path(), &accepted.id()), "unavailable");
        assert_eq!(retry_in(dir.path()).pending, 2);
        assert_eq!(
            read_pending(&dir.path().join(format!("{}.json", accepted.id())))
                .unwrap()
                .evidence,
            accepted
        );
        let other = Device::load_or_create_in(&dir.path().join("other")).unwrap();
        assert!(accept_in(dir.path(), &verified.id(), &other).is_err());
        assert!(accept_in(dir.path(), "../invalid", &other).is_err());
    }

    #[test]
    fn failed_acknowledgements_keep_the_complete_signed_record() {
        let dir = tempfile::tempdir().unwrap();
        let server = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        let device = ed25519_dalek::SigningKey::from_bytes(&[2; 32]);
        let authorization = SignedChallenge::issue(
            Challenge {
                origin: "http://127.0.0.1:1".into(),
                grant_id: "grant".into(),
                manifest: "manifest".into(),
                holder: hex::encode(device.verifying_key().to_bytes()),
                nonce: "nonce".into(),
                issued_at: 1,
                expires_at: u64::MAX,
            },
            &server,
        );
        let evidence = Evidence::sign(authorization, EvidenceKind::Verified, &device);
        let path = enqueue("http://127.0.0.1:1", evidence.clone(), None, dir.path()).unwrap();
        let result = retry_in(dir.path());
        assert_eq!((result.pending, result.recorded), (1, 0));
        let saved: Pending = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(saved.evidence, evidence);
        assert!(saved
            .evidence
            .verify(&hex::encode(server.verifying_key().to_bytes())));
    }

    /// A retry pass holds the pass lock across its network round trips, so a
    /// second call must report the outbox as it stands instead of queueing
    /// behind a slow server.
    #[test]
    fn a_retry_pass_in_flight_does_not_stall_the_next_call() {
        use std::io::BufRead;
        let home = tempfile::tempdir().unwrap();
        let _state = crate::identity::test_state_dir(home.path());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        enqueue(
            &base,
            report(&base, "stall", u64::MAX, EvidenceKind::Verified),
            None,
            &outbox(),
        )
        .unwrap();
        let (accepted, in_flight) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(30)))
                .unwrap();
            let _ = accepted.send(());
            // Read the request and answer nothing: the pass stays stuck on
            // its round trip while it holds the lock.
            let mut reader = std::io::BufReader::new(&stream);
            let mut line = String::new();
            loop {
                if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                    break;
                }
                line.clear();
            }
            std::thread::sleep(Duration::from_secs(8));
        });
        let passes = std::thread::spawn(retry_evidence);
        in_flight
            .recv_timeout(Duration::from_secs(5))
            .expect("the stalled pass never reached the server");
        let start = std::time::Instant::now();
        let status = retry_evidence();
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "a pass in flight stalled this caller"
        );
        assert_eq!(
            (status.pending, status.recorded, status.failed),
            (1, 0, 0),
            "the snapshot reports the outbox without sending"
        );
        let stalled = passes.join().unwrap();
        assert_eq!(
            (stalled.pending, stalled.recorded, stalled.failed),
            (1, 0, 0),
            "the stalled pass retains the report for its retry"
        );
        server.join().unwrap();
    }

    /// Answers two sequential requests on one listener: the evidence
    /// challenge refresh, then the acknowledgement submit. Returns each
    /// request's path and body for assertion.
    fn serve_refresh_then_submit(
        listener: std::net::TcpListener,
        responses: Vec<(u16, String)>,
        seen: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            use std::io::{BufRead, Read, Write};
            for (status, body) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut reader = std::io::BufReader::new(&stream);
                let mut request = String::new();
                let mut length = 0;
                for _ in 0..64 {
                    let mut line = String::new();
                    assert!(reader.read_line(&mut line).unwrap() > 0);
                    if line == "\r\n" {
                        break;
                    }
                    if request.is_empty() {
                        request = line.trim().to_owned();
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = value.trim().parse::<usize>().unwrap();
                    }
                }
                assert!(length < 16384);
                let mut payload = vec![0; length];
                reader.read_exact(&mut payload).unwrap();
                seen.lock().unwrap().push((
                    request.split(' ').nth(1).unwrap().to_owned(),
                    String::from_utf8(payload).unwrap(),
                ));
                write!(
                    stream,
                    "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        })
    }

    fn near_expiry_pending(
        dir: &Path,
        base: &str,
        device: &Device,
        expires_in: u64,
        token: Option<String>,
    ) -> (Evidence, String) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let server = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        let authorization = SignedChallenge::issue(
            Challenge {
                origin: base.to_owned(),
                grant_id: "grant".into(),
                manifest: "manifest".into(),
                holder: device.holder_key_hex(),
                nonce: "original".into(),
                issued_at: 1,
                expires_at: now + expires_in,
            },
            &server,
        );
        let evidence = Evidence::sign(authorization, EvidenceKind::Verified, &device.signing_key());
        let id = evidence.id();
        enqueue(base, evidence.clone(), token, dir).unwrap();
        (evidence, id)
    }

    #[test]
    fn acceptance_refreshes_a_near_expiry_authorization_from_a_fresh_challenge() {
        let dir = tempfile::tempdir().unwrap();
        let device = Device::load_or_create_in(&dir.path().join("device")).unwrap();
        let outbox = dir.path().join("outbox");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let (original, id) = near_expiry_pending(&outbox, &base, &device, 100, Some("tok".into()));
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let server_key = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        let fresh = SignedChallenge::issue(
            Challenge {
                origin: original.authorization.challenge.origin.clone(),
                grant_id: "grant".into(),
                manifest: "manifest".into(),
                holder: device.holder_key_hex(),
                nonce: "fresh".into(),
                issued_at: now,
                expires_at: now + 7 * 86400,
            },
            &server_key,
        );
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let accepted_id =
            Evidence::sign(fresh.clone(), EvidenceKind::Accepted, &device.signing_key()).id();
        let server = serve_refresh_then_submit(
            listener,
            vec![
                (200, serde_json::to_value(&fresh).unwrap().to_string()),
                (
                    200,
                    serde_json::json!({"id": accepted_id, "recorded": true}).to_string(),
                ),
            ],
            std::sync::Arc::clone(&seen),
        );
        assert_eq!(
            accept_in(&outbox, &id, &device).unwrap(),
            "recorded",
            "a near-expiry authorization must be refreshed, not refused"
        );
        server.join().unwrap();
        let requests = seen.lock().unwrap().clone();
        assert_eq!(requests.len(), 2);
        assert!(
            requests[0].0.ends_with("/api/s/tok/evidence-challenge"),
            "{}",
            requests[0].0
        );
        assert!(requests[0].1.contains(&device.holder_key_hex()));
        // The accepted statement carries the fresh authorization.
        assert!(requests[1].1.contains("\"nonce\":\"fresh\""));
        let accepted = read_pending(&outbox.join("accepted").join(format!("{id}.json"))).unwrap();
        assert_eq!(
            accepted.evidence.authorization.challenge.expires_at,
            fresh.challenge.expires_at
        );
    }

    #[test]
    fn an_expired_authorization_without_a_token_names_re_verification() {
        let dir = tempfile::tempdir().unwrap();
        let device = Device::load_or_create_in(&dir.path().join("device")).unwrap();
        let outbox = dir.path().join("outbox");
        let (_original, id) = near_expiry_pending(&outbox, "http://127.0.0.1:1", &device, 0, None);
        let error = accept_in(&outbox, &id, &device).unwrap_err().to_string();
        assert!(
            error.contains("verify the saved delivery files again"),
            "{error}"
        );
    }

    #[test]
    fn a_mismatched_fresh_challenge_is_refused_and_keeps_the_cached_one() {
        let dir = tempfile::tempdir().unwrap();
        let device = Device::load_or_create_in(&dir.path().join("device")).unwrap();
        let outbox = dir.path().join("outbox");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let (original, id) = near_expiry_pending(&outbox, &base, &device, 100, Some("tok".into()));
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let server_key = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        // A fresh challenge for a different grant must not replace the
        // verified delivery's authorization.
        let mismatched = SignedChallenge::issue(
            Challenge {
                origin: original.authorization.challenge.origin.clone(),
                grant_id: "other-grant".into(),
                manifest: "manifest".into(),
                holder: device.holder_key_hex(),
                nonce: "fresh".into(),
                issued_at: now,
                expires_at: now + 7 * 86400,
            },
            &server_key,
        );
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let accepted_id = Evidence::sign(
            original.authorization.clone(),
            EvidenceKind::Accepted,
            &device.signing_key(),
        )
        .id();
        let server = serve_refresh_then_submit(
            listener,
            vec![
                (200, serde_json::to_value(&mismatched).unwrap().to_string()),
                (
                    200,
                    serde_json::json!({"id": accepted_id, "recorded": true}).to_string(),
                ),
            ],
            std::sync::Arc::clone(&seen),
        );
        assert_eq!(
            accept_in(&outbox, &id, &device).unwrap(),
            "recorded",
            "the cached authorization is still valid and must be used"
        );
        server.join().unwrap();
        let requests = seen.lock().unwrap().clone();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].0.ends_with("/api/s/tok/evidence-challenge"));
        assert!(
            requests[1].1.contains("\"nonce\":\"original\""),
            "the accepted statement must carry the original authorization: {}",
            requests[1].1
        );
    }
}
