//! Persistent state: request links and their completed uploads.
//!
//! SQLite (WAL, synchronous FULL) in the data directory. Request metadata
//! and upload headers are stored separately from typed file records. Mutations
//! commit durably before returning; capped session events stay on the link row.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(test)]
use std::cell::Cell;

use rusqlite::{Connection, OptionalExtension as _};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use vot_sdk::object::ObjectId;

use crate::config::Config;

pub mod conversion;
mod evidence;
mod notifications;
mod received;
pub use notifications::*;
pub use received::{UploadFilesPage, UploadHeader, UploadPage};
mod routes;
mod trade;
pub use trade::*;
mod webhooks;
mod workflows;
pub use evidence::*;
pub use routes::{InboundRoute, OutboundControl};
pub use webhooks::*;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FileRecord {
    /// Path as named inside the uploaded package.
    pub path: String,
    /// Path actually stored on disk, relative to the owning tenant's subtree.
    pub stored_as: String,
    pub bytes: u64,
    /// Hash suite of the object root ("blake3" or "sha256").
    pub suite: String,
    /// Hex object root the received bytes verified against.
    pub root: String,
    /// Whether a signed `.vot-receipt` sidecar was written next to the file.
    #[serde(default)]
    pub receipt: bool,
    /// Set when the admin deleted the stored file. The freed name can be
    /// reused by later, different content, so a tombstoned record must never
    /// satisfy dedupe even if a same-length file sits at its path again.
    #[serde(default)]
    pub deleted: bool,
}

/// A session that ended without a completed upload: cancelled by the sender
/// or interrupted (disconnect, expiry, terminal error). Kept per link, newest
/// last, capped, so the admin can see what went wrong and how far it got.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionEvent {
    pub at: u64,
    pub started_at: u64,
    /// "cancelled", "interrupted", or "rejected" (begin refused the package).
    pub outcome: String,
    pub detail: String,
    pub received_bytes: u64,
    pub expected_bytes: u64,
    /// Chunks the sender re-sent that were already verified: retries after a
    /// response was lost in transit, so a proxy for how flaky the line was.
    /// (TCP hides actual wire loss; there is no FEC at this layer.)
    #[serde(default)]
    pub replayed_chunks: u64,
    /// Chunks the server refused (bad proof, bounds, state).
    #[serde(default)]
    pub rejected_chunks: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UploadRecord {
    pub id: String,
    /// When the session was created; 0 on records from before this field.
    #[serde(default)]
    pub started_at: u64,
    pub completed_at: u64,
    /// See [`SessionEvent::replayed_chunks`].
    #[serde(default)]
    pub replayed_chunks: u64,
    #[serde(default)]
    pub rejected_chunks: u64,
    /// Transport that completed the upload; `None` is the legacy HTTP value.
    #[serde(default)]
    pub transport: Option<String>,
    /// Hex root of the verified package manifest.
    pub package_root: String,
    pub total_bytes: u64,
    pub files: Vec<FileRecord>,
    /// The session ended before every file was received; `files` holds only
    /// the ones that were published, so they stay visible to retention,
    /// dedupe, and the operator instead of lingering on disk unrecorded.
    #[serde(default)]
    pub partial: bool,
    /// What happened during the transfer, as facts; the admin page renders
    /// the sentences. Capped at LOG_CAP entries by the writer.
    #[serde(default)]
    pub log: Vec<LogEvent>,
}

/// One transfer log entry. `kind` is one of opened, reattached, published,
/// quiet, finished, cancelled, interrupted, dropped, elided.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LogEvent {
    pub at: u64,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
}

/// A fetch capability minted for a grant. See the manifests schema.
#[derive(Clone, Debug, PartialEq)]
pub struct FetchTicket {
    pub holder: String,
    pub grant_token_hash: String,
    pub policy_revision: u64,
    pub token_id: String,
    pub grant_id: String,
    pub manifest_root: String,
    pub expires_at: u64,
    pub delivered_at: Option<u64>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct OutboundGrant {
    pub id: String,
    pub token_hash: String,
    pub password_hash: Option<String>,
    pub tenant: String,
    pub link_id: String,
    pub upload_id: String,
    pub package_root: String,
    pub name: String,
    pub suite: String,
    pub root: String,
    pub file_index: usize,
    pub bytes: u64,
    pub label: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub revoked_at: Option<u64>,
    pub downloads: u64,
    pub max_downloads: Option<u64>,

    pub notifications: Option<crate::store::NotificationPolicy>,
    pub first_download_at: Option<u64>,
    pub last_download_at: Option<u64>,
    pub files: Vec<OutboundGrantFile>,
}

impl OutboundGrant {
    pub(crate) fn validate_names(&self) -> Result<(), String> {
        if self.files.is_empty() {
            crate::paths::admit_portable_paths([self.name.as_str()])
        } else {
            crate::paths::admit_portable_paths(self.files.iter().map(|file| file.name.as_str()))
        }
    }
}

pub struct OutboundGrantFilesPage {
    pub grant: OutboundGrant,
    pub file_count: usize,
    /// Sum over every file in the grant, not only the returned page.
    pub total_bytes: u64,
    pub files: Vec<(usize, OutboundGrantFile)>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AutomationToken {
    pub id: String,
    pub token_hash: String,
    pub tenant: String,
    pub label: String,
    /// Library directory this token may share, itself or below; None means
    /// any directory in the tenant's library.
    pub directory: Option<String>,
    pub permissions: Vec<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub revoked_at: Option<u64>,
    pub last_used_at: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct AutomationOperation {
    pub token_id: String,
    pub operation_id: String,
    pub request_hash: String,
    pub grant_id: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutboundDownloadResult {
    pub first_download: bool,
    pub completed_delivery: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OutboundGrantFile {
    pub source: String,
    pub name: String,
    pub suite: String,
    pub root: String,
    pub bytes: u64,
    pub receipt_b64: String,
    #[serde(default)]
    pub downloads: u64,
    #[serde(default)]
    pub first_download_at: Option<u64>,
    #[serde(default)]
    pub last_download_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Link {
    pub id: String,
    pub label: String,
    /// Owning tenant key ("" = the default tenant).
    #[serde(default)]
    pub tenant: String,
    /// Destination subdirectory relative to the owning tenant's subtree.
    pub dest: String,
    #[serde(default)]
    pub password_hash: Option<String>,
    pub created_at: u64,
    #[serde(default)]
    pub expires_at: Option<u64>,
    #[serde(default)]
    pub max_bytes: Option<u64>,
    pub active: bool,
    #[serde(default)]
    pub legal_hold: bool,
    #[serde(default)]
    pub notifications: Option<crate::store::NotificationPolicy>,
    #[serde(default)]
    pub uploads: Vec<UploadRecord>,
    #[serde(default)]
    pub events: Vec<SessionEvent>,
}

#[derive(Serialize)]
pub struct LinkCursor {
    pub created_at: u64,
    pub id: String,
}

pub struct LinkPage {
    pub links: Vec<Link>,
    pub next_cursor: Option<LinkCursor>,
}

impl Link {
    pub fn usable_now(&self) -> bool {
        self.active && self.expires_at.is_none_or(|at| now_unix() < at)
    }
}

/// A tenant namespace: its own links, receive subtree, and quotas.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tenant {
    /// URL-safe key used in paths and tokens ("" is reserved for default).
    pub key: String,
    #[serde(skip)]
    pub incarnation: String,
    pub label: String,
    /// Group whose members administer this tenant's links (SSO mapping).
    pub admin_group: Option<String>,
    /// Cap on received-but-not-deleted bytes across the tenant's links.
    pub max_total_bytes: Option<u64>,
    pub max_links: Option<u64>,
    /// Cap on concurrent upload sessions for the whole tenant.
    pub max_sessions: Option<u64>,
    pub created_at: u64,
}

/// Recipient-facing branding for a tenant ("" is the default tenant).
#[derive(Clone, Debug, Default, Serialize)]
pub struct Branding {
    pub tenant: String,
    pub name: String,
    /// Empty or "#rrggbb".
    pub color: String,
    /// Empty when no logo is stored; else "png", "jpg", or "svg".
    pub logo_ext: String,
    pub footer_text: String,
    pub footer_link_label: String,
    pub footer_link_url: String,
    pub updated_at: u64,
}

/// An in-progress upload session, persisted so its VOT staging files can
/// re-attach after a restart instead of the transfer starting over.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistedUploadSession {
    pub committed_upload_id: Option<String>,
    pub push_key: Option<String>,
    pub id: String,
    pub link_id: String,
    pub tenant: String,
    pub dest_dir: PathBuf,
    pub dest_rel: String,
    pub package: ObjectId,
    pub max_total_bytes: Option<u64>,
    pub started_at: u64,
    pub files: Vec<PersistedUploadFile>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistedUploadFile {
    pub entry: usize,
    pub display_path: String,
    pub stored_components: Vec<String>,
    pub object: ObjectId,
    pub staging_path: PathBuf,
    pub journal_path: PathBuf,
    pub incarnation: [u8; 16],
    pub profile: vot_sdk_file::CommitProfile,
    pub nas_contract: vot_sdk_file::NasContract,
    /// Contiguous covered offset from zero; the restart resumes from here.
    pub prefix_bytes: u64,
    pub published: bool,
    /// Whether the published file's receipt sidecar was written, carried
    /// into the upload record at finish.
    pub receipt: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct TenantUsage {
    pub tenant: String,
    pub links: u64,
    pub received_bytes: u64,
}

pub struct RetainedReservation {
    pub id: String,
    pub push_key: Option<String>,
    pub bytes: u64,
}

impl Tenant {
    /// The namespace files for this tenant publish into, relative to the
    /// receive root. The default tenant keeps today's layout so existing
    /// deployments see no path change.
    pub fn path_prefix(&self) -> Vec<String> {
        crate::paths::tenant_prefix(&self.key)
    }
}

/// An SSO principal recorded at last successful sign-in.
#[derive(Clone, Debug, Serialize)]
pub struct Principal {
    pub subject: String,
    pub blocked: bool,
    pub credential_version: u64,
    pub last_login_at: u64,
    pub last_groups: Vec<String>,
    #[serde(rename = "grants")]
    pub last_grants: serde_json::Value,
    pub source: String,
    /// The provisioning system's own id for this user (SCIM externalId).
    pub external_id: Option<String>,
    /// Unix seconds the row was created; 0 for rows older than schema v22.
    pub created_at: u64,
}

#[derive(Clone, Copy)]
enum PrincipalPageOrder {
    LastLogin,
    Subject,
}

/// A SCIM group: a name the sign-in role mapping can match, plus members.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScimGroup {
    pub id: String,
    pub display_name: String,
    pub external_id: Option<String>,
    pub created_at: u64,
    pub members: Vec<String>,
}

/// One settings PUT: write TEXT (including empty disable) or delete the row.
#[derive(Clone, Debug)]
pub enum SettingWrite {
    Set(String),
    Reset,
}

/// Env values with a written settings row overlaid. Callers must not cache
/// this across requests: a PUT is visible on the next read.
#[derive(Clone, Debug)]
pub struct ResolvedSettings {
    /// Configured when the relay host and sender address are present.
    pub smtp: Option<ResolvedSmtp>,
    pub audit_retention_days: u64,
    pub upload_retention_days: u64,
    pub default_max_total_bytes: Option<u64>,
    pub default_max_links: Option<u64>,
    pub default_max_sessions: Option<u64>,
    pub public_password_login: bool,
    pub sso_session_secs: u64,
    /// SCIM bearer; None means /scim/v2 answers 401 to everything. A stored
    /// value is `sha256:<hex>`; an env value is the plain token.
    pub scim_token: Option<String>,
    /// The bearer saved before the current one, kept valid until cleared so
    /// a rotation has no gap. Always a stored hash, never from env.
    pub scim_token_previous: Option<String>,
    /// Bearer for GET /api/replica, stored as `sha256:<hex>`; env is plain.
    pub replica_token: Option<String>,
    /// SSO sign-in is refused for subjects without a principal row.
    pub require_provisioning: bool,
    /// When true, new upload sessions are refused so active ones can finish
    /// before a restart. Downloads and admin are unaffected.
    pub draining: bool,
}

/// Assembled SMTP channel. Username and password are optional.
#[derive(Clone, Debug)]
pub struct ResolvedSmtp {
    pub host: String,
    pub port: u16,
    pub starttls: bool,
    pub username: Option<String>,
    pub password: Option<String>,
    pub from: String,
}

/// Resolved settings plus whether each key came from the database or env.
/// `source` is `"env"` when the row is absent or its TEXT was invalid.
#[derive(Clone, Debug)]
pub struct SettingsOverlay {
    pub resolved: ResolvedSettings,

    pub smtp_host: Option<String>,
    pub smtp_host_source: &'static str,
    pub smtp_port: u16,
    pub smtp_port_source: &'static str,
    pub smtp_starttls: bool,
    pub smtp_starttls_source: &'static str,
    pub smtp_username: Option<String>,
    pub smtp_username_source: &'static str,
    pub smtp_password_set: bool,
    pub smtp_password_source: &'static str,
    pub smtp_from: Option<String>,
    pub smtp_from_source: &'static str,

    pub audit_retention_days_source: &'static str,
    pub upload_retention_days_source: &'static str,
    pub default_max_total_bytes_source: &'static str,
    pub default_max_links_source: &'static str,
    pub default_max_sessions_source: &'static str,
    pub public_password_login_source: &'static str,
    pub sso_session_secs_source: &'static str,
    pub scim_token_set: bool,
    pub scim_token_source: &'static str,
    pub scim_token_previous_set: bool,
    pub replica_token_set: bool,
    pub replica_token_source: &'static str,
    pub require_provisioning_source: &'static str,
    pub draining_source: &'static str,
}

pub(crate) const SCHEMA_VERSION: u64 = 44;
pub(crate) const DELIVERED_CANDIDATE_PAGE: usize = 128;

#[cfg(test)]
const TENANT_RECEIVED_VM_UNOBSERVED: u64 = u64::MAX;

#[cfg(test)]
thread_local! {
    static LAST_TENANT_RECEIVED_VM_STEPS: Cell<u64> = const { Cell::new(TENANT_RECEIVED_VM_UNOBSERVED) };
}

#[cfg(test)]
const AUDIT_VM_STEPS_UNOBSERVED: u64 = u64::MAX;

#[cfg(test)]
thread_local! {
    static LAST_AUDIT_VM_STEPS: Cell<u64> = const { Cell::new(AUDIT_VM_STEPS_UNOBSERVED) };
}

pub const OUTBOUND_DOWNLOAD_LIMIT_REACHED: &str = "outbound download limit reached";

const SETTINGS_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    updated_by TEXT NOT NULL DEFAULT ''
);
";

const PRINCIPALS_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS principals (
    subject TEXT PRIMARY KEY,
    credential_version INTEGER NOT NULL DEFAULT 1,
    blocked INTEGER NOT NULL DEFAULT 0,
    last_login_at INTEGER NOT NULL DEFAULT 0,
    last_groups TEXT NOT NULL DEFAULT '[]',
    last_grants TEXT NOT NULL DEFAULT '[]',
    source TEXT NOT NULL DEFAULT 'sso',
    external_id TEXT,
    created_at INTEGER NOT NULL DEFAULT 0
);
";

const PRINCIPALS_IDENTITY_INDEX: &str =
    "CREATE INDEX IF NOT EXISTS principals_external_id ON principals (external_id);";

// Membership can name a subject before provisioning; group names map to roles.
const SCIM_GROUPS_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS scim_groups (
    id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL UNIQUE,
    external_id TEXT,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS scim_group_members (
    group_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    PRIMARY KEY (group_id, subject)
);
CREATE INDEX IF NOT EXISTS scim_group_members_subject ON scim_group_members (subject);
";

const FILES_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS files (
    link_id TEXT NOT NULL,
    tenant TEXT NOT NULL DEFAULT '',
    upload_id TEXT NOT NULL,
    file_index INTEGER NOT NULL,
    bytes_hi INTEGER NOT NULL,
    bytes_lo INTEGER NOT NULL,
    deleted INTEGER NOT NULL DEFAULT 0,
    stored_as TEXT NOT NULL DEFAULT '',
    path TEXT NOT NULL,
    suite TEXT NOT NULL,
    root TEXT NOT NULL,
    receipt INTEGER NOT NULL,
    PRIMARY KEY (link_id, upload_id, file_index)
);
CREATE INDEX IF NOT EXISTS files_tenant_live ON files(tenant, deleted, bytes_hi, bytes_lo);
CREATE INDEX IF NOT EXISTS files_quota_identity ON files(
    tenant,
    CASE WHEN stored_as = '' THEN 1 ELSE 0 END,
    CASE WHEN stored_as = '' THEN '' ELSE stored_as END,
    CASE WHEN stored_as = '' THEN link_id ELSE '' END,
    CASE WHEN stored_as = '' THEN upload_id ELSE '' END,
    CASE WHEN stored_as = '' THEN file_index ELSE 0 END,
    bytes_hi DESC,
    bytes_lo DESC
) WHERE deleted = 0;
CREATE INDEX IF NOT EXISTS files_link_path ON files(link_id, stored_as);
CREATE INDEX IF NOT EXISTS files_delivered_object
ON files(tenant, link_id, suite, root, bytes_hi, bytes_lo, stored_as) WHERE deleted = 0;
CREATE TABLE IF NOT EXISTS link_uploads (
    position INTEGER PRIMARY KEY,
    link_id TEXT NOT NULL,
    tenant TEXT NOT NULL,
    upload_id TEXT NOT NULL,
    document TEXT NOT NULL,
    file_count INTEGER NOT NULL,
    UNIQUE(link_id, upload_id)
);
CREATE INDEX IF NOT EXISTS link_uploads_tenant ON link_uploads(tenant);
CREATE INDEX IF NOT EXISTS link_uploads_link_position ON link_uploads(link_id, position);
";

/// A grant's VOT package root, and the capabilities minted for it. A root
/// is a function of the files, so two grants over one file set share it;
/// the ticket, keyed by the capability's token id, is what names a grant
/// at admission. `delivered_at` closes a ticket's reservation against
/// `max_downloads`.
const OUTBOUND_GRANT_MANIFESTS_SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS outbound_grant_manifests (
        grant_id TEXT PRIMARY KEY,
        manifest_root TEXT NOT NULL,
        created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS outbound_fetch_tickets (
        token_id TEXT PRIMARY KEY,
        grant_id TEXT NOT NULL,
        manifest_root TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        delivered_at INTEGER,
        holder TEXT NOT NULL DEFAULT '',
        grant_token_hash TEXT NOT NULL DEFAULT '',
        policy_revision INTEGER NOT NULL DEFAULT 0,
        admitted_at INTEGER
    );
    CREATE INDEX IF NOT EXISTS outbound_fetch_tickets_grant ON outbound_fetch_tickets(grant_id, expires_at);
";

const OUTBOUND_INDEXES: &str = "
CREATE INDEX IF NOT EXISTS outbound_fetch_tickets_expires ON outbound_fetch_tickets(expires_at);
CREATE INDEX IF NOT EXISTS outbound_grants_open_expires
    ON outbound_grants(expires_at) WHERE revoked_at IS NULL;
";

// Recent pages use rowid order while exports use at,rowid order. Rowid is
// implicit in ordinary indexes, so it cannot appear in CREATE INDEX.
const AUDIT_INDEXES: &str = "
CREATE INDEX IF NOT EXISTS audit_log_tenant ON audit_log(tenant);
CREATE INDEX IF NOT EXISTS audit_log_event ON audit_log(event);
CREATE INDEX IF NOT EXISTS audit_log_tenant_at ON audit_log(tenant,at);
CREATE INDEX IF NOT EXISTS audit_log_event_at ON audit_log(event,at);
";

const OUTBOUND_GRANTS_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS outbound_grants (
    id TEXT PRIMARY KEY,
    token_hash TEXT UNIQUE NOT NULL,
    password_hash TEXT,
    tenant TEXT NOT NULL,
    link_id TEXT NOT NULL,
    upload_id TEXT NOT NULL,
    package_root TEXT NOT NULL,
    name TEXT NOT NULL,
    suite TEXT NOT NULL,
    root TEXT NOT NULL,
    file_index INTEGER NOT NULL,
    bytes_hi INTEGER NOT NULL,
    bytes_lo INTEGER NOT NULL,
    label TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER,
    downloads INTEGER NOT NULL DEFAULT 0,
    max_downloads INTEGER,
    first_download_at INTEGER,
    last_download_at INTEGER,
    files_json TEXT NOT NULL DEFAULT '[]',
    file_count INTEGER NOT NULL DEFAULT 1,
    notifications_json TEXT,
    share_token TEXT
);
CREATE INDEX IF NOT EXISTS outbound_grants_tenant_created ON outbound_grants(tenant, created_at);
CREATE INDEX IF NOT EXISTS outbound_grants_file
    ON outbound_grants(tenant, link_id, upload_id, file_index);
";

const OUTBOUND_GRANT_FILES_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS outbound_grant_files (
    grant_id TEXT NOT NULL,
    file_index INTEGER NOT NULL,
    source TEXT NOT NULL,
    name TEXT NOT NULL,
    suite TEXT NOT NULL,
    root TEXT NOT NULL,
    bytes_hi INTEGER NOT NULL,
    bytes_lo INTEGER NOT NULL,
    receipt_b64 TEXT NOT NULL,
    downloads INTEGER NOT NULL DEFAULT 0,
    first_download_at INTEGER,
    last_download_at INTEGER,
    PRIMARY KEY (grant_id, file_index)
);
CREATE INDEX IF NOT EXISTS outbound_grant_files_downloads
    ON outbound_grant_files(grant_id, downloads);
";

const AUTOMATION_TOKENS_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS automation_tokens (
    id TEXT PRIMARY KEY,
    token_hash TEXT UNIQUE NOT NULL,
    tenant TEXT NOT NULL,
    label TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER,
    last_used_at INTEGER,
    directory TEXT,
    permissions TEXT NOT NULL DEFAULT '[\"deliveries:create\"]'
);
CREATE INDEX IF NOT EXISTS automation_tokens_tenant_created
    ON automation_tokens(tenant, created_at);
";

const BRANDING_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS branding (
    tenant TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    color TEXT NOT NULL DEFAULT '',
    logo_ext TEXT NOT NULL DEFAULT '',
    updated_at INTEGER NOT NULL,
    footer_text TEXT NOT NULL DEFAULT '',
    footer_link_label TEXT NOT NULL DEFAULT '',
    footer_link_url TEXT NOT NULL DEFAULT ''
);
";

// In-progress upload sessions, so a partial transfer can re-attach its VOT
// staging file after a restart instead of starting over. One session row
// plus one row per file; per-file `prefix_bytes` is the contiguous covered
// offset a restart resumes from.
const UPLOAD_SESSIONS_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS upload_sessions (
    id TEXT PRIMARY KEY,
    link_id TEXT NOT NULL,
    tenant TEXT NOT NULL,
    dest_dir TEXT NOT NULL,
    dest_rel TEXT NOT NULL,
    package_suite INTEGER NOT NULL,
    package_root TEXT NOT NULL,
    package_length INTEGER NOT NULL,
    max_total_bytes INTEGER,
    started_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    push_key TEXT,
    committed_upload_id TEXT
);
CREATE UNIQUE INDEX upload_sessions_push_key ON upload_sessions(push_key) WHERE push_key IS NOT NULL;
CREATE INDEX upload_sessions_quota_live ON upload_sessions(tenant, id) WHERE committed_upload_id IS NULL;
CREATE TABLE IF NOT EXISTS upload_session_files (
    session_id TEXT NOT NULL,
    entry INTEGER NOT NULL,
    display_path TEXT NOT NULL,
    stored_components TEXT NOT NULL,
    object_suite INTEGER NOT NULL,
    object_root TEXT NOT NULL,
    object_length INTEGER NOT NULL,
    staging_path TEXT NOT NULL,
    journal_path TEXT NOT NULL,
    incarnation TEXT NOT NULL,
    prefix_bytes INTEGER NOT NULL DEFAULT 0,
    published INTEGER NOT NULL DEFAULT 0,
    receipt INTEGER NOT NULL DEFAULT 0,
    commit_profile TEXT NOT NULL DEFAULT 'balanced' CHECK (commit_profile IN ('fast', 'balanced', 'strict')),
    nas_contract TEXT NOT NULL DEFAULT 'unqualified' CHECK (nas_contract IN ('unqualified', 'server_acknowledged')),
    PRIMARY KEY (session_id, entry)
);
";

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    at INTEGER NOT NULL,
    tenant TEXT NOT NULL DEFAULT '',
    actor TEXT NOT NULL DEFAULT '',
    event TEXT NOT NULL,
    subject TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS audit_log_at ON audit_log(at);
CREATE TABLE IF NOT EXISTS tenants (
    key TEXT PRIMARY KEY,
    incarnation TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    admin_group TEXT,
    max_total_bytes INTEGER,
    max_links INTEGER,
    max_sessions INTEGER,
    created_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS links (
    id TEXT PRIMARY KEY,
    tenant TEXT NOT NULL DEFAULT '',
    label TEXT NOT NULL,
    dest TEXT NOT NULL DEFAULT '',
    password_hash TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    max_bytes INTEGER,
    active INTEGER NOT NULL DEFAULT 1,
    events_json TEXT NOT NULL DEFAULT '[]',
    legal_hold INTEGER NOT NULL DEFAULT 0,
    notifications_json TEXT
);
CREATE INDEX links_tenant ON links(tenant);
CREATE INDEX links_tenant_created ON links(tenant, created_at DESC, id DESC);
CREATE TABLE automation_operations (
    token_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    grant_id TEXT NOT NULL UNIQUE,
    PRIMARY KEY (token_id, operation_id)
);
CREATE TABLE delivery_storage_credentials(id TEXT PRIMARY KEY REFERENCES delivery_storage(id), document TEXT NOT NULL);
CREATE TABLE receive_workflows(link_id TEXT PRIMARY KEY REFERENCES links(id) ON DELETE CASCADE, document TEXT NOT NULL);
CREATE TABLE receive_workflow_uploads(link_id TEXT NOT NULL REFERENCES links(id) ON DELETE CASCADE, upload_id TEXT NOT NULL, PRIMARY KEY(link_id,upload_id));
";

const AUDIT_COUNT_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS audit_log_count (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    rows INTEGER NOT NULL
);
INSERT OR IGNORE INTO audit_log_count(id, rows)
SELECT 1, (SELECT count(*) FROM audit_log)
WHERE NOT EXISTS (SELECT 1 FROM audit_log_count WHERE id = 1);
CREATE TRIGGER IF NOT EXISTS audit_log_count_insert
AFTER INSERT ON audit_log
BEGIN
    UPDATE audit_log_count SET rows = rows + 1 WHERE id = 1;
END;
CREATE TRIGGER IF NOT EXISTS audit_log_count_delete
AFTER DELETE ON audit_log
BEGIN
    UPDATE audit_log_count SET rows = rows - 1 WHERE id = 1;
END;
";

const QUOTA_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS tenant_quota_usage (
    tenant TEXT PRIMARY KEY,
    bytes_hi INTEGER NOT NULL CHECK (bytes_hi BETWEEN 0 AND 4294967295),
    bytes_lo INTEGER NOT NULL CHECK (bytes_lo BETWEEN 0 AND 4294967295),
    state INTEGER NOT NULL CHECK (state IN (0, 1, 2))
);
";

const QUOTA_INDEXES: &str = "
CREATE INDEX IF NOT EXISTS files_quota_identity ON files(
    tenant,
    CASE WHEN stored_as = '' THEN 1 ELSE 0 END,
    CASE WHEN stored_as = '' THEN '' ELSE stored_as END,
    CASE WHEN stored_as = '' THEN link_id ELSE '' END,
    CASE WHEN stored_as = '' THEN upload_id ELSE '' END,
    CASE WHEN stored_as = '' THEN file_index ELSE 0 END,
    bytes_hi DESC,
    bytes_lo DESC
) WHERE deleted = 0;
CREATE INDEX IF NOT EXISTS upload_sessions_quota_live
    ON upload_sessions(tenant, id) WHERE committed_upload_id IS NULL;
";

const QUOTA_BASE: i64 = 4_294_967_296;
const QUOTA_MAX_LIMB: i64 = 4_294_967_295;
// tenant_quota_usage.state: 0 exact, 1 saturated, 2 dirty.

fn quota_identity(alias: &str) -> String {
    format!(
        "CASE WHEN {alias}.stored_as = '' THEN 1 ELSE 0 END,
         CASE WHEN {alias}.stored_as = '' THEN '' ELSE {alias}.stored_as END,
         CASE WHEN {alias}.stored_as = '' THEN {alias}.link_id ELSE '' END,
         CASE WHEN {alias}.stored_as = '' THEN {alias}.upload_id ELSE '' END,
         CASE WHEN {alias}.stored_as = '' THEN {alias}.file_index ELSE 0 END",
    )
}

fn quota_probe(reference: &str, exclude: &str, column: &str) -> String {
    format!(
        "SELECT {column} FROM files AS candidate
         WHERE candidate.tenant = {reference}.tenant AND candidate.deleted = 0
           AND ({identity}) = ({reference_identity})
           AND NOT (candidate.link_id = {exclude}.link_id
                    AND candidate.upload_id = {exclude}.upload_id
                    AND candidate.file_index = {exclude}.file_index)
         ORDER BY candidate.bytes_hi DESC, candidate.bytes_lo DESC LIMIT 1",
        identity = quota_identity("candidate"),
        reference_identity = quota_identity(reference),
    )
}

fn quota_add_update(reference: &str, exclude: &str, live: &str) -> String {
    let previous_hi = quota_probe(reference, exclude, "candidate.bytes_hi");
    let previous_lo = quota_probe(reference, exclude, "candidate.bytes_lo");
    format!(
        "UPDATE tenant_quota_usage
         SET bytes_hi = CASE WHEN bytes_hi + q.delta_hi + (bytes_lo + q.delta_lo >= {base}) > {max}
                             THEN {max} ELSE bytes_hi + q.delta_hi + (bytes_lo + q.delta_lo >= {base}) END,
             bytes_lo = (bytes_lo + q.delta_lo) % {base},
             state = CASE WHEN bytes_hi + q.delta_hi + (bytes_lo + q.delta_lo >= {base}) > {max}
                               OR (bytes_hi + q.delta_hi + (bytes_lo + q.delta_lo >= {base}) = {max}
                                   AND (bytes_lo + q.delta_lo) % {base} = {max})
                          THEN 1 ELSE 0 END
         FROM (
             SELECT CASE WHEN {reference}.bytes_hi > old.bytes_hi
                              OR ({reference}.bytes_hi = old.bytes_hi AND {reference}.bytes_lo > old.bytes_lo)
                         THEN {reference}.bytes_hi - old.bytes_hi - ({reference}.bytes_lo < old.bytes_lo)
                         ELSE 0 END AS delta_hi,
                    CASE WHEN {reference}.bytes_hi > old.bytes_hi
                              OR ({reference}.bytes_hi = old.bytes_hi AND {reference}.bytes_lo > old.bytes_lo)
                         THEN ({reference}.bytes_lo - old.bytes_lo + {base}) % {base}
                         ELSE 0 END AS delta_lo
             FROM (SELECT COALESCE(({previous_hi}), 0) AS bytes_hi,
                          COALESCE(({previous_lo}), 0) AS bytes_lo) AS old
         ) AS q
         WHERE tenant = {reference}.tenant AND state = 0 AND {live}",
        base=QUOTA_BASE,
        max=QUOTA_MAX_LIMB,
    )
}

fn quota_remove_update(reference: &str, exclude: &str, live: &str) -> String {
    let remaining_hi = quota_probe(reference, exclude, "candidate.bytes_hi");
    let remaining_lo = quota_probe(reference, exclude, "candidate.bytes_lo");
    format!(
        "UPDATE tenant_quota_usage
         SET bytes_hi = CASE WHEN bytes_hi < q.delta_hi
                                  OR (bytes_hi = q.delta_hi AND bytes_lo < q.delta_lo)
                             THEN bytes_hi
                             ELSE bytes_hi - q.delta_hi - (bytes_lo < q.delta_lo) END,
             bytes_lo = CASE WHEN bytes_hi < q.delta_hi
                                  OR (bytes_hi = q.delta_hi AND bytes_lo < q.delta_lo)
                             THEN bytes_lo
                             ELSE (bytes_lo - q.delta_lo + {base}) % {base} END,
             state = CASE WHEN state = 1 AND q.removed THEN 2
                          WHEN state = 0 AND (bytes_hi < q.delta_hi
                               OR (bytes_hi = q.delta_hi AND bytes_lo < q.delta_lo)) THEN 2
                          ELSE state END
         FROM (
             SELECT CASE WHEN old.bytes_hi > remaining.bytes_hi
                              OR (old.bytes_hi = remaining.bytes_hi AND old.bytes_lo > remaining.bytes_lo)
                         THEN 1 ELSE 0 END AS removed,
                    CASE WHEN old.bytes_hi > remaining.bytes_hi
                              OR (old.bytes_hi = remaining.bytes_hi AND old.bytes_lo > remaining.bytes_lo)
                         THEN old.bytes_hi - remaining.bytes_hi - (old.bytes_lo < remaining.bytes_lo)
                         ELSE 0 END AS delta_hi,
                    CASE WHEN old.bytes_hi > remaining.bytes_hi
                              OR (old.bytes_hi = remaining.bytes_hi AND old.bytes_lo > remaining.bytes_lo)
                         THEN (old.bytes_lo - remaining.bytes_lo + {base}) % {base}
                         ELSE 0 END AS delta_lo
             FROM (SELECT {reference}.bytes_hi, {reference}.bytes_lo) AS old
             CROSS JOIN (SELECT COALESCE(({remaining_hi}), 0) AS bytes_hi,
                                COALESCE(({remaining_lo}), 0) AS bytes_lo) AS remaining
         ) AS q
         WHERE tenant = {reference}.tenant AND state IN (0, 1) AND {live}",
        base=QUOTA_BASE,
    )
}

fn quota_ensure_row(reference: &str, exclude: &str) -> String {
    format!(
        "INSERT INTO tenant_quota_usage(tenant, bytes_hi, bytes_lo, state)
         SELECT {reference}.tenant, 0, 0,
                CASE WHEN EXISTS(
                    SELECT 1 FROM files AS existing
                    WHERE existing.tenant = {reference}.tenant AND existing.deleted = 0
                      AND NOT (existing.link_id = {exclude}.link_id
                               AND existing.upload_id = {exclude}.upload_id
                               AND existing.file_index = {exclude}.file_index)
                ) THEN 2 ELSE 0 END
         WHERE NOT EXISTS(SELECT 1 FROM tenant_quota_usage WHERE tenant={reference}.tenant)
         ON CONFLICT(tenant) DO NOTHING;"
    )
}

fn quota_trigger_sql() -> String {
    let add_insert = quota_add_update("NEW", "NEW", "1");
    let remove_delete = quota_remove_update("OLD", "OLD", "1");
    let remove_update = quota_remove_update("OLD", "NEW", "OLD.deleted = 0");
    let add_update = quota_add_update("NEW", "NEW", "NEW.deleted = 0");
    let ensure_insert = quota_ensure_row("NEW", "NEW");
    let ensure_delete = quota_ensure_row("OLD", "OLD");
    let ensure_old_update = quota_ensure_row("OLD", "NEW");
    let ensure_new_update = quota_ensure_row("NEW", "NEW");
    format!(
        "CREATE TRIGGER tenant_quota_usage_insert AFTER INSERT ON files
         WHEN NEW.deleted = 0 BEGIN
             {ensure_insert}
             {add_insert};
         END;
         CREATE TRIGGER tenant_quota_usage_delete AFTER DELETE ON files
         WHEN OLD.deleted = 0
              AND NOT EXISTS(
                  SELECT 1 FROM tenant_quota_usage
                  WHERE tenant=OLD.tenant AND state=2
              ) BEGIN
             {ensure_delete}
             {remove_delete};
         END;
         CREATE TRIGGER tenant_quota_usage_update
         AFTER UPDATE OF tenant, link_id, upload_id, file_index, bytes_hi, bytes_lo, deleted, stored_as ON files
         WHEN (OLD.tenant, OLD.link_id, OLD.upload_id, OLD.file_index, OLD.bytes_hi, OLD.bytes_lo, OLD.deleted, OLD.stored_as)
            IS NOT (NEW.tenant, NEW.link_id, NEW.upload_id, NEW.file_index, NEW.bytes_hi, NEW.bytes_lo, NEW.deleted, NEW.stored_as)
         BEGIN
             {ensure_old_update}
             {ensure_new_update}
             {remove_update};
             {add_update};
         END;",
    )
}

/// Audit rows the store failed to persist since boot; exported on /metrics.
pub static AUDIT_INSERT_FAILURES: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

pub struct Store {
    pub(crate) upload_allocation: Mutex<()>,
    connection: Mutex<Connection>,
    pub(crate) event_signer: std::sync::Arc<crate::receipt::ReceiptSigner>,
    path: PathBuf,
    settings_generation: std::sync::atomic::AtomicU64,
}

impl Store {
    pub fn open(data_dir: &Path) -> Result<Self, String> {
        if data_dir
            .join("state.json")
            .try_exists()
            .map_err(|e| e.to_string())?
        {
            return Err("state.json is unsupported; preserve it and use a matching release to export the data".into());
        }
        std::fs::create_dir_all(data_dir)
            .map_err(|error| format!("create {}: {error}", data_dir.display()))?;
        crate::paths::tighten_private_dir(data_dir)?;
        crate::paths::tighten_private_dir_contents(&data_dir.join("backups"))?;
        let promotion = data_dir
            .join(crate::standby::STATUS_FILE)
            .try_exists()
            .map_err(|e| e.to_string())?;
        let path = data_dir.join("votport.db");
        // Closing another descriptor for a live SQLite file releases its POSIX locks.
        // Tighten permissions before opening; new journals inherit the database mode.
        match crate::paths::tighten_private_file(&path)? {
            true => {}
            false if promotion => {
                return Err("standby has no database; pull a valid replica before promotion".into())
            }
            false => match crate::paths::create_private_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    crate::paths::tighten_private_file(&path)?;
                }
                Err(error) => return Err(format!("create {}: {error}", path.display())),
            },
        }
        let wal = path.with_file_name("votport.db-wal");
        let shm = path.with_file_name("votport.db-shm");
        crate::paths::tighten_private_file(&wal)?;
        crate::paths::tighten_private_file(&shm)?;
        let mut connection =
            Connection::open(&path).map_err(|error| format!("open {}: {error}", path.display()))?;
        // Refusing an unsupported database must not checkpoint its surviving WAL.
        connection
            .set_db_config(
                rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
                true,
            )
            .map_err(|e| e.to_string())?;
        connection
            .create_scalar_function(
                "votport_within",
                2,
                rusqlite::functions::FunctionFlags::SQLITE_UTF8
                    | rusqlite::functions::FunctionFlags::SQLITE_DETERMINISTIC,
                |context| {
                    Ok(crate::workflow::within(
                        &context.get::<String>(0)?,
                        &context.get::<String>(1)?,
                    ))
                },
            )
            .map_err(|e| e.to_string())?;
        if promotion {
            validate_schema(&connection, SCHEMA_VERSION)
                .map_err(|e| format!("pull a valid replica before promotion: {e}"))?;
        } else {
            initialize_schema(&mut connection)?;
        }
        let transaction = connection.transaction().map_err(|e| e.to_string())?;
        transaction
            .execute_batch(workflows::INDEXES)
            .map_err(|e| e.to_string())?;
        transaction
            .execute_batch(OUTBOUND_INDEXES)
            .map_err(|e| e.to_string())?;
        transaction
            .execute_batch(AUDIT_INDEXES)
            .map_err(|e| e.to_string())?;
        transaction
            .execute_batch(AUDIT_COUNT_SCHEMA)
            .map_err(|e| e.to_string())?;
        transaction.commit().map_err(|e| e.to_string())?;
        connection
            .set_db_config(
                rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
                false,
            )
            .map_err(|e| e.to_string())?;
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(|error| error.to_string())?;
        // A completed mutation must survive power loss.
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(|error| error.to_string())?;
        // Read-path tuning; durability is governed by the two pragmas above.
        // 64 MiB page cache keeps hot index pages resident, mmap skips a
        // copy for OS-cached pages, and temp b-trees stay off disk.
        connection
            .pragma_update(None, "cache_size", -64000)
            .map_err(|error| error.to_string())?;
        connection
            .pragma_update(None, "mmap_size", 268435456)
            .map_err(|error| error.to_string())?;
        connection
            .pragma_update(None, "temp_store", "MEMORY")
            .map_err(|error| error.to_string())?;
        // The hot-path statement set must fit or the LRU silently defeats
        // prepare_cached; default capacity is too small at 16.
        connection.set_prepared_statement_cache_capacity(64);
        std::fs::File::open(data_dir)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("sync {}: {error}", data_dir.display()))?;
        let store = Self {
            upload_allocation: Mutex::new(()),
            connection: Mutex::new(connection),
            event_signer: std::sync::Arc::new(crate::receipt::ReceiptSigner::load_or_create(
                data_dir,
            )?),
            path: path.clone(),
            settings_generation: std::sync::atomic::AtomicU64::new(0),
        };
        Ok(store)
    }

    /// Runs `f` with the connection, mapping SQL errors into strings.
    pub(crate) fn with<T>(
        &self,
        f: impl FnOnce(&Connection) -> rusqlite::Result<T>,
    ) -> Result<T, String> {
        let connection = self.connection.lock().expect("store poisoned");
        f(&connection).map_err(|error| error.to_string())
    }

    pub fn health_check(&self) -> Result<(), String> {
        self.with(|connection| {
            connection
                .query_row("SELECT 1", [], |row| row.get::<_, i64>(0))
                .and_then(|_| {
                    connection
                        .query_row("SELECT 1 FROM meta LIMIT 1", [], |row| row.get::<_, i64>(0))
                })
                .map(|_| ())
        })
    }

    pub fn admin_password_hash(&self) -> Result<Option<String>, String> {
        self.with(|connection| {
            connection
                .query_row(
                    "SELECT value FROM meta WHERE key = 'admin_password_hash'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .optional()
        })
    }

    pub fn set_admin_password_hash(&self, hash: String) -> Result<(), String> {
        self.with(|connection| {
            connection
                .execute(
                    "INSERT INTO meta (key, value) VALUES ('admin_password_hash', ?1)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    [hash],
                )
                .map(|_| ())
        })
    }

    pub fn insert_automation_token(&self, token: AutomationToken) -> Result<(), String> {
        self.with(|connection| {
            connection
                .execute(
                    "INSERT INTO automation_tokens
                         (id, token_hash, tenant, label, created_at, expires_at, revoked_at,
                          last_used_at, directory, permissions)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    rusqlite::params![
                        token.id,
                        token.token_hash,
                        token.tenant,
                        token.label,
                        i64::try_from(token.created_at).unwrap_or(i64::MAX),
                        i64::try_from(token.expires_at).unwrap_or(i64::MAX),
                        token
                            .revoked_at
                            .map(|at| i64::try_from(at).unwrap_or(i64::MAX)),
                        token
                            .last_used_at
                            .map(|at| i64::try_from(at).unwrap_or(i64::MAX)),
                        token.directory,
                        serde_json::to_string(&token.permissions).unwrap(),
                    ],
                )
                .map(|_| ())
        })
    }

    pub fn automation_tokens(&self, tenant: &str) -> Result<Vec<AutomationToken>, String> {
        self.with(|connection| {
            let mut statement = connection.prepare(
                "SELECT id, token_hash, tenant, label, created_at, expires_at, revoked_at,
                        last_used_at, directory, permissions
                 FROM automation_tokens
                 WHERE tenant = ?1 ORDER BY created_at, rowid",
            )?;
            let rows = statement.query_map([tenant], map_automation_token)?;
            rows.collect::<Result<Vec<_>, _>>()
        })
    }

    pub fn authenticate_automation_token(
        &self,
        token_hash: &str,
        at: u64,
    ) -> Result<Option<AutomationToken>, String> {
        let at = i64::try_from(at).unwrap_or(i64::MAX);
        self.with(|connection| {
            connection
                .query_row(
                    "UPDATE automation_tokens
                     SET last_used_at = ?2
                     WHERE token_hash = ?1 AND revoked_at IS NULL AND expires_at > ?2
                     RETURNING id, token_hash, tenant, label, created_at, expires_at,
                               revoked_at, last_used_at, directory, permissions",
                    rusqlite::params![token_hash, at],
                    map_automation_token,
                )
                .optional()
        })
    }

    pub fn revoke_automation_token(&self, tenant: &str, id: &str, at: u64) -> Result<bool, String> {
        self.with(|connection| {
            connection
                .execute(
                    "UPDATE automation_tokens SET revoked_at = ?3
                     WHERE tenant = ?1 AND id = ?2 AND revoked_at IS NULL",
                    rusqlite::params![tenant, id, i64::try_from(at).unwrap_or(i64::MAX)],
                )
                .map(|changed| changed > 0)
        })
    }

    pub fn automation_operation(
        &self,
        token_id: &str,
        operation_id: &str,
    ) -> Result<Option<AutomationOperation>, String> {
        self.with(|connection| connection.query_row(
            "SELECT token_id, operation_id, request_hash, grant_id FROM automation_operations WHERE token_id = ?1 AND operation_id = ?2",
            rusqlite::params![token_id, operation_id],
            |row| Ok(AutomationOperation { token_id: row.get(0)?, operation_id: row.get(1)?, request_hash: row.get(2)?, grant_id: row.get(3)? }),
        ).optional())
    }

    pub fn automation_delivery(
        &self,
        token_id: &str,
        grant_id: &str,
    ) -> Result<Option<(String, String)>, String> {
        self.with(|connection| connection.query_row(
            "SELECT o.operation_id, g.token_hash FROM automation_operations o JOIN outbound_grants g ON g.id = o.grant_id WHERE o.token_id = ?1 AND o.grant_id = ?2",
            rusqlite::params![token_id, grant_id], |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional())
    }

    pub fn automation_deliveries(
        &self,
        token_id: &str,
        after: i64,
        limit: usize,
    ) -> Result<Vec<(i64, String, String)>, String> {
        self.with(|connection| {
            let mut statement = connection.prepare("SELECT o.rowid, o.grant_id, g.token_hash FROM automation_operations o JOIN outbound_grants g ON g.id = o.grant_id WHERE o.token_id = ?1 AND o.rowid > ?2 ORDER BY o.rowid LIMIT ?3")?;
            let rows = statement.query_map(rusqlite::params![token_id, after, limit as i64], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
            rows.collect()
        })
    }

    pub fn links(&self, tenant: &str) -> Result<Vec<Link>, String> {
        self.with(|connection| {
            let mut statement = connection.prepare(
                "SELECT id, tenant, label, dest, password_hash, created_at, expires_at, max_bytes,
                        active, legal_hold, events_json, notifications_json
                 FROM links WHERE tenant = ?1 ORDER BY rowid",
            )?;
            let rows =
                statement.query_map([tenant], |row| row_to_link_with_uploads(connection, row))?;
            rows.collect::<Result<Vec<_>, _>>()
        })
    }

    /// Spools one grouped pass of live received-file metadata. The caller can
    /// release the Store lock before checking each path on the storage volume.
    pub(crate) fn write_tenant_live_files<W: std::io::Write>(
        &self,
        tenant: &str,
        output: &mut W,
    ) -> Result<(), String> {
        self.with(|connection| {
            walk_quota_files(connection, Some(tenant), |identity, bytes| {
                serde_json::to_writer(&mut *output, &(&identity.stored_as, bytes))
                    .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
                output
                    .write_all(b"\n")
                    .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))
            })?;
            Ok(())
        })
    }

    /// Live received files in one tenant namespace (count, bytes), a physical
    /// file counted once however many records reference it.
    pub fn tenant_stored(&self, tenant: &str) -> Result<(u64, u64), String> {
        self.with(|connection| {
            let (count, total, state) = quota_fold(connection, tenant)?;
            Ok((count, if state == 1 { u64::MAX } else { total }))
        })
    }

    /// Issued downloads in one tenant namespace: links usable now (not
    /// revoked, not expired, not exhausted), request sets in total,
    /// and how many of `active_hashes` (token hashes with a download in
    /// flight) belong to this tenant.
    pub fn outbound_summary(
        &self,
        tenant: &str,
        now: u64,
        active_hashes: &[String],
    ) -> Result<OutboundSummary, String> {
        let hashes = serde_json::to_string(active_hashes).unwrap_or_else(|_| "[]".to_owned());
        self.with(|connection| {
            connection
                .prepare_cached(
                    "SELECT COALESCE(SUM(revoked_at IS NULL AND expires_at > ?2
                                         AND (max_downloads IS NULL OR downloads < max_downloads)), 0),
                            COALESCE(SUM(downloads), 0),
                            COALESCE(SUM(token_hash IN (SELECT value FROM json_each(?3))), 0)
                     FROM outbound_grants WHERE tenant = ?1",
                )?
                .query_row(
                    rusqlite::params![tenant, i64::try_from(now).unwrap_or(i64::MAX), hashes],
                    |row| {
                        let open: i64 = row.get(0)?;
                        let deliveries: i64 = row.get(1)?;
                        let active: i64 = row.get(2)?;
                        Ok(OutboundSummary {
                            open_grants: u64::try_from(open).unwrap_or(0),
                            deliveries: u64::try_from(deliveries).unwrap_or(0),
                            active: u64::try_from(active).unwrap_or(0),
                        })
                    },
                )
        })
    }

    /// Counts the current in-flight grants using only their bounded token-hash
    /// set. The status cache owns the full grant scan; this keeps active state
    /// current without repeating it.
    pub(crate) fn outbound_active_count(
        &self,
        tenant: &str,
        active_hashes: &[String],
    ) -> Result<u64, String> {
        let hashes = serde_json::to_string(active_hashes).unwrap_or_else(|_| "[]".to_owned());
        self.with(|connection| {
            connection
                .prepare_cached(
                    "SELECT COUNT(DISTINCT active.value)
                     FROM json_each(?2) AS active
                     WHERE EXISTS(
                         SELECT 1 FROM outbound_grants
                         WHERE token_hash = active.value AND tenant = ?1
                     )",
                )?
                .query_row(rusqlite::params![tenant, hashes], |row| {
                    let count: i64 = row.get(0)?;
                    Ok(u64::try_from(count).unwrap_or(0))
                })
        })
    }

    /// Uploads completed at or after `since` in one tenant namespace (count,
    /// bytes), partial records excluded. Polled, so the statement is cached
    /// and the tenant filter keeps links_tenant_created in play.
    pub fn uploads_since(&self, tenant: &str, since: u64) -> Result<(u64, u64), String> {
        self.with(|connection| {
            let mut statement = connection.prepare_cached(
                "SELECT upload.document -> '$.total_bytes'
                 FROM links JOIN link_uploads AS upload ON upload.link_id=links.id
                 WHERE links.tenant = ?1
                   AND json_extract(upload.document, '$.completed_at') >= ?2
                   AND COALESCE(json_extract(upload.document, '$.partial'), 0) = 0",
            )?;
            let rows = statement.query_map(
                rusqlite::params![tenant, i64::try_from(since).unwrap_or(i64::MAX)],
                |row| {
                    let token = row.get::<_, Option<String>>(0)?;
                    token
                        .map(|token| {
                            serde_json::from_str::<u64>(&token).map_err(|error| {
                                rusqlite::Error::ToSqlConversionFailure(Box::new(error))
                            })
                        })
                        .transpose()
                        .map(|total| total.unwrap_or(0))
                },
            )?;
            let mut count = 0u64;
            let mut bytes = 0u64;
            for row in rows {
                let total = row?;
                count = count.saturating_add(1);
                bytes = bytes.saturating_add(total);
            }
            Ok((count, bytes))
        })
    }

    /// Global search across one tenant: requests by label, destination, or
    /// id; downloads by label or file name; received files by path. Each
    /// group is capped at `limit`, newest first. Paths live inside each
    /// link's upload JSON, so the file group walks the tenant's links.
    // ponytail: the file group parses every upload record in the tenant per
    // keystroke; a path column on `files` or FTS5 is the upgrade once a
    // tenant holds tens of thousands of records.
    pub fn search(&self, tenant: &str, query: &str, limit: u64) -> Result<SearchResults, String> {
        let needle = format!("%{}%", escape_like(&query.to_lowercase()));
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        self.with(|connection| {
            let requests = connection
                .prepare_cached(
                    "SELECT id, label, dest, active, expires_at, created_at
                     FROM links
                     WHERE tenant = ?1
                       AND (lower(label) LIKE ?2 ESCAPE '\\'
                            OR lower(dest) LIKE ?2 ESCAPE '\\'
                            OR id LIKE ?2 ESCAPE '\\')
                     ORDER BY created_at DESC LIMIT ?3",
                )?
                .query_map(rusqlite::params![tenant, needle, limit], |row| {
                    let expires_at: Option<i64> = row.get(4)?;
                    Ok(SearchRequest {
                        id: row.get(0)?,
                        label: row.get(1)?,
                        dest: row.get(2)?,
                        active: row.get::<_, i64>(3)? != 0,
                        expires_at: expires_at.and_then(|at| u64::try_from(at).ok()),
                        created_at: row
                            .get::<_, i64>(5)
                            .map(|at| u64::try_from(at).unwrap_or(0))?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let downloads = connection
                .prepare_cached(
                    "SELECT id, label, name, created_at, revoked_at IS NOT NULL
                     FROM outbound_grants
                     WHERE tenant = ?1
                       AND (lower(label) LIKE ?2 ESCAPE '\\'
                            OR lower(name) LIKE ?2 ESCAPE '\\')
                     ORDER BY created_at DESC LIMIT ?3",
                )?
                .query_map(rusqlite::params![tenant, needle, limit], |row| {
                    Ok(SearchDownload {
                        id: row.get(0)?,
                        label: row.get(1)?,
                        name: row.get(2)?,
                        created_at: row
                            .get::<_, i64>(3)
                            .map(|at| u64::try_from(at).unwrap_or(0))?,
                        revoked: row.get::<_, i64>(4)? != 0,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let files = connection
                .prepare_cached(
                    "SELECT links.id, links.label,
                            upload.upload_id,
                            file.path, file.bytes_hi, file.bytes_lo,
                            json_extract(upload.document, '$.completed_at')
                     FROM links JOIN link_uploads AS upload ON upload.link_id=links.id
                     JOIN files AS file ON file.link_id=upload.link_id AND file.upload_id=upload.upload_id
                     WHERE links.tenant = ?1
                       AND file.deleted = 0
                       AND lower(file.path) LIKE ?2 ESCAPE '\\'
                     ORDER BY json_extract(upload.document, '$.completed_at') DESC LIMIT ?3",
                )?
                .query_map(rusqlite::params![tenant, needle, limit], |row| {
                    Ok(SearchFile {
                        link_id: row.get(0)?,
                        link_label: row.get(1)?,
                        upload_id: row.get(2)?,
                        path: row.get(3)?,
                        bytes: (u64::from(row.get::<_, u32>(4)?) << 32) | u64::from(row.get::<_, u32>(5)?),
                        completed_at: row
                            .get::<_, i64>(6)
                            .map(|at| u64::try_from(at).unwrap_or(0))?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(SearchResults {
                requests,
                downloads,
                files,
            })
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn links_page(
        &self,
        tenant: &str,
        limit: u64,
        before: Option<&LinkCursor>,
        search: &str,
        status: &str,
        now: u64,
        route_eligible: bool,
    ) -> Result<LinkPage, String> {
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        let sql_limit = i64::try_from(limit.saturating_add(1)).unwrap_or(i64::MAX);
        let (before_set, before_created_at, before_id) = before
            .map(|cursor| {
                (
                    1_i64,
                    i64::try_from(cursor.created_at).unwrap_or(i64::MAX),
                    cursor.id.as_str(),
                )
            })
            .unwrap_or((0, 0, ""));
        let search = escape_like(search).to_lowercase();
        let now = i64::try_from(now).unwrap_or(i64::MAX);
        self.with(|connection| {
            let mut statement = connection.prepare(
                "SELECT id, tenant, label, dest, password_hash, created_at, expires_at, max_bytes,
                        active, legal_hold, events_json, notifications_json
                 FROM links
                 WHERE tenant = ?1
                   AND (?2 = '' OR lower(label) LIKE '%' || ?2 || '%' ESCAPE '\\'
                        OR lower(dest) LIKE '%' || ?2 || '%' ESCAPE '\\'
                        OR id = ?2)
                   AND (?3 = 'all'
                        OR (?3 = 'open' AND active != 0
                            AND (expires_at IS NULL OR expires_at > ?4))
                        OR (?3 = 'closed' AND (active = 0
                            OR (expires_at IS NOT NULL AND expires_at <= ?4))))
                   AND (?9 = 0 OR (
                        password_hash IS NULL AND active != 0
                        AND (expires_at IS NULL OR expires_at > ?4)
                        AND NOT EXISTS(SELECT 1 FROM link_uploads WHERE link_id=links.id)
                        AND NOT EXISTS(SELECT 1 FROM trade_endpoints WHERE id=links.id)
                        AND NOT EXISTS(SELECT 1 FROM inbound_routes WHERE link_id=links.id)))
                   AND (?5 = 0 OR created_at < ?6
                        OR (created_at = ?6 AND id < ?7))
                 ORDER BY created_at DESC, id DESC
                 LIMIT ?8",
            )?;
            let rows = statement.query_map(
                rusqlite::params![
                    tenant,
                    search,
                    status,
                    now,
                    before_set,
                    before_created_at,
                    before_id,
                    sql_limit,
                    route_eligible,
                ],
                row_to_link,
            )?;
            rows.collect::<Result<Vec<_>, _>>()
        })
        .map(|mut links| {
            let next_cursor = if links.len() > limit {
                links.truncate(limit);
                links.last().map(|link| LinkCursor {
                    created_at: link.created_at,
                    id: link.id.clone(),
                })
            } else {
                None
            };
            LinkPage { links, next_cursor }
        })
    }

    /// Link policy and capped events, with no upload history.
    pub fn link_metadata(&self, tenant: &str, id: &str) -> Result<Option<Link>, String> {
        let connection = self.connection.lock().expect("store poisoned");
        read_link_metadata(&connection, tenant, id)
    }

    pub fn link(&self, tenant: &str, id: &str) -> Result<Option<Link>, String> {
        self.with(|connection| {
            connection
                .query_row(
                    "SELECT id, tenant, label, dest, password_hash, created_at, expires_at, max_bytes,
                            active, legal_hold, events_json, notifications_json
                     FROM links WHERE tenant = ?1 AND id = ?2",
                    rusqlite::params![tenant, id],
                    |row| row_to_link_with_uploads(connection, row),
                )
                .optional()
        })
    }

    /// Looks a link up by id alone, for the public upload protocol: the
    /// 128-bit id is the capability, and senders never know a tenant key.
    /// Administrative reads stay tenant-scoped.
    pub fn link_by_id(&self, id: &str) -> Result<Option<Link>, String> {
        self.with(|connection| {
            connection
                .query_row(
                    "SELECT id, tenant, label, dest, password_hash, created_at, expires_at, max_bytes,
                            active, legal_hold, events_json, notifications_json
                     FROM links WHERE id = ?1",
                    [id],
                    |row| row_to_link_with_uploads(connection, row),
                )
                .optional()
        })
    }

    /// Public upload routes need link policy, not its ever-growing history.
    pub fn upload_link(&self, id: &str) -> Result<Option<Link>, String> {
        self.with(|connection| {
            connection
                .prepare_cached(
                    "SELECT id, tenant, label, dest, password_hash, created_at, expires_at,
                            max_bytes, active, legal_hold, '[]' AS events_json, notifications_json
                     FROM links WHERE id = ?1",
                )?
                .query_row([id], row_to_link)
                .optional()
        })
    }

    /// Selected upload lookup for received sources and legacy download grants.
    pub fn link_upload(
        &self,
        tenant: &str,
        link_id: &str,
        upload_id: &str,
    ) -> Result<Option<UploadRecord>, String> {
        self.with(|connection| read_upload(connection, tenant, link_id, upload_id))
    }

    pub(crate) fn delivered_candidates(
        &self,
        tenant: &str,
        link_id: &str,
        object: &ObjectId,
        after: &str,
    ) -> Result<Vec<(String, bool)>, String> {
        let (hi, lo) = split_bytes(object.length);
        self.with(|connection| {
            let mut statement = connection.prepare_cached(
                "SELECT stored_as, receipt FROM files
                 WHERE tenant=?1 AND link_id=?2 AND suite=?3 AND root=?4
                   AND bytes_hi=?5 AND bytes_lo=?6 AND deleted=0 AND stored_as>?7
                 ORDER BY stored_as LIMIT ?8",
            )?;
            let rows = statement.query_map(
                rusqlite::params![
                    tenant,
                    link_id,
                    crate::session::suite_name(object.suite),
                    hex::encode(object.root),
                    hi,
                    lo,
                    after,
                    DELIVERED_CANDIDATE_PAGE as i64,
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            rows.collect()
        })
    }

    pub fn uploads_by_id(&self, id: &str) -> Result<Option<Vec<UploadRecord>>, String> {
        self.with(|connection| {
            connection
                .query_row("SELECT events_json FROM links WHERE id=?1", [id], |row| {
                    let _: Vec<SessionEvent> = parse_json(&row.get::<_, String>(0)?, 0)?;
                    read_uploads(connection, id)
                })
                .optional()
        })
    }

    pub fn insert_link(&self, link: Link) -> Result<(), InsertLinkError> {
        self.insert_link_with_workflow(link, None)
    }

    pub fn insert_link_with_workflow(
        &self,
        link: Link,
        workflow: Option<&crate::workflow::ReceiveWorkflow>,
    ) -> Result<(), InsertLinkError> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let transaction = connection
            .transaction()
            .map_err(|error| InsertLinkError::Store(error.to_string()))?;
        // Named tenants have no FK; refuse inside this lock so a concurrent
        // remove_tenant cannot commit an orphan link.
        if !link.tenant.is_empty() {
            let exists: i64 = transaction
                .query_row(
                    "SELECT EXISTS (SELECT 1 FROM tenants WHERE key = ?1)",
                    [&link.tenant],
                    |row| row.get(0),
                )
                .map_err(|error| InsertLinkError::Store(error.to_string()))?;
            if exists == 0 {
                return Err(InsertLinkError::NamedTenantGone);
            }
        }
        insert_link_row(&transaction, &link)
            .map_err(|error| InsertLinkError::Store(error.to_string()))?;
        if let Some(workflow) = workflow {
            workflows::set_receive_workflow(&transaction, &link.tenant, &link.id, workflow)
                .map_err(InsertLinkError::Store)?;
        }
        transaction
            .commit()
            .map_err(|error| InsertLinkError::Store(error.to_string()))?;
        Ok(())
    }

    /// Changes link metadata and capped events without loading upload history.
    pub fn update_link(
        &self,
        tenant: &str,
        id: &str,
        mutate: impl FnOnce(&mut Link),
    ) -> Result<bool, String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let transaction = connection.transaction().map_err(|e| e.to_string())?;
        let Some(mut link) = read_link_metadata(&transaction, tenant, id)? else {
            return Ok(false);
        };
        mutate(&mut link);
        if link.password_hash.is_some() {
            let paired: bool = transaction
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM trade_endpoints WHERE id=?1)",
                    [id],
                    |r| r.get(0),
                )
                .map_err(|e| e.to_string())?;
            if paired {
                return Err("paired receiving endpoints use route credentials; manage permissions in Trade routes".into());
            }
        }
        write_link_row(&transaction, &link).map_err(|e| e.to_string())?;
        transaction.commit().map_err(|e| e.to_string())?;
        Ok(true)
    }

    pub fn remove_upload(&self, tenant: &str, id: &str, upload_id: &str) -> Result<bool, String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let transaction = connection.transaction().map_err(|e| e.to_string())?;
        if workflows::receive_pending(&transaction, tenant, id).map_err(|e| e.to_string())? {
            return Err("incoming workflows still use this history; wait for their deliveries to be archived before deleting it".into());
        }
        let changed = transaction
            .execute(
                "DELETE FROM link_uploads WHERE tenant=?1 AND link_id=?2 AND upload_id=?3
             AND EXISTS(SELECT 1 FROM links WHERE tenant=?1 AND id=?2)",
                rusqlite::params![tenant, id, upload_id],
            )
            .map_err(|e| e.to_string())?;
        if changed == 0 {
            return Ok(false);
        }
        transaction
            .execute(
                "DELETE FROM files WHERE tenant=?1 AND link_id=?2 AND upload_id=?3",
                rusqlite::params![tenant, id, upload_id],
            )
            .map_err(|e| e.to_string())?;
        transaction.commit().map_err(|e| e.to_string())?;
        Ok(true)
    }

    pub fn append_upload(
        &self,
        tenant: &str,
        id: &str,
        upload: UploadRecord,
    ) -> Result<bool, String> {
        self.append_upload_inner(tenant, id, upload, None)
            .map(|id| id.is_some())
    }

    pub fn append_upload_from_session(
        &self,
        tenant: &str,
        id: &str,
        upload: UploadRecord,
        session: &str,
    ) -> Result<Option<String>, String> {
        self.append_upload_inner(tenant, id, upload, Some(session))
    }

    fn append_upload_inner(
        &self,
        tenant: &str,
        id: &str,
        upload: UploadRecord,
        session: Option<&str>,
    ) -> Result<Option<String>, String> {
        let upload_json = upload_header_json(&upload).map_err(|e| e.to_string())?;
        let mut connection = self.connection.lock().expect("store poisoned");
        let transaction = connection.transaction().map_err(|e| e.to_string())?;
        if let Some(session) = session {
            let committed = transaction.query_row(
                "SELECT committed_upload_id FROM upload_sessions WHERE id=?1 AND tenant=?2 AND link_id=?3",
                rusqlite::params![session, tenant, id], |row| row.get::<_, Option<String>>(0),
            ).optional().map_err(|e| e.to_string())?
                .ok_or("upload admission is missing at completion")?;
            if committed.is_some() {
                return Ok(committed);
            }
        }
        let Some(events_json) = transaction
            .query_row(
                "SELECT events_json FROM links WHERE tenant=?1 AND id=?2",
                rusqlite::params![tenant, id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| e.to_string())?
        else {
            return Ok(None);
        };
        let _: Vec<SessionEvent> = parse_json(&events_json, 0).map_err(|e| e.to_string())?;
        if !upload.partial && session.is_none() {
            if let Some(previous) =
                read_upload(&transaction, tenant, id, &upload.id).map_err(|e| e.to_string())?
            {
                if previous != upload {
                    return Err("upload identity changed".into());
                }
                workflows::queue_received(&transaction, &self.event_signer, tenant, id, &upload)?;
                transaction.commit().map_err(|e| e.to_string())?;
                return Ok(Some(upload.id));
            }
        }
        if upload.partial {
            if let Some(mut previous) =
                read_upload(&transaction, tenant, id, &upload.id).map_err(|e| e.to_string())?
            {
                if !previous.partial || previous.package_root != upload.package_root {
                    return Err("recovery upload identity changed".into());
                }
                for file in upload.files {
                    if let Some(existing) = previous
                        .files
                        .iter_mut()
                        .find(|existing| existing.stored_as == file.stored_as)
                    {
                        if (
                            existing.bytes,
                            existing.suite.as_str(),
                            existing.root.as_str(),
                        ) != (file.bytes, file.suite.as_str(), file.root.as_str())
                        {
                            return Err("recovered file identity changed".into());
                        }
                        existing.receipt |= file.receipt;
                    } else {
                        previous.files.push(file);
                    }
                }
                previous.total_bytes = previous
                    .files
                    .iter()
                    .fold(0_u64, |total, file| total.saturating_add(file.bytes));
                previous.completed_at = upload.completed_at;
                write_upload(&transaction, tenant, id, &previous).map_err(|e| e.to_string())?;
                sync_upload_files(&transaction, id, tenant, &previous)
                    .map_err(|e| e.to_string())?;
                transaction.commit().map_err(|e| e.to_string())?;
                return Ok(Some(upload.id));
            }
        }
        transaction
            .execute(
                "INSERT INTO link_uploads(link_id,tenant,upload_id,document,file_count) VALUES (?1,?2,?3,?4,?5)",
                rusqlite::params![id, tenant, upload.id, upload_json, i64::try_from(upload.files.len()).unwrap_or(i64::MAX)],
            )
            .map_err(|e| e.to_string())?;
        if let Some(session) = session {
            routes::complete_route(
                &transaction,
                &self.event_signer,
                tenant,
                id,
                session,
                &upload,
            )?;
        }
        insert_upload_files(&transaction, id, tenant, &upload).map_err(|e| e.to_string())?;
        workflows::queue_received(&transaction, &self.event_signer, tenant, id, &upload)?;
        if let Some(session) = session.filter(|_| !upload.partial) {
            let changed = transaction.execute(
                "UPDATE upload_sessions SET committed_upload_id=?2 WHERE id=?1 AND committed_upload_id IS NULL",
                rusqlite::params![session, upload.id],
            ).map_err(|e| e.to_string())?;
            if changed != 1 {
                return Err("upload admission changed at completion".into());
            }
        }
        transaction.commit().map_err(|e| e.to_string())?;
        Ok(Some(upload.id))
    }

    pub fn tombstone_files(
        &self,
        tenant: &str,
        id: &str,
        stored_paths: &std::collections::HashSet<&str>,
    ) -> Result<bool, String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let transaction = connection.transaction().map_err(|e| e.to_string())?;
        if read_link_metadata(&transaction, tenant, id)?.is_none() {
            return Ok(false);
        }
        {
            let mut statement = transaction.prepare_cached(
                "UPDATE files SET deleted=1 WHERE tenant=?1 AND link_id=?2 AND stored_as=?3 AND deleted=0",
            ).map_err(|e| e.to_string())?;
            for path in stored_paths {
                statement
                    .execute(rusqlite::params![tenant, id, path])
                    .map_err(|e| e.to_string())?;
            }
        }
        transaction.commit().map_err(|e| e.to_string())?;
        Ok(true)
    }

    pub fn remove_link(&self, tenant: &str, id: &str) -> Result<bool, String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        if workflows::receive_pending(&transaction, tenant, id).map_err(|e| e.to_string())? {
            return Err(
                "incoming workflows still use this request; wait for their deliveries to be archived before deleting it".into(),
            );
        }
        // SQLite foreign keys are off, so the trade tables declared ON DELETE
        // CASCADE are cleared here; a live peer route blocks the delete.
        let enrolled: bool = transaction.query_row("SELECT EXISTS(SELECT 1 FROM trade_routes WHERE tenant=?1 AND endpoint=?2 AND direction='incoming' AND json_extract(document,'$.state')<>'revoked')", [tenant, id], |row| row.get(0)).map_err(|e| e.to_string())?;
        if enrolled {
            return Err("trade routes still deliver to this request; revoke them under Trade routes before deleting it".into());
        }
        for statement in [
            "DELETE FROM trade_rotations WHERE route_id IN (SELECT id FROM trade_routes WHERE tenant=?1 AND endpoint=?2)",
            "DELETE FROM trade_routes WHERE tenant=?1 AND endpoint=?2 AND direction='incoming'",
            "DELETE FROM trade_invitations WHERE tenant=?1 AND endpoint=?2",
            "DELETE FROM trade_endpoints WHERE tenant=?1 AND id=?2",
        ] {
            transaction
                .execute(statement, [tenant, id])
                .map_err(|error| error.to_string())?;
        }
        transaction
            .execute(
                "DELETE FROM files
                 WHERE link_id IN (SELECT id FROM links WHERE tenant = ?1 AND id = ?2)",
                rusqlite::params![tenant, id],
            )
            .map_err(|error| error.to_string())?;
        transaction
            .execute(
                "DELETE FROM link_uploads WHERE tenant=?1 AND link_id=?2",
                [tenant, id],
            )
            .map_err(|e| e.to_string())?;
        let changed = transaction
            .execute(
                "DELETE FROM links WHERE tenant = ?1 AND id = ?2",
                [tenant, id],
            )
            .map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(changed > 0)
    }

    // ------------------------------------------------------------- tenants

    pub fn insert_tenant(&self, tenant: Tenant) -> Result<(), InsertTenantError> {
        self.with(|connection| {
            // Filesystems commonly compare names case-insensitively even
            // though SQLite's primary key does not.
            let folded = tenant.key.to_lowercase();
            let mut statement = connection.prepare("SELECT key FROM tenants")?;
            let keys = statement.query_map([], |row| row.get::<_, String>(0))?;
            for key in keys {
                if key?.to_lowercase() == folded {
                    return Ok(Some(InsertTenantError::AlreadyExists));
                }
            }
            drop(statement);
            connection.execute(
                "INSERT INTO tenants (key, label, admin_group, max_total_bytes, max_links, max_sessions, created_at, incarnation)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    tenant.key,
                    tenant.label,
                    tenant.admin_group,
                    tenant.max_total_bytes.map(encode_quota),
                    tenant.max_links.map(encode_quota),
                    tenant.max_sessions.map(encode_quota),
                    i64::try_from(tenant.created_at).unwrap_or(0),
                    crate::auth::random_token()
                ],
            )?;
            Ok(None)
        })
        .map_err(InsertTenantError::Store)
        .and_then(|refusal| match refusal {
            None => Ok(()),
            Some(error) => Err(error),
        })
    }

    pub fn tenants(&self) -> Result<Vec<Tenant>, String> {
        self.with(|connection| {
            let mut statement = connection.prepare(
                "SELECT key, label, admin_group, CAST(max_total_bytes AS TEXT),
                        CAST(max_links AS TEXT), CAST(max_sessions AS TEXT), created_at, incarnation
                 FROM tenants ORDER BY rowid",
            )?;
            let rows = statement.query_map([], map_tenant)?;
            rows.collect::<Result<Vec<_>, _>>()
        })
    }

    pub fn tenant(&self, key: &str) -> Result<Option<Tenant>, String> {
        self.with(|connection| {
            connection
                .query_row(
                    "SELECT key, label, admin_group, CAST(max_total_bytes AS TEXT),
                            CAST(max_links AS TEXT), CAST(max_sessions AS TEXT), created_at, incarnation
                     FROM tenants WHERE key = ?1",
                    [key],
                    map_tenant,
                )
                .optional()
        })
    }

    pub(crate) fn tenant_incarnations<'a>(
        &self,
        keys: impl IntoIterator<Item = &'a str>,
    ) -> Result<HashMap<String, String>, String> {
        self.with(|connection| {
            let mut statement =
                connection.prepare_cached("SELECT incarnation FROM tenants WHERE key=?1")?;
            let mut incarnations = HashMap::new();
            for key in keys {
                if let Some(incarnation) = statement
                    .query_row([key], |row| row.get::<_, String>(0))
                    .optional()?
                {
                    incarnations.insert(key.to_owned(), incarnation);
                }
            }
            Ok(incarnations)
        })
    }

    pub fn tenant_link_count(&self, key: &str) -> Result<u64, String> {
        self.with(|connection| {
            connection
                .query_row(
                    "SELECT COUNT(*) FROM links WHERE tenant = ?1",
                    [key],
                    |row| row.get::<_, i64>(0),
                )
                .map(|count| count.max(0) as u64)
        })
    }

    /// Deletes a tenant row atomically unless links still reference it.
    /// Ok(Some(())) = deleted, Ok(None) = absent,
    /// Ok(Some(links)) via Err variant... see [`TenantRemoval`].
    pub fn remove_tenant(&self, key: &str) -> Result<TenantRemoval, String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let routes_pending: bool = transaction.query_row("SELECT EXISTS(SELECT 1 FROM outbound_routes r JOIN delivery_jobs j ON j.id=r.job_id WHERE j.tenant=?1 AND j.state<>'suspended' AND r.ack IS NULL
            AND (r.revocation IS NOT NULL OR j.state='cancelled'
                OR (j.state IN ('retiring','retired') AND json_extract(j.document,'$.checks.retired_from')='cancelled')
                OR json_extract(j.document,'$.checks.source_revoked_at') IS NOT NULL
                OR COALESCE(json_extract(j.document,'$.checks.destinations.' || r.destination_id || '.state'),'')<>'complete'))",[key],|row|row.get(0)).map_err(|e|e.to_string())?;
        if routes_pending {
            return Ok(TenantRemoval::HasRoutes);
        }
        let removal = {
            let changed = transaction
                .execute(
                    "DELETE FROM tenants WHERE key = ?1
                 AND NOT EXISTS (SELECT 1 FROM links WHERE tenant = ?1)",
                    [key],
                )
                .map_err(|error| error.to_string())?;
            if changed > 0 {
                TenantRemoval::Deleted
            } else {
                let exists: i64 = transaction
                    .query_row(
                        "SELECT EXISTS (SELECT 1 FROM tenants WHERE key = ?1)",
                        [key],
                        |row| row.get(0),
                    )
                    .map_err(|error| error.to_string())?;
                if exists == 0 {
                    TenantRemoval::Absent
                } else {
                    TenantRemoval::HasLinks
                }
            }
        };
        if matches!(removal, TenantRemoval::Deleted | TenantRemoval::Absent) {
            transaction
                .execute(
                    "UPDATE tenant_quota_usage SET state=2 WHERE tenant=?1",
                    [key],
                )
                .map_err(|e| e.to_string())?;
            transaction
                .execute("DELETE FROM files WHERE tenant=?1", [key])
                .map_err(|e| e.to_string())?;
            transaction
                .execute("DELETE FROM tenant_quota_usage WHERE tenant=?1", [key])
                .map_err(|e| e.to_string())?;
            transaction
                .execute("DELETE FROM link_uploads WHERE tenant=?1", [key])
                .map_err(|e| e.to_string())?;
            transaction.execute("DELETE FROM upload_session_files WHERE session_id IN (SELECT id FROM upload_sessions WHERE tenant=?1)", [key]).map_err(|error| error.to_string())?;
            transaction
                .execute("DELETE FROM upload_sessions WHERE tenant=?1", [key])
                .map_err(|error| error.to_string())?;
            transaction.execute("DELETE FROM trade_rotations WHERE route_id IN (SELECT id FROM trade_routes WHERE tenant=?1)",[key]).map_err(|e|e.to_string())?;
            transaction.execute("DELETE FROM trade_delivery_policies WHERE route_id IN (SELECT id FROM inbound_routes WHERE tenant=?1)",[key]).map_err(|e|e.to_string())?;
            transaction.execute("DELETE FROM delivery_storage_credentials WHERE id IN (SELECT id FROM trade_routes WHERE tenant=?1 AND direction='outgoing')",[key]).map_err(|e|e.to_string())?;
            transaction.execute("DELETE FROM delivery_storage WHERE id IN (SELECT id FROM trade_routes WHERE tenant=?1 AND direction='outgoing')",[key]).map_err(|e|e.to_string())?;
            transaction.execute("DELETE FROM route_uploads WHERE route_id IN (SELECT id FROM inbound_routes WHERE tenant=?1)",[key]).map_err(|e|e.to_string())?;
            transaction
                .execute("DELETE FROM inbound_routes WHERE tenant=?1", [key])
                .map_err(|e| e.to_string())?;
            transaction.execute("DELETE FROM outbound_routes WHERE job_id IN (SELECT id FROM delivery_jobs WHERE tenant=?1)",[key]).map_err(|e|e.to_string())?;
            transaction.execute("DELETE FROM notification_job_overrides WHERE job_id IN (SELECT id FROM delivery_jobs WHERE tenant=?1)",[key]).map_err(|e|e.to_string())?;
            workflows::remove_storage_tenant(&transaction, key)?;
            for table in [
                "delivery_manifests",
                "delivery_evidence",
                "delivery_policy_cache",
            ] {
                transaction.execute(&format!("DELETE FROM {table} WHERE grant_id IN (SELECT id FROM outbound_grants WHERE tenant=?1)"), [key]).map_err(|e| e.to_string())?;
            }
            transaction
                .execute("DELETE FROM delivery_events WHERE tenant=?1", [key])
                .map_err(|e| e.to_string())?;
            for table in [
                "delivery_jobs",
                "delivery_projects",
                "delivery_webhooks",
                "delivery_webhook_attempts",
                "notification_destinations",
                "notification_defaults",
                "trade_invitations",
                "trade_endpoints",
                "trade_routes",
            ] {
                transaction
                    .execute(&format!("DELETE FROM {table} WHERE tenant=?1"), [key])
                    .map_err(|e| e.to_string())?;
            }
            transaction
                .execute(
                    "DELETE FROM outbound_grant_files
                     WHERE grant_id IN (SELECT id FROM outbound_grants WHERE tenant = ?1)",
                    [key],
                )
                .map_err(|error| error.to_string())?;
            transaction
                .execute("DELETE FROM outbound_grants WHERE tenant = ?1", [key])
                .map_err(|error| error.to_string())?;
            transaction.execute("DELETE FROM automation_operations WHERE token_id IN (SELECT id FROM automation_tokens WHERE tenant = ?1)", [key])
                .map_err(|error| error.to_string())?;
            transaction
                .execute("DELETE FROM automation_tokens WHERE tenant = ?1", [key])
                .map_err(|error| error.to_string())?;
            transaction
                .execute("DELETE FROM branding WHERE tenant = ?1", [key])
                .map_err(|error| error.to_string())?;
        }
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(removal)
    }

    pub fn update_tenant(&self, tenant: &Tenant) -> Result<bool, String> {
        self.with(|connection| {
            let changed = connection.execute(
                "UPDATE tenants SET label = ?2, admin_group = ?3, max_total_bytes = ?4,
                                    max_links = ?5, max_sessions = ?6
                 WHERE key = ?1",
                rusqlite::params![
                    tenant.key,
                    tenant.label,
                    tenant.admin_group,
                    tenant.max_total_bytes.map(encode_quota),
                    tenant.max_links.map(encode_quota),
                    tenant.max_sessions.map(encode_quota),
                ],
            )?;
            Ok(changed > 0)
        })
    }

    // ------------------------------------------------------------ branding

    pub fn branding(&self, tenant: &str) -> Result<Option<Branding>, String> {
        self.with(|connection| {
            connection
                .prepare_cached(
                    "SELECT tenant, name, color, logo_ext, updated_at, footer_text, footer_link_label, footer_link_url
                     FROM branding WHERE tenant = ?1",
                )?
                .query_row([tenant], |row| {
                    Ok(Branding {
                        tenant: row.get(0)?,
                        name: row.get(1)?,
                        color: row.get(2)?,
                        logo_ext: row.get(3)?,
                        updated_at: row.get::<_, i64>(4)?.max(0) as u64,
                        footer_text: row.get(5)?,
                        footer_link_label: row.get(6)?,
                        footer_link_url: row.get(7)?,
                    })
                })
                .optional()
        })
    }

    pub fn set_branding(&self, branding: &Branding) -> Result<(), String> {
        self.with(|connection| {
            connection
                .prepare_cached(
                    "INSERT INTO branding (tenant, name, color, logo_ext, updated_at, footer_text, footer_link_label, footer_link_url)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                     ON CONFLICT(tenant) DO UPDATE SET
                        name = excluded.name, color = excluded.color,
                        logo_ext = excluded.logo_ext, updated_at = excluded.updated_at,
                        footer_text = excluded.footer_text, footer_link_label = excluded.footer_link_label,
                        footer_link_url = excluded.footer_link_url",
                )?
                .execute(rusqlite::params![
                    branding.tenant,
                    branding.name,
                    branding.color,
                    branding.logo_ext,
                    i64::try_from(branding.updated_at).unwrap_or(i64::MAX),
                    branding.footer_text,
                    branding.footer_link_label,
                    branding.footer_link_url,
                ])
                .map(|_| ())
        })
    }

    pub fn delete_branding(&self, tenant: &str) -> Result<bool, String> {
        self.with(|connection| {
            connection
                .prepare_cached("DELETE FROM branding WHERE tenant = ?1")?
                .execute([tenant])
                .map(|changed| changed > 0)
        })
    }

    // ------------------------------------------------- upload session resume

    /// Replaces in-progress session metadata, refusing completed IDs and push keys.
    pub fn insert_upload_session(&self, session: &PersistedUploadSession) -> Result<(), String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let committed: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM upload_sessions WHERE (id=?1 OR push_key=?2) AND committed_upload_id IS NOT NULL)",
            rusqlite::params![session.id, session.push_key], |row| row.get(0),
        ).map_err(|error| error.to_string())?;
        if committed || session.committed_upload_id.is_some() {
            return Err("completed upload is awaiting publication cleanup".into());
        }
        transaction
            .execute(
                "INSERT OR REPLACE INTO upload_sessions
                 (id, link_id, tenant, dest_dir, dest_rel, package_suite,
                  package_root, package_length, max_total_bytes, started_at, created_at, push_key)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                rusqlite::params![
                    session.id,
                    session.link_id,
                    session.tenant,
                    session.dest_dir.to_string_lossy(),
                    session.dest_rel,
                    i64::from(session.package.suite),
                    hex::encode(session.package.root),
                    i64::try_from(session.package.length).unwrap_or(i64::MAX),
                    session
                        .max_total_bytes
                        .map(|value| i64::try_from(value).unwrap_or(i64::MAX)),
                    i64::try_from(session.started_at).unwrap_or(i64::MAX),
                    i64::try_from(now_unix()).unwrap_or(i64::MAX),
                    session.push_key,
                ],
            )
            .map_err(|error| error.to_string())?;
        transaction
            .execute(
                "DELETE FROM upload_session_files WHERE session_id = ?1",
                [&session.id],
            )
            .map_err(|error| error.to_string())?;
        for file in &session.files {
            transaction
                .execute(
                    "INSERT INTO upload_session_files
                     (session_id, entry, display_path, stored_components, object_suite,
                      object_root, object_length, staging_path, journal_path, incarnation,
                      prefix_bytes, published, receipt, commit_profile, nas_contract)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                    rusqlite::params![
                        session.id,
                        i64::try_from(file.entry).unwrap_or(i64::MAX),
                        file.display_path,
                        serde_json::to_string(&file.stored_components).unwrap_or_default(),
                        i64::from(file.object.suite),
                        hex::encode(file.object.root),
                        i64::try_from(file.object.length).unwrap_or(i64::MAX),
                        file.staging_path.to_string_lossy(),
                        file.journal_path.to_string_lossy(),
                        hex::encode(file.incarnation),
                        i64::try_from(file.prefix_bytes).unwrap_or(i64::MAX),
                        i64::from(file.published),
                        i64::from(file.receipt),
                        match file.profile {
                            vot_sdk_file::CommitProfile::Fast => "fast",
                            vot_sdk_file::CommitProfile::Balanced => "balanced",
                            vot_sdk_file::CommitProfile::Strict => "strict",
                        },
                        match file.nas_contract {
                            vot_sdk_file::NasContract::Unqualified => "unqualified",
                            vot_sdk_file::NasContract::ServerAcknowledged => "server_acknowledged",
                        },
                    ],
                )
                .map_err(|error| error.to_string())?;
        }
        transaction.commit().map_err(|error| error.to_string())
    }

    /// Checkpoints file prefixes and publication flags in one transaction.
    /// Under-claiming is safe: resume re-sends from the previous checkpoint.
    pub fn update_upload_file_progress(
        &self,
        session_id: &str,
        progress: impl IntoIterator<Item = (usize, u64, bool, bool)>,
    ) -> Result<(), String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        {
            let mut update = transaction
                .prepare_cached(
                    "UPDATE upload_session_files
                     SET prefix_bytes = ?3, published = ?4, receipt = ?5
                     WHERE session_id = ?1 AND entry = ?2",
                )
                .map_err(|error| error.to_string())?;
            for (entry, prefix_bytes, published, receipt) in progress {
                let updated = update
                    .execute(rusqlite::params![
                        session_id,
                        i64::try_from(entry).unwrap_or(i64::MAX),
                        i64::try_from(prefix_bytes).unwrap_or(i64::MAX),
                        i64::from(published),
                        i64::from(receipt),
                    ])
                    .map_err(|error| error.to_string())?;
                if updated != 1 {
                    return Err("upload admission is missing at checkpoint".to_owned());
                }
            }
        }
        transaction.commit().map_err(|error| error.to_string())
    }

    pub(crate) fn visit_pending_upload_paths(
        &self,
        tenant: &str,
        mut visit: impl FnMut(&str, &[String]) -> Result<(), String>,
    ) -> Result<(), String> {
        self.with(|connection| {
            let mut statement = connection.prepare_cached(
                "SELECT s.dest_rel,f.stored_components FROM upload_sessions s
                 JOIN upload_session_files f ON f.session_id=s.id
                 WHERE s.tenant=?1 AND s.committed_upload_id IS NULL AND f.published=0",
            )?;
            let mut rows = statement.query([tenant])?;
            while let Some(row) = rows.next()? {
                let destination: String = row.get(0)?;
                let components: Vec<String> = parse_json(&row.get::<_, String>(1)?, 1)?;
                if let Err(error) = visit(&destination, &components) {
                    return Ok(Err(error));
                }
            }
            Ok(Ok(()))
        })?
    }

    /// Every persisted session with its files, for boot re-attach.
    pub fn load_upload_sessions(&self) -> Result<Vec<PersistedUploadSession>, String> {
        self.load_sessions(false, None)
    }

    pub fn load_push_sessions(&self) -> Result<Vec<PersistedUploadSession>, String> {
        self.load_sessions(true, None)
    }

    pub fn load_push_session(&self, key: &str) -> Result<Option<PersistedUploadSession>, String> {
        Ok(self.load_sessions(true, Some(key))?.into_iter().next())
    }

    fn load_sessions(
        &self,
        push_only: bool,
        push_key: Option<&str>,
    ) -> Result<Vec<PersistedUploadSession>, String> {
        self.with(|connection| {
            let mut sessions = Vec::new();
            let mut statement = connection.prepare(
                "SELECT id, link_id, tenant, dest_dir, dest_rel, package_suite,
                        package_root, package_length, max_total_bytes, started_at, push_key, committed_upload_id
                 FROM upload_sessions WHERE (NOT ?1 OR push_key IS NOT NULL) AND (?2 IS NULL OR push_key = ?2) ORDER BY created_at",
            )?;
            let rows = statement.query_map(rusqlite::params![push_only, push_key], |row| {
                Ok(PersistedUploadSession {
                    committed_upload_id: row.get(11)?,
                    push_key: row.get(10)?,
                    id: row.get(0)?,
                    link_id: row.get(1)?,
                    tenant: row.get(2)?,
                    dest_dir: PathBuf::from(row.get::<_, String>(3)?),
                    dest_rel: row.get(4)?,
                    package: object_from_row(row.get(5)?, &row.get::<_, String>(6)?, row.get(7)?)?,
                    max_total_bytes: row
                        .get::<_, Option<i64>>(8)?
                        .map(|value| value.max(0) as u64),
                    started_at: row.get::<_, i64>(9)?.max(0) as u64,
                    files: Vec::new(),
                })
            })?;
            for session in rows {
                sessions.push(session?);
            }
            let mut file_statement = connection.prepare(
                "SELECT entry, display_path, stored_components, object_suite, object_root,
                        object_length, staging_path, journal_path, incarnation,
                        prefix_bytes, published, receipt, commit_profile, nas_contract
                 FROM upload_session_files WHERE session_id = ?1 ORDER BY entry",
            )?;
            for session in &mut sessions {
                let files = file_statement.query_map([&session.id], |row| {
                    let components: Vec<String> =
                        serde_json::from_str(&row.get::<_, String>(2)?).unwrap_or_default();
                    let incarnation_hex: String = row.get(8)?;
                    let incarnation: [u8; 16] = hex::decode(&incarnation_hex)
                        .ok()
                        .and_then(|bytes| bytes.try_into().ok())
                        .ok_or_else(|| {
                            rusqlite::Error::FromSqlConversionFailure(
                                8,
                                rusqlite::types::Type::Text,
                                "incarnation is not 16 bytes".into(),
                            )
                        })?;
                    Ok(PersistedUploadFile {
                        entry: row.get::<_, i64>(0)?.max(0) as usize,
                        display_path: row.get(1)?,
                        stored_components: components,
                        object: object_from_row(
                            row.get(3)?,
                            &row.get::<_, String>(4)?,
                            row.get(5)?,
                        )?,
                        staging_path: PathBuf::from(row.get::<_, String>(6)?),
                        journal_path: PathBuf::from(row.get::<_, String>(7)?),
                        incarnation,
                        profile: match row.get::<_, String>(12)?.as_str() {
                            "fast" => vot_sdk_file::CommitProfile::Fast,
                            "balanced" => vot_sdk_file::CommitProfile::Balanced,
                            "strict" => vot_sdk_file::CommitProfile::Strict,
                            _ => {
                                return Err(rusqlite::Error::FromSqlConversionFailure(
                                    12,
                                    rusqlite::types::Type::Text,
                                    "invalid commit profile".into(),
                                ))
                            }
                        },
                        nas_contract: match row.get::<_, String>(13)?.as_str() {
                            "unqualified" => vot_sdk_file::NasContract::Unqualified,
                            "server_acknowledged" => vot_sdk_file::NasContract::ServerAcknowledged,
                            _ => {
                                return Err(rusqlite::Error::FromSqlConversionFailure(
                                    13,
                                    rusqlite::types::Type::Text,
                                    "invalid NAS contract".into(),
                                ))
                            }
                        },
                        prefix_bytes: row.get::<_, i64>(9)?.max(0) as u64,
                        published: row.get::<_, i64>(10)? != 0,
                        receipt: row.get::<_, i64>(11)? != 0,
                    })
                })?;
                for file in files {
                    session.files.push(file?);
                }
            }
            Ok(sessions)
        })
    }

    /// Removes a session and its files, on completion, abort, or a refused
    /// re-attach.
    pub fn delete_upload_session(&self, session_id: &str) -> Result<(), String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        transaction
            .execute(
                "DELETE FROM upload_session_files WHERE session_id = ?1",
                [session_id],
            )
            .map_err(|error| error.to_string())?;
        transaction
            .execute("DELETE FROM upload_sessions WHERE id = ?1", [session_id])
            .map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())
    }

    // ----------------------------------------------------------- principals

    pub fn principal(&self, subject: &str) -> Result<Option<Principal>, String> {
        self.with(|connection| {
            connection
                .query_row(
                    "SELECT subject, credential_version, blocked, last_login_at,
                            last_groups, last_grants, source, external_id, created_at
                     FROM principals WHERE subject = ?1",
                    [subject],
                    map_principal,
                )
                .optional()
        })
    }

    pub fn principals_page(
        &self,
        limit: usize,
        offset: usize,
        query: Option<&str>,
    ) -> Result<(Vec<Principal>, u64), String> {
        self.principals_page_ordered(limit, offset, query, PrincipalPageOrder::LastLogin)
    }

    /// SCIM clients use offset pagination without a sort parameter. Subject is
    /// immutable, so it keeps a page walk stable while login timestamps move.
    pub fn scim_principals_page(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<(Vec<Principal>, u64), String> {
        self.principals_page_ordered(limit, offset, None, PrincipalPageOrder::Subject)
    }

    fn principals_page_ordered(
        &self,
        limit: usize,
        offset: usize,
        query: Option<&str>,
        order: PrincipalPageOrder,
    ) -> Result<(Vec<Principal>, u64), String> {
        let limit = i64::try_from(limit).map_err(|_| "principal limit overflow".to_owned())?;
        let offset = i64::try_from(offset).map_err(|_| "principal offset overflow".to_owned())?;
        let query = query.map(|value| format!("%{}%", escape_like(value)));
        let order = match order {
            PrincipalPageOrder::LastLogin => "last_login_at DESC, subject ASC",
            PrincipalPageOrder::Subject => "subject ASC",
        };
        self.with(|connection| {
            let total = connection.query_row(
                "SELECT COUNT(*) FROM principals
                 WHERE (?1 IS NULL OR subject LIKE ?1 ESCAPE '\\' COLLATE NOCASE)",
                rusqlite::params![query.as_deref()],
                |row| row.get::<_, i64>(0),
            )?;
            let mut statement = connection.prepare(&format!(
                "SELECT subject, credential_version, blocked, last_login_at,
                        last_groups, last_grants, source, external_id, created_at
                 FROM principals
                 WHERE (?1 IS NULL OR subject LIKE ?1 ESCAPE '\\' COLLATE NOCASE)
                 ORDER BY {order}
                 LIMIT ?2 OFFSET ?3",
            ))?;
            let rows =
                statement.query_map(rusqlite::params![query, limit, offset], map_principal)?;
            Ok((
                rows.collect::<Result<Vec<_>, _>>()?,
                u64::try_from(total).unwrap_or(0),
            ))
        })
    }

    /// Inserts or refreshes last-login fields without resetting version or block.
    /// Blocked principals retain their previous login fields and are returned.
    pub fn upsert_sso_principal(
        &self,
        subject: &str,
        groups: &[String],
        grants: &serde_json::Value,
    ) -> Result<Principal, String> {
        let groups_json = serde_json::to_string(groups).unwrap_or_else(|_| "[]".to_owned());
        let grants_json = serde_json::to_string(grants).unwrap_or_else(|_| "[]".to_owned());
        let at = i64::try_from(now_unix()).unwrap_or(0);
        self.with(|connection| {
            connection.query_row(
                "INSERT INTO principals (subject, last_login_at, last_groups, last_grants, source, created_at)
                 VALUES (?1, ?2, ?3, ?4, 'sso', ?2)
                 ON CONFLICT(subject) DO UPDATE SET
                    last_login_at = CASE WHEN blocked = 0
                                         THEN excluded.last_login_at ELSE last_login_at END,
                    last_groups = CASE WHEN blocked = 0
                                       THEN excluded.last_groups ELSE last_groups END,
                    last_grants = CASE WHEN blocked = 0
                                       THEN excluded.last_grants ELSE last_grants END
                 RETURNING subject, credential_version, blocked, last_login_at,
                           last_groups, last_grants, source, external_id, created_at",
                rusqlite::params![subject, at, groups_json, grants_json],
                map_principal,
            )
        })
    }

    /// SCIM create: a new unblocked row with source 'scim'. Returns false
    /// when the subject already exists, whatever its state.
    pub fn provision_principal(
        &self,
        subject: &str,
        external_id: Option<&str>,
    ) -> Result<bool, String> {
        let at = i64::try_from(now_unix()).unwrap_or(0);
        self.with(|connection| {
            let changed = connection.execute(
                "INSERT OR IGNORE INTO principals (subject, source, external_id, created_at)
                 VALUES (?1, 'scim', ?2, ?3)",
                rusqlite::params![subject, external_id, at],
            )?;
            Ok(changed > 0)
        })
    }

    pub fn principal_by_external_id(&self, external_id: &str) -> Result<Option<Principal>, String> {
        self.with(|connection| {
            connection
                .query_row(
                    "SELECT subject, credential_version, blocked, last_login_at,
                            last_groups, last_grants, source, external_id, created_at
                     FROM principals WHERE external_id = ?1 ORDER BY subject LIMIT 1",
                    [external_id],
                    map_principal,
                )
                .optional()
        })
    }

    // ----------------------------------------------------------- scim groups

    /// Creates a group with its members; None when the name is taken.
    pub fn create_scim_group(
        &self,
        display_name: &str,
        external_id: Option<&str>,
        members: &[String],
    ) -> Result<Option<ScimGroup>, String> {
        let id = crate::auth::random_token();
        let at = i64::try_from(now_unix()).unwrap_or(0);
        let mut connection = self.connection.lock().expect("store poisoned");
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let inserted = transaction
            .execute(
                "INSERT OR IGNORE INTO scim_groups (id, display_name, external_id, created_at)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![id, display_name, external_id, at],
            )
            .map_err(|error| error.to_string())?;
        if inserted == 0 {
            return Ok(None);
        }
        write_scim_members(&transaction, &id, members).map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())?;
        drop(connection);
        self.scim_group(&id)
    }

    pub fn scim_group(&self, id: &str) -> Result<Option<ScimGroup>, String> {
        self.with(|connection| {
            let Some(mut group) = connection
                .query_row(
                    "SELECT id, display_name, external_id, created_at FROM scim_groups WHERE id = ?1",
                    [id],
                    map_scim_group,
                )
                .optional()?
            else {
                return Ok(None);
            };
            group.members = read_scim_members(connection, id)?;
            Ok(Some(group))
        })
    }

    pub fn scim_group_by_name(&self, display_name: &str) -> Result<Option<ScimGroup>, String> {
        self.scim_group_by_column("display_name", display_name)
    }

    /// First group carrying the provider's id, by name when two share it.
    pub fn scim_group_by_external_id(
        &self,
        external_id: &str,
    ) -> Result<Option<ScimGroup>, String> {
        self.scim_group_by_column("external_id", external_id)
    }

    fn scim_group_by_column(&self, column: &str, value: &str) -> Result<Option<ScimGroup>, String> {
        let id = self.with(|connection| {
            connection
                .query_row(
                    &format!(
                        "SELECT id FROM scim_groups WHERE {column} = ?1 ORDER BY display_name LIMIT 1"
                    ),
                    [value],
                    |row| row.get::<_, String>(0),
                )
                .optional()
        })?;
        match id {
            Some(id) => self.scim_group(&id),
            None => Ok(None),
        }
    }

    /// Groups ordered by name, members included, plus the total count.
    pub fn scim_groups_page(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<(Vec<ScimGroup>, u64), String> {
        let limit = i64::try_from(limit).map_err(|_| "group limit overflow".to_owned())?;
        let offset = i64::try_from(offset).map_err(|_| "group offset overflow".to_owned())?;
        self.with(|connection| {
            let total = connection.query_row("SELECT COUNT(*) FROM scim_groups", [], |row| {
                row.get::<_, i64>(0)
            })?;
            let mut statement = connection.prepare(
                "SELECT id, display_name, external_id, created_at FROM scim_groups
                 ORDER BY display_name LIMIT ?1 OFFSET ?2",
            )?;
            let mut groups = statement
                .query_map(rusqlite::params![limit, offset], map_scim_group)?
                .collect::<Result<Vec<_>, _>>()?;
            for group in &mut groups {
                group.members = read_scim_members(connection, &group.id)?;
            }
            Ok((groups, u64::try_from(total).unwrap_or(0)))
        })
    }

    /// Replaces the name (when given) and the whole member list. Ok(false)
    /// when the group does not exist; Err on a name collision.
    pub fn replace_scim_group(
        &self,
        id: &str,
        display_name: Option<&str>,
        members: Option<&[String]>,
    ) -> Result<bool, String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let exists: i64 = transaction
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM scim_groups WHERE id = ?1)",
                [id],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        if exists == 0 {
            return Ok(false);
        }
        if let Some(display_name) = display_name {
            transaction
                .execute(
                    "UPDATE scim_groups SET display_name = ?2 WHERE id = ?1",
                    rusqlite::params![id, display_name],
                )
                .map_err(|error| match error {
                    rusqlite::Error::SqliteFailure(failure, _)
                        if failure.code == rusqlite::ErrorCode::ConstraintViolation =>
                    {
                        SCIM_GROUP_NAME_TAKEN.to_owned()
                    }
                    other => other.to_string(),
                })?;
        }
        if let Some(members) = members {
            transaction
                .execute("DELETE FROM scim_group_members WHERE group_id = ?1", [id])
                .map_err(|error| error.to_string())?;
            write_scim_members(&transaction, id, members).map_err(|error| error.to_string())?;
        }
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(true)
    }

    /// Adds or removes members without touching the rest. Ok(false) when
    /// the group does not exist.
    pub fn change_scim_group_members(
        &self,
        id: &str,
        add: &[String],
        remove: &[String],
    ) -> Result<bool, String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let exists: i64 = transaction
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM scim_groups WHERE id = ?1)",
                [id],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        if exists == 0 {
            return Ok(false);
        }
        write_scim_members(&transaction, id, add).map_err(|error| error.to_string())?;
        for subject in remove {
            transaction
                .execute(
                    "DELETE FROM scim_group_members WHERE group_id = ?1 AND subject = ?2",
                    rusqlite::params![id, subject],
                )
                .map_err(|error| error.to_string())?;
        }
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(true)
    }

    pub fn delete_scim_group(&self, id: &str) -> Result<bool, String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        transaction
            .execute("DELETE FROM scim_group_members WHERE group_id = ?1", [id])
            .map_err(|error| error.to_string())?;
        let deleted = transaction
            .execute("DELETE FROM scim_groups WHERE id = ?1", [id])
            .map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(deleted > 0)
    }

    /// Names of the groups a subject belongs to, for the sign-in role
    /// mapping.
    pub fn scim_groups_of(&self, subject: &str) -> Result<Vec<String>, String> {
        self.with(|connection| {
            let mut statement = connection.prepare(
                "SELECT g.display_name FROM scim_group_members m
                 JOIN scim_groups g ON g.id = m.group_id
                 WHERE m.subject = ?1 ORDER BY g.display_name",
            )?;
            let rows = statement.query_map([subject], |row| row.get::<_, String>(0))?;
            rows.collect()
        })
    }

    /// Missing row accepts cv 1 only. A present row must match version and be
    /// unblocked. A read failure denies: this decides whether a session is
    /// still valid, and the safe answer to "cannot tell" is no. The local
    /// break-glass subject never reaches here, so denying cannot lock the
    /// operator out.
    pub fn principal_allows(&self, subject: &str, credential_version: u64) -> bool {
        match self.principal(subject) {
            Ok(None) => credential_version == 1,
            Ok(Some(row)) => credential_version == row.credential_version && !row.blocked,
            Err(error) => {
                tracing::error!(%error, subject, "principal read failed; refusing the session");
                false
            }
        }
    }

    pub fn revoke_principal(&self, subject: &str) -> Result<bool, String> {
        self.with(|connection| {
            let changed = connection.execute(
                "UPDATE principals SET credential_version = credential_version + 1, blocked = 1
                 WHERE subject = ?1",
                [subject],
            )?;
            Ok(changed > 0)
        })
    }

    pub fn unblock_principal(&self, subject: &str) -> Result<bool, String> {
        self.with(|connection| {
            let exists: i64 = connection.query_row(
                "SELECT EXISTS (SELECT 1 FROM principals WHERE subject = ?1)",
                [subject],
                |row| row.get(0),
            )?;
            if exists == 0 {
                return Ok(false);
            }
            connection.execute(
                "UPDATE principals SET blocked = 0 WHERE subject = ?1",
                [subject],
            )?;
            Ok(true)
        })
    }

    // ------------------------------------------------- operations helpers

    /// Consistent snapshot of the database via SQLite's VACUUM INTO. The
    /// destination must not exist. Runs on its own connection so the
    /// full-database rewrite never holds the shared store lock: WAL lets
    /// this reader proceed alongside the serving connection.
    pub fn backup_into(&self, destination: &Path) -> Result<(), String> {
        let connection = Connection::open(&self.path)
            .map_err(|error| format!("open {}: {error}", self.path.display()))?;
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|error| error.to_string())?;
        connection
            .execute("VACUUM INTO ?1", [destination.to_string_lossy().as_ref()])
            .map_err(|error| error.to_string())?;
        crate::paths::tighten_private_file(destination).map(|_| ())
    }

    /// Every link across every tenant. Internal use only for complete scans;
    /// administrative API reads stay tenant-scoped.
    pub fn all_links(&self) -> Result<Vec<Link>, String> {
        self.with(|connection| {
            let mut statement = connection.prepare(
                "SELECT id, tenant, label, dest, password_hash, created_at, expires_at, max_bytes,
                        active, legal_hold, events_json, notifications_json
                 FROM links ORDER BY rowid",
            )?;
            let rows = statement.query_map([], |row| row_to_link_with_uploads(connection, row))?;
            rows.collect::<Result<Vec<_>, _>>()
        })
    }

    /// Link identities for the retention sweep. The caller hydrates each link
    /// separately so one pass never keeps every tenant's upload history alive.
    pub(crate) fn retention_link_ids(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<(String, String)>, String> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        self.with(|connection| {
            if let Some(after) = after {
                let mut statement = connection.prepare_cached(
                    "SELECT tenant, id FROM links
                     WHERE id > ?1
                     ORDER BY id LIMIT ?2",
                )?;
                let rows = statement.query_map(rusqlite::params![after, limit], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })?;
                rows.collect()
            } else {
                let mut statement = connection
                    .prepare_cached("SELECT tenant, id FROM links ORDER BY id LIMIT ?1")?;
                let rows = statement.query_map([limit], |row| Ok((row.get(0)?, row.get(1)?)))?;
                rows.collect()
            }
        })
    }

    pub fn audit_count(&self) -> Result<u64, String> {
        self.with(|connection| {
            connection
                .query_row("SELECT rows FROM audit_log_count WHERE id = 1", [], |row| {
                    row.get::<_, i64>(0)
                })
                .map(|value| value.max(0) as u64)
        })
    }

    // -------------------------------------------------------------- settings

    pub fn setting(&self, key: &str) -> Result<Option<String>, String> {
        self.with(|connection| {
            connection
                .query_row("SELECT value FROM settings WHERE key = ?1", [key], |row| {
                    row.get(0)
                })
                .optional()
        })
    }

    pub fn settings_map(&self) -> Result<HashMap<String, String>, String> {
        self.with(|connection| {
            let mut statement = connection.prepare("SELECT key, value FROM settings")?;
            let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
            rows.collect::<Result<HashMap<_, _>, _>>()
        })
    }

    pub fn put_settings(
        &self,
        actor: &str,
        writes: &[(String, SettingWrite)],
    ) -> Result<(), String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let now = i64::try_from(now_unix()).unwrap_or(0);
        for (key, write) in writes {
            match write {
                SettingWrite::Set(value) => {
                    transaction
                        .execute(
                            "INSERT INTO settings (key, value, updated_at, updated_by)
                             VALUES (?1, ?2, ?3, ?4)
                             ON CONFLICT(key) DO UPDATE SET
                                value = excluded.value,
                                updated_at = excluded.updated_at,
                                updated_by = excluded.updated_by",
                            rusqlite::params![key, value, now, actor],
                        )
                        .map_err(|error| error.to_string())?;
                }
                SettingWrite::Reset => {
                    transaction
                        .execute("DELETE FROM settings WHERE key = ?1", [key])
                        .map_err(|error| error.to_string())?;
                }
            }
        }
        transaction.commit().map_err(|error| error.to_string())?;
        self.settings_generation
            .fetch_add(1, std::sync::atomic::Ordering::Release);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn delete_setting(&self, key: &str) -> Result<(), String> {
        self.with(|connection| {
            connection.execute("DELETE FROM settings WHERE key = ?1", [key])?;
            self.settings_generation
                .fetch_add(1, std::sync::atomic::Ordering::Release);
            Ok(())
        })
    }

    pub(crate) fn settings_generation(&self) -> u64 {
        self.settings_generation
            .load(std::sync::atomic::Ordering::Acquire)
    }

    pub fn overlay(&self, config: &Config) -> Result<SettingsOverlay, String> {
        Ok(overlay_rows(&self.settings_map()?, config))
    }

    pub fn resolved_settings(&self, config: &Config) -> Result<ResolvedSettings, String> {
        Ok(self.overlay(config)?.resolved)
    }

    /// Quotas that apply to `tenant_key`: the tenant row for a named
    /// namespace, or `default_max_*` for the implicit default tenant.
    pub fn quotas_for(&self, tenant_key: &str, config: &Config) -> Result<Quotas, String> {
        if tenant_key.is_empty() {
            let settings = self.resolved_settings(config)?;
            Ok((
                settings.default_max_total_bytes,
                settings.default_max_links,
                settings.default_max_sessions,
            ))
        } else {
            Ok(self
                .tenant(tenant_key)?
                .map(|tenant| {
                    (
                        tenant.max_total_bytes,
                        tenant.max_links,
                        tenant.max_sessions,
                    )
                })
                .unwrap_or((None, None, None)))
        }
    }

    // -------------------------------------------------------------- quotas

    /// Bytes received-and-not-deleted across a tenant's links.
    pub fn tenant_received_bytes(&self, tenant: &str) -> Result<u64, String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let mut statement = connection
            .prepare_cached(
                "SELECT bytes_hi,bytes_lo,state FROM tenant_quota_usage WHERE tenant=?1",
            )
            .map_err(|e| e.to_string())?;
        #[cfg(test)]
        statement.reset_status(rusqlite::StatementStatus::VmStep);
        let state: Option<(i64, i64, i64)> = statement
            .query_row([tenant], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .optional()
            .map_err(|e| e.to_string())?;
        #[cfg(test)]
        LAST_TENANT_RECEIVED_VM_STEPS.with(|steps| {
            steps.set(
                u64::try_from(statement.get_status(rusqlite::StatementStatus::VmStep)).unwrap(),
            )
        });
        drop(statement);
        let Some((mut bytes_hi, mut bytes_lo, mut state)) = state else {
            let live: bool = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM files WHERE tenant=?1 AND deleted=0)",
                    [tenant],
                    |row| row.get(0),
                )
                .map_err(|e| e.to_string())?;
            if live {
                return Err(
                    "tenant quota aggregate is missing for live files; refusing admission".into(),
                );
            }
            return Ok(0);
        };
        if !(0..=QUOTA_MAX_LIMB).contains(&bytes_hi)
            || !(0..=QUOTA_MAX_LIMB).contains(&bytes_lo)
            || !(0..=2).contains(&state)
        {
            return Err("tenant quota aggregate is invalid; refusing admission".into());
        }
        if state == 2 {
            let transaction = connection.transaction().map_err(|e| e.to_string())?;
            rebuild_tenant_quota(&transaction, tenant).map_err(|e| e.to_string())?;
            transaction.commit().map_err(|e| e.to_string())?;
            (bytes_hi, bytes_lo, state) = connection
                .query_row(
                    "SELECT bytes_hi,bytes_lo,state FROM tenant_quota_usage WHERE tenant=?1",
                    [tenant],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(|e| e.to_string())?;
        }
        if state == 1 {
            Ok(u64::MAX)
        } else {
            Ok((u64::try_from(bytes_hi).unwrap() << 32) | u64::try_from(bytes_lo).unwrap())
        }
    }

    pub fn tenant_admission_usage(
        &self,
        tenant: &str,
    ) -> Result<(u64, Vec<RetainedReservation>), String> {
        let received = self.tenant_received_bytes(tenant)?;
        let retained = self.with(|connection| {
            let mut statement = connection.prepare_cached("SELECT id,push_key,package_length FROM upload_sessions WHERE tenant=?1 AND committed_upload_id IS NULL AND EXISTS(SELECT 1 FROM upload_session_files WHERE session_id=upload_sessions.id)")?;
            let rows = statement.query_map([tenant], |row| Ok(RetainedReservation {
                id: row.get(0)?, push_key: row.get(1)?, bytes: row.get::<_, i64>(2)?.max(0) as u64,
            }))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
        })?;
        Ok((received, retained))
    }

    /// Link and live-byte totals for every tenant. File bytes come from the
    /// same aggregate used for admission so admin holdings cannot disagree.
    pub fn tenant_usage(&self) -> Result<Vec<TenantUsage>, String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let result = (|| -> rusqlite::Result<Vec<TenantUsage>> {
            let transaction = connection.transaction()?;
            let namespaces = transaction
                .prepare(
                    "WITH namespaces(tenant) AS (
                         SELECT ''
                         UNION SELECT key FROM tenants
                         UNION SELECT tenant FROM links
                     )
                     SELECT n.tenant,q.state FROM namespaces n
                     LEFT JOIN tenant_quota_usage q USING (tenant)
                     ORDER BY n.tenant",
                )?
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, Option<i64>>(1)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            for (tenant, state) in &namespaces {
                match state {
                    Some(2) => {
                        rebuild_tenant_quota(&transaction, tenant)?;
                    }
                    Some(0 | 1) => {}
                    Some(_) => return Err(rusqlite::Error::InvalidQuery),
                    None => {
                        let live: bool = transaction.query_row(
                            "SELECT EXISTS(SELECT 1 FROM files WHERE tenant=?1 AND deleted=0)",
                            [tenant],
                            |row| row.get(0),
                        )?;
                        if live {
                            return Err(rusqlite::Error::InvalidQuery);
                        }
                        transaction.execute(
                        "INSERT INTO tenant_quota_usage(tenant,bytes_hi,bytes_lo,state) VALUES (?1,0,0,0)",
                        [tenant],
                    )?;
                    }
                }
            }
            let mut statement = transaction.prepare(
                "WITH link_counts AS (
                 SELECT tenant, COUNT(*) AS links FROM links GROUP BY tenant
             )
             SELECT n.tenant, COALESCE(link_counts.links, 0), q.bytes_hi, q.bytes_lo, q.state
             FROM (
                 SELECT '' AS tenant
                 UNION SELECT key FROM tenants
                 UNION SELECT tenant FROM links
             ) AS n
             JOIN tenant_quota_usage AS q ON q.tenant=n.tenant
             LEFT JOIN link_counts USING (tenant)
             ORDER BY n.tenant",
            )?;
            let rows = statement.query_map([], |row| {
                let state: i64 = row.get(4)?;
                let received_bytes = if state == 1 {
                    u64::MAX
                } else {
                    let bytes_hi: i64 = row.get(2)?;
                    let bytes_lo: i64 = row.get(3)?;
                    if !(0..=QUOTA_MAX_LIMB).contains(&bytes_hi)
                        || !(0..=QUOTA_MAX_LIMB).contains(&bytes_lo)
                    {
                        return Err(rusqlite::Error::InvalidQuery);
                    }
                    (u64::try_from(bytes_hi).unwrap() << 32) | u64::try_from(bytes_lo).unwrap()
                };
                Ok(TenantUsage {
                    tenant: row.get(0)?,
                    links: row.get::<_, i64>(1)?.max(0) as u64,
                    received_bytes,
                })
            })?;
            let result = rows.collect::<rusqlite::Result<Vec<_>>>()?;
            drop(statement);
            transaction.commit()?;
            Ok(result)
        })();
        result.map_err(|e| e.to_string())
    }

    // ------------------------------------------------------ outbound grants

    pub fn insert_outbound_grant(&self, grant: OutboundGrant) -> Result<(), String> {
        self.insert_outbound_grant_with_operation(grant, None)
    }

    pub fn insert_outbound_grant_with_operation(
        &self,
        grant: OutboundGrant,
        operation: Option<&AutomationOperation>,
    ) -> Result<(), String> {
        self.insert_workflow_grant(grant, operation, None, None)
    }

    pub fn insert_workflow_grant(
        &self,
        mut grant: OutboundGrant,
        operation: Option<&AutomationOperation>,
        job: Option<&crate::workflow::Job>,
        share_token: Option<&str>,
    ) -> Result<(), String> {
        if share_token.is_some_and(|token| crate::auth::hash_token(token) != grant.token_hash) {
            return Err("download token does not match grant".into());
        }
        grant.validate_names()?;
        let delivery_digest = evidence::grant_digest(&grant);
        let (bytes_hi, bytes_lo) = split_bytes(grant.bytes);
        let files_json = serde_json::to_string(&grant.files).unwrap_or_else(|_| "[]".to_owned());
        let file_count = i64::try_from(grant.files.len().max(1)).unwrap_or(i64::MAX);
        let grant_id = grant.id.clone();
        let mut connection = self.connection.lock().expect("store poisoned");
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        workflows::check_grant_creation(&transaction, &grant, job)?;
        if let Some(policy) =
            notifications::notification_job_override_in(&transaction, &grant.tenant, &grant.id)
                .map_err(|e| e.to_string())?
        {
            grant.notifications = Some(policy);
        }
        if let Some(job) = job {
            workflows::finish_job(
                &transaction,
                &self.event_signer,
                job,
                &grant,
                &delivery_digest,
            )?;
        }
        transaction.execute(
                "INSERT INTO outbound_grants
                 (id, token_hash, password_hash, tenant, link_id, upload_id, package_root, name, suite,
                  root, file_index, bytes_hi, bytes_lo, label, created_at, expires_at, revoked_at,
                  downloads, max_downloads, first_download_at, last_download_at,
                  files_json, file_count, notifications_json, share_token)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25)",
                rusqlite::params![
                    &grant_id,
                    grant.token_hash,
                    grant.password_hash,
                    grant.tenant,
                    grant.link_id,
                    grant.upload_id,
                    grant.package_root,
                    grant.name,
                    grant.suite,
                    grant.root,
                    i64::try_from(grant.file_index).unwrap_or(i64::MAX),
                    bytes_hi,
                    bytes_lo,
                    grant.label,
                    i64::try_from(grant.created_at).unwrap_or(i64::MAX),
                    i64::try_from(grant.expires_at).unwrap_or(i64::MAX),
                    grant.revoked_at.map(|at| i64::try_from(at).unwrap_or(i64::MAX)),
                    i64::try_from(grant.downloads).unwrap_or(i64::MAX),
                    grant
                        .max_downloads
                        .map(|count| i64::try_from(count).unwrap_or(i64::MAX)),
                    grant
                        .first_download_at
                        .map(|at| i64::try_from(at).unwrap_or(i64::MAX)),
                    grant
                        .last_download_at
                        .map(|at| i64::try_from(at).unwrap_or(i64::MAX)),
                    files_json,
                    file_count,
                    serde_json::to_string(&grant.notifications).map_err(|e| e.to_string())?,
                    share_token.filter(|_| job.is_none()),
                ],
            )
            .map_err(|error| error.to_string())?;
        let mut child = transaction
            .prepare(
                "INSERT INTO outbound_grant_files
             (grant_id, file_index, source, name, suite, root, bytes_hi, bytes_lo,
              receipt_b64, downloads, first_download_at, last_download_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            )
            .map_err(|error| error.to_string())?;
        for (index, file) in grant.files.into_iter().enumerate() {
            let (file_bytes_hi, file_bytes_lo) = split_bytes(file.bytes);
            child
                .execute(rusqlite::params![
                    &grant_id,
                    i64::try_from(index).unwrap_or(i64::MAX),
                    file.source,
                    file.name,
                    file.suite,
                    file.root,
                    file_bytes_hi,
                    file_bytes_lo,
                    file.receipt_b64,
                    i64::try_from(file.downloads).unwrap_or(i64::MAX),
                    file.first_download_at
                        .map(|at| i64::try_from(at).unwrap_or(i64::MAX)),
                    file.last_download_at
                        .map(|at| i64::try_from(at).unwrap_or(i64::MAX)),
                ])
                .map_err(|error| error.to_string())?;
        }
        drop(child);
        transaction
            .execute(
                "INSERT INTO delivery_manifests(grant_id,digest) VALUES (?1,?2)",
                rusqlite::params![grant_id, delivery_digest],
            )
            .map_err(|e| e.to_string())?;
        if let Some(operation) = operation {
            let active: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM automation_tokens WHERE id = ?1 AND revoked_at IS NULL AND expires_at > ?2)",
                rusqlite::params![operation.token_id, now_unix() as i64], |row| row.get(0),
            ).map_err(|error| error.to_string())?;
            if !active {
                return Err("automation token expired or revoked".to_owned());
            }
            transaction.execute(
                "INSERT INTO automation_operations (token_id, operation_id, request_hash, grant_id) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![operation.token_id, operation.operation_id, operation.request_hash, grant_id],
            ).map_err(|error| error.to_string())?;
        }
        transaction.commit().map_err(|error| error.to_string())
    }

    pub fn outbound_grants(&self, tenant: &str) -> Result<Vec<OutboundGrant>, String> {
        self.with(|connection| {
            let mut statement = connection.prepare(
                "SELECT id, token_hash, password_hash, tenant, link_id, upload_id, package_root,
                        name, suite, root, file_index, bytes_hi, bytes_lo, label, created_at,
                        expires_at, revoked_at, downloads, max_downloads, notifications_json, first_download_at,
                        last_download_at,
                        files_json
                 FROM outbound_grants WHERE tenant = ?1 ORDER BY created_at, rowid",
            )?;
            let rows = statement.query_map([tenant], map_outbound_grant)?;
            let mut grants = rows.collect::<Result<Vec<_>, _>>()?;
            for grant in &mut grants {
                overlay_outbound_file_counters(connection, grant)?;
            }
            Ok(grants)
        })
    }

    pub fn outbound_grants_page(
        &self,
        tenant: &str,
        limit: usize,
        offset: usize,
        file_preview_limit: usize,
    ) -> Result<(Vec<(OutboundGrant, usize)>, u64), String> {
        let limit = i64::try_from(limit).map_err(|_| "outbound grant limit overflow".to_owned())?;
        let offset =
            i64::try_from(offset).map_err(|_| "outbound grant offset overflow".to_owned())?;
        let file_preview_limit = i64::try_from(file_preview_limit)
            .map_err(|_| "outbound grant file preview limit overflow".to_owned())?;
        self.with(|connection| {
            let grants = {
                let mut statement = connection.prepare(
                    "SELECT id, token_hash, password_hash, tenant, link_id, upload_id, package_root,
                            name, suite, root, file_index, bytes_hi, bytes_lo, label, created_at,
                            expires_at, revoked_at, downloads, max_downloads, notifications_json, first_download_at,
                            last_download_at,
                            file_count,
                            CASE WHEN file_count <= ?4
                                 THEN files_json ELSE '[]' END AS files_json
                     FROM outbound_grants WHERE tenant = ?1
                     ORDER BY created_at DESC, rowid DESC LIMIT ?2 OFFSET ?3",
                )?;
                let rows = statement.query_map(
                    rusqlite::params![tenant, limit, offset, file_preview_limit],
                    map_outbound_grant_page,
                )?;
                let mut grants = rows.collect::<Result<Vec<_>, _>>()?;
                for (grant, _) in &mut grants {
                    overlay_outbound_file_counters(connection, grant)?;
                }
                grants
            };
            let total =
                connection
                    .query_row(
                        "SELECT COUNT(*) FROM outbound_grants WHERE tenant = ?1",
                        [tenant],
                        |row| row.get::<_, i64>(0),
                    )
                    .map(|count| count.max(0) as u64)?;
            Ok((grants, total))
        })
    }

    pub fn outbound_grant_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<OutboundGrant>, String> {
        self.with(|connection| {
            connection
                .prepare_cached(
                    "SELECT id, token_hash, password_hash, tenant, link_id, upload_id, package_root,
                            name, suite, root, file_index, bytes_hi, bytes_lo, label, created_at,
                            expires_at, revoked_at, downloads, max_downloads, notifications_json, first_download_at,
                            last_download_at,
                            files_json
                     FROM outbound_grants WHERE token_hash = ?1",
                )?
                .query_row([token_hash], map_outbound_grant)
                .optional()
                .and_then(|grant| {
                    grant
                        .map(|mut grant| {
                            overlay_outbound_file_counters(connection, &mut grant)?;
                            Ok(grant)
                        })
                        .transpose()
                })
        })
    }

    /// The manifest root recorded for a grant's VOT package, if one was built.
    pub fn outbound_grant_manifest_root(&self, grant_id: &str) -> Result<Option<String>, String> {
        self.with(|connection| {
            connection
                .query_row(
                    "SELECT manifest_root FROM outbound_grant_manifests WHERE grant_id = ?1",
                    [grant_id],
                    |row| row.get(0),
                )
                .optional()
        })
    }

    pub fn put_outbound_grant_manifest(
        &self,
        grant_id: &str,
        manifest_root: &str,
        now: u64,
    ) -> Result<(), String> {
        self.with(|connection| {
            connection
                .execute(
                    "INSERT INTO outbound_grant_manifests (grant_id, manifest_root, created_at)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT(grant_id) DO UPDATE SET manifest_root = excluded.manifest_root,
                                                         created_at = excluded.created_at",
                    rusqlite::params![grant_id, manifest_root, now as i64],
                )
                .map(|_| ())
        })
    }

    /// One grant by id, for fetch admission through its ticket.
    pub fn outbound_grant_by_id(&self, id: &str) -> Result<Option<OutboundGrant>, String> {
        self.with(|connection| {
            connection
                .prepare_cached(
                    "SELECT id, token_hash, password_hash, tenant, link_id, upload_id, package_root,
                            name, suite, root, file_index, bytes_hi, bytes_lo, label, created_at,
                            expires_at, revoked_at, downloads, max_downloads, notifications_json, first_download_at,
                            last_download_at,
                            files_json
                     FROM outbound_grants WHERE id = ?1",
                )?
                .query_row([id], map_outbound_grant)
                .optional()
                .and_then(|grant| {
                    grant
                        .map(|mut grant| {
                            overlay_outbound_file_counters(connection, &mut grant)?;
                            Ok(grant)
                        })
                        .transpose()
                })
        })
    }

    /// Records a minted fetch capability against its grant, only if the
    /// deliveries recorded plus the tickets still live and undelivered leave
    /// room under `max_downloads`. An unadmitted ticket from this same
    /// holder is replaced by the new capability in the same transaction;
    /// admitted tickets and other holders still consume the reservation.
    /// The insert and replacement are atomic, so two mints racing for the
    /// last delivery cannot both reserve it.
    pub fn put_fetch_ticket(&self, ticket: &FetchTicket, now: u64) -> Result<bool, String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let tx = connection.transaction().map_err(|e| e.to_string())?;
        let job = workflows::release_in(&tx, &ticket.grant_id)?;
        if job.as_ref().map_or(0, |job| job.project.revision) != ticket.policy_revision
            || job.as_ref().is_some_and(|job| {
                !job.request.recipients.is_empty()
                    && !job.request.recipients.contains(&ticket.holder)
            })
        {
            return Ok(false);
        }
        let changed = tx.execute(
            "INSERT INTO outbound_fetch_tickets(token_id,grant_id,manifest_root,expires_at,delivered_at,holder,grant_token_hash,policy_revision)
             SELECT ?1,?2,?3,?4,NULL,?5,?6,?7 FROM outbound_grants g WHERE g.id=?2 AND g.token_hash=?6 AND g.revoked_at IS NULL AND g.expires_at>?8
             AND (g.max_downloads IS NULL OR g.downloads+(SELECT COUNT(*) FROM outbound_fetch_tickets WHERE grant_id=?2 AND (admitted_at IS NOT NULL OR (grant_token_hash=?6 AND policy_revision=?7 AND holder<>?5)) AND expires_at>?8 AND delivered_at IS NULL)<g.max_downloads)",
            rusqlite::params![ticket.token_id,ticket.grant_id,ticket.manifest_root,ticket.expires_at as i64,ticket.holder,ticket.grant_token_hash,ticket.policy_revision as i64,now as i64]).map_err(|e| e.to_string())?;
        if changed == 1 {
            tx.execute(
                "DELETE FROM outbound_fetch_tickets
                 WHERE grant_id = ?1 AND holder = ?2 AND token_id <> ?3
                   AND expires_at > ?4 AND delivered_at IS NULL AND admitted_at IS NULL",
                rusqlite::params![ticket.grant_id, ticket.holder, ticket.token_id, now as i64],
            )
            .map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(changed == 1)
    }

    pub fn admit_fetch_ticket(&self, ticket: &FetchTicket, now: u64) -> Result<bool, String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let job = workflows::release_in(&tx, &ticket.grant_id)?;
        if job.as_ref().map_or(0, |job| job.project.revision) != ticket.policy_revision
            || job.as_ref().is_some_and(|job| {
                !job.request.recipients.is_empty()
                    && !job.request.recipients.contains(&ticket.holder)
            })
        {
            return Ok(false);
        }
        let changed = tx.execute("UPDATE outbound_fetch_tickets SET admitted_at=COALESCE(admitted_at,?4) WHERE token_id=?1 AND grant_id=?2 AND grant_token_hash=?3 AND expires_at>?4 AND EXISTS(SELECT 1 FROM outbound_grants WHERE id=?2 AND token_hash=?3 AND revoked_at IS NULL AND expires_at>?4 AND (max_downloads IS NULL OR downloads<max_downloads))", rusqlite::params![ticket.token_id,ticket.grant_id,ticket.grant_token_hash,now as i64]).map_err(|error|error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(changed == 1)
    }

    pub fn fetch_ticket(&self, token_id: &str) -> Result<Option<FetchTicket>, String> {
        self.with(|connection| {
            connection
                .query_row(
                    "SELECT token_id, grant_id, manifest_root, expires_at, delivered_at, holder, grant_token_hash, policy_revision
                     FROM outbound_fetch_tickets WHERE token_id = ?1",
                    [token_id],
                    map_fetch_ticket,
                )
                .optional()
        })
    }

    /// Tickets not yet expired, delivered or not: a capability is good for
    /// its whole window, so a restart warms servers for these and the
    /// registry keeps their state.
    pub fn unexpired_fetch_tickets(&self, now: u64) -> Result<Vec<FetchTicket>, String> {
        self.with(|connection| {
            connection
                .prepare_cached(
                    "SELECT token_id, grant_id, manifest_root, expires_at, delivered_at, holder, grant_token_hash, policy_revision
                     FROM outbound_fetch_tickets WHERE expires_at > ?1",
                )?
                .query_map([now as i64], map_fetch_ticket)?
                .collect()
        })
    }

    /// Manifest roots of grants still open: what the serve registry keeps a
    /// server for.
    pub fn servable_manifest_roots(&self, now: u64) -> Result<Vec<String>, String> {
        self.with(|connection| {
            connection
                .prepare_cached(
                    "SELECT m.manifest_root FROM outbound_grant_manifests m
                     JOIN outbound_grants g ON g.id = m.grant_id
                     WHERE g.revoked_at IS NULL AND g.expires_at > ?1
                       AND (g.max_downloads IS NULL OR g.downloads < g.max_downloads)",
                )?
                .query_map([now as i64], |row| row.get(0))?
                .collect()
        })
    }

    /// Drops tickets expired for more than a day; the audit log keeps the
    /// mint and the delivery.
    pub fn prune_fetch_tickets(&self, before: u64) -> Result<usize, String> {
        self.with(|connection| {
            connection.execute(
                "DELETE FROM outbound_fetch_tickets WHERE expires_at < ?1",
                [before as i64],
            )
        })
    }

    /// Looks up one outbound file without parsing the full manifest.
    pub fn outbound_grant_file_by_token_hash(
        &self,
        token_hash: &str,
        index: usize,
    ) -> Result<Option<(OutboundGrant, Option<OutboundGrantFile>)>, String> {
        self.with(|connection| {
            let parent = connection
                .prepare_cached(
                    "SELECT id, token_hash, password_hash, tenant, link_id, upload_id, package_root,
                            name, suite, root, file_index, bytes_hi, bytes_lo, label, created_at,
                            expires_at, revoked_at, downloads, max_downloads, notifications_json,
                            first_download_at, last_download_at, file_count
                     FROM outbound_grants WHERE token_hash = ?1",
                )?
                .query_row([token_hash], |row| {
                        let file_count = row.get::<_, i64>("file_count")?;
                        let file_count = usize::try_from(file_count.max(0)).map_err(|error| {
                            rusqlite::Error::FromSqlConversionFailure(
                                0,
                                rusqlite::types::Type::Integer,
                                Box::new(error),
                            )
                        })?;
                        Ok((map_outbound_grant_base(row)?, file_count))
                })
                .optional()?;
            let Some((grant, file_count)) = parent else {
                return Ok(None);
            };
            if index >= file_count {
                return Ok(None);
            }
            let row = connection
                .prepare_cached(
                    "SELECT source, name, suite, root, bytes_hi, bytes_lo, receipt_b64,
                            downloads, first_download_at, last_download_at
                     FROM outbound_grant_files WHERE grant_id = ?1 AND file_index = ?2",
                )?
                .query_row(
                    rusqlite::params![grant.id, i64::try_from(index).unwrap_or(i64::MAX)],
                    map_outbound_grant_file,
                )
                .optional()?;
            if row.is_none() {
                let has_children: bool = connection.query_row(
                    "SELECT EXISTS (SELECT 1 FROM outbound_grant_files WHERE grant_id = ?1)",
                    [&grant.id],
                    |row| row.get(0),
                )?;
                if has_children || file_count != 1 {
                    return Ok(None);
                }
                let files_json: String = connection.query_row(
                    "SELECT files_json FROM outbound_grants WHERE id = ?1",
                    [&grant.id],
                    |row| row.get(0),
                )?;
                if !serde_json::from_str::<Vec<OutboundGrantFile>>(&files_json)
                    .map(|files| files.is_empty())
                    .unwrap_or(false)
                {
                    return Ok(None);
                }
            }
            Ok(Some((grant, row)))
        })
    }

    /// Looks up one page of outbound files without parsing the full manifest.
    pub fn outbound_grant_files_page_by_token_hash(
        &self,
        token_hash: &str,
        offset: usize,
        limit: usize,
    ) -> Result<Option<OutboundGrantFilesPage>, String> {
        let offset =
            i64::try_from(offset).map_err(|_| "outbound file offset overflow".to_owned())?;
        let limit = i64::try_from(limit).map_err(|_| "outbound file limit overflow".to_owned())?;
        self.with(|connection| {
            let parent = connection
                .prepare_cached(
                    "SELECT id, token_hash, password_hash, tenant, link_id, upload_id, package_root,
                            name, suite, root, file_index, bytes_hi, bytes_lo, label, created_at,
                            expires_at, revoked_at, downloads, max_downloads, notifications_json,
                            first_download_at, last_download_at, file_count
                     FROM outbound_grants WHERE token_hash = ?1",
                )?
                .query_row([token_hash], |row| {
                        let file_count = row.get::<_, i64>("file_count")?;
                        let file_count = usize::try_from(file_count.max(0)).map_err(|error| {
                            rusqlite::Error::FromSqlConversionFailure(
                                0,
                                rusqlite::types::Type::Integer,
                                Box::new(error),
                            )
                        })?;
                        Ok((map_outbound_grant_base(row)?, file_count))
                })
                .optional()?;
            let Some((grant, file_count)) = parent else {
                return Ok(None);
            };
            let mut statement = connection.prepare(
                "SELECT file_index, source, name, suite, root, bytes_hi, bytes_lo, receipt_b64,
                        downloads, first_download_at, last_download_at
                 FROM outbound_grant_files
                 WHERE grant_id = ?1 AND file_index >= ?2
                 ORDER BY file_index
                 LIMIT ?3",
            )?;
            let rows = statement.query_map(rusqlite::params![grant.id, offset, limit], |row| {
                Ok((
                    usize::try_from(row.get::<_, i64>("file_index")?).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Integer,
                            Box::new(error),
                        )
                    })?,
                    map_outbound_grant_file(row)?,
                ))
            })?;
            let mut files = rows.collect::<Result<Vec<_>, _>>()?;
            if files.is_empty() && offset == 0 && file_count == 1 {
                let has_children: bool = connection.query_row(
                    "SELECT EXISTS (SELECT 1 FROM outbound_grant_files WHERE grant_id = ?1)",
                    [&grant.id],
                    |row| row.get(0),
                )?;
                if !has_children {
                    let files_json: String = connection.query_row(
                        "SELECT files_json FROM outbound_grants WHERE id = ?1",
                        [&grant.id],
                        |row| row.get(0),
                    )?;
                    if serde_json::from_str::<Vec<OutboundGrantFile>>(&files_json)
                        .map(|files| files.is_empty())
                        .unwrap_or(false)
                    {
                        files.push((
                            0,
                            OutboundGrantFile {
                                source: String::new(),
                                name: grant.name.clone(),
                                suite: grant.suite.clone(),
                                root: grant.root.clone(),
                                bytes: grant.bytes,
                                receipt_b64: String::new(),
                                downloads: grant.downloads,
                                first_download_at: grant.first_download_at,
                                last_download_at: grant.last_download_at,
                            },
                        ));
                    }
                }
            }
            let (bytes_hi, bytes_lo): (i64, i64) = connection.query_row(
                "SELECT COALESCE(SUM(bytes_hi), 0), COALESCE(SUM(bytes_lo), 0)
                 FROM outbound_grant_files WHERE grant_id = ?1",
                [&grant.id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            let total_bytes = match combine_byte_sums(bytes_hi, bytes_lo) {
                0 => grant.bytes,
                total => total,
            };
            Ok(Some(OutboundGrantFilesPage {
                grant,
                file_count,
                total_bytes,
                files,
            }))
        })
    }

    /// Private bearer storage follows the workflow token model. Never include
    /// it in grant listings, audits, or public metadata.
    pub(crate) fn outbound_share_token(
        &self,
        tenant: &str,
        id: &str,
    ) -> Result<Option<String>, String> {
        self.with(|connection| {
            connection.query_row(
                "SELECT CASE WHEN j.id IS NULL THEN g.share_token ELSE j.token END, g.token_hash
                 FROM outbound_grants AS g
                 LEFT JOIN delivery_jobs AS j ON j.id=g.id AND j.tenant=g.tenant
                 WHERE g.tenant=?1 AND g.id=?2 AND g.revoked_at IS NULL",
                rusqlite::params![tenant, id],
                |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, String>(1)?)),
            ).optional().map(|row| row.and_then(|(token, hash)|
                token.filter(|token| crate::auth::hash_token(token) == hash)))
        })
    }

    pub fn rotate_outbound_grant_token(
        &self,
        tenant: &str,
        id: &str,
        token: &str,
    ) -> Result<bool, String> {
        self.with(|connection| {
            connection
                .execute(
                    "UPDATE outbound_grants SET token_hash=?3, share_token=?4
                     WHERE tenant=?1 AND id=?2 AND revoked_at IS NULL
                     AND NOT EXISTS(SELECT 1 FROM delivery_jobs WHERE id=?2)",
                    rusqlite::params![tenant, id, crate::auth::hash_token(token), token],
                )
                .map(|changed| changed > 0)
        })
    }

    pub fn extend_outbound_grant(
        &self,
        tenant: &str,
        id: &str,
        seconds: u64,
        now: u64,
    ) -> Result<Option<u64>, String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let result = (|| {
            let retired: bool = transaction.query_row("SELECT EXISTS(SELECT 1 FROM delivery_jobs WHERE id=?1 AND tenant=?2 AND state IN ('retiring','retired','suspended'))",rusqlite::params![id,tenant],|row| row.get(0)).map_err(|error| error.to_string())?;
            if retired {
                return Err("delivery is no longer active; create a new job".into());
            }
            let existing: Option<i64> = transaction
                .query_row(
                    "SELECT expires_at FROM outbound_grants
                     WHERE tenant = ?1 AND id = ?2 AND revoked_at IS NULL",
                    rusqlite::params![tenant, id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|error| error.to_string())?;
            let Some(existing) = existing else {
                return Ok(None);
            };
            let base = (existing.max(0) as u64).max(now.min(i64::MAX as u64));
            let new_expiry = base.saturating_add(seconds).min(i64::MAX as u64);
            let changed = transaction
                .execute(
                    "UPDATE outbound_grants SET expires_at = ?3
                     WHERE tenant = ?1 AND id = ?2 AND revoked_at IS NULL",
                    rusqlite::params![tenant, id, new_expiry as i64],
                )
                .map_err(|error| error.to_string())?;
            if changed == 0 {
                return Ok(None);
            }
            Ok(Some(new_expiry))
        })();
        match result {
            Ok(result) => {
                transaction.commit().map_err(|error| error.to_string())?;
                Ok(result)
            }
            Err(error) => Err(error),
        }
    }

    pub fn revoke_outbound_grant(&self, tenant: &str, id: &str, at: u64) -> Result<bool, String> {
        self.with(|connection| {
            connection.execute(
                "UPDATE outbound_grants SET revoked_at = ?3
                 WHERE tenant = ?1 AND id = ?2 AND revoked_at IS NULL",
                rusqlite::params![tenant, id, i64::try_from(at).unwrap_or(i64::MAX)],
            )
        })
        .map(|changed| changed > 0)
    }

    pub fn record_outbound_download(
        &self,
        id: &str,
        indexes: &[usize],
        at: u64,
    ) -> Result<OutboundDownloadResult, String> {
        self.record_download(id, indexes, at, None)
    }

    pub fn record_fetch_download(
        &self,
        id: &str,
        indexes: &[usize],
        at: u64,
        token: &str,
    ) -> Result<OutboundDownloadResult, String> {
        self.record_download(id, indexes, at, Some(token))
    }

    fn record_download(
        &self,
        id: &str,
        indexes: &[usize],
        at: u64,
        ticket: Option<&str>,
    ) -> Result<OutboundDownloadResult, String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let result = (|| {
            let (downloads, max_downloads, first_download_at, normalized, file_count): (
                i64,
                Option<i64>,
                Option<i64>,
                bool,
                i64,
            ) = transaction
                .query_row(
                    "SELECT g.downloads, g.max_downloads, g.first_download_at,
                                EXISTS (SELECT 1 FROM outbound_grant_files
                                        WHERE grant_id = g.id),
                                g.file_count
                         FROM outbound_grants AS g WHERE g.id = ?1",
                    [id],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    },
                )
                .optional()
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "outbound grant not found".to_owned())?;
            let file_count = usize::try_from(file_count)
                .map_err(|_| "outbound grant file count out of range".to_owned())?;
            let downloads = downloads.max(0) as u64;
            let max_downloads = max_downloads.and_then(|max| u64::try_from(max).ok());
            if max_downloads.is_some_and(|max| downloads >= max) {
                return Err(OUTBOUND_DOWNLOAD_LIMIT_REACHED.to_owned());
            }
            if normalized {
                let mut unique_indexes = indexes.to_vec();
                unique_indexes.sort_unstable();
                unique_indexes.dedup();
                let was_all_files_downloaded = downloads > 0;
                let first_download = first_download_at.is_none();
                let at = i64::try_from(at).unwrap_or(i64::MAX);
                let first_download_at = if first_download {
                    Some(at)
                } else {
                    first_download_at
                };
                let max_downloads =
                    max_downloads.map(|value| i64::try_from(value).unwrap_or(i64::MAX));
                let full_range = file_count > 0
                    && indexes.len() == file_count
                    && indexes.iter().copied().eq(0..file_count);
                if full_range {
                    let file_count_i64 = i64::try_from(file_count).unwrap_or(i64::MAX);
                    let changed = transaction
                        .execute(
                            "UPDATE outbound_grant_files
                             SET downloads = CASE WHEN downloads = 9223372036854775807
                                                  THEN downloads ELSE downloads + 1 END,
                                 first_download_at = COALESCE(first_download_at, ?3),
                                 last_download_at = ?3
                             WHERE grant_id = ?1
                               AND (?2 IS NULL OR downloads < ?2)",
                            rusqlite::params![id, max_downloads, at],
                        )
                        .map_err(|error| error.to_string())?;
                    if changed != file_count {
                        let (child_count, in_range_count, exhausted): (i64, i64, bool) =
                            transaction
                                .query_row(
                                    "SELECT
                                         (SELECT COUNT(*) FROM outbound_grant_files
                                          WHERE grant_id = ?1),
                                         (SELECT COUNT(*) FROM outbound_grant_files
                                          WHERE grant_id = ?1 AND file_index >= 0
                                            AND file_index < ?2),
                                         EXISTS (SELECT 1 FROM outbound_grant_files
                                          WHERE grant_id = ?1
                                            AND ?3 IS NOT NULL AND downloads >= ?3)",
                                    rusqlite::params![id, file_count_i64, max_downloads],
                                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                                )
                                .map_err(|error| error.to_string())?;
                        if child_count == file_count_i64
                            && in_range_count == file_count_i64
                            && exhausted
                        {
                            return Err(OUTBOUND_DOWNLOAD_LIMIT_REACHED.to_owned());
                        }
                        return Err("outbound file index out of range".to_owned());
                    }
                } else {
                    let mut update = transaction
                        .prepare_cached(
                            "UPDATE outbound_grant_files
                             SET downloads = CASE WHEN downloads = 9223372036854775807
                                                  THEN downloads ELSE downloads + 1 END,
                                 first_download_at = COALESCE(first_download_at, ?3),
                                 last_download_at = ?3
                             WHERE grant_id = ?1 AND file_index = ?2
                               AND (?4 IS NULL OR downloads < ?4)",
                        )
                        .map_err(|error| error.to_string())?;
                    for index in &unique_indexes {
                        let index = i64::try_from(*index).unwrap_or(i64::MAX);
                        let changed = update
                            .execute(rusqlite::params![id, index, at, max_downloads,])
                            .map_err(|error| error.to_string())?;
                        if changed == 0 {
                            let exists: bool = transaction
                                .query_row(
                                    "SELECT EXISTS (SELECT 1 FROM outbound_grant_files
                                                     WHERE grant_id = ?1 AND file_index = ?2)",
                                    rusqlite::params![id, index],
                                    |row| row.get(0),
                                )
                                .map_err(|error| error.to_string())?;
                            if exists {
                                return Err(OUTBOUND_DOWNLOAD_LIMIT_REACHED.to_owned());
                            }
                            return Err("outbound file index out of range".to_owned());
                        }
                    }
                }
                let downloads = if unique_indexes.is_empty() {
                    downloads
                } else {
                    transaction
                        .query_row(
                            "SELECT downloads FROM outbound_grant_files
                             WHERE grant_id = ?1 ORDER BY downloads LIMIT 1",
                            [id],
                            |row| row.get::<_, i64>(0),
                        )
                        .map(|value| value.max(0) as u64)
                        .map_err(|error| error.to_string())?
                };
                let completed_delivery = !was_all_files_downloaded && downloads > 0;
                transaction
                    .execute(
                        "UPDATE outbound_grants
                         SET downloads = ?2, first_download_at = ?3, last_download_at = ?4
                         WHERE id = ?1",
                        rusqlite::params![
                            id,
                            i64::try_from(downloads).unwrap_or(i64::MAX),
                            first_download_at,
                            at,
                        ],
                    )
                    .map_err(|error| error.to_string())?;
                return Ok(OutboundDownloadResult {
                    first_download,
                    completed_delivery,
                });
            }
            let files_json: String = transaction
                .query_row(
                    "SELECT files_json FROM outbound_grants WHERE id = ?1",
                    [id],
                    |row| row.get(0),
                )
                .map_err(|error| error.to_string())?;
            let files: Vec<OutboundGrantFile> = serde_json::from_str(&files_json)
                .map_err(|error| format!("parse outbound grant files: {error}"))?;
            if !files.is_empty() {
                return Err("outbound grant files are not normalized".to_owned());
            }
            let mut unique_indexes = indexes.to_vec();
            unique_indexes.sort_unstable();
            unique_indexes.dedup();
            if unique_indexes.iter().any(|&index| index != 0) {
                return Err("outbound file index out of range".to_owned());
            }
            let first_download = first_download_at.is_none();
            let at = i64::try_from(at).unwrap_or(i64::MAX);
            let first_download_at = if first_download {
                Some(at)
            } else {
                first_download_at
            };
            let downloads = downloads.saturating_add(1);
            transaction
                .execute(
                    "UPDATE outbound_grants
                     SET downloads = ?2, first_download_at = ?3, last_download_at = ?4
                     WHERE id = ?1",
                    rusqlite::params![
                        id,
                        i64::try_from(downloads).unwrap_or(i64::MAX),
                        first_download_at,
                        at,
                    ],
                )
                .map_err(|error| error.to_string())?;
            Ok(OutboundDownloadResult {
                first_download,
                completed_delivery: first_download,
            })
        })();
        match result {
            Ok(result) => {
                if let Some(ticket) = ticket {
                    let changed = transaction.execute("UPDATE outbound_fetch_tickets SET delivered_at=COALESCE(delivered_at,?3) WHERE token_id=?1 AND grant_id=?2", rusqlite::params![ticket, id, i64::try_from(at).unwrap_or(i64::MAX)]).map_err(|error| error.to_string())?;
                    if changed != 1 {
                        return Err("fetch completion ticket does not match its grant".to_owned());
                    }
                }
                transaction.commit().map_err(|error| error.to_string())?;
                Ok(result)
            }
            Err(error) => Err(error),
        }
    }

    pub fn has_active_outbound_grant(
        &self,
        tenant: &str,
        link_id: &str,
        upload_id: &str,
        file_index: usize,
        now: u64,
    ) -> Result<bool, String> {
        self.with(|connection| {
            connection.query_row(
                "SELECT EXISTS (
                     SELECT 1 FROM outbound_grants
                     WHERE tenant = ?1 AND link_id = ?2 AND upload_id = ?3 AND file_index = ?4
                       AND revoked_at IS NULL AND expires_at > ?5
                       AND (max_downloads IS NULL OR downloads < max_downloads)
                 )",
                rusqlite::params![
                    tenant,
                    link_id,
                    upload_id,
                    i64::try_from(file_index).unwrap_or(i64::MAX),
                    i64::try_from(now).unwrap_or(i64::MAX),
                ],
                |row| row.get::<_, i64>(0),
            )
        })
        .map(|exists| exists != 0)
    }

    pub fn has_active_library_grant(
        &self,
        tenant: &str,
        source: &str,
        now: u64,
    ) -> Result<bool, String> {
        self.with(|connection| {
            let mut statement = connection.prepare(
                "SELECT files_json
                 FROM outbound_grants
                 WHERE tenant = ?1 AND length(trim(files_json)) > 2
                   AND revoked_at IS NULL AND expires_at > ?2
                   AND (max_downloads IS NULL OR downloads < max_downloads)",
            )?;
            let rows = statement.query_map(
                rusqlite::params![tenant, i64::try_from(now).unwrap_or(i64::MAX)],
                |row| row.get::<_, String>(0),
            )?;
            for row in rows {
                let files: Vec<OutboundGrantFile> =
                    serde_json::from_str(&row?).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?;
                if files.iter().any(|file| file.source == source) {
                    return Ok(true);
                }
            }
            Ok(false)
        })
        .map_err(|error| error.to_string())
    }

    pub fn active_outbound_file_keys(
        &self,
        tenant: &str,
        link_id: &str,
        now: u64,
    ) -> Result<Vec<(String, usize)>, String> {
        self.with(|connection| {
            let mut statement = connection.prepare(
                "SELECT upload_id, file_index
                 FROM outbound_grants
                 WHERE tenant = ?1 AND link_id = ?2
                   AND revoked_at IS NULL AND expires_at > ?3
                   AND (max_downloads IS NULL OR downloads < max_downloads)",
            )?;
            let rows = statement.query_map(
                rusqlite::params![tenant, link_id, i64::try_from(now).unwrap_or(i64::MAX)],
                |row| {
                    let upload_id = row.get::<_, String>(0)?;
                    let file_index = usize::try_from(row.get::<_, i64>(1)?).map_err(|_| {
                        rusqlite::Error::FromSqlConversionFailure(
                            1,
                            rusqlite::types::Type::Integer,
                            Box::new(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "outbound grant file index is outside usize range",
                            )),
                        )
                    })?;
                    Ok((upload_id, file_index))
                },
            )?;
            rows.collect::<Result<Vec<_>, _>>()
        })
    }

    /// Returns globally referenced object keys for non-expired, non-revoked
    /// outbound grants. Catalogs are content-addressed, so tenant is omitted.
    pub fn active_outbound_object_keys(
        &self,
        now: u64,
    ) -> Result<Vec<(String, String, u64)>, String> {
        self.with(|connection| {
            let mut statement = connection.prepare(
                "SELECT suite, root, bytes_hi, bytes_lo
                 FROM outbound_grants
                 WHERE revoked_at IS NULL AND expires_at > ?1
                 UNION
                 SELECT files.suite, files.root, files.bytes_hi, files.bytes_lo
                 FROM outbound_grant_files AS files
                 JOIN outbound_grants AS grants ON grants.id = files.grant_id
                 WHERE grants.revoked_at IS NULL AND grants.expires_at > ?1
                 ORDER BY suite, root, bytes_hi, bytes_lo",
            )?;
            let rows = statement.query_map([i64::try_from(now).unwrap_or(i64::MAX)], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    combine_byte_sums(row.get(2)?, row.get(3)?),
                ))
            })?;
            rows.collect::<Result<Vec<_>, _>>()
        })
    }

    pub fn link_has_active_outbound_grants(
        &self,
        tenant: &str,
        link_id: &str,
        now: u64,
    ) -> Result<bool, String> {
        self.with(|connection| {
            connection.query_row(
                "SELECT EXISTS (
                     SELECT 1 FROM outbound_grants
                     WHERE tenant = ?1 AND link_id = ?2
                       AND revoked_at IS NULL AND expires_at > ?3
                       AND (max_downloads IS NULL OR downloads < max_downloads)
                 )",
                rusqlite::params![tenant, link_id, i64::try_from(now).unwrap_or(i64::MAX),],
                |row| row.get::<_, i64>(0),
            )
        })
        .map(|exists| exists != 0)
    }
}

fn escape_like(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

fn insert_link_row(connection: &Connection, link: &Link) -> rusqlite::Result<()> {
    connection.execute(
        "INSERT INTO links (id, tenant, label, dest, password_hash, created_at, expires_at, max_bytes,
                            active, legal_hold, events_json, notifications_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        link_params(link),
    )?;
    for upload in &link.uploads {
        connection.execute(
            "INSERT INTO link_uploads(link_id,tenant,upload_id,document,file_count) VALUES (?1,?2,?3,?4,?5)",
            rusqlite::params![
                link.id,
                link.tenant,
                upload.id,
                upload_header_json(upload)?,
                i64::try_from(upload.files.len()).unwrap_or(i64::MAX)
            ],
        )?;
        insert_upload_files(connection, &link.id, &link.tenant, upload)?;
    }
    Ok(())
}

fn write_link_row(connection: &Connection, link: &Link) -> rusqlite::Result<()> {
    connection.execute(
        "UPDATE links SET label = ?3, dest = ?4, password_hash = ?5, created_at = ?6,
                          expires_at = ?7, max_bytes = ?8, active = ?9,
                          legal_hold = ?10, events_json = ?11, notifications_json = ?12
         WHERE id = ?1 AND tenant = ?2",
        link_params(link),
    )?;
    Ok(())
}

fn upload_header_json(upload: &UploadRecord) -> rusqlite::Result<String> {
    let header = UploadRecord {
        id: upload.id.clone(),
        started_at: upload.started_at,
        completed_at: upload.completed_at,
        replayed_chunks: upload.replayed_chunks,
        rejected_chunks: upload.rejected_chunks,
        transport: upload.transport.clone(),
        package_root: upload.package_root.clone(),
        total_bytes: upload.total_bytes,
        files: Vec::new(),
        partial: upload.partial,
        log: upload.log.clone(),
    };
    serde_json::to_string(&header).map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
}

fn read_uploads(connection: &Connection, id: &str) -> rusqlite::Result<Vec<UploadRecord>> {
    connection
        .prepare_cached("SELECT document,file_count,upload_id,tenant FROM link_uploads WHERE link_id=?1 ORDER BY position")?
        .query_map([id], |row| hydrate_upload(connection, id, row))?
        .collect()
}

fn read_upload(
    connection: &Connection,
    tenant: &str,
    link_id: &str,
    upload_id: &str,
) -> rusqlite::Result<Option<UploadRecord>> {
    connection
        .prepare_cached(
            "SELECT document,file_count,upload_id,tenant FROM link_uploads WHERE tenant=?1 AND link_id=?2 AND upload_id=?3
         AND EXISTS(SELECT 1 FROM links WHERE tenant=?1 AND id=?2)",
        )?
        .query_row([tenant, link_id, upload_id], |row| hydrate_upload(connection, link_id, row))
        .optional()
}

fn hydrate_upload(
    connection: &Connection,
    link_id: &str,
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<UploadRecord> {
    let mut upload: UploadRecord = parse_json(&row.get::<_, String>(0)?, 0)?;
    let count: i64 = row.get(1)?;
    let id: String = row.get(2)?;
    let tenant: String = row.get(3)?;
    let invalid = || {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            "upload file records do not match their header".into(),
        )
    };
    if upload.id != id || !upload.files.is_empty() {
        return Err(invalid());
    }
    let mut statement = connection.prepare_cached(
        "SELECT file_index,path,stored_as,bytes_hi,bytes_lo,suite,root,receipt,deleted
         FROM files WHERE tenant=?1 AND link_id=?2 AND upload_id=?3 ORDER BY file_index",
    )?;
    let mut rows = statement.query([tenant.as_str(), link_id, id.as_str()])?;
    while let Some(row) = rows.next()? {
        let index: i64 = row.get(0)?;
        if index != i64::try_from(upload.files.len()).unwrap_or(i64::MAX) || index >= count {
            return Err(invalid());
        }
        upload.files.push(row_to_upload_file(row)?);
    }
    if i64::try_from(upload.files.len()).unwrap_or(i64::MAX) != count {
        return Err(invalid());
    }
    Ok(upload)
}

fn row_to_upload_file(row: &rusqlite::Row<'_>) -> rusqlite::Result<FileRecord> {
    Ok(FileRecord {
        path: row.get(1)?,
        stored_as: row.get(2)?,
        bytes: (u64::from(row.get::<_, u32>(3)?) << 32) | u64::from(row.get::<_, u32>(4)?),
        suite: row.get(5)?,
        root: row.get(6)?,
        receipt: row.get(7)?,
        deleted: row.get(8)?,
    })
}

fn write_upload(
    connection: &Connection,
    tenant: &str,
    id: &str,
    upload: &UploadRecord,
) -> rusqlite::Result<()> {
    connection.execute(
        "UPDATE link_uploads SET document=?4,file_count=?5 WHERE tenant=?1 AND link_id=?2 AND upload_id=?3",
        rusqlite::params![tenant, id, upload.id, upload_header_json(upload)?, i64::try_from(upload.files.len()).unwrap_or(i64::MAX)],
    )?;
    Ok(())
}

fn row_to_link_with_uploads(
    connection: &Connection,
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<Link> {
    let mut link = row_to_link(row)?;
    link.uploads = read_uploads(connection, &link.id)?;
    Ok(link)
}

fn insert_upload_files(
    connection: &Connection,
    link_id: &str,
    tenant: &str,
    upload: &UploadRecord,
) -> rusqlite::Result<()> {
    let mut insert = connection.prepare_cached(
        "INSERT INTO files(link_id,tenant,upload_id,file_index,bytes_hi,bytes_lo,deleted,stored_as,path,suite,root,receipt)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
    )?;
    for (index, file) in upload.files.iter().enumerate() {
        let (hi, lo) = split_bytes(file.bytes);
        insert.execute(rusqlite::params![
            link_id,
            tenant,
            upload.id,
            i64::try_from(index).unwrap_or(i64::MAX),
            hi,
            lo,
            file.deleted,
            file.stored_as,
            file.path,
            file.suite,
            file.root,
            file.receipt
        ])?;
    }
    Ok(())
}

fn sync_upload_files(
    connection: &Connection,
    link_id: &str,
    tenant: &str,
    upload: &UploadRecord,
) -> rusqlite::Result<()> {
    // Compare in SQLite so recovery does not duplicate the full file list in a map.
    let mut upsert = connection.prepare_cached(
        "INSERT INTO files(link_id,tenant,upload_id,file_index,bytes_hi,bytes_lo,deleted,stored_as,path,suite,root,receipt)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)
         ON CONFLICT(link_id,upload_id,file_index) DO UPDATE SET
         tenant=excluded.tenant,bytes_hi=excluded.bytes_hi,bytes_lo=excluded.bytes_lo,deleted=excluded.deleted,stored_as=excluded.stored_as,
         path=excluded.path,suite=excluded.suite,root=excluded.root,receipt=excluded.receipt
         WHERE (tenant,bytes_hi,bytes_lo,deleted,stored_as,path,suite,root,receipt)
            IS NOT (excluded.tenant,excluded.bytes_hi,excluded.bytes_lo,excluded.deleted,excluded.stored_as,excluded.path,excluded.suite,excluded.root,excluded.receipt)",
    )?;
    for (index, file) in upload.files.iter().enumerate() {
        let index = i64::try_from(index).unwrap_or(i64::MAX);
        let (hi, lo) = split_bytes(file.bytes);
        upsert.execute(rusqlite::params![
            link_id,
            tenant,
            upload.id,
            index,
            hi,
            lo,
            file.deleted,
            file.stored_as,
            file.path,
            file.suite,
            file.root,
            file.receipt
        ])?;
    }
    connection.execute(
        "DELETE FROM files WHERE link_id=?1 AND upload_id=?2 AND file_index>=?3",
        rusqlite::params![
            link_id,
            upload.id,
            i64::try_from(upload.files.len()).unwrap_or(i64::MAX)
        ],
    )?;
    Ok(())
}

fn split_bytes(bytes: u64) -> (i64, i64) {
    ((bytes >> 32) as i64, (bytes & 0xffff_ffff) as i64)
}

fn combine_byte_sums(hi: i64, lo: i64) -> u64 {
    u64::try_from(hi)
        .ok()
        .and_then(|hi| hi.checked_mul(1 << 32))
        .and_then(|bytes| u64::try_from(lo).ok().and_then(|lo| bytes.checked_add(lo)))
        .unwrap_or(u64::MAX)
}

struct QuotaIdentity {
    tenant: String,
    stored_as: String,
    discriminator: i64,
    link_id: String,
    upload_id: String,
    file_index: i64,
}

impl PartialEq for QuotaIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.tenant == other.tenant
            && self.discriminator == other.discriminator
            && if self.discriminator == 0 {
                self.stored_as == other.stored_as
            } else {
                self.link_id == other.link_id
                    && self.upload_id == other.upload_id
                    && self.file_index == other.file_index
            }
    }
}

impl Eq for QuotaIdentity {}

fn quota_live_file_sql(tenant: bool) -> &'static str {
    if tenant {
        "SELECT tenant,stored_as,link_id,upload_id,file_index,bytes_hi,bytes_lo
         FROM files WHERE tenant=?1 AND deleted=0
         ORDER BY tenant,
             CASE WHEN stored_as='' THEN 1 ELSE 0 END,
             CASE WHEN stored_as='' THEN '' ELSE stored_as END,
             CASE WHEN stored_as='' THEN link_id ELSE '' END,
             CASE WHEN stored_as='' THEN upload_id ELSE '' END,
             CASE WHEN stored_as='' THEN file_index ELSE 0 END,
             bytes_hi DESC, bytes_lo DESC"
    } else {
        "SELECT tenant,stored_as,link_id,upload_id,file_index,bytes_hi,bytes_lo
         FROM files WHERE deleted=0
         ORDER BY tenant,
             CASE WHEN stored_as='' THEN 1 ELSE 0 END,
             CASE WHEN stored_as='' THEN '' ELSE stored_as END,
             CASE WHEN stored_as='' THEN link_id ELSE '' END,
             CASE WHEN stored_as='' THEN upload_id ELSE '' END,
             CASE WHEN stored_as='' THEN file_index ELSE 0 END,
             bytes_hi DESC, bytes_lo DESC"
    }
}

fn walk_quota_files(
    connection: &Connection,
    tenant: Option<&str>,
    mut visit: impl FnMut(&QuotaIdentity, u64) -> rusqlite::Result<()>,
) -> rusqlite::Result<()> {
    let mut statement = connection.prepare(quota_live_file_sql(tenant.is_some()))?;
    let mut rows = match tenant {
        Some(tenant) => statement.query([tenant])?,
        None => statement.query([])?,
    };
    let mut previous = None;
    while let Some(row) = rows.next()? {
        let tenant: String = row.get(0)?;
        let stored_as: String = row.get(1)?;
        let link_id: String = row.get(2)?;
        let upload_id: String = row.get(3)?;
        let file_index: i64 = row.get(4)?;
        let bytes_hi: i64 = row.get(5)?;
        let bytes_lo: i64 = row.get(6)?;
        if !(0..=QUOTA_MAX_LIMB).contains(&bytes_hi) || !(0..=QUOTA_MAX_LIMB).contains(&bytes_lo) {
            return Err(rusqlite::Error::FromSqlConversionFailure(
                5,
                rusqlite::types::Type::Integer,
                "file byte limbs are outside the u32 range".into(),
            ));
        }
        let identity = QuotaIdentity {
            discriminator: i64::from(stored_as.is_empty()),
            tenant,
            stored_as,
            link_id,
            upload_id,
            file_index,
        };
        let bytes = (u64::try_from(bytes_hi).unwrap() << 32) | u64::try_from(bytes_lo).unwrap();
        if previous.as_ref() != Some(&identity) {
            visit(&identity, bytes)?;
            previous = Some(identity);
        }
    }
    Ok(())
}

fn quota_fold(connection: &Connection, tenant: &str) -> rusqlite::Result<(u64, u64, u8)> {
    let mut count = 0_u64;
    let mut total = 0_u64;
    let mut saturated = false;
    walk_quota_files(connection, Some(tenant), |_identity, bytes| {
        count = count.saturating_add(1);
        if let Some(value) = total.checked_add(bytes) {
            total = value;
        } else {
            total = u64::MAX;
            saturated = true;
        }
        Ok(())
    })?;
    Ok((
        count,
        total,
        if saturated || total == u64::MAX { 1 } else { 0 },
    ))
}

fn backfill_quota_usage(connection: &Connection) -> rusqlite::Result<()> {
    fn flush(
        connection: &Connection,
        tenant: Option<String>,
        bytes: u64,
        saturated: bool,
    ) -> rusqlite::Result<()> {
        let Some(tenant) = tenant else {
            return Ok(());
        };
        let (bytes_hi, bytes_lo) = split_bytes(bytes);
        connection.execute(
            "INSERT INTO tenant_quota_usage(tenant,bytes_hi,bytes_lo,state)
             VALUES (?1,?2,?3,?4)",
            rusqlite::params![
                tenant,
                bytes_hi,
                bytes_lo,
                i64::from(saturated || bytes == u64::MAX)
            ],
        )?;
        Ok(())
    }

    let mut previous_tenant = None;
    let mut total = 0_u64;
    let mut saturated = false;
    connection.execute("DELETE FROM tenant_quota_usage", [])?;
    walk_quota_files(connection, None, |identity, bytes| {
        if previous_tenant.as_deref() != Some(identity.tenant.as_str()) {
            flush(connection, previous_tenant.take(), total, saturated)?;
            previous_tenant = Some(identity.tenant.clone());
            total = 0;
            saturated = false;
        }
        if let Some(value) = total.checked_add(bytes) {
            total = value;
        } else {
            total = u64::MAX;
            saturated = true;
        }
        Ok(())
    })?;
    flush(connection, previous_tenant, total, saturated)?;
    connection.execute(
        "INSERT OR IGNORE INTO tenant_quota_usage(tenant,bytes_hi,bytes_lo,state)
         SELECT key,0,0,0 FROM tenants",
        [],
    )?;
    connection.execute(
        "INSERT OR IGNORE INTO tenant_quota_usage(tenant,bytes_hi,bytes_lo,state) VALUES ('',0,0,0)",
        [],
    )?;
    Ok(())
}

fn rebuild_tenant_quota(connection: &Connection, tenant: &str) -> rusqlite::Result<u64> {
    let (count, total, state) = quota_fold(connection, tenant)?;
    let (bytes_hi, bytes_lo) = split_bytes(if state == 1 { u64::MAX } else { total });
    connection.execute(
        "INSERT INTO tenant_quota_usage(tenant,bytes_hi,bytes_lo,state) VALUES (?1,?2,?3,?4)
         ON CONFLICT(tenant) DO UPDATE SET bytes_hi=excluded.bytes_hi,bytes_lo=excluded.bytes_lo,state=excluded.state",
        rusqlite::params![tenant, bytes_hi, bytes_lo, state],
    )?;
    Ok(count)
}

fn install_quota_schema(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(QUOTA_SCHEMA)?;
    connection.execute_batch(QUOTA_INDEXES)?;
    connection.execute_batch(
        "DROP TRIGGER IF EXISTS tenant_quota_usage_insert;
         DROP TRIGGER IF EXISTS tenant_quota_usage_delete;
         DROP TRIGGER IF EXISTS tenant_quota_usage_update;",
    )?;
    backfill_quota_usage(connection)?;
    connection.execute_batch(&quota_trigger_sql())?;
    validate_quota_schema(connection).map_err(|error| {
        rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            error,
        )))
    })?;
    Ok(())
}

fn validate_quota_schema(connection: &Connection) -> Result<(), String> {
    let table_sql: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type='table' AND name='tenant_quota_usage'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    let table_sql =
        table_sql.ok_or("tenant quota aggregate table is missing; refusing to start")?;
    for column in ["tenant", "bytes_hi", "bytes_lo", "state"] {
        let exists: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('tenant_quota_usage') WHERE name=?1)",
                [column],
                |row| row.get(0),
            )
            .map_err(|e| e.to_string())?;
        if !exists {
            return Err(format!(
                "tenant quota aggregate column {column} is missing; refusing to start"
            ));
        }
    }
    let normalized_table = normalize_schema_sql(&table_sql);
    let canonical_table = QUOTA_SCHEMA
        .split("CREATE TABLE IF NOT EXISTS tenant_quota_usage")
        .nth(1)
        .map(|suffix| normalize_schema_sql(&format!("CREATE TABLE tenant_quota_usage{suffix}")));
    if canonical_table.as_deref() != Some(normalized_table.as_str()) {
        return Err("tenant quota aggregate table definition is invalid; refusing to start".into());
    }
    let index_sql: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type='index' AND name='files_quota_identity'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    let index_sql = index_sql.ok_or("tenant quota identity index is missing; refusing to start")?;
    let normalized_index = normalize_schema_sql(&index_sql);
    let canonical_index = QUOTA_INDEXES
        .split("CREATE INDEX IF NOT EXISTS files_quota_identity")
        .nth(1)
        .and_then(|sql| {
            sql.split("CREATE INDEX IF NOT EXISTS upload_sessions_quota_live")
                .next()
        })
        .map(|sql| normalize_schema_sql(&format!("CREATE INDEX files_quota_identity{sql}")));
    if canonical_index.as_deref() != Some(normalized_index.as_str()) {
        return Err("tenant quota identity index definition is invalid; refusing to start".into());
    }
    let session_index_sql: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type='index' AND name='upload_sessions_quota_live'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    let session_index_sql =
        session_index_sql.ok_or("tenant retained-session index is missing; refusing to start")?;
    let canonical_session_index = QUOTA_INDEXES
        .split("CREATE INDEX IF NOT EXISTS upload_sessions_quota_live")
        .nth(1)
        .map(|sql| normalize_schema_sql(&format!("CREATE INDEX upload_sessions_quota_live{sql}")));
    let normalized_session_index = normalize_schema_sql(&session_index_sql);
    if canonical_session_index.as_deref() != Some(normalized_session_index.as_str()) {
        return Err(
            "tenant retained-session index definition is invalid; refusing to start".into(),
        );
    }
    let expected = quota_trigger_sql();
    for name in [
        "tenant_quota_usage_insert",
        "tenant_quota_usage_delete",
        "tenant_quota_usage_update",
    ] {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type='trigger' AND name=?1",
                [name],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        let actual = actual
            .ok_or_else(|| format!("tenant quota trigger {name} is missing; refusing to start"))?;
        let actual = normalize_schema_sql(&actual);
        let expected_sql = expected
            .split("CREATE TRIGGER")
            .find(|sql| sql.contains(name))
            .unwrap_or_default();
        let expected = normalize_schema_sql(&format!("CREATE TRIGGER{expected_sql}"));
        if actual != expected {
            return Err(format!(
                "tenant quota trigger {name} definition is invalid; refusing to start"
            ));
        }
    }
    Ok(())
}

pub(crate) fn normalize_schema_sql(sql: &str) -> String {
    let mut normalized = String::with_capacity(sql.len());
    let mut characters = sql.chars().peekable();
    let mut quote = None;
    let mut pending_space = false;
    while let Some(character) = characters.next() {
        if let Some(delimiter) = quote {
            normalized.push(character);
            if character == delimiter {
                if characters.peek() == Some(&delimiter) {
                    normalized.push(characters.next().expect("peeked quote"));
                } else {
                    quote = None;
                }
            }
            continue;
        }
        match character {
            '\'' | '"' | '`' => {
                if pending_space && !normalized.is_empty() {
                    normalized.push(' ');
                }
                pending_space = false;
                quote = Some(character);
                normalized.push(character);
            }
            character if character.is_ascii_whitespace() => pending_space = true,
            ';' => {
                while normalized.ends_with(' ') {
                    normalized.pop();
                }
                normalized.push(';');
                pending_space = true;
            }
            character => {
                if pending_space && !normalized.is_empty() {
                    normalized.push(' ');
                }
                pending_space = false;
                normalized.extend(character.to_lowercase());
            }
        }
    }
    while normalized.ends_with(' ') || normalized.ends_with(';') {
        normalized.pop();
    }
    normalized
}

fn encode_quota(value: u64) -> String {
    format!("u:{value}")
}

fn decode_quota(value: Option<String>, column: usize) -> rusqlite::Result<Option<u64>> {
    value
        .map(|value| {
            value
                .strip_prefix("u:")
                .unwrap_or(&value)
                .parse()
                .map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        column,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })
        })
        .transpose()
}

fn link_params(link: &Link) -> [rusqlite::types::Value; 12] {
    use rusqlite::types::Value as V;
    let events = serde_json::to_string(&link.events).unwrap_or_else(|_| "[]".to_owned());
    [
        V::from(link.id.clone()),
        V::from(link.tenant.clone()),
        V::from(link.label.clone()),
        V::from(link.dest.clone()),
        link.password_hash.clone().map(V::from).unwrap_or(V::Null),
        V::from(i64::try_from(link.created_at).unwrap_or(i64::MAX)),
        link.expires_at
            .map(|at| V::from(i64::try_from(at).unwrap_or(i64::MAX)))
            .unwrap_or(V::Null),
        link.max_bytes
            .map(|b| i64::try_from(b).unwrap_or(i64::MAX))
            .map(V::from)
            .unwrap_or(V::Null),
        V::from(link.active),
        V::from(link.legal_hold),
        V::from(events),
        V::from(serde_json::to_string(&link.notifications).expect("serializable notifications")),
    ]
}

fn row_to_link(row: &rusqlite::Row<'_>) -> rusqlite::Result<Link> {
    let events_json: String = row.get("events_json")?;
    Ok(Link {
        id: row.get("id")?,
        tenant: row.get("tenant")?,
        label: row.get("label")?,
        dest: row.get("dest")?,
        password_hash: row.get("password_hash")?,
        created_at: row.get::<_, i64>("created_at")?.max(0) as u64,
        expires_at: row
            .get::<_, Option<i64>>("expires_at")?
            .and_then(|value| u64::try_from(value).ok()),
        max_bytes: row
            .get::<_, Option<i64>>("max_bytes")?
            .and_then(|value| u64::try_from(value).ok()),
        active: row.get::<_, i64>("active")? != 0,
        legal_hold: row.get::<_, i64>("legal_hold")? != 0,

        notifications: row
            .get::<_, Option<String>>("notifications_json")?
            .map(|text| parse_json(&text, row.as_ref().column_index("notifications_json")?))
            .transpose()?
            .flatten(),
        uploads: Vec::new(),
        events: parse_json(&events_json, row.as_ref().column_index("events_json")?)?,
    })
}

fn map_fetch_ticket(row: &rusqlite::Row<'_>) -> rusqlite::Result<FetchTicket> {
    Ok(FetchTicket {
        holder: row.get(5)?,
        grant_token_hash: row.get(6)?,
        policy_revision: row.get::<_, i64>(7)?.max(0) as u64,
        token_id: row.get(0)?,
        grant_id: row.get(1)?,
        manifest_root: row.get(2)?,
        expires_at: row.get::<_, i64>(3)?.max(0) as u64,
        delivered_at: row.get::<_, Option<i64>>(4)?.map(|at| at.max(0) as u64),
    })
}

fn map_outbound_grant(row: &rusqlite::Row<'_>) -> rusqlite::Result<OutboundGrant> {
    let mut grant = map_outbound_grant_base(row)?;
    grant.files = parse_json(&row.get::<_, String>("files_json")?, 20)?;
    Ok(grant)
}

fn map_outbound_grant_base(row: &rusqlite::Row<'_>) -> rusqlite::Result<OutboundGrant> {
    Ok(OutboundGrant {
        id: row.get("id")?,
        token_hash: row.get("token_hash")?,
        password_hash: row.get("password_hash")?,
        tenant: row.get("tenant")?,
        link_id: row.get("link_id")?,
        upload_id: row.get("upload_id")?,
        package_root: row.get("package_root")?,
        name: row.get("name")?,
        suite: row.get("suite")?,
        root: row.get("root")?,
        file_index: usize::try_from(row.get::<_, i64>("file_index")?.max(0)).unwrap_or(usize::MAX),
        bytes: combine_byte_sums(row.get("bytes_hi")?, row.get("bytes_lo")?),
        label: row.get("label")?,
        created_at: row.get::<_, i64>("created_at")?.max(0) as u64,
        expires_at: row.get::<_, i64>("expires_at")?.max(0) as u64,
        revoked_at: row
            .get::<_, Option<i64>>("revoked_at")?
            .and_then(|value| u64::try_from(value).ok()),
        downloads: row.get::<_, i64>("downloads")?.max(0) as u64,
        max_downloads: row
            .get::<_, Option<i64>>("max_downloads")?
            .and_then(|value| u64::try_from(value).ok()),

        notifications: row
            .get::<_, Option<String>>("notifications_json")?
            .map(|text| parse_json(&text, 0))
            .transpose()?
            .flatten(),
        first_download_at: row
            .get::<_, Option<i64>>("first_download_at")?
            .and_then(|value| u64::try_from(value).ok()),
        last_download_at: row
            .get::<_, Option<i64>>("last_download_at")?
            .and_then(|value| u64::try_from(value).ok()),
        files: Vec::new(),
    })
}

fn map_outbound_grant_file(row: &rusqlite::Row<'_>) -> rusqlite::Result<OutboundGrantFile> {
    Ok(OutboundGrantFile {
        source: row.get("source")?,
        name: row.get("name")?,
        suite: row.get("suite")?,
        root: row.get("root")?,
        bytes: combine_byte_sums(row.get("bytes_hi")?, row.get("bytes_lo")?),
        receipt_b64: row.get("receipt_b64")?,
        downloads: row.get::<_, i64>("downloads")?.max(0) as u64,
        first_download_at: row
            .get::<_, Option<i64>>("first_download_at")?
            .and_then(|value| u64::try_from(value).ok()),
        last_download_at: row
            .get::<_, Option<i64>>("last_download_at")?
            .and_then(|value| u64::try_from(value).ok()),
    })
}

fn overlay_outbound_file_counters(
    connection: &Connection,
    grant: &mut OutboundGrant,
) -> rusqlite::Result<()> {
    if grant.files.is_empty() {
        return Ok(());
    }
    let mut statement = connection.prepare(
        "SELECT file_index, downloads, first_download_at, last_download_at
         FROM outbound_grant_files WHERE grant_id = ?1 ORDER BY file_index",
    )?;
    let rows = statement.query_map([&grant.id], |row| {
        Ok((
            row.get::<_, i64>("file_index")?,
            row.get::<_, i64>("downloads")?,
            row.get::<_, Option<i64>>("first_download_at")?,
            row.get::<_, Option<i64>>("last_download_at")?,
        ))
    })?;
    for row in rows {
        let (index, downloads, first, last) = row?;
        if let Some(file) = grant
            .files
            .get_mut(usize::try_from(index).unwrap_or(usize::MAX))
        {
            file.downloads = downloads.max(0) as u64;
            file.first_download_at = first.and_then(|value| u64::try_from(value).ok());
            file.last_download_at = last.and_then(|value| u64::try_from(value).ok());
        }
    }
    Ok(())
}

fn map_outbound_grant_page(row: &rusqlite::Row<'_>) -> rusqlite::Result<(OutboundGrant, usize)> {
    let grant = map_outbound_grant(row)?;
    let file_count = row.get::<_, i64>("file_count")?;
    let file_count = usize::try_from(file_count).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })?;
    Ok((grant, file_count))
}

fn map_automation_token(row: &rusqlite::Row<'_>) -> rusqlite::Result<AutomationToken> {
    Ok(AutomationToken {
        id: row.get("id")?,
        token_hash: row.get("token_hash")?,
        tenant: row.get("tenant")?,
        label: row.get("label")?,
        directory: row.get("directory")?,
        permissions: serde_json::from_str(&row.get::<_, String>("permissions")?).map_err(
            |error| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            },
        )?,
        created_at: row.get::<_, i64>("created_at")?.max(0) as u64,
        expires_at: row.get::<_, i64>("expires_at")?.max(0) as u64,
        revoked_at: row
            .get::<_, Option<i64>>("revoked_at")?
            .and_then(|value| u64::try_from(value).ok()),
        last_used_at: row
            .get::<_, Option<i64>>("last_used_at")?
            .and_then(|value| u64::try_from(value).ok()),
    })
}

fn read_link_metadata(
    connection: &Connection,
    tenant: &str,
    id: &str,
) -> Result<Option<Link>, String> {
    connection
        .query_row(
            "SELECT id, tenant, label, dest, password_hash, created_at, expires_at, max_bytes,
                        active, legal_hold, events_json, notifications_json
             FROM links WHERE tenant = ?1 AND id = ?2",
            rusqlite::params![tenant, id],
            row_to_link,
        )
        .optional()
        .map_err(|error| error.to_string())
}

/// One row of the audit log as exported.
#[derive(Clone, Debug, Serialize)]
pub struct AuditRow {
    pub rowid: i64,
    pub at: u64,
    pub tenant: String,
    pub actor: String,
    pub event: String,
    pub subject: String,
    pub detail: serde_json::Value,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct OutboundSummary {
    pub open_grants: u64,
    /// The grant-level counter: a multi-file link counts once every file
    /// has been fetched, the same figure the Deliver list shows.
    pub deliveries: u64,
    pub active: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct SearchResults {
    pub requests: Vec<SearchRequest>,
    pub downloads: Vec<SearchDownload>,
    pub files: Vec<SearchFile>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SearchRequest {
    pub id: String,
    pub label: String,
    pub dest: String,
    pub active: bool,
    pub expires_at: Option<u64>,
    pub created_at: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct SearchDownload {
    pub id: String,
    pub label: String,
    pub name: String,
    pub created_at: u64,
    pub revoked: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct SearchFile {
    pub link_id: String,
    pub link_label: String,
    pub upload_id: String,
    pub path: String,
    pub bytes: u64,
    pub completed_at: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct AuditFilters<'a> {
    pub event: Option<&'a str>,
    pub query: Option<&'a str>,
}

fn append_audit_filters(
    sql: &mut String,
    parameters: &mut Vec<rusqlite::types::Value>,
    tenant: Option<&str>,
    filters: AuditFilters<'_>,
) {
    if let Some(tenant) = tenant {
        sql.push_str(" AND tenant = ?");
        parameters.push(rusqlite::types::Value::Text(tenant.to_owned()));
    }
    if let Some(event) = filters.event.filter(|value| !value.is_empty()) {
        sql.push_str(" AND event = ?");
        parameters.push(rusqlite::types::Value::Text(event.to_owned()));
    }
    if let Some(query) = filters.query.filter(|value| !value.is_empty()) {
        sql.push_str(
            " AND (instr(lower(CASE WHEN tenant = '' THEN 'default' ELSE tenant END), lower(?)) > 0
                    OR instr(lower(actor), lower(?)) > 0
                    OR instr(lower(event), lower(?)) > 0
                    OR instr(lower(subject), lower(?)) > 0)",
        );
        for _ in 0..4 {
            parameters.push(rusqlite::types::Value::Text(query.to_owned()));
        }
    }
}

fn map_tenant(row: &rusqlite::Row<'_>) -> rusqlite::Result<Tenant> {
    Ok(Tenant {
        incarnation: row.get(7)?,
        key: row.get(0)?,
        label: row.get(1)?,
        admin_group: row.get(2)?,
        max_total_bytes: decode_quota(row.get(3)?, 3)?,
        max_links: decode_quota(row.get(4)?, 4)?,
        max_sessions: decode_quota(row.get(5)?, 5)?,
        created_at: row.get::<_, i64>(6)?.max(0) as u64,
    })
}

pub const SCIM_GROUP_NAME_TAKEN: &str = "scim group name taken";

fn map_scim_group(row: &rusqlite::Row<'_>) -> rusqlite::Result<ScimGroup> {
    Ok(ScimGroup {
        id: row.get("id")?,
        display_name: row.get("display_name")?,
        external_id: row.get("external_id")?,
        created_at: row.get::<_, i64>("created_at")?.max(0) as u64,
        members: Vec::new(),
    })
}

fn read_scim_members(connection: &Connection, id: &str) -> rusqlite::Result<Vec<String>> {
    let mut statement = connection
        .prepare("SELECT subject FROM scim_group_members WHERE group_id = ?1 ORDER BY subject")?;
    let rows = statement.query_map([id], |row| row.get::<_, String>(0))?;
    rows.collect()
}

fn write_scim_members(
    connection: &Connection,
    id: &str,
    members: &[String],
) -> rusqlite::Result<()> {
    for subject in members {
        connection.execute(
            "INSERT OR IGNORE INTO scim_group_members (group_id, subject) VALUES (?1, ?2)",
            rusqlite::params![id, subject],
        )?;
    }
    Ok(())
}

fn map_principal(row: &rusqlite::Row<'_>) -> rusqlite::Result<Principal> {
    let last_groups: String = row.get("last_groups")?;
    let last_grants: String = row.get("last_grants")?;
    Ok(Principal {
        subject: row.get("subject")?,
        credential_version: row.get::<_, i64>("credential_version")?.max(0) as u64,
        blocked: row.get::<_, i64>("blocked")? != 0,
        last_login_at: row.get::<_, i64>("last_login_at")?.max(0) as u64,
        last_groups: parse_json(&last_groups, 4)?,
        last_grants: parse_json(&last_grants, 5)?,
        source: row.get("source")?,
        external_id: row.get("external_id")?,
        created_at: row.get::<_, i64>("created_at")?.max(0) as u64,
    })
}

fn map_audit_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditRow> {
    Ok(AuditRow {
        rowid: row.get(0)?,
        at: row.get::<_, i64>(1)?.max(0) as u64,
        tenant: row.get(2)?,
        actor: row.get(3)?,
        event: row.get(4)?,
        subject: row.get(5)?,
        detail: parse_json(&row.get::<_, String>(6)?, 6)?,
    })
}

fn parse_json<T: DeserializeOwned>(text: &str, column: usize) -> rusqlite::Result<T> {
    serde_json::from_str(text).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })
}

fn insert_audit_row(
    connection: &Connection,
    at: u64,
    tenant: &str,
    actor: &str,
    event: &str,
    subject: &str,
    detail: &serde_json::Value,
) -> rusqlite::Result<usize> {
    connection
        .prepare_cached(
            "INSERT INTO audit_log (at, tenant, actor, event, subject, detail)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )?
        .execute(rusqlite::params![
            i64::try_from(at).unwrap_or(0),
            tenant,
            actor,
            event,
            subject,
            detail.to_string()
        ])
}

impl Store {
    /// Inserts one audit row. Best effort: the tracing event at the call site
    /// is the operational record; the row is the queryable one.
    pub fn audit(
        &self,
        tenant: &str,
        actor: &str,
        event: &str,
        subject: &str,
        detail: &serde_json::Value,
    ) {
        if let Err(error) = self.with(|connection| {
            insert_audit_row(
                connection,
                now_unix(),
                tenant,
                actor,
                event,
                subject,
                detail,
            )
        }) {
            // Best-effort by design: the tracing event above each call site
            // still records the action. The counter lets operators alert on
            // the divergence between the log and the exportable trail.
            AUDIT_INSERT_FAILURES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::warn!(%error, event, "audit row insert failed");
        }
    }

    /// Changes a legal hold and records it in the same transaction.
    pub fn set_link_legal_hold(
        &self,
        tenant: &str,
        id: &str,
        legal_hold: bool,
        actor: &str,
    ) -> Result<bool, String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let updated = transaction
            .execute(
                "UPDATE links SET legal_hold = ?3 WHERE tenant = ?1 AND id = ?2",
                rusqlite::params![tenant, id, legal_hold],
            )
            .map_err(|error| error.to_string())?;
        if updated == 0 {
            return Ok(false);
        }
        insert_audit_row(
            &transaction,
            now_unix(),
            tenant,
            actor,
            "link_legal_hold_changed",
            id,
            &serde_json::json!({ "legal_hold": legal_hold }),
        )
        .map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(true)
    }

    /// Audit rows strictly after the (at, rowid) cursor, oldest first,
    /// capped. `Some(tenant)` matches that exact namespace, including the
    /// default tenant. `None` explicitly selects all tenants.
    pub fn audit_export(
        &self,
        tenant: Option<&str>,
        since: u64,
        after_rowid: u64,
        limit: u64,
    ) -> Result<Vec<AuditRow>, String> {
        self.audit_export_filtered(tenant, since, after_rowid, limit, AuditFilters::default())
    }

    pub fn audit_export_filtered(
        &self,
        tenant: Option<&str>,
        since: u64,
        after_rowid: u64,
        limit: u64,
        filters: AuditFilters<'_>,
    ) -> Result<Vec<AuditRow>, String> {
        self.with(|connection| {
            Self::audit_export_query(connection, tenant, since, after_rowid, limit, filters)
        })
    }

    pub fn audit_recent(
        &self,
        tenant: Option<&str>,
        before_rowid: u64,
        limit: u64,
    ) -> Result<Vec<AuditRow>, String> {
        self.audit_recent_filtered(tenant, before_rowid, limit, AuditFilters::default())
    }

    pub fn audit_recent_filtered(
        &self,
        tenant: Option<&str>,
        before_rowid: u64,
        limit: u64,
        filters: AuditFilters<'_>,
    ) -> Result<Vec<AuditRow>, String> {
        self.with(|connection| {
            let mut sql = "SELECT rowid, at, tenant, actor, event, subject, detail
                            FROM audit_log
                            WHERE 1"
                .to_owned();
            let mut parameters = Vec::new();
            append_audit_filters(&mut sql, &mut parameters, tenant, filters);
            if before_rowid != 0 {
                sql.push_str(" AND rowid < ?");
                parameters.push(rusqlite::types::Value::Integer(
                    i64::try_from(before_rowid).unwrap_or(i64::MAX),
                ));
            }
            sql.push_str(" ORDER BY rowid DESC LIMIT ?");
            parameters.push(rusqlite::types::Value::Integer(
                i64::try_from(limit).unwrap_or(i64::MAX),
            ));
            let mut statement = connection.prepare_cached(&sql)?;
            #[cfg(test)]
            statement.reset_status(rusqlite::StatementStatus::VmStep);
            let rows = statement
                .query_map(rusqlite::params_from_iter(parameters), map_audit_row)?
                .collect();
            #[cfg(test)]
            LAST_AUDIT_VM_STEPS.with(|steps| {
                steps.set(
                    u64::try_from(statement.get_status(rusqlite::StatementStatus::VmStep)).unwrap(),
                )
            });
            rows
        })
    }

    fn audit_export_query(
        connection: &Connection,
        tenant: Option<&str>,
        since: u64,
        after_rowid: u64,
        limit: u64,
        filters: AuditFilters<'_>,
    ) -> rusqlite::Result<Vec<AuditRow>> {
        let since = i64::try_from(since).unwrap_or(0);
        let after_rowid = i64::try_from(after_rowid).unwrap_or(0);
        let limit = i64::try_from(limit).unwrap_or(1000);
        let mut sql = "SELECT rowid, at, tenant, actor, event, subject, detail
                        FROM audit_log
                        WHERE (at,rowid) > (?1,?2)"
            .to_owned();
        let mut parameters = vec![
            rusqlite::types::Value::Integer(since),
            rusqlite::types::Value::Integer(after_rowid),
        ];
        append_audit_filters(&mut sql, &mut parameters, tenant, filters);
        sql.push_str(" ORDER BY at, rowid LIMIT ?");
        parameters.push(rusqlite::types::Value::Integer(limit));
        let mut statement = connection.prepare_cached(&sql)?;
        #[cfg(test)]
        statement.reset_status(rusqlite::StatementStatus::VmStep);
        let rows = statement
            .query_map(rusqlite::params_from_iter(parameters), map_audit_row)?
            .collect();
        #[cfg(test)]
        LAST_AUDIT_VM_STEPS.with(|steps| {
            steps.set(
                u64::try_from(statement.get_status(rusqlite::StatementStatus::VmStep)).unwrap(),
            )
        });
        rows
    }

    /// Deletes audit rows older than `before`; returns how many.
    pub fn audit_prune(&self, before: u64) -> Result<usize, String> {
        self.with(|connection| {
            connection.execute(
                "DELETE FROM audit_log WHERE at < ?1",
                [i64::try_from(before).unwrap_or(0)],
            )
        })
    }
}

/// Outcome of [`Store::remove_tenant`].
#[derive(Debug, PartialEq)]
pub enum TenantRemoval {
    HasRoutes,
    Deleted,
    Absent,
    HasLinks,
}

/// The three caps that apply to a namespace: total bytes, links, concurrent
/// sessions. None is unlimited.
pub type Quotas = (Option<u64>, Option<u64>, Option<u64>);

/// Outcome of [`Store::insert_tenant`].
#[derive(Debug, PartialEq)]
pub enum InsertTenantError {
    /// A tenant with that key is already there.
    AlreadyExists,
    Store(String),
}

/// Outcome of [`Store::insert_link`].
#[derive(Debug, PartialEq)]
pub enum InsertLinkError {
    NamedTenantGone,
    Store(String),
}

fn initialize_schema(connection: &mut Connection) -> Result<(), String> {
    let empty: bool = connection
        .query_row(
            "SELECT NOT EXISTS(SELECT 1 FROM sqlite_schema)",
            [],
            |row| row.get(0),
        )
        .map_err(|e| e.to_string())?;
    if !empty {
        let stored: u64 = connection
            .query_row(
                "SELECT value FROM meta WHERE key='schema_version'",
                [],
                |row| row.get::<_, String>(0),
            )
            .map_err(|e| e.to_string())?
            .parse()
            .map_err(|_| "database schema version is invalid; refusing to start")?;
        if stored == 41 || stored == 42 || stored == 43 {
            validate_schema(connection, stored)?;
            let transaction = connection.transaction().map_err(|e| e.to_string())?;
            if stored == 41 {
                transaction
                    .execute_batch(
                        "ALTER TABLE outbound_grants ADD COLUMN share_token TEXT;
                         UPDATE meta SET value='42' WHERE key='schema_version';",
                    )
                    .map_err(|e| e.to_string())?;
            }
            if stored == 41 || stored == 42 {
                install_quota_schema(&transaction).map_err(|e| e.to_string())?;
            }
            transaction
                .execute_batch(AUDIT_COUNT_SCHEMA)
                .map_err(|e| e.to_string())?;
            transaction
                .execute("UPDATE meta SET value='44' WHERE key='schema_version'", [])
                .map_err(|e| e.to_string())?;
            transaction.commit().map_err(|e| e.to_string())?;
        }
        return validate_schema(connection, SCHEMA_VERSION);
    }
    let transaction = connection.transaction().map_err(|e| e.to_string())?;
    for schema in [
        SCHEMA,
        AUDIT_COUNT_SCHEMA,
        SETTINGS_SCHEMA,
        PRINCIPALS_SCHEMA,
        PRINCIPALS_IDENTITY_INDEX,
        SCIM_GROUPS_SCHEMA,
        FILES_SCHEMA,
        QUOTA_SCHEMA,
        OUTBOUND_GRANTS_SCHEMA,
        OUTBOUND_GRANT_FILES_SCHEMA,
        AUTOMATION_TOKENS_SCHEMA,
        BRANDING_SCHEMA,
        UPLOAD_SESSIONS_SCHEMA,
        OUTBOUND_GRANT_MANIFESTS_SCHEMA,
        OUTBOUND_INDEXES,
        AUDIT_INDEXES,
        evidence::SCHEMA,
        workflows::SCHEMA,
        workflows::INDEXES,
        webhooks::SCHEMA,
        routes::SCHEMA,
        notifications::SCHEMA,
        trade::SCHEMA,
    ] {
        transaction
            .execute_batch(schema)
            .map_err(|e| format!("schema: {e}"))?;
    }
    transaction.execute_batch("CREATE INDEX delivery_jobs_received ON delivery_jobs(tenant,json_extract(document,'$.received.link_id')) WHERE json_extract(document,'$.received') IS NOT NULL;
        INSERT INTO meta(key,value) VALUES ('tenant_storage_layout','reserved-v1');")
        .map_err(|e| e.to_string())?;
    transaction
        .execute_batch(&quota_trigger_sql())
        .map_err(|e| format!("quota schema: {e}"))?;
    transaction
        .execute(
            "INSERT INTO tenant_quota_usage(tenant,bytes_hi,bytes_lo,state) VALUES ('',0,0,0)",
            [],
        )
        .map_err(|e| e.to_string())?;
    transaction
        .execute(
            "INSERT INTO meta(key,value) VALUES ('schema_version',?1)",
            [SCHEMA_VERSION.to_string()],
        )
        .map_err(|e| e.to_string())?;
    transaction.commit().map_err(|e| e.to_string())?;
    tracing::info!(schema_version = SCHEMA_VERSION, "initialized database");
    Ok(())
}

pub(crate) fn validate_schema(connection: &Connection, expected: u64) -> Result<(), String> {
    let version: Option<String> = connection
        .query_row(
            "SELECT value FROM meta WHERE key='schema_version'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| format!("unsupported database schema: {e}"))?;
    let version = version.ok_or("database schema version is missing; refusing to start")?;
    let stored = version
        .parse::<u64>()
        .map_err(|_| "database schema version is invalid; refusing to start")?;
    if stored != expected {
        return Err(format!("database schema version {stored} is unsupported by this binary ({expected}); preserve the database and use a matching release"));
    }
    let layout: Option<String> = connection
        .query_row(
            "SELECT value FROM meta WHERE key='tenant_storage_layout'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    if layout.as_deref() != Some("reserved-v1") {
        return Err("unsupported tenant storage layout; preserve the database and receiving files and use a matching release".into());
    }
    if expected >= 43 {
        validate_quota_schema(connection)?;
    }
    Ok(())
}

fn overlay_rows(rows: &HashMap<String, String>, config: &Config) -> SettingsOverlay {
    let (smtp_host, smtp_host_source) = overlay_text(rows, "smtp_host", config.smtp_host.clone());
    let (smtp_port, smtp_port_source) = overlay_port(rows, "smtp_port", config.smtp_port);
    let (smtp_starttls, smtp_starttls_source) =
        overlay_bool(rows, "smtp_starttls", config.smtp_starttls);
    let (smtp_username, smtp_username_source) =
        overlay_text(rows, "smtp_username", config.smtp_username.clone());
    let (smtp_password, smtp_password_source) =
        overlay_text(rows, "smtp_password", config.smtp_password.clone());
    let smtp_password_set = smtp_password.is_some();
    let (smtp_from, smtp_from_source) = overlay_text(rows, "smtp_from", config.smtp_from.clone());
    let smtp = assemble_smtp(
        smtp_host.clone(),
        smtp_port,
        smtp_starttls,
        smtp_username.clone(),
        smtp_password.clone(),
        smtp_from.clone(),
    );
    let (audit_retention_days, audit_retention_days_source) =
        overlay_u64(rows, "audit_retention_days", config.audit_retention_days);
    let (upload_retention_days, upload_retention_days_source) =
        overlay_u64(rows, "upload_retention_days", config.upload_retention_days);
    let (default_max_total_bytes, default_max_total_bytes_source) = overlay_positive(
        rows,
        "default_max_total_bytes",
        config.default_max_total_bytes,
    );
    let (default_max_links, default_max_links_source) =
        overlay_positive(rows, "default_max_links", config.default_max_links);
    let (default_max_sessions, default_max_sessions_source) =
        overlay_positive(rows, "default_max_sessions", config.default_max_sessions);
    let (public_password_login, public_password_login_source) =
        overlay_bool(rows, "public_password_login", config.public_password_login);
    let (sso_session_secs, sso_session_secs_source) =
        overlay_u64(rows, "sso_session_secs", config.sso_session_secs);
    let (scim_token, scim_token_source) =
        overlay_text(rows, "scim_token", config.scim_token.clone());
    let (scim_token_previous, _) = overlay_text(rows, "scim_token_previous", None);
    let (replica_token, replica_token_source) =
        overlay_text(rows, "replica_token", config.replica_token.clone());
    let (require_provisioning, require_provisioning_source) =
        overlay_bool(rows, "require_provisioning", config.require_provisioning);
    // The write path refuses zero; a hand-edited row falls back to env.
    let (sso_session_secs, sso_session_secs_source) = if sso_session_secs == 0 {
        tracing::error!(
            key = "sso_session_secs",
            "invalid settings value; using env default"
        );
        (config.sso_session_secs, "env")
    } else {
        (sso_session_secs, sso_session_secs_source)
    };
    // No env default: draining is an operator action, off unless the db says
    // otherwise.
    let (draining, draining_source) = overlay_bool(rows, "draining", false);
    SettingsOverlay {
        resolved: ResolvedSettings {
            smtp,
            audit_retention_days,
            upload_retention_days,
            default_max_total_bytes,
            default_max_links,
            default_max_sessions,
            public_password_login,
            sso_session_secs,
            scim_token: scim_token.clone(),
            scim_token_previous: scim_token_previous.clone(),
            replica_token: replica_token.clone(),
            require_provisioning,
            draining,
        },

        smtp_host,
        smtp_host_source,
        smtp_port,
        smtp_port_source,
        smtp_starttls,
        smtp_starttls_source,
        smtp_username,
        smtp_username_source,
        smtp_password_set,
        smtp_password_source,
        smtp_from,
        smtp_from_source,

        audit_retention_days_source,
        upload_retention_days_source,
        default_max_total_bytes_source,
        default_max_links_source,
        default_max_sessions_source,
        public_password_login_source,
        sso_session_secs_source,
        scim_token_set: scim_token.is_some(),
        scim_token_source,
        scim_token_previous_set: scim_token_previous.is_some(),
        replica_token_set: replica_token.is_some(),
        replica_token_source,
        require_provisioning_source,
        draining_source,
    }
}

fn overlay_text(
    rows: &HashMap<String, String>,
    key: &str,
    env: Option<String>,
) -> (Option<String>, &'static str) {
    match rows.get(key) {
        None => (env, "env"),
        Some(value) if value.is_empty() => (None, "db"),
        Some(value) => (Some(value.clone()), "db"),
    }
}

fn overlay_u64(rows: &HashMap<String, String>, key: &str, env: u64) -> (u64, &'static str) {
    match rows.get(key) {
        None => (env, "env"),
        Some(value) => match value.parse::<u64>() {
            Ok(parsed) => (parsed, "db"),
            Err(_) => {
                tracing::error!(key, value, "invalid settings value; using env default");
                (env, "env")
            }
        },
    }
}

fn overlay_positive(
    rows: &HashMap<String, String>,
    key: &str,
    env: Option<u64>,
) -> (Option<u64>, &'static str) {
    match rows.get(key) {
        None => (env, "env"),
        Some(value) => match value.parse::<u64>() {
            Ok(parsed) if parsed > 0 => (Some(parsed), "db"),
            _ => {
                tracing::error!(key, value, "invalid settings value; using env default");
                (env, "env")
            }
        },
    }
}

fn overlay_port(rows: &HashMap<String, String>, key: &str, env: u16) -> (u16, &'static str) {
    match rows.get(key) {
        None => (env, "env"),
        Some(value) => match value.parse::<u16>() {
            Ok(parsed) if parsed >= 1 => (parsed, "db"),
            _ => {
                tracing::error!(key, value, "invalid settings value; using env default");
                (env, "env")
            }
        },
    }
}

fn trimmed_option(value: Option<String>) -> Option<String> {
    value.and_then(|raw| {
        let trimmed = raw.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    })
}

fn assemble_smtp(
    host: Option<String>,
    port: u16,
    starttls: bool,
    username: Option<String>,
    password: Option<String>,
    from: Option<String>,
) -> Option<ResolvedSmtp> {
    let host = trimmed_option(host)?;
    let from = trimmed_option(from)?;
    Some(ResolvedSmtp {
        host,
        port,
        starttls,
        username: trimmed_option(username),
        password,
        from,
    })
}

fn overlay_bool(rows: &HashMap<String, String>, key: &str, env: bool) -> (bool, &'static str) {
    match rows.get(key) {
        None => (env, "env"),
        Some(value) if value == "1" => (true, "db"),
        Some(value) if value == "0" => (false, "db"),
        Some(value) => {
            tracing::error!(key, value, "invalid settings value; using env default");
            (env, "env")
        }
    }
}

/// Rebuilds an ObjectId from its stored suite, hex root, and length.
fn object_from_row(suite: i64, root_hex: &str, length: i64) -> rusqlite::Result<ObjectId> {
    let root: [u8; 32] = hex::decode(root_hex)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                "object root is not 32 bytes".into(),
            )
        })?;
    Ok(ObjectId {
        suite: u16::try_from(suite).unwrap_or(0),
        root,
        length: length.max(0) as u64,
    })
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn legacy_upload_records_default_to_http_transport() {
        let record: UploadRecord = serde_json::from_str(
            r#"{"id":"legacy","completed_at":1,"package_root":"root","total_bytes":0,"files":[]}"#,
        )
        .unwrap();
        assert_eq!(record.transport, None);
    }

    #[test]
    fn a_broken_table_is_an_error_not_a_panic() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .with(|connection| connection.execute_batch("DROP TABLE links"))
            .unwrap();
        // The point of the Result: a handler answers 500 and logs, instead of
        // a panicked task dropping the connection with nothing recorded.
        assert!(store.links("").is_err());
        assert!(store.link("", "any").is_err());
        assert!(store.all_links().is_err());
        // A principal that cannot be read denies the session rather than
        // admitting it.
        store
            .with(|connection| connection.execute_batch("DROP TABLE principals"))
            .unwrap();
        assert!(!store.principal_allows("user@example.com", 1));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn external_sqlite_readers_preserve_open_database_locks() {
        use std::os::unix::fs::MetadataExt as _;

        const CHILD_DATABASE: &str = "VOTPORT_TEST_EXTERNAL_DATABASE";
        const CHILD_BACKUP: &str = "VOTPORT_TEST_EXTERNAL_BACKUP";
        if let Some(path) = std::env::var_os(CHILD_DATABASE) {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            let retained = matches!(
                rustix::fs::fcntl_lock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive,),
                Err(rustix::io::Errno::AGAIN | rustix::io::Errno::ACCESS)
            );
            drop(file);
            println!("database lock retained={retained}");
            let connection = Connection::open(&path).unwrap();
            let count: i64 = connection
                .query_row("SELECT count(*) FROM links", [], |row| row.get(0))
                .unwrap();
            assert_eq!(count, 1);
            if let Some(destination) = std::env::var_os(CHILD_BACKUP) {
                connection
                    .execute("VACUUM INTO ?1", [destination.to_str().unwrap()])
                    .unwrap();
            }
            return;
        }

        for (reopen, backup) in [(false, false), (false, true), (true, false), (true, true)] {
            let directory = tempfile::tempdir().unwrap();
            let store = Store::open(directory.path()).unwrap();
            store.insert_link(test_link("before-reader")).unwrap();
            let store = if reopen {
                drop(store);
                Store::open(directory.path()).unwrap()
            } else {
                store
            };
            let files = ["votport.db", "votport.db-wal", "votport.db-shm"]
                .map(|name| directory.path().join(name));
            let identities = files.each_ref().map(|path| {
                let metadata = std::fs::metadata(path).unwrap();
                assert_eq!(metadata.mode() & 0o777, 0o600);
                (metadata.dev(), metadata.ino())
            });
            let mut command = tokio::process::Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "store::tests::external_sqlite_readers_preserve_open_database_locks",
                    "--nocapture",
                ])
                .env(CHILD_DATABASE, &files[0])
                .env_remove(CHILD_BACKUP)
                .kill_on_drop(true);
            if backup {
                command.env(CHILD_BACKUP, directory.path().join("external.db"));
            }
            let output = tokio::time::timeout(std::time::Duration::from_secs(20), command.output())
                .await
                .expect("external SQLite reader timed out")
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
            let shared_lock =
                String::from_utf8_lossy(&output.stdout).contains("database lock retained=true");
            let locks_retained = files.iter().zip(identities).all(|(path, identity)| {
                std::fs::metadata(path)
                    .is_ok_and(|metadata| (metadata.dev(), metadata.ino()) == identity)
            });
            store.insert_link(test_link("after-reader")).unwrap();
            assert!(store.link("", "after-reader").unwrap().is_some());
            let snapshot = store.backup_into(&directory.path().join("snapshot.db"));
            drop(store);
            let reopened = Store::open(directory.path()).unwrap();
            let durable = reopened.link("", "after-reader").unwrap().is_some();
            assert!(shared_lock && locks_retained && snapshot.is_ok() && durable,
                "reopen={reopen}, external backup={backup}: shared lock={shared_lock}, database/WAL identities retained={locks_retained}, snapshot={snapshot:?}, acknowledged write survived={durable}");
        }
    }

    #[test]
    fn delivered_candidates_match_full_identity_and_seek_past_aliases() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        for suite in [1, 2] {
            for length in [0, u64::from(u32::MAX), 1_u64 << 32, u64::MAX] {
                let object = ObjectId {
                    suite,
                    root: [7; 32],
                    length,
                };
                store.with(|c| {
                    c.execute("DELETE FROM files", [])?;
                    let mut insert = c.prepare("INSERT INTO files (tenant, link_id, upload_id, file_index, bytes_hi, bytes_lo, deleted, stored_as, path, suite, root, receipt) VALUES (?1, ?2, ?3, 0, ?4, ?5, ?6, ?7, 'original', ?8, ?9, 1)")?;
                    for variant in 0..8 {
                        let (hi, lo) = split_bytes(if variant == 5 { length ^ (1_u64 << 32) } else if variant == 6 { length ^ 1 } else { length });
                        insert.execute(rusqlite::params![
                            if variant == 1 { "other" } else { "tenant" },
                            if variant == 2 { "other" } else { "link" },
                            variant.to_string(), hi, lo, variant == 7, format!("candidate-{variant}"),
                            crate::session::suite_name(if variant == 3 { 3 - suite } else { suite }),
                            hex::encode(if variant == 4 { [8; 32] } else { object.root }),
                        ])?;
                    }
                    Ok(())
                }).unwrap();
                assert_eq!(
                    store
                        .delivered_candidates("tenant", "link", &object, "")
                        .unwrap(),
                    [("candidate-0".into(), true)]
                );
                assert!(store
                    .delivered_candidates("tenant", "link", &object, "candidate-0")
                    .unwrap()
                    .is_empty());
                store.with(|c| {
                    let (hi, lo) = split_bytes(length);
                    let mut insert = c.prepare("INSERT INTO files (tenant, link_id, upload_id, file_index, bytes_hi, bytes_lo, deleted, stored_as, path, suite, root, receipt) VALUES ('tenant', 'link', ?1, 0, ?2, ?3, 0, 'a-alias', 'original', ?4, ?5, 0)")?;
                    for i in 0..DELIVERED_CANDIDATE_PAGE * 2 + 1 {
                        insert.execute(rusqlite::params![format!("alias-{i}"), hi, lo, crate::session::suite_name(suite), hex::encode(object.root)])?;
                    }
                    Ok(())
                }).unwrap();
                let page = store
                    .delivered_candidates("tenant", "link", &object, "")
                    .unwrap();
                assert_eq!(page.len(), DELIVERED_CANDIDATE_PAGE);
                assert!(page.iter().all(|row| row == &("a-alias".into(), false)));
                assert_eq!(
                    store
                        .delivered_candidates("tenant", "link", &object, &page.last().unwrap().0)
                        .unwrap(),
                    [("candidate-0".into(), true)]
                );
            }
        }
    }

    pub(crate) fn test_link(id: &str) -> Link {
        Link {
            id: id.to_owned(),
            tenant: String::new(),
            label: "test".to_owned(),
            dest: String::new(),
            password_hash: None,
            created_at: 0,
            expires_at: None,
            max_bytes: None,
            active: true,
            legal_hold: false,

            notifications: None,
            uploads: Vec::new(),
            events: Vec::new(),
        }
    }

    pub(crate) fn link_in(tenant: &str, id: &str) -> Link {
        Link {
            tenant: tenant.to_owned(),
            ..test_link(id)
        }
    }

    pub(crate) fn test_tenant(key: &str) -> Tenant {
        Tenant {
            incarnation: String::new(),
            key: key.to_owned(),
            label: key.to_owned(),
            admin_group: None,
            max_total_bytes: None,
            max_links: None,
            max_sessions: None,
            created_at: 0,
        }
    }

    pub(crate) fn test_outbound_grant(id: &str, tenant: &str, file_index: usize) -> OutboundGrant {
        OutboundGrant {
            id: id.to_owned(),
            token_hash: format!("hash-{id}"),
            password_hash: None,
            tenant: tenant.to_owned(),
            link_id: "link".to_owned(),
            upload_id: "upload".to_owned(),
            package_root: "package".to_owned(),
            name: "file.bin".to_owned(),
            suite: "blake3".to_owned(),
            root: format!("root-{id}"),
            file_index,
            bytes: u64::MAX,
            label: "download".to_owned(),
            created_at: 10,
            expires_at: 20,
            revoked_at: None,
            downloads: 0,
            max_downloads: None,

            notifications: None,
            first_download_at: None,
            last_download_at: None,
            files: Vec::new(),
        }
    }

    #[test]
    fn tenant_incarnation_survives_updates_and_reopen_but_not_recreation() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.insert_tenant(test_tenant("acme")).unwrap();
        let mut tenant = store.tenant("acme").unwrap().unwrap();
        let incarnation = tenant.incarnation.clone();
        assert_eq!(hex::decode(&incarnation).unwrap().len(), 16);
        tenant.label = "updated".into();
        tenant.incarnation = "must-not-replace".into();
        assert!(store.update_tenant(&tenant).unwrap());
        assert_eq!(
            store.tenant("acme").unwrap().unwrap().incarnation,
            incarnation
        );
        drop(store);
        let store = Store::open(directory.path()).unwrap();
        assert_eq!(
            store.tenant("acme").unwrap().unwrap().incarnation,
            incarnation
        );
        assert_eq!(store.remove_tenant("acme").unwrap(), TenantRemoval::Deleted);
        store.insert_tenant(test_tenant("acme")).unwrap();
        let replacement = store.tenant("acme").unwrap().unwrap();
        assert_eq!(replacement.created_at, tenant.created_at);
        assert_ne!(replacement.incarnation, incarnation);
    }

    #[test]
    fn tenant_removal_clears_retained_uploads_atomically_and_only_in_that_tenant() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let residue = |tenant: &str| {
            store.with(|connection| {
                connection.execute("INSERT INTO link_uploads(link_id,tenant,upload_id,document,file_count) VALUES (?1,?1,'retained','{}',1)", [tenant])?;
                connection.execute("INSERT INTO files(link_id,tenant,upload_id,file_index,bytes_hi,bytes_lo,stored_as,path,suite,root,receipt) VALUES (?1,?1,'retained',0,0,8,'frame','frame','blake3','aa',0)", [tenant])
            }).unwrap();
        };
        let retained = |tenant: &str| {
            store.with(|connection| connection.query_row(
                "SELECT (SELECT count(*) FROM link_uploads WHERE tenant=?1),(SELECT count(*) FROM files WHERE tenant=?1)", [tenant],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )).unwrap()
        };
        for key in ["acme", "other"] {
            store.insert_tenant(test_tenant(key)).unwrap();
            residue(key);
        }
        assert_eq!(store.tenant_received_bytes("acme").unwrap(), 8);
        let object = vot_sdk::object::ObjectId {
            suite: 1,
            root: [7; 32],
            length: 8,
        };
        for (id, tenant, committed) in [
            ("pending", "acme", false),
            ("committed", "acme", true),
            ("other", "other", false),
        ] {
            store
                .insert_upload_session(&PersistedUploadSession {
                    id: id.into(),
                    tenant: tenant.into(),
                    link_id: "removed-link".into(),
                    push_key: None,
                    committed_upload_id: None,
                    dest_dir: directory.path().join(tenant),
                    dest_rel: String::new(),
                    package: object.clone(),
                    max_total_bytes: None,
                    started_at: 0,
                    files: vec![PersistedUploadFile {
                        entry: 0,
                        display_path: "frame".into(),
                        stored_components: vec!["frame".into()],
                        object: object.clone(),
                        staging_path: Default::default(),
                        journal_path: Default::default(),
                        incarnation: [0; 16],
                        profile: vot_sdk_file::CommitProfile::Balanced,
                        nas_contract: vot_sdk_file::NasContract::Unqualified,
                        prefix_bytes: 0,
                        published: false,
                        receipt: false,
                    }],
                })
                .unwrap();
            if committed {
                store
                    .with(|connection| {
                        connection.execute(
                            "UPDATE upload_sessions SET committed_upload_id='finished' WHERE id=?1",
                            [id],
                        )
                    })
                    .unwrap();
            }
        }
        store.with(|connection| connection.execute_batch("CREATE TRIGGER fail_upload_removal BEFORE DELETE ON upload_session_files WHEN OLD.session_id='pending' BEGIN SELECT RAISE(ABORT, 'fixture'); END;")).unwrap();
        assert!(store.remove_tenant("acme").is_err());
        assert!(store.tenant("acme").unwrap().is_some());
        assert_eq!(store.tenant_received_bytes("acme").unwrap(), 8);
        assert_eq!(retained("acme"), (1, 1));
        assert_eq!(retained("other"), (1, 1));
        assert_eq!(store.load_upload_sessions().unwrap().len(), 3);
        assert_eq!(
            store
                .with(|connection| connection.query_row(
                    "SELECT COUNT(*) FROM upload_session_files",
                    [],
                    |row| row.get::<_, i64>(0)
                ))
                .unwrap(),
            3
        );
        store
            .with(|connection| connection.execute_batch("DROP TRIGGER fail_upload_removal;"))
            .unwrap();
        assert_eq!(store.remove_tenant("acme").unwrap(), TenantRemoval::Deleted);
        assert_eq!(retained("acme"), (0, 0));
        assert_eq!(retained("other"), (1, 1));
        residue("acme");
        assert_eq!(store.remove_tenant("acme").unwrap(), TenantRemoval::Absent);
        assert_eq!(retained("acme"), (0, 0));
        assert_eq!(retained("other"), (1, 1));
        let remaining = store.load_upload_sessions().unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].tenant, "other");
        assert_eq!(
            store
                .with(|connection| connection.query_row(
                    "SELECT COUNT(*) FROM upload_session_files",
                    [],
                    |row| row.get::<_, i64>(0)
                ))
                .unwrap(),
            1
        );
        store.insert_tenant(test_tenant("acme")).unwrap();
        assert!(store.tenant_admission_usage("acme").unwrap().1.is_empty());
        assert_eq!(store.tenant_admission_usage("other").unwrap().1.len(), 1);
    }

    #[test]
    fn grant_insertion_refuses_ambiguous_and_nonportable_names() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut grant = test_outbound_grant("ambiguous", "", 0);
        for name in ["XML:EDL/file.mov", "CON.txt", "clip.mov."] {
            grant.name = name.into();
            assert!(store
                .insert_outbound_grant(grant.clone())
                .unwrap_err()
                .contains("not portable"));
        }
        grant.files = ["Café.mov", "Cafe\u{301}.mov"]
            .into_iter()
            .map(|name| OutboundGrantFile {
                source: name.into(),
                name: name.into(),
                suite: "blake3".into(),
                root: "00".repeat(32),
                bytes: 1,
                receipt_b64: String::new(),
                downloads: 0,
                first_download_at: None,
                last_download_at: None,
            })
            .collect();
        assert!(store
            .insert_outbound_grant(grant.clone())
            .unwrap_err()
            .contains("collide"));
        assert!(store.outbound_grants("").unwrap().is_empty());
        grant.files[1].name = "second.mov".into();
        store.insert_outbound_grant(grant.clone()).unwrap();
        assert_eq!(store.outbound_grants("").unwrap(), vec![grant]);
    }

    #[test]
    fn automation_tokens_preserve_permissions_across_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .insert_automation_token(test_automation_token("agent", "tenant"))
            .unwrap();
        drop(store);
        let reopened = Store::open(directory.path()).unwrap();
        let token = reopened
            .authenticate_automation_token("hash-agent", 15)
            .unwrap()
            .unwrap();
        assert_eq!(token.tenant, "tenant");
        assert_eq!(token.permissions, ["deliveries:create"]);
        assert!(reopened
            .automation_operation("agent", "missing")
            .unwrap()
            .is_none());
    }

    fn test_automation_token(id: &str, tenant: &str) -> AutomationToken {
        AutomationToken {
            id: id.to_owned(),
            token_hash: format!("hash-{id}"),
            tenant: tenant.to_owned(),
            label: format!("Token {id}"),
            directory: None,
            permissions: vec!["deliveries:create".to_owned()],
            created_at: 10,
            expires_at: 20,
            revoked_at: None,
            last_used_at: None,
        }
    }

    #[test]
    fn outbound_grants_round_trip_full_byte_range() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let schema = store
            .with(|connection| {
                connection.query_row(
                    "SELECT value FROM meta WHERE key = 'schema_version'",
                    [],
                    |row| row.get::<_, String>(0),
                )
            })
            .unwrap();
        assert_eq!(schema, SCHEMA_VERSION.to_string());
        assert!(store
            .with(|connection| {
                connection.query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'outbound_grants'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
            })
            .unwrap() > 0);

        let grant = test_outbound_grant("g1", "acme", 3);
        store.insert_outbound_grant(grant.clone()).unwrap();
        assert_eq!(store.outbound_grants("acme").unwrap(), vec![grant]);
    }

    #[test]
    fn outbound_summary_counts_open_links_deliveries_and_active_downloads() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let open = test_outbound_grant("open", "acme", 1);
        let mut used = test_outbound_grant("used", "acme", 1);
        used.downloads = 2;
        used.max_downloads = Some(2);
        let mut revoked = test_outbound_grant("gone", "acme", 1);
        revoked.revoked_at = Some(5);
        let other = test_outbound_grant("other", "beta", 1);
        for grant in [open.clone(), used, revoked, other] {
            store.insert_outbound_grant(grant).unwrap();
        }
        // The status handler keeps the part of each in-flight key before the
        // first colon: the grant's token hash.
        let active = vec![open.token_hash.clone(), "hash-other".to_owned()];
        let summary = store.outbound_summary("acme", 10, &active).unwrap();
        assert_eq!(summary.open_grants, 1, "used and revoked are not open");
        assert_eq!(summary.deliveries, 2);
        assert_eq!(summary.active, 1, "the other tenant's download is not ours");
        assert_eq!(store.outbound_active_count("acme", &active).unwrap(), 1);
        let expired = store.outbound_summary("acme", 25, &[]).unwrap();
        assert_eq!(expired.open_grants, 0);
        assert_eq!(expired.active, 0);
    }

    #[test]
    fn uploads_since_preserves_u64_max_and_saturates_sum_overflow() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let upload = |id: &str, total_bytes| UploadRecord {
            id: id.to_owned(),
            started_at: 1,
            completed_at: 10,
            replayed_chunks: 0,
            rejected_chunks: 0,
            transport: None,
            package_root: String::new(),
            total_bytes,
            files: Vec::new(),
            partial: false,
            log: Vec::new(),
        };
        let mut first = test_link("first");
        first.uploads = vec![upload("max", u64::MAX)];
        store.insert_link(first).unwrap();
        assert_eq!(store.uploads_since("", 0).unwrap(), (1, u64::MAX));

        let mut second = test_link("second");
        second.uploads = vec![upload("one", 1)];
        store.insert_link(second).unwrap();
        assert_eq!(store.uploads_since("", 0).unwrap(), (2, u64::MAX));
    }

    #[test]
    fn outbound_grants_round_trip_multiple_library_files() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut grant = test_outbound_grant("library", "acme", 0);
        grant.files = vec![
            OutboundGrantFile {
                source: "objects/a".to_owned(),
                name: "a.txt".to_owned(),
                suite: "blake3".to_owned(),
                root: "aa".to_owned(),
                bytes: 3,
                receipt_b64: "receipt-a".to_owned(),
                downloads: 0,
                first_download_at: None,
                last_download_at: None,
            },
            OutboundGrantFile {
                source: "objects/b".to_owned(),
                name: "b.txt".to_owned(),
                suite: "sha256".to_owned(),
                root: "bb".to_owned(),
                bytes: u64::MAX,
                receipt_b64: "receipt-b".to_owned(),
                downloads: 0,
                first_download_at: None,
                last_download_at: None,
            },
        ];
        store.insert_outbound_grant(grant.clone()).unwrap();
        assert_eq!(
            store.outbound_grant_by_token_hash("hash-library").unwrap(),
            Some(grant)
        );
        store.record_outbound_download("library", &[0], 30).unwrap();
        assert_eq!(
            store
                .with(|connection| connection.query_row(
                    "SELECT file_count FROM outbound_grants WHERE id = 'library'",
                    [],
                    |row| row.get::<_, i64>(0),
                ))
                .unwrap(),
            2
        );
        let page = store.outbound_grants_page("acme", 10, 0, 2).unwrap().0;
        assert_eq!(page[0].0.files[0].downloads, 1);
    }

    #[test]
    fn normalized_file_lookup_and_download_do_not_parse_or_rewrite_manifest() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut grant = test_outbound_grant("normalized", "acme", 0);
        grant.files = (0..3)
            .map(|index| OutboundGrantFile {
                source: format!("objects/{index}"),
                name: format!("file-{index}"),
                suite: "blake3".to_owned(),
                root: format!("root-{index}"),
                bytes: if index == 2 { u64::MAX } else { index + 1 },
                receipt_b64: format!("receipt-{index}"),
                downloads: 0,
                first_download_at: None,
                last_download_at: None,
            })
            .collect();
        store.insert_outbound_grant(grant.clone()).unwrap();
        let original_json: String = store
            .with(|connection| {
                connection.query_row(
                    "SELECT files_json FROM outbound_grants WHERE id = 'normalized'",
                    [],
                    |row| row.get(0),
                )
            })
            .unwrap();
        store
            .with(|connection| {
                connection.execute(
                    "UPDATE outbound_grants SET files_json = 'deliberately invalid' WHERE id = 'normalized'",
                    [],
                )
            })
            .unwrap();
        let (_, file) = store
            .outbound_grant_file_by_token_hash("hash-normalized", 2)
            .unwrap()
            .unwrap();
        assert_eq!(file.unwrap().bytes, u64::MAX);
        store
            .record_outbound_download("normalized", &[2], 30)
            .unwrap();
        let current_json: String = store
            .with(|connection| {
                connection.query_row(
                    "SELECT files_json FROM outbound_grants WHERE id = 'normalized'",
                    [],
                    |row| row.get(0),
                )
            })
            .unwrap();
        assert_eq!(current_json, "deliberately invalid");
        store
            .with(|connection| {
                connection.execute(
                    "UPDATE outbound_grants SET files_json = ?1 WHERE id = 'normalized'",
                    [&original_json],
                )
            })
            .unwrap();
        let full = store
            .outbound_grant_by_token_hash("hash-normalized")
            .unwrap()
            .unwrap();
        assert_eq!(full.files[2].downloads, 1);
        store
            .with(|connection| {
                connection.execute(
                    "UPDATE outbound_grant_files SET downloads = 9223372036854775807
                     WHERE grant_id = 'normalized' AND file_index = 2",
                    [],
                )
            })
            .unwrap();
        store
            .record_outbound_download("normalized", &[2], 31)
            .unwrap();
        let saturated: i64 = store
            .with(|connection| {
                connection.query_row(
                    "SELECT downloads FROM outbound_grant_files
                     WHERE grant_id = 'normalized' AND file_index = 2",
                    [],
                    |row| row.get(0),
                )
            })
            .unwrap();
        assert_eq!(saturated, i64::MAX);
    }

    #[test]
    fn legacy_file_lookup_allows_only_scalar_index_zero() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .insert_outbound_grant(test_outbound_grant("legacy-lookup", "acme", 0))
            .unwrap();
        let (grant, file) = store
            .outbound_grant_file_by_token_hash("hash-legacy-lookup", 0)
            .unwrap()
            .unwrap();
        assert_eq!(grant.id, "legacy-lookup");
        assert!(file.is_none());
        assert!(store
            .outbound_grant_file_by_token_hash("hash-legacy-lookup", 1)
            .unwrap()
            .is_none());

        let mut normalized = test_outbound_grant("missing-child", "acme", 0);
        normalized.files = vec![OutboundGrantFile {
            source: "objects/only".to_owned(),
            name: "only".to_owned(),
            suite: "blake3".to_owned(),
            root: "root".to_owned(),
            bytes: 1,
            receipt_b64: String::new(),
            downloads: 0,
            first_download_at: None,
            last_download_at: None,
        }];
        store.insert_outbound_grant(normalized).unwrap();
        store
            .with(|connection| {
                connection.execute(
                    "DELETE FROM outbound_grant_files WHERE grant_id = 'missing-child'",
                    [],
                )
            })
            .unwrap();
        assert!(store
            .outbound_grant_file_by_token_hash("hash-missing-child", 0)
            .unwrap()
            .is_none());
        let page = store
            .outbound_grant_files_page_by_token_hash("hash-missing-child", 0, 100)
            .unwrap()
            .unwrap();
        assert!(page.files.is_empty());
    }

    #[test]
    fn protected_outbound_grant_password_round_trips() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut grant = test_outbound_grant("protected", "acme", 0);
        grant.password_hash = Some("argon2id-hash".to_owned());

        store.insert_outbound_grant(grant.clone()).unwrap();

        assert_eq!(
            store
                .outbound_grant_by_token_hash("hash-protected")
                .unwrap(),
            Some(grant)
        );
    }

    #[test]
    fn outbound_grants_are_tenant_scoped_and_hash_lookup_is_global() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .insert_outbound_grant(test_outbound_grant("g1", "acme", 0))
            .unwrap();
        store
            .insert_outbound_grant(test_outbound_grant("g2", "other", 1))
            .unwrap();

        assert_eq!(store.outbound_grants("acme").unwrap().len(), 1);
        assert_eq!(
            store
                .outbound_grant_by_token_hash("hash-g1")
                .unwrap()
                .unwrap()
                .id,
            "g1"
        );
    }

    #[test]
    fn active_library_grants_match_source_with_tenant_and_lifecycle_scope() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut active = test_outbound_grant("active", "acme", 0);
        active.files = vec![OutboundGrantFile {
            source: "project/file.bin".to_owned(),
            name: "file.bin".to_owned(),
            suite: "blake3".to_owned(),
            root: "root".to_owned(),
            bytes: 1,
            receipt_b64: "receipt".to_owned(),
            downloads: 0,
            first_download_at: None,
            last_download_at: None,
        }];
        store.insert_outbound_grant(active).unwrap();

        let mut other = test_outbound_grant("other", "other", 0);
        other.files = vec![OutboundGrantFile {
            source: "other/file.bin".to_owned(),
            name: "file.bin".to_owned(),
            suite: "blake3".to_owned(),
            root: "root".to_owned(),
            bytes: 1,
            receipt_b64: "receipt".to_owned(),
            downloads: 0,
            first_download_at: None,
            last_download_at: None,
        }];
        store.insert_outbound_grant(other).unwrap();

        for (id, revoked_at, expires_at, downloads, max_downloads) in [
            ("expired", None, Some(14), 0, None),
            ("revoked", Some(12), Some(20), 0, None),
            ("spent", None, Some(20), 1, Some(1)),
        ] {
            let mut grant = test_outbound_grant(id, "acme", 0);
            grant.files = vec![OutboundGrantFile {
                source: "ignored/file.bin".to_owned(),
                name: "file.bin".to_owned(),
                suite: "blake3".to_owned(),
                root: "root".to_owned(),
                bytes: 1,
                receipt_b64: "receipt".to_owned(),
                downloads: 0,
                first_download_at: None,
                last_download_at: None,
            }];
            grant.revoked_at = revoked_at;
            grant.expires_at = expires_at.unwrap();
            grant.downloads = downloads;
            grant.max_downloads = max_downloads;
            store.insert_outbound_grant(grant).unwrap();
        }

        assert!(store
            .has_active_library_grant("acme", "project/file.bin", 15)
            .unwrap());
        assert!(!store
            .has_active_library_grant("other", "project/file.bin", 15)
            .unwrap());
        assert!(!store
            .has_active_library_grant("acme", "ignored/file.bin", 15)
            .unwrap());
    }

    #[test]
    fn outbound_grants_page_is_newest_first_bounded_and_tenant_scoped() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        for id in ["g1", "g2", "g3"] {
            store
                .insert_outbound_grant(test_outbound_grant(id, "acme", 0))
                .unwrap();
        }
        store
            .insert_outbound_grant(test_outbound_grant("other", "other", 0))
            .unwrap();

        let page = store.outbound_grants_page("acme", 2, 0, 64).unwrap();
        assert_eq!(page.1, 3);
        assert_eq!(
            page.0
                .into_iter()
                .map(|(grant, _)| grant.id)
                .collect::<Vec<_>>(),
            ["g3", "g2"]
        );
        assert_eq!(
            store
                .outbound_grants_page("acme", 2, 2, 64)
                .unwrap()
                .0
                .into_iter()
                .map(|(grant, _)| grant.id)
                .collect::<Vec<_>>(),
            ["g1"]
        );
        assert!(store
            .outbound_grants_page("acme", 2, 3, 64)
            .unwrap()
            .0
            .is_empty());
        assert_eq!(store.outbound_grants_page("other", 2, 0, 64).unwrap().1, 1);
    }

    #[test]
    fn outbound_grants_page_reports_counts_and_bounds_file_previews() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let legacy = test_outbound_grant("legacy", "acme", 0);
        store.insert_outbound_grant(legacy).unwrap();
        let mut small = test_outbound_grant("small", "acme", 0);
        small.files = (0..2)
            .map(|index| OutboundGrantFile {
                source: format!("small-{index}"),
                name: format!("small-{index}.txt"),
                suite: "blake3".to_owned(),
                root: format!("small-root-{index}"),
                bytes: index + 1,
                receipt_b64: "receipt".to_owned(),
                downloads: 0,
                first_download_at: None,
                last_download_at: None,
            })
            .collect();
        store.insert_outbound_grant(small).unwrap();
        let mut large = test_outbound_grant("large", "acme", 0);
        large.files = (0..3)
            .map(|index| OutboundGrantFile {
                source: format!("large-{index}"),
                name: format!("large-{index}.txt"),
                suite: "blake3".to_owned(),
                root: format!("large-root-{index}"),
                bytes: index + 1,
                receipt_b64: "receipt".to_owned(),
                downloads: 0,
                first_download_at: None,
                last_download_at: None,
            })
            .collect();
        store.insert_outbound_grant(large).unwrap();

        let counts = store
            .with(|connection| {
                let mut statement = connection.prepare(
                    "SELECT id, file_count FROM outbound_grants WHERE tenant = 'acme' ORDER BY id",
                )?;
                let rows = statement.query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })?;
                rows.collect::<Result<Vec<_>, _>>()
            })
            .unwrap();
        assert_eq!(
            counts,
            [
                ("large".to_owned(), 3),
                ("legacy".to_owned(), 1),
                ("small".to_owned(), 2),
            ]
        );

        let page = store.outbound_grants_page("acme", 10, 0, 2).unwrap().0;
        let find = |id: &str| page.iter().find(|(grant, _)| grant.id == id).unwrap();
        let (legacy, legacy_count) = find("legacy");
        assert_eq!(*legacy_count, 1);
        assert!(legacy.files.is_empty());
        let (small, small_count) = find("small");
        assert_eq!(*small_count, 2);
        assert_eq!(small.files.len(), 2);
        let (large, large_count) = find("large");
        assert_eq!(*large_count, 3);
        assert!(large.files.is_empty());
    }

    #[test]
    fn automation_tokens_round_trip_and_list_by_tenant() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let token = test_automation_token("t1", "acme");
        store.insert_automation_token(token.clone()).unwrap();
        store
            .insert_automation_token(test_automation_token("t2", "other"))
            .unwrap();

        assert_eq!(store.automation_tokens("acme").unwrap(), vec![token]);
        assert!(store.automation_tokens("missing").unwrap().is_empty());
    }

    #[test]
    fn remove_tenant_cleans_outbound_credentials_atomically() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.insert_tenant(test_tenant("acme")).unwrap();
        let mut grant = test_outbound_grant("grant", "acme", 0);
        grant.files = vec![OutboundGrantFile {
            source: "objects/file".to_owned(),
            name: "file".to_owned(),
            suite: "blake3".to_owned(),
            root: "root".to_owned(),
            bytes: 1,
            receipt_b64: String::new(),
            downloads: 0,
            first_download_at: None,
            last_download_at: None,
        }];
        store.insert_outbound_grant(grant).unwrap();
        store
            .insert_automation_token(test_automation_token("token", "acme"))
            .unwrap();

        assert_eq!(store.remove_tenant("acme").unwrap(), TenantRemoval::Deleted);
        assert!(store.outbound_grants("acme").unwrap().is_empty());
        assert!(store
            .outbound_grant_by_token_hash("hash-grant")
            .unwrap()
            .is_none());
        assert_eq!(
            store
                .with(|connection| connection.query_row(
                    "SELECT COUNT(*) FROM outbound_grant_files",
                    [],
                    |row| row.get::<_, i64>(0),
                ))
                .unwrap(),
            0
        );
        assert!(store.automation_tokens("acme").unwrap().is_empty());
        assert!(store
            .authenticate_automation_token("hash-token", 15)
            .unwrap()
            .is_none());
    }

    #[test]
    fn automation_token_authentication_updates_last_used_atomically() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .insert_automation_token(test_automation_token("t1", "acme"))
            .unwrap();

        let authenticated = store
            .authenticate_automation_token("hash-t1", 15)
            .unwrap()
            .unwrap();
        assert_eq!(authenticated.last_used_at, Some(15));
        assert_eq!(store.automation_tokens("acme").unwrap()[0], authenticated);
        assert!(store
            .authenticate_automation_token("hash-t1", 20)
            .unwrap()
            .is_none());
    }

    #[test]
    fn automation_token_revocation_is_tenant_scoped_and_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .insert_automation_token(test_automation_token("t1", "acme"))
            .unwrap();

        assert!(!store.revoke_automation_token("other", "t1", 12).unwrap());
        assert!(store
            .authenticate_automation_token("hash-t1", 15)
            .unwrap()
            .is_some());
        assert!(store.revoke_automation_token("acme", "t1", 16).unwrap());
        assert!(!store.revoke_automation_token("acme", "t1", 17).unwrap());
        assert_eq!(
            store.automation_tokens("acme").unwrap()[0].revoked_at,
            Some(16)
        );
        assert!(store
            .authenticate_automation_token("hash-t1", 18)
            .unwrap()
            .is_none());
    }

    #[test]
    fn outbound_grant_expiry_and_revoke_control_active_state() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .insert_outbound_grant(test_outbound_grant("g1", "acme", 0))
            .unwrap();

        assert!(store
            .has_active_outbound_grant("acme", "link", "upload", 0, 19)
            .unwrap());
        assert!(!store
            .has_active_outbound_grant("acme", "link", "upload", 0, 20)
            .unwrap());
        assert!(store.revoke_outbound_grant("acme", "g1", 12).unwrap());
        assert!(!store.revoke_outbound_grant("acme", "g1", 13).unwrap());
        assert!(!store
            .has_active_outbound_grant("acme", "link", "upload", 0, 11)
            .unwrap());
    }

    #[test]
    fn serve_prune_queries_preserve_expiry_revoke_and_ticket_retention() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut open = test_outbound_grant("open", "acme", 0);
        open.expires_at = 200;
        let mut expired = test_outbound_grant("expired", "acme", 0);
        expired.expires_at = 10;
        let mut revoked = test_outbound_grant("revoked", "acme", 0);
        revoked.expires_at = 200;
        revoked.revoked_at = Some(3);
        let mut exhausted = test_outbound_grant("exhausted", "acme", 0);
        exhausted.expires_at = 200;
        exhausted.max_downloads = Some(1);
        exhausted.downloads = 1;
        for grant in [open, expired, revoked, exhausted] {
            store.insert_outbound_grant(grant).unwrap();
        }
        store
            .with(|connection| {
                for (grant_id, root) in [
                    ("open", "root-open"),
                    ("expired", "root-expired"),
                    ("revoked", "root-revoked"),
                    ("exhausted", "root-exhausted"),
                ] {
                    connection.execute(
                        "INSERT INTO outbound_grant_manifests(grant_id,manifest_root,created_at) VALUES (?1,?2,0)",
                        rusqlite::params![grant_id, root],
                    )?;
                }
                for (token_id, expires_at) in [("old", 10), ("boundary", 20), ("live", 30)] {
                    connection.execute(
                        "INSERT INTO outbound_fetch_tickets(token_id,grant_id,manifest_root,expires_at) VALUES (?1,'open','root-open',?2)",
                        rusqlite::params![token_id, expires_at],
                    )?;
                }
                Ok(())
            })
            .unwrap();

        assert_eq!(
            store.servable_manifest_roots(20).unwrap(),
            vec!["root-open".to_owned()]
        );
        assert_eq!(store.prune_fetch_tickets(20).unwrap(), 1);
        let remaining: Vec<String> = store
            .with(|connection| {
                connection
                    .prepare("SELECT token_id FROM outbound_fetch_tickets ORDER BY token_id")?
                    .query_map([], |row| row.get(0))?
                    .collect()
            })
            .unwrap();
        assert_eq!(remaining, ["boundary".to_owned(), "live".to_owned()]);
    }

    #[test]
    fn fetch_delivery_and_ticket_commit_atomically() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut grant = test_outbound_grant("g1", "acme", 0);
        grant.max_downloads = Some(1);
        store.insert_outbound_grant(grant).unwrap();
        store
            .insert_outbound_grant(test_outbound_grant("g2", "acme", 0))
            .unwrap();
        let ticket = FetchTicket {
            holder: "holder".into(),
            grant_token_hash: "hash-g1".into(),
            policy_revision: 0,
            token_id: "ticket".into(),
            grant_id: "g1".into(),
            manifest_root: "00".repeat(32),
            expires_at: 19,
            delivered_at: None,
        };
        assert!(store.put_fetch_ticket(&ticket, 1).unwrap());
        let connection = rusqlite::Connection::open(directory.path().join("votport.db")).unwrap();
        connection.execute_batch("CREATE TRIGGER fail_ticket BEFORE UPDATE OF delivered_at ON outbound_fetch_tickets BEGIN SELECT RAISE(FAIL, 'fixture'); END;").unwrap();
        assert!(store
            .record_fetch_download("g1", &[0], 10, "ticket")
            .is_err());
        assert_eq!(
            store.outbound_grant_by_id("g1").unwrap().unwrap().downloads,
            0
        );
        assert_eq!(
            store.fetch_ticket("ticket").unwrap().unwrap().delivered_at,
            None
        );
        connection
            .execute_batch("DROP TRIGGER fail_ticket;")
            .unwrap();
        for (grant, token) in [("g2", "ticket"), ("g1", "missing")] {
            assert!(store.record_fetch_download(grant, &[0], 10, token).is_err());
            assert_eq!(
                store
                    .outbound_grant_by_id(grant)
                    .unwrap()
                    .unwrap()
                    .downloads,
                0
            );
        }
        store
            .record_fetch_download("g1", &[0], 10, "ticket")
            .unwrap();
        assert_eq!(
            store.outbound_grant_by_id("g1").unwrap().unwrap().downloads,
            1
        );
        assert_eq!(
            store.fetch_ticket("ticket").unwrap().unwrap().delivered_at,
            Some(10)
        );
        assert!(!store.admit_fetch_ticket(&ticket, 11).unwrap());
    }

    #[test]
    fn outbound_download_count_and_active_link_query_round_trip() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .insert_outbound_grant(test_outbound_grant("g1", "acme", 0))
            .unwrap();
        let mut other = test_outbound_grant("g2", "acme", 1);
        other.link_id = "other-link".to_owned();
        other.expires_at = 100;
        store.insert_outbound_grant(other).unwrap();

        assert_eq!(
            store.record_outbound_download("g1", &[0], 100).unwrap(),
            OutboundDownloadResult {
                first_download: true,
                completed_delivery: true,
            }
        );
        assert_eq!(
            store.record_outbound_download("g1", &[0], 110).unwrap(),
            OutboundDownloadResult {
                first_download: false,
                completed_delivery: false,
            }
        );
        let grant = store
            .outbound_grant_by_token_hash("hash-g1")
            .unwrap()
            .unwrap();
        assert_eq!(grant.downloads, 2);
        assert_eq!(grant.first_download_at, Some(100));
        assert_eq!(grant.last_download_at, Some(110));
        assert!(store
            .record_outbound_download("missing", &[0], 100)
            .is_err());
        assert!(store
            .link_has_active_outbound_grants("acme", "link", 19)
            .unwrap());
        assert!(!store
            .link_has_active_outbound_grants("other", "link", 19)
            .unwrap());
        assert!(store
            .link_has_active_outbound_grants("acme", "other-link", 99)
            .unwrap());
        assert!(!store
            .link_has_active_outbound_grants("acme", "other-link", 100)
            .unwrap());
    }

    #[test]
    fn outbound_download_limit_refuses_after_one_download() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut grant = test_outbound_grant("limited", "acme", 0);
        grant.max_downloads = Some(1);
        store.insert_outbound_grant(grant).unwrap();

        assert!(store
            .has_active_outbound_grant("acme", "link", "upload", 0, 19)
            .unwrap());
        store.record_outbound_download("limited", &[0], 15).unwrap();
        let downloaded = store
            .outbound_grant_by_token_hash("hash-limited")
            .unwrap()
            .unwrap();
        let error = store
            .record_outbound_download("limited", &[0], 16)
            .unwrap_err();
        assert_eq!(error, OUTBOUND_DOWNLOAD_LIMIT_REACHED);
        assert_eq!(
            store
                .outbound_grant_by_token_hash("hash-limited")
                .unwrap()
                .unwrap(),
            downloaded
        );
        assert!(!store
            .has_active_outbound_grant("acme", "link", "upload", 0, 19)
            .unwrap());
        assert!(!store
            .link_has_active_outbound_grants("acme", "link", 19)
            .unwrap());
    }

    #[test]
    fn saved_download_address_survives_restart_and_rotates_atomically() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let token = crate::auth::random_token();
        let mut grant = test_outbound_grant("saved", "acme", 0);
        grant.token_hash = crate::auth::hash_token(&token);
        assert!(store
            .insert_workflow_grant(grant.clone(), None, None, Some("wrong"))
            .is_err());
        assert!(store.outbound_grant_by_id("saved").unwrap().is_none());
        store
            .insert_workflow_grant(grant.clone(), None, None, Some(&token))
            .unwrap();
        assert_eq!(store.outbound_share_token("other", "saved").unwrap(), None);
        assert_eq!(store.outbound_share_token("acme", "missing").unwrap(), None);
        store
            .with(|connection| {
                connection
                    .execute(
                        "UPDATE outbound_grants SET share_token='mismatched' WHERE id='saved'",
                        [],
                    )
                    .map(|_| ())
            })
            .unwrap();
        assert_eq!(store.outbound_share_token("acme", "saved").unwrap(), None);
        store
            .with(|connection| {
                connection
                    .execute(
                        "UPDATE outbound_grants SET share_token=?1 WHERE id='saved'",
                        [&token],
                    )
                    .map(|_| ())
            })
            .unwrap();
        drop(store);
        let store = Store::open(directory.path()).unwrap();
        assert_eq!(
            store
                .outbound_share_token("acme", "saved")
                .unwrap()
                .as_deref(),
            Some(token.as_str())
        );
        let next = crate::auth::random_token();
        store
            .with(|connection| {
                connection.execute_batch(
                    "CREATE TRIGGER refuse_token BEFORE UPDATE OF share_token ON outbound_grants
             BEGIN SELECT RAISE(ABORT, 'fixture refusal'); END;",
                )
            })
            .unwrap();
        assert!(store
            .rotate_outbound_grant_token("acme", "saved", &next)
            .is_err());
        assert_eq!(
            store
                .outbound_share_token("acme", "saved")
                .unwrap()
                .as_deref(),
            Some(token.as_str())
        );
        assert_eq!(store.outbound_grant_by_id("saved").unwrap().unwrap(), grant);
        store
            .with(|connection| connection.execute_batch("DROP TRIGGER refuse_token"))
            .unwrap();
        assert!(store
            .rotate_outbound_grant_token("acme", "saved", &next)
            .unwrap());
        assert_eq!(
            store.outbound_share_token("acme", "saved").unwrap(),
            Some(next)
        );
        assert!(store
            .outbound_grant_by_token_hash(&crate::auth::hash_token(&token))
            .unwrap()
            .is_none());
        store.revoke_outbound_grant("acme", "saved", 12).unwrap();
        assert_eq!(store.outbound_share_token("acme", "saved").unwrap(), None);
    }

    #[test]
    fn current_schema_installs_maintenance_indexes_on_reopen_and_promotion() {
        for promotion in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let store = Store::open(directory.path()).unwrap();
            store
                .with(|connection| {
                    connection.execute_batch(
                        "DROP INDEX delivery_jobs_deadline_pending;
                         DROP INDEX delivery_jobs_retirement_due;
                         DROP INDEX outbound_fetch_tickets_expires;
                         DROP INDEX outbound_grants_open_expires;
                         DROP INDEX audit_log_tenant;
                         DROP INDEX audit_log_event;
                         DROP INDEX audit_log_tenant_at;
                         DROP INDEX audit_log_event_at;
                         ",
                    )
                })
                .unwrap();
            drop(store);
            if promotion {
                std::fs::write(directory.path().join(crate::standby::STATUS_FILE), b"{}").unwrap();
            }
            let store = Store::open(directory.path()).unwrap();
            assert!(store.claim_snapshot_retirement(1).unwrap().is_none());
            store.escalate_delivery_jobs(1).unwrap();
            let indexes = store
                .with(|connection| {
                    connection
                        .prepare(
                            "SELECT name FROM sqlite_schema WHERE type='index' AND name IN (
                                'delivery_jobs_deadline_pending',
                                'delivery_jobs_retirement_due',
                                'outbound_fetch_tickets_expires',
                                'outbound_grants_open_expires',
                                'audit_log_tenant',
                                'audit_log_event',
                                'audit_log_tenant_at',
                                'audit_log_event_at'
                            ) ORDER BY name",
                        )?
                        .query_map([], |row| row.get(0))?
                        .collect::<rusqlite::Result<Vec<String>>>()
                })
                .unwrap();
            assert_eq!(
                indexes,
                [
                    "audit_log_event".to_owned(),
                    "audit_log_event_at".to_owned(),
                    "audit_log_tenant".to_owned(),
                    "audit_log_tenant_at".to_owned(),
                    "delivery_jobs_deadline_pending".to_owned(),
                    "delivery_jobs_retirement_due".to_owned(),
                    "outbound_fetch_tickets_expires".to_owned(),
                    "outbound_grants_open_expires".to_owned()
                ],
                "promotion {promotion}"
            );
        }
    }

    #[test]
    fn schema41_upgrade_preserves_existing_grants_and_can_store_new_addresses() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let grant = test_outbound_grant("preserved", "acme", 0);
        store.insert_outbound_grant(grant.clone()).unwrap();
        store
            .with(|connection| {
                connection
                    .execute(
                        "INSERT INTO files
                     (link_id,tenant,upload_id,file_index,bytes_hi,bytes_lo,deleted,
                      stored_as,path,suite,root,receipt)
                     VALUES ('anonymous-link','', 'anonymous-upload',0,0,13,0,
                             'anonymous-object','anonymous-object','blake3','root',0)",
                        [],
                    )
                    .and_then(|_| {
                        connection.execute(
                            "INSERT INTO files
                         (link_id,tenant,upload_id,file_index,bytes_hi,bytes_lo,deleted,
                          stored_as,path,suite,root,receipt)
                         VALUES ('duplicate-low','', 'duplicate-upload',0,0,5,0,
                                 'shared-object','shared-object','blake3','root',0)",
                            [],
                        )
                    })
                    .and_then(|_| {
                        connection.execute(
                            "INSERT INTO files
                         (link_id,tenant,upload_id,file_index,bytes_hi,bytes_lo,deleted,
                          stored_as,path,suite,root,receipt)
                         VALUES ('duplicate-high','', 'duplicate-upload',1,0,17,0,
                                 'shared-object','shared-object','blake3','root',0)",
                            [],
                        )
                    })
            })
            .unwrap();
        store
            .with(|connection| {
                connection.execute_batch(
                    "DROP INDEX delivery_jobs_retirement_due;
             DROP INDEX delivery_jobs_deadline_pending;
             DROP INDEX outbound_fetch_tickets_expires;
             DROP INDEX outbound_grants_open_expires;
             ALTER TABLE outbound_grants DROP COLUMN share_token;
             UPDATE meta SET value='41' WHERE key='schema_version';",
                )
            })
            .unwrap();
        drop(store);
        let store = Store::open(directory.path()).unwrap();
        assert_eq!(
            store.outbound_grant_by_id("preserved").unwrap().unwrap(),
            grant
        );
        assert_eq!(
            store.outbound_share_token("acme", "preserved").unwrap(),
            None
        );
        assert_eq!(store.tenant_received_bytes("").unwrap(), 30);
        let token = crate::auth::random_token();
        assert!(store
            .rotate_outbound_grant_token("acme", "preserved", &token)
            .unwrap());
        assert_eq!(
            store.outbound_share_token("acme", "preserved").unwrap(),
            Some(token)
        );
        drop(store);
        let store = Store::open(directory.path()).unwrap();
        store
            .with(|connection| {
                let version: String = connection.query_row(
                    "SELECT value FROM meta WHERE key='schema_version'",
                    [],
                    |row| row.get(0),
                )?;
                assert_eq!(version, SCHEMA_VERSION.to_string());
                let indexes: Vec<String> = connection
                    .prepare(
                        "SELECT name FROM sqlite_schema WHERE type='index' AND name IN (
                            'delivery_jobs_deadline_pending',
                            'delivery_jobs_retirement_due',
                            'outbound_fetch_tickets_expires',
                            'outbound_grants_open_expires',
                            'audit_log_tenant',
                            'audit_log_event',
                            'audit_log_tenant_at',
                            'audit_log_event_at'
                        ) ORDER BY name",
                    )?
                    .query_map([], |row| row.get(0))?
                    .collect::<rusqlite::Result<_>>()?;
                assert_eq!(
                    indexes,
                    [
                        "audit_log_event".to_owned(),
                        "audit_log_event_at".to_owned(),
                        "audit_log_tenant".to_owned(),
                        "audit_log_tenant_at".to_owned(),
                        "delivery_jobs_deadline_pending".to_owned(),
                        "delivery_jobs_retirement_due".to_owned(),
                        "outbound_fetch_tickets_expires".to_owned(),
                        "outbound_grants_open_expires".to_owned()
                    ]
                );
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn current_schema_rejects_quota_literal_mutations() {
        for (left, right) in [
            ("SELECT 'a b'", "SELECT 'ab'"),
            ("SELECT ';'", "SELECT ''"),
            ("SELECT 'A'", "SELECT 'a'"),
            ("SELECT 'a'' b'", "SELECT 'a''b'"),
            ("SELECT a b", "SELECT ab"),
            ("SELECT 1; SELECT 2", "SELECT 1 SELECT 2"),
        ] {
            assert_ne!(normalize_schema_sql(left), normalize_schema_sql(right));
        }
        assert_eq!(
            normalize_schema_sql("  SELECT \n'A'' B' ;  "),
            "select 'A'' B'"
        );
        for (kind, name) in [
            ("trigger", "tenant_quota_usage_insert"),
            ("index", "files_quota_identity"),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let store = Store::open(directory.path()).unwrap();
            store
                .with(|connection| {
                    connection.execute_batch("PRAGMA writable_schema=ON")?;
                    let changed = connection.execute(
                        "UPDATE sqlite_schema
                         SET sql=replace(sql, ?1, ?2)
                         WHERE type=?3 AND name=?4",
                        rusqlite::params!["stored_as = ''", "stored_as = ' '", kind, name],
                    )?;
                    connection.execute_batch("PRAGMA writable_schema=OFF")?;
                    assert_eq!(changed, 1, "{kind} {name} was not changed");
                    Ok(())
                })
                .unwrap();
            drop(store);

            let error = match Store::open(directory.path()) {
                Ok(_) => panic!("malformed {kind} {name} was accepted"),
                Err(error) => error,
            };
            assert!(
                error.contains("definition is invalid"),
                "{kind} {name}: {error}"
            );
        }
    }

    #[test]
    fn outbound_grant_token_rotation_is_tenant_scoped() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .insert_outbound_grant(test_outbound_grant("rotate", "acme", 0))
            .unwrap();

        assert!(!store
            .rotate_outbound_grant_token("other", "rotate", "new-hash")
            .unwrap());
        assert!(store
            .rotate_outbound_grant_token("acme", "rotate", "new-hash")
            .unwrap());
        assert!(store
            .outbound_grant_by_token_hash("hash-rotate")
            .unwrap()
            .is_none());
        assert_eq!(
            store
                .outbound_grant_by_token_hash(&crate::auth::hash_token("new-hash"))
                .unwrap()
                .unwrap()
                .id,
            "rotate"
        );
        store.revoke_outbound_grant("acme", "rotate", 12).unwrap();
        assert!(!store
            .rotate_outbound_grant_token("acme", "rotate", "other-hash")
            .unwrap());
    }

    #[test]
    fn outbound_grant_extension_handles_live_expired_and_scoped_rows() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut expired = test_outbound_grant("expired", "acme", 0);
        expired.expires_at = 10;
        store.insert_outbound_grant(expired).unwrap();
        store
            .insert_outbound_grant(test_outbound_grant("live", "acme", 1))
            .unwrap();
        store
            .insert_outbound_grant(test_outbound_grant("revoked", "acme", 2))
            .unwrap();
        store.revoke_outbound_grant("acme", "revoked", 12).unwrap();

        assert_eq!(
            store.extend_outbound_grant("acme", "live", 5, 15).unwrap(),
            Some(25)
        );
        assert_eq!(
            store
                .extend_outbound_grant("acme", "expired", 5, 20)
                .unwrap(),
            Some(25)
        );
        assert_eq!(
            store.extend_outbound_grant("other", "live", 5, 20).unwrap(),
            None
        );
        assert_eq!(
            store
                .extend_outbound_grant("acme", "revoked", 5, 20)
                .unwrap(),
            None
        );
        assert_eq!(
            store
                .outbound_grant_by_token_hash("hash-expired")
                .unwrap()
                .unwrap()
                .expires_at,
            25
        );
    }

    #[test]
    fn outbound_download_tracking_reports_first_and_completed_transitions() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut grant = test_outbound_grant("multi", "acme", 0);
        grant.files = vec![
            OutboundGrantFile {
                source: "objects/a".to_owned(),
                name: "a.txt".to_owned(),
                suite: "blake3".to_owned(),
                root: "aa".to_owned(),
                bytes: 3,
                receipt_b64: "receipt-a".to_owned(),
                downloads: 0,
                first_download_at: None,
                last_download_at: None,
            },
            OutboundGrantFile {
                source: "objects/b".to_owned(),
                name: "b.txt".to_owned(),
                suite: "blake3".to_owned(),
                root: "bb".to_owned(),
                bytes: 4,
                receipt_b64: "receipt-b".to_owned(),
                downloads: 0,
                first_download_at: None,
                last_download_at: None,
            },
        ];
        store.insert_outbound_grant(grant).unwrap();

        assert_eq!(
            store.record_outbound_download("multi", &[1], 100).unwrap(),
            OutboundDownloadResult {
                first_download: true,
                completed_delivery: false,
            }
        );
        assert_eq!(
            store.record_outbound_download("multi", &[0], 200).unwrap(),
            OutboundDownloadResult {
                first_download: false,
                completed_delivery: true,
            }
        );
        assert_eq!(
            store
                .record_outbound_download("multi", &[0, 1, 1], 300)
                .unwrap(),
            OutboundDownloadResult {
                first_download: false,
                completed_delivery: false,
            }
        );
        let grant = store
            .outbound_grant_by_token_hash("hash-multi")
            .unwrap()
            .unwrap();
        assert_eq!(grant.downloads, 2);
        assert_eq!(grant.first_download_at, Some(100));
        assert_eq!(grant.last_download_at, Some(300));
        assert_eq!(grant.files[0].downloads, 2);
        assert_eq!(grant.files[0].first_download_at, Some(200));
        assert_eq!(grant.files[0].last_download_at, Some(300));
        assert_eq!(grant.files[1].downloads, 2);
        assert_eq!(grant.files[1].first_download_at, Some(100));
        assert_eq!(grant.files[1].last_download_at, Some(300));

        assert_eq!(
            store
                .record_outbound_download("multi", &[0, 1], 400)
                .unwrap(),
            OutboundDownloadResult {
                first_download: false,
                completed_delivery: false,
            }
        );
        assert_eq!(
            store
                .record_outbound_download("multi", &[0, 1], 500)
                .unwrap(),
            OutboundDownloadResult {
                first_download: false,
                completed_delivery: false,
            }
        );
        let grant = store
            .outbound_grant_by_token_hash("hash-multi")
            .unwrap()
            .unwrap();
        assert_eq!(grant.downloads, 4);
        assert_eq!(grant.files[0].downloads, 4);
        assert_eq!(grant.files[1].downloads, 4);
    }

    #[test]
    fn outbound_multi_file_limit_applies_per_file_and_counts_rounds() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut grant = test_outbound_grant("multi-limit", "acme", 0);
        grant.max_downloads = Some(1);
        grant.files = (0..2)
            .map(|index| OutboundGrantFile {
                source: format!("objects/{index}"),
                name: format!("{index}.txt"),
                suite: "blake3".to_owned(),
                root: format!("root-{index}"),
                bytes: 1,
                receipt_b64: "receipt".to_owned(),
                downloads: 0,
                first_download_at: None,
                last_download_at: None,
            })
            .collect();
        store.insert_outbound_grant(grant).unwrap();

        store
            .record_outbound_download("multi-limit", &[0], 100)
            .unwrap();
        let grant = store
            .outbound_grant_by_token_hash("hash-multi-limit")
            .unwrap()
            .unwrap();
        assert_eq!(grant.downloads, 0);
        assert_eq!(grant.files[0].downloads, 1);
        assert_eq!(grant.files[1].downloads, 0);

        assert_eq!(
            store
                .record_outbound_download("multi-limit", &[0, 1], 150)
                .unwrap_err(),
            OUTBOUND_DOWNLOAD_LIMIT_REACHED
        );
        let grant = store
            .outbound_grant_by_token_hash("hash-multi-limit")
            .unwrap()
            .unwrap();
        assert_eq!(grant.files[0].downloads, 1);
        assert_eq!(grant.files[1].downloads, 0);

        let completed = store
            .record_outbound_download("multi-limit", &[1], 200)
            .unwrap();
        assert!(completed.completed_delivery);
        let grant = store
            .outbound_grant_by_token_hash("hash-multi-limit")
            .unwrap()
            .unwrap();
        assert_eq!(grant.downloads, 1);
        assert_eq!(grant.files[0].downloads, 1);
        assert_eq!(grant.files[1].downloads, 1);

        assert_eq!(
            store
                .record_outbound_download("multi-limit", &[0], 300)
                .unwrap_err(),
            OUTBOUND_DOWNLOAD_LIMIT_REACHED
        );
        let grant = store
            .outbound_grant_by_token_hash("hash-multi-limit")
            .unwrap()
            .unwrap();
        assert_eq!(grant.files[1].downloads, 1);
    }

    #[test]
    fn outbound_download_tracking_rejects_invalid_indexes_atomically() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut grant = test_outbound_grant("atomic", "acme", 0);
        grant.files = vec![OutboundGrantFile {
            source: "objects/a".to_owned(),
            name: "a.txt".to_owned(),
            suite: "blake3".to_owned(),
            root: "aa".to_owned(),
            bytes: 3,
            receipt_b64: "receipt-a".to_owned(),
            downloads: 0,
            first_download_at: None,
            last_download_at: None,
        }];
        store.insert_outbound_grant(grant.clone()).unwrap();

        assert!(store
            .record_outbound_download("atomic", &[0, 1], 100)
            .is_err());
        assert_eq!(
            store
                .outbound_grant_by_token_hash("hash-atomic")
                .unwrap()
                .unwrap(),
            grant
        );
    }

    #[test]
    fn outbound_full_range_rejects_missing_child_atomically() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut grant = test_outbound_grant("missing-child", "acme", 0);
        grant.files = (0..2)
            .map(|index| OutboundGrantFile {
                source: format!("objects/{index}"),
                name: format!("{index}.txt"),
                suite: "blake3".to_owned(),
                root: format!("root-{index}"),
                bytes: 1,
                receipt_b64: "receipt".to_owned(),
                downloads: 0,
                first_download_at: None,
                last_download_at: None,
            })
            .collect();
        store.insert_outbound_grant(grant).unwrap();
        store
            .with(|connection| {
                connection.execute(
                    "DELETE FROM outbound_grant_files
                     WHERE grant_id = 'missing-child' AND file_index = 1",
                    [],
                )
            })
            .unwrap();

        assert_eq!(
            store
                .record_outbound_download("missing-child", &[0, 1], 100)
                .unwrap_err(),
            "outbound file index out of range"
        );
        let downloads: Vec<i64> = store
            .with(|connection| {
                let mut statement = connection.prepare(
                    "SELECT downloads FROM outbound_grant_files
                     WHERE grant_id = 'missing-child' ORDER BY file_index",
                )?;
                let downloads = statement
                    .query_map([], |row| row.get(0))?
                    .collect::<Result<Vec<_>, _>>();
                downloads
            })
            .unwrap();
        assert_eq!(downloads, vec![0]);
    }

    #[test]
    fn legal_hold_rolls_back_when_audit_fails() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.insert_link(test_link("held")).unwrap();
        store
            .with(|connection| connection.execute_batch("DROP TABLE audit_log"))
            .unwrap();

        assert!(store
            .set_link_legal_hold("", "held", true, "admin")
            .is_err());
        assert!(!store.link("", "held").unwrap().unwrap().legal_hold);
    }

    #[test]
    fn link_upload_extracts_one_record_without_the_full_history() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut link = test_link("link-1");
        for index in 0..3 {
            link.uploads.push(UploadRecord {
                partial: false,
                log: Vec::new(),
                id: format!("up-{index}"),
                started_at: 1,
                completed_at: 2,
                replayed_chunks: 0,
                rejected_chunks: 0,
                transport: None,
                package_root: format!("root-{index}"),
                total_bytes: 5,
                files: Vec::new(),
            });
        }
        store.insert_link(link).unwrap();
        let found = store.link_upload("", "link-1", "up-1").unwrap().unwrap();
        assert_eq!(found.id, "up-1");
        assert_eq!(found.package_root, "root-1");
        assert!(store.link_upload("", "link-1", "up-9").unwrap().is_none());
        // Tenant scoping holds: the wrong namespace sees nothing.
        assert!(store
            .link_upload("other", "link-1", "up-1")
            .unwrap()
            .is_none());
    }

    #[test]
    fn schema41_quota_backfill_failure_rolls_back_without_partial_schema() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .with(|connection| {
                connection.execute_batch(
                    "DROP TRIGGER tenant_quota_usage_insert;
                     DROP TRIGGER tenant_quota_usage_delete;
                     DROP TRIGGER tenant_quota_usage_update;
                     DROP INDEX files_quota_identity;
                     DROP INDEX upload_sessions_quota_live;
                     DROP TABLE tenant_quota_usage;
                     ALTER TABLE outbound_grants DROP COLUMN share_token;
                     INSERT INTO files
                         (link_id,tenant,upload_id,file_index,bytes_hi,bytes_lo,deleted,
                          stored_as,path,suite,root,receipt)
                     VALUES ('anonymous-link','', 'anonymous-upload',0,-1,13,0,
                             'anonymous-object','anonymous-object','blake3','root',0);
                     UPDATE meta SET value='41' WHERE key='schema_version';",
                )
            })
            .unwrap();
        drop(store);

        let error = match Store::open(directory.path()) {
            Ok(_) => panic!("invalid file limbs must abort schema upgrade"),
            Err(error) => error,
        };
        assert!(
            error.contains("file byte limbs are outside the u32 range"),
            "{error}"
        );
        let connection = Connection::open(directory.path().join("votport.db")).unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT value FROM meta WHERE key='schema_version'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "41"
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE type IN ('table','trigger','index')
                       AND (name='tenant_quota_usage' OR name LIKE 'tenant_quota_usage_%'
                            OR name IN ('files_quota_identity','upload_sessions_quota_live'))",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT bytes_hi,bytes_lo FROM files WHERE link_id='anonymous-link'",
                    [],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                )
                .unwrap(),
            (-1, 13)
        );
    }

    #[test]
    fn links_round_trip_with_uploads_and_events() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut link = test_link("link-1");
        link.uploads.push(UploadRecord {
            partial: false,
            log: Vec::new(),
            id: "up-1".to_owned(),
            started_at: 1,
            completed_at: 2,
            replayed_chunks: 3,
            rejected_chunks: 4,
            transport: None,
            package_root: "aa".to_owned(),
            total_bytes: 5,
            files: vec![FileRecord {
                path: "a.txt".to_owned(),
                stored_as: "a.txt".to_owned(),
                bytes: 5,
                suite: "blake3".to_owned(),
                root: "bb".to_owned(),
                receipt: true,
                deleted: false,
            }],
        });
        link.events.push(SessionEvent {
            at: 3,
            started_at: 1,
            outcome: "cancelled".to_owned(),
            detail: "by sender".to_owned(),
            received_bytes: 6,
            expected_bytes: 7,
            replayed_chunks: 8,
            rejected_chunks: 9,
        });
        store.insert_link(link).unwrap();

        let loaded = store.link("", "link-1").unwrap().unwrap();
        assert_eq!(loaded.uploads.len(), 1);
        assert!(loaded.uploads[0].files[0].receipt);
        assert_eq!(loaded.events[0].outcome, "cancelled");
        assert_eq!(store.links("").unwrap().len(), 1);
        let upload_link = store.upload_link("link-1").unwrap().unwrap();
        assert!(upload_link.uploads.is_empty());
        assert!(upload_link.events.is_empty());
        assert_eq!(store.uploads_by_id("link-1").unwrap().unwrap().len(), 1);
        assert!(store.upload_link("missing").unwrap().is_none());
        assert!(store.uploads_by_id("missing").unwrap().is_none());
        store
            .with(|connection| {
                connection.execute(
                    "UPDATE link_uploads SET document = 'broken' WHERE link_id = 'link-1'",
                    [],
                )
            })
            .unwrap();
        assert!(store.uploads_by_id("link-1").is_err());
        assert!(store.link("", "link-1").is_err());
        store
            .with(|connection| {
                connection.execute_batch("DELETE FROM link_uploads WHERE link_id='link-1'; UPDATE links SET events_json='broken' WHERE id='link-1';")
            })
            .unwrap();
        assert!(store.uploads_by_id("link-1").is_err());
        assert!(store.link("", "link-1").is_err());
    }

    #[test]
    fn update_and_remove_report_presence() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.insert_link(test_link("link-1")).unwrap();
        let found = store
            .update_link("", "link-1", |link| link.active = false)
            .unwrap();
        assert!(found);
        assert!(!store.link("", "link-1").unwrap().unwrap().active);
        assert!(!store.update_link("", "missing", |_| {}).unwrap());
        assert!(store.remove_link("", "link-1").unwrap());
        assert!(!store.remove_link("", "link-1").unwrap());
        assert!(store.link("", "link-1").unwrap().is_none());
    }

    #[test]
    fn tombstones_do_not_decode_upload_headers() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut link = test_link("link");
        link.uploads.push(UploadRecord {
            id: "upload".into(),
            started_at: 1,
            completed_at: 2,
            replayed_chunks: 0,
            rejected_chunks: 0,
            transport: None,
            package_root: "package".into(),
            total_bytes: 1,
            partial: false,
            log: Vec::new(),
            files: vec![FileRecord {
                path: "display".into(),
                stored_as: "stored".into(),
                bytes: 1,
                suite: "blake3".into(),
                root: "aa".into(),
                receipt: true,
                deleted: false,
            }],
        });
        let mut alias = link.uploads[0].clone();
        alias.id = "alias".into();
        link.uploads.push(alias);
        let mut unrelated = link.uploads[0].clone();
        unrelated.id = "unrelated".into();
        unrelated.files[0].stored_as = "other".into();
        link.uploads.push(unrelated);
        store.insert_link(link).unwrap();
        store
            .with(|connection| {
                connection.execute_batch(
                    "UPDATE link_uploads SET document='{}' WHERE link_id='link';
             CREATE TRIGGER fail_alias_tombstone BEFORE UPDATE ON files
             WHEN old.upload_id='alias' BEGIN SELECT RAISE(FAIL,'fixture alias failure'); END;",
                )
            })
            .unwrap();
        let paths = std::collections::HashSet::from(["stored"]);
        assert!(store
            .tombstone_files("", "link", &paths)
            .unwrap_err()
            .contains("fixture alias failure"));
        assert_eq!(store.tenant_received_bytes("").unwrap(), 2);
        assert_eq!(
            store
                .with(|c| {
                    c.query_row("SELECT count(*) FROM files WHERE deleted=0", [], |row| {
                        row.get::<_, i64>(0)
                    })
                })
                .unwrap(),
            3
        );
        store
            .with(|c| c.execute_batch("DROP TRIGGER fail_alias_tombstone"))
            .unwrap();
        assert!(!store
            .tombstone_files("other-tenant", "link", &paths)
            .unwrap());
        assert_eq!(store.tenant_received_bytes("").unwrap(), 2);
        assert_eq!(
            store
                .with(|c| {
                    c.query_row("SELECT count(*) FROM files WHERE deleted=0", [], |row| {
                        row.get::<_, i64>(0)
                    })
                })
                .unwrap(),
            3
        );
        assert!(store.link_upload("", "link", "upload").is_err());
        assert!(store
            .tombstone_files("", "link", &std::collections::HashSet::from(["stored"]))
            .unwrap());
        let mut spool = Vec::new();
        store.write_tenant_live_files("", &mut spool).unwrap();
        let live: Vec<(String, u64)> = spool
            .split(|byte| *byte == b'\n')
            .filter(|row| !row.is_empty())
            .map(|row| serde_json::from_slice(row).unwrap())
            .collect();
        assert_eq!(live, vec![("other".to_owned(), 1)]);
        assert!(store.link_upload("", "link", "upload").is_err());
        assert!(store.link_upload("", "link", "unrelated").is_err());
    }

    #[test]
    fn upload_headers_stay_small_and_typed_files_round_trip() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut link = test_link("link");
        let upload = UploadRecord {
            id: "upload".into(),
            started_at: 11,
            completed_at: 22,
            replayed_chunks: 3,
            rejected_chunks: 4,
            transport: Some("native".into()),
            package_root: "aa".repeat(32),
            total_bytes: u64::MAX,
            partial: true,
            log: vec![LogEvent {
                at: 22,
                kind: "interrupted".into(),
                path: None,
                bytes: Some(u64::MAX),
                secs: Some(5),
                count: Some(2048),
            }],
            files: (0..2048)
                .map(|index| FileRecord {
                    path: format!("folder/納品-{index}.mov"),
                    stored_as: format!("stored/{index}.mov"),
                    bytes: if index == 0 { u64::MAX } else { index },
                    suite: if index % 2 == 0 { "sha256" } else { "blake3" }.into(),
                    root: format!("{index:064x}"),
                    receipt: index % 2 == 0,
                    deleted: index % 2 != 0,
                })
                .collect(),
        };
        link.uploads.push(upload.clone());
        let mut empty = upload.clone();
        empty.id = "empty".into();
        empty.files.clear();
        empty.total_bytes = 0;
        link.uploads.push(empty.clone());
        store.insert_link(link).unwrap();
        let (header, count): (String, i64) = store
            .with(|c| {
                c.query_row(
                    "SELECT document,file_count FROM link_uploads WHERE upload_id='upload'",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
            })
            .unwrap();
        assert!(
            header.len() < 1024,
            "header includes file-sized metadata: {}",
            header.len()
        );
        assert_eq!(count, 2048);
        let header: serde_json::Value = serde_json::from_str(&header).unwrap();
        assert_eq!(header["files"], serde_json::json!([]));
        drop(store);
        let store = Store::open(directory.path()).unwrap();
        assert_eq!(
            store.link_upload("", "link", "upload").unwrap().unwrap(),
            upload
        );
        assert_eq!(
            store.link_upload("", "link", "empty").unwrap().unwrap(),
            empty
        );
        assert_eq!(
            store.uploads_by_id("link").unwrap().unwrap(),
            vec![upload, empty]
        );
        let result = store.search("", "納品-0.mov", 10).unwrap();
        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].bytes, u64::MAX);
        assert_eq!(result.files[0].upload_id, "upload");
        assert!(store.search("", "納品-1.mov", 10).unwrap().files.is_empty());
    }

    #[test]
    fn full_upload_reads_refuse_missing_or_misindexed_file_records() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut link = test_link("link");
        link.uploads.push(UploadRecord {
            id: "upload".into(),
            started_at: 1,
            completed_at: 2,
            replayed_chunks: 0,
            rejected_chunks: 0,
            transport: None,
            package_root: "package".into(),
            total_bytes: 2,
            partial: false,
            log: Vec::new(),
            files: (0..2)
                .map(|index| FileRecord {
                    path: format!("file-{index}"),
                    stored_as: format!("stored-{index}"),
                    bytes: 1,
                    suite: "blake3".into(),
                    root: "aa".into(),
                    receipt: true,
                    deleted: false,
                })
                .collect(),
        });
        store.insert_link(link).unwrap();
        store
            .with(|c| c.execute("UPDATE files SET file_index=2 WHERE file_index=0", []))
            .unwrap();
        assert!(store
            .link_upload("", "link", "upload")
            .unwrap_err()
            .contains("do not match"));
        store
            .with(|c| c.execute("UPDATE files SET file_index=0 WHERE file_index=2", []))
            .unwrap();
        for count in [-1, 1, 3] {
            store
                .with(|c| c.execute("UPDATE link_uploads SET file_count=?1", [count]))
                .unwrap();
            assert!(store
                .link_upload("", "link", "upload")
                .unwrap_err()
                .contains("do not match"));
        }
        store
            .with(|c| {
                c.execute_batch(
                    "UPDATE link_uploads SET file_count=2; DELETE FROM files WHERE file_index=0",
                )
            })
            .unwrap();
        assert!(store
            .link_upload("", "link", "upload")
            .unwrap_err()
            .contains("do not match"));
        assert!(store.uploads_by_id("link").is_err());
    }

    #[test]
    fn link_policy_updates_do_not_decode_upload_history() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.insert_link(test_link("link")).unwrap();
        store.with(|connection| connection.execute(
            "INSERT INTO link_uploads(link_id,tenant,upload_id,document,file_count) VALUES ('link','','bad','{}',0)", [],
        )).unwrap();
        assert!(store
            .update_link("", "link", |link| link.active = false)
            .unwrap());
        assert!(!store.upload_link("link").unwrap().unwrap().active);
        assert!(store.uploads_by_id("link").is_err());
    }

    #[test]
    fn upload_mutations_preserve_other_records_and_rollback_together() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let record = |id: &str, path: &str, partial| UploadRecord {
            id: id.into(),
            started_at: 1,
            completed_at: 2,
            replayed_chunks: 0,
            rejected_chunks: 0,
            transport: None,
            package_root: "package".into(),
            total_bytes: 1,
            partial,
            log: Vec::new(),
            files: vec![FileRecord {
                path: path.into(),
                stored_as: path.into(),
                bytes: 1,
                suite: "blake3".into(),
                root: "aa".into(),
                receipt: false,
                deleted: false,
            }],
        };
        let mut link = test_link("history");
        link.uploads = vec![
            record("first", "shared", true),
            record("second", "shared", true),
            record("third", "other", false),
        ];
        store.insert_link(link).unwrap();
        let third = store
            .with(|c| {
                c.query_row(
                    "SELECT position,document FROM link_uploads WHERE upload_id='third'",
                    [],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
                )
            })
            .unwrap();
        store.with(|c| c.execute_batch("CREATE TABLE history_writes(upload_id TEXT, kind TEXT);
            CREATE TRIGGER history_update AFTER UPDATE ON link_uploads BEGIN INSERT INTO history_writes VALUES(new.upload_id,'update'); END;
            CREATE TABLE file_updates(upload_id TEXT);
            CREATE TRIGGER file_update AFTER UPDATE ON files BEGIN INSERT INTO file_updates VALUES(new.upload_id); END;
            CREATE TRIGGER history_delete AFTER DELETE ON link_uploads BEGIN INSERT INTO history_writes VALUES(old.upload_id,'delete'); END;
            CREATE TRIGGER history_insert AFTER INSERT ON link_uploads BEGIN INSERT INTO history_writes VALUES(new.upload_id,'insert'); END;
            CREATE TRIGGER fail_file_delete BEFORE DELETE ON files BEGIN SELECT RAISE(ABORT,'fixture delete failure'); END;")).unwrap();
        assert!(!store.remove_upload("other", "history", "first").unwrap());
        assert!(!store.remove_upload("", "history", "missing").unwrap());
        assert!(store
            .remove_upload("", "history", "first")
            .unwrap_err()
            .contains("fixture delete failure"));
        assert!(store.link_upload("", "history", "first").unwrap().is_some());
        store
            .with(|c| c.execute_batch("DROP TRIGGER fail_file_delete"))
            .unwrap();
        assert!(store.remove_upload("", "history", "first").unwrap());
        store
            .update_link("", "history", |link| link.active = false)
            .unwrap();
        store.with(|c| c.execute_batch("CREATE TRIGGER fail_history_update BEFORE UPDATE ON files BEGIN SELECT RAISE(ABORT,'fixture update failure'); END;")).unwrap();
        let paths = std::collections::HashSet::from(["shared"]);
        assert!(store
            .tombstone_files("", "history", &paths)
            .unwrap_err()
            .contains("fixture update failure"));
        assert!(
            !store
                .link_upload("", "history", "second")
                .unwrap()
                .unwrap()
                .files[0]
                .deleted
        );
        assert_eq!(store.tenant_received_bytes("").unwrap(), 2);
        store
            .with(|c| c.execute_batch("DROP TRIGGER fail_history_update"))
            .unwrap();
        store.tombstone_files("", "history", &paths).unwrap();
        assert_eq!(
            store
                .with(|c| c.query_row(
                    "SELECT count(*) FROM history_writes WHERE kind='update'",
                    [],
                    |row| row.get::<_, i64>(0),
                ))
                .unwrap(),
            0
        );
        let mut recovered = record("second", "shared", true);
        recovered.files[0].receipt = true;
        recovered
            .files
            .push(record("extra", "extra", true).files.remove(0));
        store
            .append_upload("", "history", recovered.clone())
            .unwrap();
        let file_updates = || {
            store
                .with(|c| {
                    c.query_row("SELECT count(*) FROM file_updates", [], |row| {
                        row.get::<_, i64>(0)
                    })
                })
                .unwrap()
        };
        assert_eq!(file_updates(), 2);
        store
            .append_upload("", "history", recovered.clone())
            .unwrap();
        assert_eq!(
            file_updates(),
            2,
            "unchanged recovery must not rewrite file rows"
        );
        let second = store.link_upload("", "history", "second").unwrap().unwrap();
        assert!(second.files[0].deleted && second.files[0].receipt);
        assert_eq!(second.files[1].stored_as, "extra");
        assert!(!second.files[1].deleted);
        assert_eq!(second.total_bytes, 2);
        assert_eq!(store.tenant_received_bytes("").unwrap(), 2);
        let before = serde_json::to_string(&second).unwrap();
        recovered.files[0].root = "changed".into();
        assert!(store
            .append_upload("", "history", recovered.clone())
            .unwrap_err()
            .contains("file identity"));
        recovered.package_root = "changed".into();
        assert!(store
            .append_upload("", "history", recovered)
            .unwrap_err()
            .contains("upload identity"));
        assert_eq!(
            serde_json::to_string(&store.link_upload("", "history", "second").unwrap().unwrap())
                .unwrap(),
            before
        );
        let full = record("third", "other", false);
        store.append_upload("", "history", full.clone()).unwrap();
        let mut conflicting = full;
        conflicting.files[0].root = "different".into();
        assert!(store
            .append_upload("", "history", conflicting)
            .unwrap_err()
            .contains("upload identity"));
        store.with(|c| c.execute_batch("CREATE TRIGGER fail_file_insert BEFORE INSERT ON files BEGIN SELECT RAISE(ABORT,'fixture insert failure'); END;")).unwrap();
        assert!(store
            .append_upload("", "history", record("last", "last", false))
            .is_err());
        assert!(store.link_upload("", "history", "last").unwrap().is_none());
        store
            .with(|c| c.execute_batch("DROP TRIGGER fail_file_insert"))
            .unwrap();
        store
            .append_upload("", "history", record("aaa", "last", false))
            .unwrap();
        assert_eq!(
            store
                .with(|c| c.query_row(
                    "SELECT position,document FROM link_uploads WHERE upload_id='third'",
                    [],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                ))
                .unwrap(),
            third
        );
        assert_eq!(
            store
                .with(|c| c.query_row(
                    "SELECT count(*) FROM history_writes WHERE upload_id='third'",
                    [],
                    |row| row.get::<_, i64>(0)
                ))
                .unwrap(),
            0
        );
        let files = store
            .with(|c| {
                c.prepare(
                    "SELECT upload_id,file_index,deleted FROM files ORDER BY upload_id,file_index",
                )?
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, bool>(2)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()
            })
            .unwrap();
        assert_eq!(
            files,
            [
                ("aaa".into(), 0, false),
                ("second".into(), 0, true),
                ("second".into(), 1, false),
                ("third".into(), 0, false)
            ]
        );
        let ids = || {
            store
                .uploads_by_id("history")
                .unwrap()
                .unwrap()
                .into_iter()
                .map(|upload| upload.id)
                .collect::<Vec<_>>()
        };
        assert_eq!(ids(), ["second", "third", "aaa"]);
        let snapshot = directory.path().join("snapshot");
        std::fs::create_dir(&snapshot).unwrap();
        store.backup_into(&snapshot.join("votport.db")).unwrap();
        let restored = Store::open(&snapshot).unwrap();
        assert_eq!(
            restored
                .uploads_by_id("history")
                .unwrap()
                .unwrap()
                .into_iter()
                .map(|upload| upload.id)
                .collect::<Vec<_>>(),
            ids()
        );
        assert_eq!(restored.tenant_received_bytes("").unwrap(), 3);
        assert!(store.remove_link("", "history").unwrap());
        assert_eq!(
            store
                .with(
                    |c| c.query_row("SELECT count(*) FROM link_uploads", [], |row| row
                        .get::<_, i64>(0))
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn links_preserve_insertion_order() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.insert_link(test_link("b")).unwrap();
        store.insert_link(test_link("a")).unwrap();
        let ids: Vec<String> = store
            .links("")
            .unwrap()
            .into_iter()
            .map(|link| link.id)
            .collect();
        assert_eq!(ids, ["b", "a"]);
    }

    #[test]
    fn admin_hash_persists_across_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        assert!(store.admin_password_hash().unwrap().is_none());
        store
            .set_admin_password_hash("argon2-hash".to_owned())
            .unwrap();
        drop(store);
        let reopened = Store::open(directory.path()).unwrap();
        assert_eq!(
            reopened.admin_password_hash().unwrap().as_deref(),
            Some("argon2-hash")
        );
    }

    #[test]
    fn optional_columns_round_trip() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut link = test_link("link-1");
        link.password_hash = Some("argon2".to_owned());
        link.expires_at = Some(12345);
        link.max_bytes = Some(999);
        store.insert_link(link).unwrap();
        drop(store);
        let reopened = Store::open(directory.path()).unwrap();
        let loaded = reopened.link("", "link-1").unwrap().unwrap();
        assert_eq!(loaded.password_hash.as_deref(), Some("argon2"));
        assert_eq!(loaded.expires_at, Some(12345));
        assert_eq!(loaded.max_bytes, Some(999));
        // And the None side survives too.
        let mut bare = test_link("link-2");
        bare.expires_at = None;
        reopened.insert_link(bare).unwrap();
        assert_eq!(
            reopened.link("", "link-2").unwrap().unwrap().expires_at,
            None
        );
    }

    #[test]
    fn audit_rows_round_trip_export_and_prune() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.audit(
            "",
            "",
            "link_created",
            "link-1",
            &serde_json::json!({ "label": "x" }),
        );
        store.audit("", "", "admin_login", "10.0.0.1", &serde_json::json!({}));

        let rows = store.audit_export(None, 0, 0, 100).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].event, "link_created");
        assert_eq!(rows[0].tenant, "");
        assert_eq!(rows[0].detail["label"], "x");
        // `since` is strictly greater-than (rows share second granularity).
        let after_all = store
            .audit_export(None, rows.last().unwrap().at + 1, 0, 100)
            .unwrap();
        assert!(after_all.is_empty());
        assert_eq!(store.audit_export(None, 0, 0, 1).unwrap().len(), 1);

        // Pruning removes only rows strictly older than the cutoff.
        let now = now_unix();
        let pruned = store.audit_prune(now + 1).unwrap();
        assert_eq!(pruned, 2);
        assert!(store.audit_export(None, 0, 0, 100).unwrap().is_empty());

        store.audit("", "", "test", "corrupt", &serde_json::json!({}));
        store
            .with(|connection| connection.execute("UPDATE audit_log SET detail = 'broken'", []))
            .unwrap();
        assert!(store.audit_export(None, 0, 0, 100).is_err());
    }

    #[test]
    fn audit_count_tracks_mutations_rollbacks_pruning_and_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        assert_eq!(store.audit_count().unwrap(), 0);
        store.audit("", "", "committed", "one", &serde_json::json!({}));
        assert_eq!(store.audit_count().unwrap(), 1);

        store
            .with(|connection| {
                connection.execute(
                    "INSERT INTO audit_log(at,tenant,actor,event,subject,detail)
                     VALUES (?1,'','',?2,'two','{}')",
                    rusqlite::params![now_unix() as i64, "direct"],
                )
            })
            .unwrap();
        assert_eq!(store.audit_count().unwrap(), 2);

        store
            .with(|connection| {
                connection.execute_batch("BEGIN")?;
                connection.execute(
                    "INSERT INTO audit_log(at,tenant,actor,event,subject,detail)
                     VALUES (?1,'','',?2,'rolled-back','{}')",
                    rusqlite::params![now_unix() as i64, "rollback"],
                )?;
                connection.execute_batch("ROLLBACK")
            })
            .unwrap();
        assert_eq!(store.audit_count().unwrap(), 2);

        store
            .with(|connection| connection.execute("DELETE FROM audit_log WHERE event='direct'", []))
            .unwrap();
        assert_eq!(store.audit_count().unwrap(), 1);
        assert_eq!(store.audit_prune(now_unix() + 1).unwrap(), 1);
        assert_eq!(store.audit_count().unwrap(), 0);

        drop(store);
        let reopened = Store::open(directory.path()).unwrap();
        assert_eq!(reopened.audit_count().unwrap(), 0);
    }

    #[test]
    fn audit_count_reads_retained_counter_after_audit_history_removed() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.audit("", "", "first", "one", &serde_json::json!({}));
        store.audit("", "", "second", "two", &serde_json::json!({}));
        store.audit("", "", "third", "three", &serde_json::json!({}));
        assert_eq!(store.audit_count().unwrap(), 3);

        store
            .with(|connection| connection.execute_batch("DROP TABLE audit_log"))
            .unwrap();
        assert_eq!(store.audit_count().unwrap(), 3);
    }
}

#[cfg(test)]
mod tenant_tests {
    use super::tests::{link_in, test_tenant};
    use super::*;

    #[test]
    fn links_are_invisible_across_tenants() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .insert_tenant(Tenant {
                incarnation: String::new(),
                key: "acme".to_owned(),
                label: "Acme".to_owned(),
                admin_group: None,
                max_total_bytes: None,
                max_links: None,
                max_sessions: None,
                created_at: 0,
            })
            .unwrap();
        store.insert_link(link_in("acme", "secret-link")).unwrap();
        store.insert_link(link_in("", "default-link")).unwrap();

        assert!(store.link("acme", "secret-link").unwrap().is_some());
        // Another tenant (and the default) cannot see or touch it.
        assert!(store.link("", "secret-link").unwrap().is_none());
        assert!(!store.update_link("", "secret-link", |_| {}).unwrap());
        assert!(!store.remove_link("", "secret-link").unwrap());
        assert_eq!(store.links("acme").unwrap().len(), 1);
        assert_eq!(store.links("").unwrap().len(), 1);
    }

    #[test]
    fn tenant_crud_refuses_while_links_remain() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .insert_tenant(Tenant {
                incarnation: String::new(),
                key: "acme".to_owned(),
                label: String::new(),
                admin_group: Some("acme-admins".to_owned()),
                max_total_bytes: Some(1024),
                max_links: Some(2),
                max_sessions: Some(1),
                created_at: 0,
            })
            .unwrap();
        assert_eq!(store.tenants().unwrap().len(), 1);
        assert_eq!(store.tenant("acme").unwrap().unwrap().max_links, Some(2));
        assert!(store.tenant("missing").unwrap().is_none());

        store.insert_link(link_in("acme", "blocked")).unwrap();
        // The handler refuses deletion while links remain; the store exposes
        // the count and the raw delete.
        assert_eq!(store.tenant_link_count("acme").unwrap(), 1);

        store.remove_link("acme", "blocked").unwrap();
        assert_eq!(store.tenant_link_count("acme").unwrap(), 0);
        assert_eq!(store.remove_tenant("acme").unwrap(), TenantRemoval::Deleted);
        assert!(store.tenant("acme").unwrap().is_none());
        let err = store.insert_link(link_in("acme", "orphan")).unwrap_err();
        assert_eq!(err, InsertLinkError::NamedTenantGone);
        assert!(store.link("acme", "orphan").unwrap().is_none());
    }

    #[test]
    fn received_bytes_count_live_files_only() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut link = link_in("acme", "link-1");
        let mut file = FileRecord {
            path: "a.bin".to_owned(),
            stored_as: "a.bin".to_owned(),
            bytes: 500,
            suite: "blake3".to_owned(),
            root: "aa".to_owned(),
            receipt: false,
            deleted: false,
        };
        link.uploads.push(UploadRecord {
            partial: false,
            log: Vec::new(),
            id: "up".to_owned(),
            started_at: 0,
            completed_at: 0,
            replayed_chunks: 0,
            rejected_chunks: 0,
            transport: None,
            package_root: "cc".to_owned(),
            total_bytes: 500,
            files: vec![file.clone()],
        });
        store.insert_tenant(test_tenant("acme")).unwrap();
        store.insert_link(link.clone()).unwrap();
        assert_eq!(store.tenant_received_bytes("acme").unwrap(), 500);
        assert_eq!(store.tenant_received_bytes("").unwrap(), 0);
        let usage = store.tenant_usage().unwrap();
        assert_eq!(usage.len(), 2);
        assert_eq!(usage[0].tenant, "");
        assert_eq!(usage[0].links, 0);
        assert_eq!(usage[1].tenant, "acme");
        assert_eq!(usage[1].links, 1);
        assert_eq!(usage[1].received_bytes, 500);

        store
            .with(|connection| {
                connection.execute_batch(
                    "CREATE TRIGGER fail_file_update BEFORE UPDATE ON files
                     BEGIN SELECT RAISE(FAIL, 'test file failure'); END;",
                )
            })
            .unwrap();
        assert!(store
            .tombstone_files(
                "acme",
                "link-1",
                &std::collections::HashSet::from(["a.bin"])
            )
            .is_err());
        assert!(!store.link("acme", "link-1").unwrap().unwrap().uploads[0].files[0].deleted);
        assert_eq!(store.tenant_received_bytes("acme").unwrap(), 500);
        store
            .with(|connection| connection.execute_batch("DROP TRIGGER fail_file_update"))
            .unwrap();

        file.deleted = true;
        link.uploads[0].files[0] = file;
        store
            .tombstone_files(
                "acme",
                "link-1",
                &std::collections::HashSet::from(["a.bin"]),
            )
            .unwrap();
        assert_eq!(store.tenant_received_bytes("acme").unwrap(), 0);
        assert_eq!(store.tenant_usage().unwrap()[1].received_bytes, 0);
        assert!(store.remove_link("acme", "link-1").unwrap());
        let files = store
            .with(|connection| {
                connection.query_row("SELECT COUNT(*) FROM files", [], |row| row.get::<_, i64>(0))
            })
            .unwrap();
        assert_eq!(files, 0);
    }

    #[test]
    fn quota_aggregate_tracks_identity_limb_and_saturation_changes() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let insert = |tenant: &str, link: &str, upload: &str, stored_as: &str, bytes: u64| {
            store
                .with(|connection| {
                    let (hi, lo) = split_bytes(bytes);
                    connection.execute(
                        "INSERT INTO files(link_id,tenant,upload_id,file_index,bytes_hi,bytes_lo,deleted,stored_as,path,suite,root,receipt)
                         VALUES (?1,?2,?3,0,?4,?5,0,?6,'path','blake3','root',0)",
                        rusqlite::params![link, tenant, upload, hi, lo, stored_as],
                    )?;
                    Ok(())
                })
                .unwrap();
        };
        insert("acme", "a", "one", "same", u64::from(u32::MAX));
        insert("acme", "b", "two", "same", (1_u64 << 32) + 1);
        insert("acme", "c", "three", "", 5);
        insert("acme", "d", "four", "c/three/0", 7);
        insert("other", "e", "five", "same", 10);
        assert_eq!(
            store.tenant_received_bytes("acme").unwrap(),
            (1_u64 << 32) + 13
        );

        store
            .with(|connection| {
                connection.execute(
                    "UPDATE files SET bytes_hi=1,bytes_lo=10 WHERE tenant='acme' AND link_id='b'",
                    [],
                )
            })
            .unwrap();
        assert_eq!(
            store.tenant_received_bytes("acme").unwrap(),
            (1_u64 << 32) + 22
        );
        store
            .with(|connection| {
                connection.execute("DELETE FROM files WHERE tenant='acme' AND link_id='b'", [])
            })
            .unwrap();
        assert_eq!(
            store.tenant_received_bytes("acme").unwrap(),
            (1_u64 << 32) + 11
        );
        store
            .with(|connection| {
                connection.execute(
                    "UPDATE files SET deleted=1 WHERE tenant='acme' AND link_id='a'",
                    [],
                )
            })
            .unwrap();
        assert_eq!(store.tenant_received_bytes("acme").unwrap(), 12);
        store
            .with(|connection| {
                connection.execute(
                    "UPDATE files SET tenant='other' WHERE tenant='acme' AND link_id='c'",
                    [],
                )
            })
            .unwrap();
        assert_eq!(store.tenant_received_bytes("acme").unwrap(), 7);
        assert_eq!(store.tenant_received_bytes("other").unwrap(), 15);

        insert("acme", "max", "six", "max", u64::MAX);
        insert("acme", "small", "seven", "small", 1);
        assert_eq!(store.tenant_received_bytes("acme").unwrap(), u64::MAX);
        store
            .with(|connection| {
                connection.execute(
                    "DELETE FROM files WHERE tenant='acme' AND link_id='small'",
                    [],
                )
            })
            .unwrap();
        assert_eq!(store.tenant_received_bytes("acme").unwrap(), u64::MAX);
        store
            .with(|connection| {
                connection.execute(
                    "DELETE FROM files WHERE tenant='acme' AND link_id='max'",
                    [],
                )
            })
            .unwrap();
        assert_eq!(store.tenant_received_bytes("acme").unwrap(), 7);
        let state = store
            .with(|connection| {
                connection.query_row(
                    "SELECT state FROM tenant_quota_usage WHERE tenant='acme'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
            })
            .unwrap();
        assert_eq!(state, 0);

        insert("acme", "tie-a", "eight", "tie", (7_u64 << 32) + 1);
        insert("acme", "tie-b", "nine", "tie", (7_u64 << 32) + 9);
        assert_eq!(
            store.tenant_received_bytes("acme").unwrap(),
            (7_u64 << 32) + 16
        );
        store
            .with(|connection| {
                connection.execute(
                    "DELETE FROM files WHERE tenant='acme' AND link_id='tie-b'",
                    [],
                )
            })
            .unwrap();
        assert_eq!(
            store.tenant_received_bytes("acme").unwrap(),
            (7_u64 << 32) + 8
        );
        store
            .with(|connection| {
                connection.execute(
                    "DELETE FROM files WHERE tenant='acme' AND link_id='tie-a'",
                    [],
                )
            })
            .unwrap();
        assert_eq!(store.tenant_received_bytes("acme").unwrap(), 7);
        store
            .with(|connection| {
                connection.execute("DELETE FROM files WHERE tenant='acme' AND link_id='d'", [])
            })
            .unwrap();
        assert_eq!(store.tenant_received_bytes("acme").unwrap(), 0);
    }

    #[test]
    fn tenant_received_bytes_admission_vm_work_is_bounded() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let insert = |start: usize, count: usize| {
            store
                .with(|connection| {
                    connection.execute_batch("BEGIN")?;
                    for index in start..start + count {
                        let (hi, lo) = split_bytes((index + 1) as u64);
                        connection.execute(
                            "INSERT INTO files(link_id,tenant,upload_id,file_index,bytes_hi,bytes_lo,deleted,stored_as,path,suite,root,receipt)
                             VALUES (?1,'acme','upload',?2,?3,?4,0,?5,?5,'blake3','root',0)",
                            rusqlite::params![format!("link-{index}"), index as i64, hi, lo, format!("path-{index}")],
                        )?;
                    }
                    connection.execute_batch("COMMIT")
                })
                .unwrap();
        };
        insert(0, 100);

        let read_work = || {
            LAST_TENANT_RECEIVED_VM_STEPS.with(|steps| steps.set(TENANT_RECEIVED_VM_UNOBSERVED));
            let value = store.tenant_received_bytes("acme").unwrap();
            let vm_steps = LAST_TENANT_RECEIVED_VM_STEPS.with(Cell::get);
            assert_ne!(
                vm_steps, TENANT_RECEIVED_VM_UNOBSERVED,
                "production reader did not report VM work"
            );
            (value, vm_steps)
        };
        assert_eq!(read_work().0, 5_050);
        let hundred_rows = read_work().1;

        insert(100, 900);
        assert_eq!(read_work().0, 500_500);
        let thousand_rows = read_work().1;

        assert!(
            (1..=500).contains(&hundred_rows),
            "aggregate read used {hundred_rows} VM callbacks"
        );
        assert!(
            (1..=500).contains(&thousand_rows),
            "aggregate read used {thousand_rows} VM callbacks"
        );
    }

    /// A deduped re-send or a partial record references a file an earlier
    /// record already counts; the physical file counts once until every
    /// record over it is tombstoned.
    #[test]
    fn shared_stored_paths_count_once() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.insert_tenant(test_tenant("acme")).unwrap();
        let record = |id: &str, files: Vec<FileRecord>| UploadRecord {
            partial: false,
            log: Vec::new(),
            id: id.to_owned(),
            started_at: 0,
            completed_at: 0,
            replayed_chunks: 0,
            rejected_chunks: 0,
            transport: None,
            package_root: "cc".to_owned(),
            total_bytes: files.iter().map(|file| file.bytes).sum(),
            files,
        };
        let file = |path: &str, bytes: u64| FileRecord {
            path: path.to_owned(),
            stored_as: path.to_owned(),
            bytes,
            suite: "blake3".to_owned(),
            root: "00".to_owned(),
            receipt: true,
            deleted: false,
        };
        let mut link = link_in("acme", "link-1");
        link.uploads
            .push(record("partial", vec![file("a.bin", 300)]));
        store.insert_link(link).unwrap();
        assert_eq!(store.tenant_received_bytes("acme").unwrap(), 300);
        // The full re-send records a.bin again beside a new file.
        store
            .append_upload(
                "acme",
                "link-1",
                record("full", vec![file("a.bin", 300), file("b.bin", 200)]),
            )
            .unwrap();
        assert_eq!(store.tenant_received_bytes("acme").unwrap(), 500);
        assert_eq!(store.tenant_usage().unwrap()[1].received_bytes, 500);
        assert_eq!(store.tenant_stored("acme").unwrap(), (2, 500));
        let mut spool = Vec::new();
        store.write_tenant_live_files("acme", &mut spool).unwrap();
        let live: Vec<(String, u64)> = spool
            .split(|byte| *byte == b'\n')
            .filter(|row| !row.is_empty())
            .map(|row| serde_json::from_slice(row).unwrap())
            .collect();
        assert_eq!(live, [("a.bin".to_owned(), 300), ("b.bin".to_owned(), 200)]);
        // Delete file tombstones every record over the path, so the bytes go.
        store
            .tombstone_files(
                "acme",
                "link-1",
                &std::collections::HashSet::from(["a.bin"]),
            )
            .unwrap();
        assert_eq!(store.tenant_received_bytes("acme").unwrap(), 200);
        let files = store
            .with(|connection| {
                connection.query_row(
                    "SELECT COUNT(*) FROM files WHERE deleted = 0 AND stored_as = 'a.bin'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
            })
            .unwrap();
        assert_eq!(
            files, 0,
            "the matcher tombstones every record over the path"
        );
    }

    #[test]
    fn scim_groups_round_trip_and_map_to_subjects() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let admins = store
            .create_scim_group(
                "votport-admins",
                Some("g1"),
                &["a@example.com".to_owned(), "b@example.com".to_owned()],
            )
            .unwrap()
            .unwrap();
        assert_eq!(admins.members, ["a@example.com", "b@example.com"]);
        assert_eq!(admins.external_id.as_deref(), Some("g1"));
        assert!(admins.created_at > 0);
        assert!(
            store
                .create_scim_group("votport-admins", None, &[])
                .unwrap()
                .is_none(),
            "names are unique"
        );
        let viewers = store
            .create_scim_group("viewers", None, &["a@example.com".to_owned()])
            .unwrap()
            .unwrap();
        assert_eq!(
            store.scim_groups_of("a@example.com").unwrap(),
            ["viewers", "votport-admins"]
        );
        assert_eq!(
            store.scim_groups_of("b@example.com").unwrap(),
            ["votport-admins"]
        );
        assert!(store.scim_groups_of("nobody").unwrap().is_empty());

        let (page, total) = store.scim_groups_page(10, 0).unwrap();
        assert_eq!(total, 2);
        assert_eq!(page[0].display_name, "viewers");
        assert_eq!(page[1].members.len(), 2);
        assert_eq!(
            store.scim_group_by_name("viewers").unwrap().unwrap().id,
            viewers.id
        );
        assert_eq!(
            store.scim_group_by_external_id("g1").unwrap().unwrap().id,
            admins.id
        );
        assert!(store.scim_group_by_external_id("g9").unwrap().is_none());

        assert!(store
            .change_scim_group_members(
                &admins.id,
                &["c@example.com".to_owned(), "a@example.com".to_owned()],
                &["b@example.com".to_owned()],
            )
            .unwrap());
        assert_eq!(
            store.scim_group(&admins.id).unwrap().unwrap().members,
            ["a@example.com", "c@example.com"]
        );
        assert!(!store
            .change_scim_group_members("missing", &[], &[])
            .unwrap());

        assert_eq!(
            store
                .replace_scim_group(&admins.id, Some("viewers"), None)
                .unwrap_err(),
            SCIM_GROUP_NAME_TAKEN
        );
        assert!(store
            .replace_scim_group(
                &admins.id,
                Some("admins"),
                Some(&["z@example.com".to_owned()]),
            )
            .unwrap());
        let renamed = store.scim_group(&admins.id).unwrap().unwrap();
        assert_eq!(renamed.display_name, "admins");
        assert_eq!(renamed.members, ["z@example.com"]);
        assert!(!store.replace_scim_group("missing", None, None).unwrap());

        assert!(store.delete_scim_group(&admins.id).unwrap());
        assert!(!store.delete_scim_group(&admins.id).unwrap());
        assert!(store.scim_groups_of("z@example.com").unwrap().is_empty());
        assert_eq!(store.scim_groups_page(10, 0).unwrap().1, 1);
    }

    #[test]
    fn received_bytes_preserve_u64_and_saturate_aggregate() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.insert_tenant(test_tenant("acme")).unwrap();
        let mut link = link_in("acme", "large");
        link.uploads.push(UploadRecord {
            partial: false,
            log: Vec::new(),
            id: "up".to_owned(),
            started_at: 0,
            completed_at: 0,
            replayed_chunks: 0,
            rejected_chunks: 0,
            transport: None,
            package_root: "root".to_owned(),
            total_bytes: u64::MAX,
            files: vec![
                FileRecord {
                    path: "large".to_owned(),
                    stored_as: "large".to_owned(),
                    bytes: u64::MAX,
                    suite: "blake3".to_owned(),
                    root: "aa".to_owned(),
                    receipt: false,
                    deleted: false,
                },
                FileRecord {
                    path: "one".to_owned(),
                    stored_as: "one".to_owned(),
                    bytes: 1,
                    suite: "blake3".to_owned(),
                    root: "bb".to_owned(),
                    receipt: false,
                    deleted: false,
                },
            ],
        });
        store.insert_link(link).unwrap();

        assert_eq!(store.tenant_received_bytes("acme").unwrap(), u64::MAX);
        assert_eq!(store.tenant_usage().unwrap()[1].received_bytes, u64::MAX);
        store
            .append_upload(
                "acme",
                "large",
                UploadRecord {
                    partial: false,
                    log: Vec::new(),
                    id: "second".to_owned(),
                    started_at: u64::MAX,
                    completed_at: u64::MAX,
                    replayed_chunks: u64::MAX,
                    rejected_chunks: u64::MAX,
                    transport: None,
                    package_root: "exact".to_owned(),
                    total_bytes: u64::MAX,
                    files: Vec::new(),
                },
            )
            .unwrap();
        let uploads = store.link("acme", "large").unwrap().unwrap().uploads;
        assert_eq!(uploads.len(), 2);
        assert_eq!(uploads[0].total_bytes, u64::MAX);
        assert_eq!(uploads[1].started_at, u64::MAX);
        assert_eq!(uploads[1].total_bytes, u64::MAX);
        let limbs = store
            .with(|connection| {
                connection.query_row(
                    "SELECT bytes_hi, bytes_lo FROM files WHERE file_index = 0",
                    [],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                )
            })
            .unwrap();
        assert_eq!(limbs, (u32::MAX as i64, u32::MAX as i64));
        store
            .with(|connection| {
                connection.execute(
                    "UPDATE link_uploads SET document='{}' WHERE link_id='large' AND upload_id='up'",
                    [],
                )
            })
            .unwrap();
        let mut next = uploads[1].clone();
        next.id = "third".into();
        assert!(store.append_upload("acme", "large", next.clone()).unwrap());
        store
            .with(|connection| {
                connection.execute(
                    "UPDATE links SET events_json = 'broken'
                     WHERE id = 'large'",
                    [],
                )
            })
            .unwrap();
        assert!(store
            .append_upload("acme", "large", {
                next.id = "fourth".into();
                next
            })
            .is_err());
    }

    #[test]
    fn tenant_quotas_preserve_u64_across_create_and_update() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut tenant = test_tenant("acme");
        tenant.max_total_bytes = Some(u64::MAX);
        tenant.max_links = Some(u64::MAX);
        tenant.max_sessions = Some(u64::MAX);
        store.insert_tenant(tenant).unwrap();
        assert_eq!(
            store.tenant("acme").unwrap().unwrap().max_total_bytes,
            Some(u64::MAX)
        );

        let mut tenant = store.tenant("acme").unwrap().unwrap();
        tenant.max_total_bytes = Some(u64::MAX - 1);
        tenant.max_links = Some(u64::MAX - 1);
        tenant.max_sessions = Some(u64::MAX - 1);
        assert!(store.update_tenant(&tenant).unwrap());
        drop(store);

        let reopened = Store::open(directory.path()).unwrap();
        let tenant = reopened.tenant("acme").unwrap().unwrap();
        assert_eq!(tenant.max_total_bytes, Some(u64::MAX - 1));
        assert_eq!(tenant.max_links, Some(u64::MAX - 1));
        assert_eq!(tenant.max_sessions, Some(u64::MAX - 1));
    }

    #[test]
    fn projection_writes_only_changed_files() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.insert_tenant(test_tenant("acme")).unwrap();
        let mut link = link_in("acme", "link");
        let file = FileRecord {
            path: "a".to_owned(),
            stored_as: "a".to_owned(),
            bytes: 1,
            suite: "blake3".to_owned(),
            root: "aa".to_owned(),
            receipt: false,
            deleted: false,
        };
        link.uploads.push(UploadRecord {
            partial: false,
            log: Vec::new(),
            id: "up".to_owned(),
            started_at: 0,
            completed_at: 0,
            replayed_chunks: 0,
            rejected_chunks: 0,
            transport: None,
            package_root: "root".to_owned(),
            total_bytes: 50,
            files: vec![file.clone(); 50],
        });
        store.insert_link(link).unwrap();
        store
            .with(|connection| {
                connection.execute_batch(
                    "CREATE TABLE projection_writes (count INTEGER NOT NULL);
                     INSERT INTO projection_writes VALUES (0);
                     CREATE TRIGGER count_file_insert AFTER INSERT ON files BEGIN
                       UPDATE projection_writes SET count = count + 1; END;
                     CREATE TRIGGER count_file_update AFTER UPDATE ON files BEGIN
                       UPDATE projection_writes SET count = count + 1; END;
                     CREATE TRIGGER count_file_delete AFTER DELETE ON files BEGIN
                       UPDATE projection_writes SET count = count + 1; END;",
                )
            })
            .unwrap();

        store
            .update_link("acme", "link", |link| link.active = false)
            .unwrap();
        store
            .append_upload(
                "acme",
                "link",
                UploadRecord {
                    partial: false,
                    log: Vec::new(),
                    id: "new".to_owned(),
                    started_at: 0,
                    completed_at: 0,
                    replayed_chunks: 0,
                    rejected_chunks: 0,
                    transport: None,
                    package_root: "new-root".to_owned(),
                    total_bytes: 1,
                    files: vec![FileRecord {
                        path: "b".to_owned(),
                        stored_as: "b".to_owned(),
                        ..file
                    }],
                },
            )
            .unwrap();
        let writes = || {
            store
                .with(|connection| {
                    connection.query_row("SELECT count FROM projection_writes", [], |row| {
                        row.get::<_, i64>(0)
                    })
                })
                .unwrap()
        };
        assert_eq!(writes(), 1);
        store
            .tombstone_files("acme", "link", &std::collections::HashSet::from(["b"]))
            .unwrap();
        assert_eq!(writes(), 2);
    }
}

#[cfg(test)]
mod ops_tests {
    use super::tests::{link_in, test_link, test_tenant};
    use super::*;

    #[test]
    fn backup_creates_a_queryable_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.insert_link(test_link("link-1")).unwrap();

        let snapshot = directory.path().join("snapshot.db");
        store.backup_into(&snapshot).unwrap();
        assert!(snapshot.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&snapshot).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        // The snapshot is a real database with the same rows: drop it into
        // a fresh data dir and open it as one.
        let restore = tempfile::tempdir().unwrap();
        std::fs::copy(&snapshot, restore.path().join("votport.db")).unwrap();
        let reopened = Store::open(restore.path()).unwrap();
        assert!(reopened.link("", "link-1").unwrap().is_some());

        // A fresh VACUUM INTO needs the destination gone; that is the
        // caller's contract.
        std::fs::remove_file(&snapshot).unwrap();
        store.backup_into(&snapshot).unwrap();
        assert!(snapshot.exists());
    }

    #[test]
    fn backup_runs_without_the_shared_store_lock() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.insert_link(test_link("link-1")).unwrap();

        // Hold the serving connection for the whole snapshot: requests keep
        // flowing while VACUUM INTO runs on its own connection.
        let guard = store.connection.lock().unwrap();
        let snapshot = directory.path().join("snapshot.db");
        store.backup_into(&snapshot).unwrap();
        drop(guard);
        assert!(snapshot.exists());
    }

    #[cfg(unix)]
    #[test]
    fn open_protects_existing_and_new_database_state() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("votport.db");
        std::fs::write(&database, b"").unwrap();
        std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o644)).unwrap();
        let backups = directory.path().join("backups");
        std::fs::create_dir(&backups).unwrap();
        let snapshot = backups.join("snapshot.db");
        std::fs::write(&snapshot, b"snapshot").unwrap();
        std::fs::set_permissions(&backups, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&snapshot, std::fs::Permissions::from_mode(0o644)).unwrap();

        let store = Store::open(directory.path()).unwrap();
        assert_eq!(
            std::fs::metadata(directory.path().join("votport.db"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(directory.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&backups).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(snapshot).unwrap().permissions().mode() & 0o777,
            0o600
        );
        for suffix in ["-wal", "-shm"] {
            let path = directory.path().join(format!("votport.db{suffix}"));
            if path.exists() {
                assert_eq!(
                    std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
        drop(store);
    }

    #[test]
    fn all_links_spans_tenants() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.insert_link(test_link("default-link")).unwrap();
        store.insert_tenant(test_tenant("acme")).unwrap();
        let mut scoped = test_link("scoped-link");
        scoped.tenant = "acme".to_owned();
        store.insert_link(scoped).unwrap();
        assert_eq!(store.all_links().unwrap().len(), 2);
    }

    #[test]
    fn retention_link_ids_page_is_bounded_and_spans_tenants() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.insert_link(test_link("a-link")).unwrap();
        store.insert_link(test_link("b-link")).unwrap();
        store.insert_tenant(test_tenant("acme")).unwrap();
        store.insert_link(link_in("acme", "c-link")).unwrap();
        store
            .with(|connection| {
                connection.execute("UPDATE links SET events_json = '{' WHERE id = 'a-link'", [])
            })
            .unwrap();

        // The page reads identities only, so an unrelated malformed history
        // does not make the bounded scan allocate or parse that history.
        let first = store.retention_link_ids(None, 2).unwrap();
        assert_eq!(
            first,
            vec![
                (String::new(), "a-link".into()),
                (String::new(), "b-link".into())
            ]
        );
        let second = store
            .retention_link_ids(Some(&first.last().unwrap().1), 2)
            .unwrap();
        assert_eq!(second, vec![("acme".into(), "c-link".into())]);
        assert!(store
            .retention_link_ids(Some(&second.last().unwrap().1), 2)
            .unwrap()
            .is_empty());
        assert!(store.retention_link_ids(None, 0).unwrap().is_empty());
    }
}

#[cfg(test)]
mod phase4_review_tests {
    use super::tests::{link_in, test_outbound_grant, test_tenant};
    use super::*;

    #[test]
    fn link_by_id_spans_tenants_for_the_public_protocol() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .insert_tenant(super::tests::test_tenant("acme"))
            .unwrap();
        store.insert_link(link_in("acme", "scoped")).unwrap();
        // Senders never know a tenant key; the id is the capability.
        assert!(store.link_by_id("scoped").unwrap().is_some());
        assert!(store.link_by_id("missing").unwrap().is_none());
    }

    #[test]
    fn audit_export_cursor_survives_same_second_rows() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        for index in 0..3 {
            store.audit(
                "",
                "",
                "event",
                &format!("row-{index}"),
                &serde_json::json!({}),
            );
        }
        // Page size 2: the third row shares the second with the first two
        // and must still be reachable through the rowid cursor.
        let page_one = store.audit_export(None, 0, 0, 2).unwrap();
        assert_eq!(page_one.len(), 2);
        let last = page_one.last().unwrap();
        let page_two = store
            .audit_export(None, last.at, last.rowid as u64, 2)
            .unwrap();
        assert_eq!(page_two.len(), 1);
        assert_eq!(page_two[0].subject, "row-2");
    }

    #[test]
    fn audit_export_filters_by_tenant() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.audit("acme", "", "link_created", "l-1", &serde_json::json!({}));
        store.audit("", "", "admin_login", "ip", &serde_json::json!({}));
        let scoped = store.audit_export(Some("acme"), 0, 0, 100).unwrap();
        assert_eq!(scoped.len(), 1);
        assert_eq!(scoped[0].tenant, "acme");
        let default = store.audit_export(Some(""), 0, 0, 100).unwrap();
        assert_eq!(default.len(), 1);
        assert_eq!(default[0].tenant, "");
        assert_eq!(store.audit_export(None, 0, 0, 100).unwrap().len(), 2);
    }

    #[test]
    fn links_page_is_stable_literal_filtered_and_tenant_scoped() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut newest = link_in("", "z-link");
        newest.created_at = 100;
        newest.label = "Hundred% match".to_owned();
        newest.dest = "incoming".to_owned();
        let mut middle = link_in("", "m-link");
        middle.created_at = 100;
        middle.label = "100X match".to_owned();
        let mut oldest = link_in("", "a-link");
        oldest.created_at = 100;
        oldest.active = false;
        store.insert_link(newest).unwrap();
        store.insert_link(middle).unwrap();
        store.insert_link(oldest).unwrap();
        store.insert_tenant(test_tenant("acme")).unwrap();
        store.insert_link(link_in("acme", "foreign")).unwrap();

        let first = store
            .links_page("", 2, None, "HUNDRED%", "all", 1000, false)
            .unwrap();
        assert_eq!(
            first
                .links
                .iter()
                .map(|link| link.id.as_str())
                .collect::<Vec<_>>(),
            vec!["z-link"]
        );

        let first = store
            .links_page("", 2, None, "", "all", 1000, false)
            .unwrap();
        assert_eq!(
            first
                .links
                .iter()
                .map(|link| link.id.as_str())
                .collect::<Vec<_>>(),
            vec!["z-link", "m-link"]
        );
        let cursor = first.next_cursor.unwrap();
        let second = store
            .links_page("", 2, Some(&cursor), "", "all", 1000, false)
            .unwrap();
        assert_eq!(second.links[0].id, "a-link");
        assert!(second.next_cursor.is_none());
        assert!(store
            .links_page("", 2, None, "", "all", 1000, false)
            .unwrap()
            .links
            .iter()
            .all(|link| link.tenant.is_empty()));
        assert_eq!(
            store
                .links_page("", 10, None, "", "open", 1000, false)
                .unwrap()
                .links
                .len(),
            2
        );
        assert_eq!(
            store
                .links_page("", 10, None, "", "closed", 1000, false)
                .unwrap()
                .links
                .len(),
            1
        );
    }

    #[test]
    fn links_page_unfiltered_query_uses_created_index() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let plan = store
            .with(|connection| {
                let mut statement = connection.prepare(
                    "EXPLAIN QUERY PLAN
                     SELECT id FROM links
                     WHERE tenant = ?1
                       AND (?2 = '' OR lower(label) LIKE '%' || ?2 || '%' ESCAPE '\\'
                            OR lower(dest) LIKE '%' || ?2 || '%' ESCAPE '\\'
                            OR id = ?2)
                       AND (?3 = 'all'
                            OR (?3 = 'open' AND active != 0
                                AND (expires_at IS NULL OR expires_at > ?4))
                            OR (?3 = 'closed' AND (active = 0
                                OR (expires_at IS NOT NULL AND expires_at <= ?4))))
                       AND (?5 = 0 OR created_at < ?6
                            OR (created_at = ?6 AND id < ?7))
                     ORDER BY created_at DESC, id DESC
                     LIMIT ?8",
                )?;
                let rows = statement.query_map(
                    rusqlite::params!["", "", "all", 1000_i64, 0_i64, 0_i64, "", 11_i64],
                    |row| row.get::<_, String>(3),
                )?;
                rows.collect::<Result<Vec<_>, _>>()
            })
            .unwrap();
        assert!(plan
            .iter()
            .any(|detail| detail.contains("USING INDEX links_tenant_created")));
    }

    #[test]
    fn active_outbound_file_keys_filter_scope_state_and_bad_indexes() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();

        store
            .insert_outbound_grant(test_outbound_grant("active", "acme", 2))
            .unwrap();
        let mut expired = test_outbound_grant("expired", "acme", 3);
        expired.expires_at = 19;
        store.insert_outbound_grant(expired).unwrap();
        let mut revoked = test_outbound_grant("revoked", "acme", 4);
        revoked.revoked_at = Some(1);
        store.insert_outbound_grant(revoked).unwrap();
        let mut spent = test_outbound_grant("spent", "acme", 5);
        spent.max_downloads = Some(1);
        spent.downloads = 1;
        store.insert_outbound_grant(spent).unwrap();
        let other_tenant = test_outbound_grant("other-tenant", "other", 6);
        store.insert_outbound_grant(other_tenant).unwrap();
        let mut other_link = test_outbound_grant("other-link", "acme", 7);
        other_link.link_id = "other-link".to_owned();
        store.insert_outbound_grant(other_link).unwrap();

        assert_eq!(
            store.active_outbound_file_keys("acme", "link", 19).unwrap(),
            vec![("upload".to_owned(), 2)]
        );
        assert!(store
            .active_outbound_file_keys("acme", "link", 20)
            .unwrap()
            .is_empty());

        store
            .with(|connection| {
                connection.execute(
                    "UPDATE outbound_grants SET file_index = ?1 WHERE id = ?2",
                    rusqlite::params![-1_i64, "active"],
                )
            })
            .unwrap();
        assert!(store.active_outbound_file_keys("acme", "link", 19).is_err());
    }

    #[test]
    fn active_outbound_object_keys_are_global_and_deduplicated() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let object = |suite: &str, root: &str, bytes: u64| OutboundGrantFile {
            source: format!("objects/{root}"),
            name: root.to_owned(),
            suite: suite.to_owned(),
            root: root.to_owned(),
            bytes,
            receipt_b64: String::new(),
            downloads: 0,
            first_download_at: None,
            last_download_at: None,
        };

        let mut legacy = test_outbound_grant("legacy", "acme", 0);
        legacy.root = "parent".to_owned();
        legacy.bytes = 3;
        store.insert_outbound_grant(legacy).unwrap();

        let mut active = test_outbound_grant("active", "other", 0);
        active.root = "parent".to_owned();
        active.bytes = 3;
        active.files = vec![object("blake3", "parent", 3), object("sha256", "child", 4)];
        store.insert_outbound_grant(active).unwrap();

        let mut expired = test_outbound_grant("expired", "acme", 0);
        expired.root = "expired-parent".to_owned();
        expired.expires_at = 19;
        expired.files = vec![object("blake3", "expired-child", 5)];
        store.insert_outbound_grant(expired).unwrap();

        let mut revoked = test_outbound_grant("revoked", "other", 0);
        revoked.root = "revoked-parent".to_owned();
        revoked.revoked_at = Some(1);
        revoked.files = vec![object("blake3", "revoked-child", 6)];
        store.insert_outbound_grant(revoked).unwrap();

        assert_eq!(
            store.active_outbound_object_keys(19).unwrap(),
            vec![
                ("blake3".to_owned(), "parent".to_owned(), 3),
                ("sha256".to_owned(), "child".to_owned(), 4),
            ]
        );
    }

    #[test]
    fn recent_audit_is_descending_and_tenant_scoped() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.audit("acme", "", "first", "a", &serde_json::json!({}));
        store.audit("acme", "", "second", "b", &serde_json::json!({}));
        store.audit("other", "", "foreign", "c", &serde_json::json!({}));

        let page = store.audit_recent(Some("acme"), 0, 1).unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].event, "second");
        let older = store
            .audit_recent(Some("acme"), page[0].rowid as u64, 10)
            .unwrap();
        assert_eq!(older.len(), 1);
        assert_eq!(older[0].event, "first");
    }

    #[test]
    fn audit_filters_match_fields_without_searching_detail() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.audit(
            "acme",
            "Alice",
            "link_created",
            "request-1",
            &serde_json::json!({"secret_marker": "needle"}),
        );
        store.audit(
            "acme",
            "Bob",
            "link_deleted",
            "request-2",
            &serde_json::json!({}),
        );
        store.audit(
            "other",
            "Alice",
            "link_created",
            "request-3",
            &serde_json::json!({}),
        );
        store.audit("", "", "default_event", "request-4", &serde_json::json!({}));

        let filters = AuditFilters {
            event: Some("link_created"),
            query: Some("ALICE"),
        };
        let recent = store
            .audit_recent_filtered(Some("acme"), 0, 100, filters)
            .unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].subject, "request-1");

        let detail_only = store
            .audit_recent_filtered(
                Some("acme"),
                0,
                100,
                AuditFilters {
                    event: None,
                    query: Some("needle"),
                },
            )
            .unwrap();
        assert!(detail_only.is_empty());

        let display_tenant = store
            .audit_recent_filtered(
                None,
                0,
                100,
                AuditFilters {
                    event: None,
                    query: Some("DEFAULT"),
                },
            )
            .unwrap();
        assert_eq!(display_tenant.len(), 1);
        assert_eq!(display_tenant[0].event, "default_event");

        let legacy = store
            .audit_export_filtered(Some("acme"), 0, 0, 100, filters)
            .unwrap();
        assert_eq!(legacy.len(), 1);
        assert_eq!(legacy[0].subject, "request-1");
    }

    #[test]
    fn filtered_audit_cursor_paginates_recent_rows() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        for subject in ["first", "second", "third"] {
            store.audit("acme", "", "match", subject, &serde_json::json!({}));
        }
        let filters = AuditFilters {
            event: Some("match"),
            query: None,
        };
        let first = store
            .audit_recent_filtered(Some("acme"), 0, 2, filters)
            .unwrap();
        assert_eq!(first.len(), 2);
        let second = store
            .audit_recent_filtered(Some("acme"), first[1].rowid as u64, 2, filters)
            .unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].subject, "first");
    }

    #[test]
    fn filtered_audit_reads_use_scope_indexes() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .with(|connection| {
                connection.execute_batch("BEGIN")?;
                for index in 0..100 {
                    connection.execute(
                        "INSERT INTO audit_log(at,tenant,actor,event,subject)
                         VALUES (?1,?2,'actor',?3,?4)",
                        rusqlite::params![
                            (index / 4) as i64,
                            if index % 10 < 2 { "acme" } else { "other" },
                            if index % 7 == 0 { "rare" } else { "common" },
                            if index == 70 { "needle" } else { "other" },
                        ],
                    )?;
                }
                connection.execute_batch("COMMIT")
            })
            .unwrap();
        fn measure_audit<F>(read: F) -> Vec<AuditRow>
        where
            F: FnOnce() -> Result<Vec<AuditRow>, String>,
        {
            LAST_AUDIT_VM_STEPS.with(|steps| steps.set(AUDIT_VM_STEPS_UNOBSERVED));
            let rows = read().unwrap();
            let vm_steps = LAST_AUDIT_VM_STEPS.with(Cell::get);
            assert!(vm_steps > 0, "audit reader did not report VM steps");
            assert!(vm_steps < 500, "audit reader used {vm_steps} VM steps");
            rows
        }

        let tenant_recent = measure_audit(|| {
            store.audit_recent_filtered(Some("acme"), 0, 5, AuditFilters::default())
        });
        assert_eq!(
            tenant_recent
                .iter()
                .map(|row| row.subject.as_str())
                .collect::<Vec<_>>(),
            ["other", "other", "other", "other", "other"]
        );
        assert!(tenant_recent.iter().all(|row| row.tenant == "acme"));
        let tenant_recent_page_two = measure_audit(|| {
            store.audit_recent_filtered(
                Some("acme"),
                tenant_recent.last().unwrap().rowid as u64,
                5,
                AuditFilters::default(),
            )
        });
        assert_eq!(tenant_recent_page_two.len(), 5);
        assert!(tenant_recent_page_two
            .iter()
            .all(|row| row.tenant == "acme"));

        let event_recent = measure_audit(|| {
            store.audit_recent_filtered(
                None,
                0,
                5,
                AuditFilters {
                    event: Some("rare"),
                    query: None,
                },
            )
        });
        assert_eq!(event_recent.len(), 5);
        assert!(event_recent.iter().all(|row| row.event == "rare"));

        let common_recent = measure_audit(|| {
            store.audit_recent_filtered(
                None,
                0,
                5,
                AuditFilters {
                    event: Some("common"),
                    query: None,
                },
            )
        });
        assert_eq!(common_recent.len(), 5);
        assert!(common_recent.iter().all(|row| row.event == "common"));

        let combined_recent = measure_audit(|| {
            store.audit_recent_filtered(
                Some("acme"),
                0,
                5,
                AuditFilters {
                    event: Some("rare"),
                    query: Some("NEEDLE"),
                },
            )
        });
        assert_eq!(combined_recent.len(), 1);
        assert_eq!(combined_recent[0].subject, "needle");

        let tenant_export = measure_audit(|| {
            store.audit_export_filtered(Some("acme"), 0, 0, 5, AuditFilters::default())
        });
        assert_eq!(
            tenant_export
                .iter()
                .map(|row| row.rowid)
                .collect::<Vec<_>>(),
            [1, 2, 11, 12, 21]
        );
        let tenant_export_page_two = measure_audit(|| {
            store.audit_export_filtered(
                Some("acme"),
                tenant_export.last().unwrap().at,
                tenant_export.last().unwrap().rowid as u64,
                5,
                AuditFilters::default(),
            )
        });
        assert_eq!(
            tenant_export_page_two
                .iter()
                .map(|row| row.rowid)
                .collect::<Vec<_>>(),
            [22, 31, 32, 41, 42]
        );

        let event_export = measure_audit(|| {
            store.audit_export_filtered(
                None,
                0,
                0,
                5,
                AuditFilters {
                    event: Some("rare"),
                    query: None,
                },
            )
        });
        assert_eq!(
            event_export.iter().map(|row| row.rowid).collect::<Vec<_>>(),
            [1, 8, 15, 22, 29]
        );

        let common_export = measure_audit(|| {
            store.audit_export_filtered(
                None,
                0,
                0,
                5,
                AuditFilters {
                    event: Some("common"),
                    query: None,
                },
            )
        });
        assert_eq!(
            common_export
                .iter()
                .map(|row| row.rowid)
                .collect::<Vec<_>>(),
            [2, 3, 4, 5, 6]
        );

        let combined_export = measure_audit(|| {
            store.audit_export_filtered(
                Some("acme"),
                0,
                0,
                5,
                AuditFilters {
                    event: Some("rare"),
                    query: None,
                },
            )
        });
        assert_eq!(
            combined_export
                .iter()
                .map(|row| row.rowid)
                .collect::<Vec<_>>(),
            [1, 22, 71, 92]
        );

        let deep_directory = tempfile::tempdir().unwrap();
        let deep_store = Store::open(deep_directory.path()).unwrap();
        deep_store
            .with(|connection| {
                connection.execute_batch("BEGIN")?;
                for index in 0..1000 {
                    connection.execute(
                        "INSERT INTO audit_log(at,tenant,actor,event,subject)
                         VALUES (?1,?2,'actor',?3,'subject')",
                        rusqlite::params![
                            (index / 4) as i64,
                            if index % 10 < 2 { "acme" } else { "other" },
                            if index % 7 == 0 { "rare" } else { "common" },
                        ],
                    )?;
                }
                connection.execute_batch("COMMIT")
            })
            .unwrap();
        let deep_export = measure_audit(|| {
            deep_store.audit_export_filtered(None, 200, 803, 5, AuditFilters::default())
        });
        assert_eq!(
            deep_export.iter().map(|row| row.rowid).collect::<Vec<_>>(),
            [804, 805, 806, 807, 808]
        );
        assert!(deep_export.iter().all(|row| row.at >= 200));
    }
}

#[cfg(test)]
mod settings_tests {
    use super::tests::{test_link, test_tenant};
    use super::*;

    fn test_config() -> Config {
        Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            push_bind: None,
            push_certificate: None,
            push_private_key: None,
            push_advertise: None,
            serve_bind: None,
            serve_advertise: None,
            data_dir: std::path::PathBuf::from("/nonexistent"),
            receive_dir: std::path::PathBuf::from("/nonexistent"),
            outbound_dir: std::path::PathBuf::from("/nonexistent"),
            web_root: std::path::PathBuf::from("../web"),
            admin_password_hash: "x".to_owned(),
            admin_token_tag: "tag".to_owned(),
            smtp_host: Some("https://env.example/hook".to_owned()),

            smtp_port: 587,
            smtp_starttls: true,
            smtp_username: None,
            smtp_password: None,
            scim_token: None,
            replica_token: None,
            smtp_from: None,

            public_url: None,
            max_upload_bytes: 1024,
            workflow_snapshot_bytes: 4 * 1024 * 1024,
            allow_hidden: false,
            session_idle_secs: 60,
            audit_retention_days: 400,
            upload_retention_days: 0,
            metrics_token: None,
            max_total_sessions: 32,
            max_link_sessions: 8,
            sso_session_secs: 7 * 24 * 3600,
            trusted_proxies: Vec::new(),
            oidc: None,
            default_max_total_bytes: None,
            default_max_links: None,
            default_max_sessions: None,
            public_password_login: true,
            require_provisioning: false,
        }
    }

    fn schema_version(data_dir: &Path) -> String {
        let connection = Connection::open(data_dir.join("votport.db")).unwrap();
        connection
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap()
    }

    #[test]
    fn empty_settings_table_follows_env() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let overlay = store.overlay(&test_config()).unwrap();
        assert_eq!(
            overlay.smtp_host.as_deref(),
            Some("https://env.example/hook")
        );
        assert_eq!(overlay.smtp_host_source, "env");
        assert_eq!(overlay.resolved.audit_retention_days, 400);
        assert_eq!(overlay.audit_retention_days_source, "env");
        assert_eq!(overlay.resolved.upload_retention_days, 0);
        assert!(overlay.resolved.default_max_total_bytes.is_none());
        assert!(overlay.resolved.public_password_login);
    }

    #[test]
    fn written_key_wins_unwritten_keys_keep_env() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .put_settings(
                "local",
                &[(
                    "smtp_host".to_owned(),
                    SettingWrite::Set("https://db.example/hook".to_owned()),
                )],
            )
            .unwrap();
        let overlay = store.overlay(&test_config()).unwrap();
        assert_eq!(
            overlay.smtp_host.as_deref(),
            Some("https://db.example/hook")
        );
        assert_eq!(overlay.smtp_host_source, "db");
        assert_eq!(overlay.resolved.audit_retention_days, 400);
        assert_eq!(overlay.audit_retention_days_source, "env");
    }

    #[test]
    fn empty_string_disables_url_despite_env() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .put_settings(
                "local",
                &[("smtp_host".to_owned(), SettingWrite::Set(String::new()))],
            )
            .unwrap();
        let overlay = store.overlay(&test_config()).unwrap();
        assert_eq!(overlay.smtp_host, None);
        assert_eq!(overlay.smtp_host_source, "db");
    }

    #[test]
    fn reset_deletes_the_row_and_env_applies() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .put_settings(
                "local",
                &[(
                    "smtp_host".to_owned(),
                    SettingWrite::Set("https://db.example/hook".to_owned()),
                )],
            )
            .unwrap();
        store
            .put_settings("local", &[("smtp_host".to_owned(), SettingWrite::Reset)])
            .unwrap();
        let overlay = store.overlay(&test_config()).unwrap();
        assert_eq!(
            overlay.smtp_host.as_deref(),
            Some("https://env.example/hook")
        );
        assert_eq!(overlay.smtp_host_source, "env");
        assert!(store.setting("smtp_host").unwrap().is_none());
    }

    #[test]
    fn invalid_stored_days_skip_to_env() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .put_settings(
                "local",
                &[(
                    "audit_retention_days".to_owned(),
                    SettingWrite::Set("nope".to_owned()),
                )],
            )
            .unwrap();
        let overlay = store.overlay(&test_config()).unwrap();
        assert_eq!(overlay.resolved.audit_retention_days, 400);
        assert_eq!(overlay.audit_retention_days_source, "env");
    }

    #[test]
    fn db_retention_is_what_the_sweeper_would_read() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .put_settings(
                "local",
                &[(
                    "audit_retention_days".to_owned(),
                    SettingWrite::Set("7".to_owned()),
                )],
            )
            .unwrap();
        assert_eq!(
            store
                .resolved_settings(&test_config())
                .unwrap()
                .audit_retention_days,
            7
        );
    }

    #[test]
    fn unsupported_schema_is_refused_without_rewriting_data() {
        let previous = "40".to_owned();
        let future = (SCHEMA_VERSION + 1).to_string();
        for version in [
            None,
            Some("3"),
            Some("31"),
            Some("34"),
            Some(previous.as_str()),
            Some(future.as_str()),
            Some("99"),
            Some("invalid"),
            Some("-1"),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let store = Store::open(directory.path()).unwrap();
            store.insert_link(test_link("preserved")).unwrap();
            drop(store);
            let path = directory.path().join("votport.db");
            let connection = Connection::open(&path).unwrap();
            connection.execute_batch("PRAGMA journal_mode=DELETE; DROP INDEX links_tenant; DROP INDEX links_tenant_created; DROP INDEX delivery_jobs_deadline_pending; DROP INDEX delivery_jobs_retirement_due; DROP INDEX outbound_fetch_tickets_expires; DROP INDEX outbound_grants_open_expires; DROP INDEX audit_log_tenant; DROP INDEX audit_log_event; DROP INDEX audit_log_tenant_at; DROP INDEX audit_log_event_at; DELETE FROM meta WHERE key='schema_version';").unwrap();
            if let Some(version) = version {
                connection
                    .execute(
                        "INSERT INTO meta(key,value) VALUES ('schema_version',?1)",
                        [version],
                    )
                    .unwrap();
            }
            drop(connection);
            let before = std::fs::read(&path).unwrap();
            assert!(
                Store::open(directory.path()).is_err(),
                "version {version:?}"
            );
            assert_eq!(std::fs::read(&path).unwrap(), before, "version {version:?}");
            let connection = Connection::open(&path).unwrap();
            let indexes: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema WHERE type='index' AND name IN (
                        'delivery_jobs_deadline_pending',
                        'delivery_jobs_retirement_due',
                        'outbound_fetch_tickets_expires',
                        'outbound_grants_open_expires',
                        'audit_log_tenant',
                        'audit_log_event',
                        'audit_log_tenant_at',
                        'audit_log_event_at'
                    )",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(indexes, 0, "version {version:?}");
            assert!(!directory.path().join("votport.db-wal").exists());
        }
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("votport.db");
        Connection::open(&path).unwrap().execute_batch("CREATE TABLE sqliteX_private(value TEXT); INSERT INTO sqliteX_private VALUES ('preserve');").unwrap();
        let before = std::fs::read(&path).unwrap();
        assert!(Store::open(directory.path()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(!directory.path().join("receipt.key").exists());
    }

    #[test]
    fn unsupported_storage_layout_is_refused_without_relayout() {
        for layout in [None, Some("old"), Some("")] {
            let directory = tempfile::tempdir().unwrap();
            let data = directory.path().join("data");
            let receive = directory.path().join("receive/acme");
            std::fs::create_dir_all(&receive).unwrap();
            std::fs::write(receive.join("frame.mov"), b"preserved payload").unwrap();
            let store = Store::open(&data).unwrap();
            store.insert_tenant(test_tenant("acme")).unwrap();
            store
                .with(|connection| {
                    connection.execute("DELETE FROM meta WHERE key='tenant_storage_layout'", [])?;
                    if let Some(layout) = layout {
                        connection.execute(
                            "INSERT INTO meta(key,value) VALUES ('tenant_storage_layout',?1)",
                            [layout],
                        )?;
                    }
                    Ok(())
                })
                .unwrap();
            drop(store);
            let path = data.join("votport.db");
            let before = std::fs::read(&path).unwrap();
            let error = Store::open(&data).err().expect("unsupported layout");
            assert!(error.contains("unsupported tenant storage layout"));
            assert_eq!(std::fs::read(&path).unwrap(), before);
            assert_eq!(
                std::fs::read(receive.join("frame.mov")).unwrap(),
                b"preserved payload"
            );
            assert!(!directory.path().join("receive/.vot-tenants.stage").exists());
        }
    }

    #[test]
    fn unsupported_schema_does_not_checkpoint_a_surviving_wal() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .with(|connection| {
                connection.set_db_config(
                    rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
                    true,
                )?;
                connection.execute("UPDATE meta SET value='34' WHERE key='schema_version'", [])?;
                Ok(())
            })
            .unwrap();
        drop(store);
        let database = directory.path().join("votport.db");
        let wal = directory.path().join("votport.db-wal");
        let database_before = std::fs::read(&database).unwrap();
        let wal_before = std::fs::read(&wal).unwrap();
        assert!(!wal_before.is_empty());
        assert!(Store::open(directory.path()).is_err());
        assert_eq!(std::fs::read(&database).unwrap(), database_before);
        assert_eq!(std::fs::read(&wal).unwrap(), wal_before);
    }

    #[test]
    fn state_json_is_preserved_and_refused_before_creating_a_database() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state.json");
        std::fs::write(&state, br#"{"links":[{"id":"preserved"}]}"#).unwrap();
        let before = std::fs::read(&state).unwrap();
        assert!(Store::open(directory.path())
            .err()
            .unwrap()
            .contains("state.json is unsupported"));
        assert_eq!(std::fs::read(&state).unwrap(), before);
        assert!(!directory.path().join("votport.db").exists());
        assert!(!directory.path().join("receipt.key").exists());
    }

    #[test]
    fn open_refuses_a_newer_schema_version() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        drop(store);
        {
            let connection = Connection::open(directory.path().join("votport.db")).unwrap();
            connection
                .execute(
                    "UPDATE meta SET value = '99' WHERE key = 'schema_version'",
                    [],
                )
                .unwrap();
        }
        let error = match Store::open(directory.path()) {
            Err(error) => error,
            Ok(_) => panic!("expected open to refuse a newer schema"),
        };
        assert!(error.contains("99"), "{error}");
        assert!(error.contains("unsupported"), "{error}");
        assert_eq!(schema_version(directory.path()), "99");
    }

    #[test]
    fn open_does_not_stamp_schema_version_down() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        drop(store);
        assert_eq!(schema_version(directory.path()), SCHEMA_VERSION.to_string());
        Store::open(directory.path()).unwrap();
        assert_eq!(schema_version(directory.path()), SCHEMA_VERSION.to_string());
    }

    #[test]
    fn schema43_refusal_preserves_invalid_quota_schema() {
        for damaged in [
            "DROP INDEX files_quota_identity;",
            "DROP TRIGGER tenant_quota_usage_insert;",
        ] {
            let directory = tempfile::tempdir().unwrap();
            drop(Store::open(directory.path()).unwrap());
            let path = directory.path().join("votport.db");
            let connection = Connection::open(&path).unwrap();
            connection
                .execute_batch(
                    "PRAGMA journal_mode=DELETE;
                     DROP TRIGGER audit_log_count_insert;
                     DROP TRIGGER audit_log_count_delete;
                     DROP TABLE audit_log_count;
                     UPDATE meta SET value='43' WHERE key='schema_version';",
                )
                .unwrap();
            connection.execute_batch(damaged).unwrap();
            drop(connection);
            let before = std::fs::read(&path).unwrap();

            assert!(Store::open(directory.path()).is_err(), "{damaged}");
            assert_eq!(schema_version(directory.path()), "43", "{damaged}");
            assert!(
                std::fs::read(&path).unwrap() == before,
                "rejected schema43 database changed: {damaged}"
            );
        }
    }

    #[test]
    fn schema43_upgrade_backfills_and_maintains_audit_count() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.audit("", "", "first", "one", &serde_json::json!({}));
        store.audit("", "", "second", "two", &serde_json::json!({}));
        drop(store);

        let connection = Connection::open(directory.path().join("votport.db")).unwrap();
        connection
            .execute_batch(
                "DROP TRIGGER audit_log_count_insert;
                 DROP TRIGGER audit_log_count_delete;
                 DROP TABLE audit_log_count;
                 UPDATE meta SET value='43' WHERE key='schema_version';",
            )
            .unwrap();
        drop(connection);

        let store = Store::open(directory.path()).unwrap();
        assert_eq!(schema_version(directory.path()), "44");
        assert_eq!(store.audit_count().unwrap(), 2);
        store.audit("", "", "third", "three", &serde_json::json!({}));
        assert_eq!(store.audit_count().unwrap(), 3);
    }

    #[test]
    fn branding_rows_round_trip_and_delete() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        assert!(store.branding("acme").unwrap().is_none());

        let branding = Branding {
            tenant: "acme".to_owned(),
            name: "Acme Corp".to_owned(),
            color: "#0a84ff".to_owned(),
            logo_ext: String::new(),
            updated_at: 42,
            ..Default::default()
        };
        store.set_branding(&branding).unwrap();
        let read = store.branding("acme").unwrap().unwrap();
        assert_eq!(read.name, "Acme Corp");
        assert_eq!(read.color, "#0a84ff");
        assert_eq!(read.logo_ext, "");
        assert_eq!(read.updated_at, 42);

        // Upsert replaces the row; the default tenant ("") is a row like any.
        store
            .set_branding(&Branding {
                logo_ext: "png".to_owned(),
                ..branding.clone()
            })
            .unwrap();
        assert_eq!(store.branding("acme").unwrap().unwrap().logo_ext, "png");
        store
            .set_branding(&Branding {
                tenant: String::new(),
                ..branding
            })
            .unwrap();
        assert_eq!(store.branding("").unwrap().unwrap().name, "Acme Corp");

        assert!(store.delete_branding("acme").unwrap());
        assert!(!store.delete_branding("acme").unwrap());
        assert!(store.branding("acme").unwrap().is_none());
        assert!(store.branding("").unwrap().is_some());
    }

    #[test]
    fn tenant_delete_removes_its_branding_row() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .insert_tenant(Tenant {
                incarnation: String::new(),
                key: "acme".to_owned(),
                label: String::new(),
                admin_group: None,
                max_total_bytes: None,
                max_links: None,
                max_sessions: None,
                created_at: 0,
            })
            .unwrap();
        store
            .set_branding(&Branding {
                tenant: "acme".to_owned(),
                name: "Acme".to_owned(),
                color: String::new(),
                logo_ext: String::new(),
                updated_at: 0,
                ..Default::default()
            })
            .unwrap();
        assert!(matches!(
            store.remove_tenant("acme").unwrap(),
            TenantRemoval::Deleted
        ));
        assert!(store.branding("acme").unwrap().is_none());
    }

    #[test]
    fn upload_sessions_round_trip() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut session = PersistedUploadSession {
            committed_upload_id: None,
            push_key: None,
            id: "abcd1234".to_owned(),
            link_id: "link-1".to_owned(),
            tenant: String::new(),
            dest_dir: PathBuf::from("/received/link-1"),
            dest_rel: String::new(),
            package: ObjectId {
                suite: 1,
                root: [7u8; 32],
                length: 100,
            },
            max_total_bytes: Some(1000),
            started_at: 42,
            files: vec![PersistedUploadFile {
                entry: 0,
                display_path: "a.bin".to_owned(),
                stored_components: vec!["a.bin".to_owned()],
                object: ObjectId {
                    suite: 1,
                    root: [9u8; 32],
                    length: 100,
                },
                staging_path: PathBuf::from("/received/link-1/.vot-1-0-2.stage"),
                journal_path: PathBuf::from("/received/link-1/.vot-1-0-2.journal"),
                incarnation: [3u8; 16],
                profile: vot_sdk_file::CommitProfile::Balanced,
                nas_contract: vot_sdk_file::NasContract::Unqualified,
                prefix_bytes: 0,
                published: false,
                receipt: false,
            }],
        };
        let mut second = session.files[0].clone();
        second.entry = 1;
        second.profile = vot_sdk_file::CommitProfile::Fast;
        second.display_path = "b.bin".to_owned();
        second.stored_components = vec!["b.bin".to_owned()];
        session.files.push(second);
        store.insert_upload_session(&session).unwrap();
        let (received, reserved) = store.tenant_admission_usage("").unwrap();
        assert_eq!(received, 0);
        assert_eq!(reserved.len(), 1);
        assert_eq!(
            (reserved[0].id.as_str(), reserved[0].bytes),
            (session.id.as_str(), 100)
        );
        assert!(store.tenant_admission_usage("other").unwrap().1.is_empty());
        store
            .update_upload_file_progress(
                &session.id,
                [(0, 64 * 1024, true, true), (1, 32, false, false)],
            )
            .unwrap();

        let loaded = store.load_upload_sessions().unwrap();
        assert_eq!(loaded.len(), 1);
        let mut expected = session.clone();
        expected.files[0].prefix_bytes = 64 * 1024;
        expected.files[0].published = true;
        expected.files[0].receipt = true;
        expected.files[1].prefix_bytes = 32;
        assert_eq!(loaded[0], expected);

        // Re-inserting the same id replaces its file rows, no duplication.
        store.insert_upload_session(&session).unwrap();
        assert_eq!(store.load_upload_sessions().unwrap()[0].files.len(), 2);
        store
            .with(|connection| {
                connection.execute_batch(
                    "CREATE TRIGGER fail_second_checkpoint BEFORE UPDATE ON upload_session_files
             WHEN NEW.entry = 1 BEGIN SELECT RAISE(FAIL, 'checkpoint failure'); END;",
                )
            })
            .unwrap();
        assert!(store
            .update_upload_file_progress(&session.id, [(0, 64, true, true), (1, 32, false, false)])
            .is_err());
        assert_eq!(store.load_upload_sessions().unwrap(), vec![session.clone()]);
        store
            .with(|connection| connection.execute_batch("DROP TRIGGER fail_second_checkpoint"))
            .unwrap();

        drop(store);
        let store = Store::open(directory.path()).unwrap();
        assert_eq!(store.load_upload_sessions().unwrap(), vec![session.clone()]);

        store.delete_upload_session(&session.id).unwrap();
        assert!(store.load_upload_sessions().unwrap().is_empty());
    }

    #[test]
    fn smtp_is_none_without_host() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut config = test_config();
        config.smtp_host = None;
        config.smtp_from = Some("votport@example.com".to_owned());

        assert!(store.resolved_settings(&config).unwrap().smtp.is_none());
    }

    #[test]
    fn smtp_is_none_without_from() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut config = test_config();
        config.smtp_host = Some("smtp.example.com".to_owned());
        config.smtp_from = None;
        assert!(store.resolved_settings(&config).unwrap().smtp.is_none());
    }

    #[test]
    fn smtp_assembles_when_host_and_from_resolve() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .put_settings(
                "local",
                &[(
                    "smtp_host".to_owned(),
                    SettingWrite::Set("db.example.com".to_owned()),
                )],
            )
            .unwrap();
        let mut config = test_config();
        config.smtp_from = Some("votport@example.com".to_owned());

        let smtp = store
            .resolved_settings(&config)
            .unwrap()
            .smtp
            .expect("host from DB plus sender from env");
        assert_eq!(smtp.host, "db.example.com");
        assert_eq!(smtp.from, "votport@example.com");

        assert_eq!(smtp.port, 587);
        assert!(smtp.starttls);
        assert!(smtp.password.is_none());
    }

    #[test]
    fn invalid_smtp_port_skips_to_env() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .put_settings(
                "local",
                &[("smtp_port".to_owned(), SettingWrite::Set("nope".to_owned()))],
            )
            .unwrap();
        let overlay = store.overlay(&test_config()).unwrap();
        assert_eq!(overlay.smtp_port, 587);
        assert_eq!(overlay.smtp_port_source, "env");
    }
}

#[cfg(test)]
mod principals_store_tests {
    use super::*;

    #[test]
    fn upsert_revoke_unblock_preserve_version() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let grants = serde_json::json!([{"tenant":"","role":"admin"}]);
        let row = store
            .upsert_sso_principal("user@example.com", &["employees".to_owned()], &grants)
            .unwrap();
        assert_eq!(row.credential_version, 1);
        assert!(!row.blocked);
        assert_eq!(row.last_groups, vec!["employees".to_owned()]);
        assert_eq!(row.source, "sso");
        assert!(store.principal_allows("user@example.com", 1));
        assert!(!store.principal_allows("user@example.com", 2));
        assert!(store.principal_allows("missing", 1));
        assert!(!store.principal_allows("missing", 2));

        store
            .with(|connection| {
                connection.execute(
                    "UPDATE principals SET last_login_at = 123 WHERE subject = ?1",
                    ["user@example.com"],
                )
            })
            .unwrap();

        assert!(store.revoke_principal("user@example.com").unwrap());
        let revoked = store.principal("user@example.com").unwrap().unwrap();
        assert_eq!(revoked.credential_version, 2);
        assert!(revoked.blocked);
        assert_eq!(revoked.last_login_at, 123);
        assert_eq!(revoked.last_groups, vec!["employees".to_owned()]);
        assert_eq!(revoked.last_grants, grants);
        assert!(!store.principal_allows("user@example.com", 1));
        assert!(!store.principal_allows("user@example.com", 2));

        let blocked_upsert = store
            .upsert_sso_principal(
                "user@example.com",
                &["after".to_owned()],
                &serde_json::json!([{"tenant":"after","role":"viewer"}]),
            )
            .unwrap();
        assert_eq!(blocked_upsert.credential_version, 2);
        assert!(blocked_upsert.blocked);
        assert_eq!(blocked_upsert.last_login_at, 123);
        assert_eq!(blocked_upsert.last_groups, vec!["employees".to_owned()]);
        assert_eq!(blocked_upsert.last_grants, grants);

        assert!(store.unblock_principal("user@example.com").unwrap());
        let unblocked = store.principal("user@example.com").unwrap().unwrap();
        assert_eq!(unblocked.credential_version, 2);
        assert!(!unblocked.blocked);
        assert!(store.principal_allows("user@example.com", 2));
        assert!(!store.principal_allows("user@example.com", 1));
        assert!(!store.revoke_principal("missing").unwrap());
        assert!(!store.unblock_principal("missing").unwrap());

        let refreshed = store
            .upsert_sso_principal(
                "user@example.com",
                &["after-unblock".to_owned()],
                &serde_json::json!([{"tenant":"after-unblock","role":"editor"}]),
            )
            .unwrap();
        assert_eq!(refreshed.credential_version, unblocked.credential_version);
        assert!(!refreshed.blocked);
        assert!(refreshed.last_login_at > 123);
        assert_eq!(refreshed.last_groups, vec!["after-unblock".to_owned()]);
        assert_eq!(
            refreshed.last_grants,
            serde_json::json!([{"tenant":"after-unblock","role":"editor"}])
        );
        assert_eq!(refreshed.source, unblocked.source);
        assert_eq!(refreshed.external_id, unblocked.external_id);
        assert_eq!(refreshed.created_at, unblocked.created_at);

        store
            .with(|connection| {
                connection.execute(
                    "UPDATE principals SET last_groups = 'broken' WHERE subject = ?1",
                    ["user@example.com"],
                )
            })
            .unwrap();
        assert!(store.principal("user@example.com").is_err());
        assert!(!store.principal_allows("user@example.com", 2));
        store
            .with(|connection| {
                connection.execute(
                    "UPDATE principals SET last_groups = '[]', last_grants = 'broken'
                     WHERE subject = ?1",
                    ["user@example.com"],
                )
            })
            .unwrap();
        assert!(store.principal("user@example.com").is_err());
        assert!(!store.principal_allows("user@example.com", 2));
    }

    #[test]
    fn principals_page_searches_literally_and_orders_stably() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        for subject in ["Alice%literal", "alice_literal", "aliceXliteral"] {
            store
                .upsert_sso_principal(subject, &[], &serde_json::json!([]))
                .unwrap();
        }
        store
            .with(|connection| connection.execute("UPDATE principals SET last_login_at = 0", []))
            .unwrap();

        let (page, total) = store.principals_page(2, 0, Some("%literal")).unwrap();
        assert_eq!(total, 1);
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].subject, "Alice%literal");

        let (page, total) = store.principals_page(2, 0, Some("_literal")).unwrap();
        assert_eq!(total, 1);
        assert_eq!(page[0].subject, "alice_literal");

        let (page, total) = store.principals_page(2, 0, Some("ALICEXLITERAL")).unwrap();
        assert_eq!(total, 1);
        assert_eq!(page[0].subject, "aliceXliteral");

        let (page, total) = store.principals_page(2, 0, None).unwrap();
        assert_eq!(total, 3);
        assert_eq!(
            page.iter()
                .map(|item| item.subject.as_str())
                .collect::<Vec<_>>(),
            ["Alice%literal", "aliceXliteral"]
        );
        let (page, total) = store.principals_page(2, 2, None).unwrap();
        assert_eq!(total, 3);
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].subject, "alice_literal");
    }
}
