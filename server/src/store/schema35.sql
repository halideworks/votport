-- Source contract: fad80c95bd18272f59a2605f96fb6f0c22fb421c (schema35). Used only by the explicit offline converter.

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    updated_by TEXT NOT NULL DEFAULT ''
);

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
CREATE INDEX IF NOT EXISTS principals_external_id ON principals (external_id);
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

CREATE TABLE IF NOT EXISTS files (
    link_id TEXT NOT NULL,
    tenant TEXT NOT NULL DEFAULT '',
    upload_index INTEGER NOT NULL,
    file_index INTEGER NOT NULL,
    bytes_hi INTEGER NOT NULL,
    bytes_lo INTEGER NOT NULL,
    deleted INTEGER NOT NULL DEFAULT 0,
    stored_as TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (link_id, upload_index, file_index)
);
CREATE INDEX IF NOT EXISTS files_tenant_live ON files(tenant, deleted, bytes_hi, bytes_lo);

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
    notifications_json TEXT
);
CREATE INDEX IF NOT EXISTS outbound_grants_tenant_created ON outbound_grants(tenant, created_at);
CREATE INDEX IF NOT EXISTS outbound_grants_file
    ON outbound_grants(tenant, link_id, upload_id, file_index);

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
    permissions TEXT NOT NULL DEFAULT '["deliveries:create"]'
);
CREATE INDEX IF NOT EXISTS automation_tokens_tenant_created
    ON automation_tokens(tenant, created_at);

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
    push_key TEXT
);
CREATE UNIQUE INDEX upload_sessions_push_key ON upload_sessions(push_key) WHERE push_key IS NOT NULL;
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
    uploads_json TEXT NOT NULL DEFAULT '[]',
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

CREATE TABLE IF NOT EXISTS delivery_manifests (
    grant_id TEXT PRIMARY KEY,
    digest TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS delivery_evidence (
    id TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL,
    holder TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('verified', 'accepted')),
    received_at INTEGER NOT NULL,
    document TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS delivery_evidence_grant ON delivery_evidence(grant_id, received_at);
CREATE TABLE IF NOT EXISTS delivery_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    payload TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    hash TEXT NOT NULL,
    issuer TEXT NOT NULL,
    signature TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS delivery_events_tenant ON delivery_events(tenant, id);

CREATE TABLE IF NOT EXISTS delivery_policy_cache(grant_id TEXT PRIMARY KEY,protected INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS delivery_storage(id TEXT PRIMARY KEY,revision INTEGER NOT NULL,document TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS delivery_projects(tenant TEXT NOT NULL, id TEXT NOT NULL, revision INTEGER NOT NULL, document TEXT NOT NULL, PRIMARY KEY(tenant,id));
CREATE TABLE IF NOT EXISTS delivery_jobs(id TEXT PRIMARY KEY, tenant TEXT NOT NULL, actor TEXT NOT NULL, operation_id TEXT NOT NULL, project_id TEXT NOT NULL, state TEXT NOT NULL, owner TEXT NOT NULL DEFAULT '', not_before INTEGER NOT NULL, deadline INTEGER, escalated INTEGER NOT NULL DEFAULT 0, document TEXT NOT NULL, UNIQUE(tenant,actor,operation_id));
CREATE INDEX IF NOT EXISTS delivery_jobs_ready ON delivery_jobs(state,not_before);
CREATE INDEX IF NOT EXISTS delivery_jobs_tenant ON delivery_jobs(tenant,id);

CREATE TABLE IF NOT EXISTS delivery_webhooks(tenant TEXT PRIMARY KEY,url TEXT NOT NULL,secret TEXT NOT NULL,revision INTEGER NOT NULL,enabled INTEGER NOT NULL,cursor INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS delivery_webhook_attempts(id INTEGER PRIMARY KEY AUTOINCREMENT,tenant TEXT NOT NULL,event_id INTEGER NOT NULL,revision INTEGER NOT NULL,status TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,next_try INTEGER NOT NULL,error TEXT,UNIQUE(tenant,event_id,revision));
CREATE INDEX IF NOT EXISTS delivery_webhook_due ON delivery_webhook_attempts(status,next_try);

CREATE TABLE IF NOT EXISTS inbound_routes(id TEXT PRIMARY KEY, tenant TEXT NOT NULL, link_id TEXT NOT NULL, issuer TEXT NOT NULL, operation_id TEXT NOT NULL, source TEXT NOT NULL, ancestry TEXT NOT NULL, session_id TEXT UNIQUE, transport TEXT, upload_id TEXT UNIQUE, receipt TEXT, revoked_at INTEGER, created_at INTEGER NOT NULL, UNIQUE(link_id,issuer,operation_id));
CREATE TABLE IF NOT EXISTS outbound_routes(job_id TEXT NOT NULL, destination_id TEXT NOT NULL, origin TEXT NOT NULL, route_id TEXT NOT NULL, peer_key TEXT NOT NULL, source TEXT NOT NULL, next_attempt INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0, revocation TEXT, ack TEXT, PRIMARY KEY(job_id,destination_id));
CREATE TABLE IF NOT EXISTS route_uploads(route_id TEXT NOT NULL, upload_id TEXT PRIMARY KEY, partial INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS inbound_routes_link ON inbound_routes(tenant,link_id);

CREATE TABLE IF NOT EXISTS notification_destinations (
    id TEXT PRIMARY KEY, tenant TEXT NOT NULL, document TEXT NOT NULL,
    last_at INTEGER, last_delivered INTEGER
);
CREATE INDEX IF NOT EXISTS notification_destinations_tenant ON notification_destinations(tenant);
CREATE TABLE IF NOT EXISTS notification_defaults (tenant TEXT PRIMARY KEY, document TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS notification_job_overrides (job_id TEXT PRIMARY KEY REFERENCES delivery_jobs(id) ON DELETE CASCADE, document TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS trade_endpoints(id TEXT PRIMARY KEY REFERENCES links(id) ON DELETE CASCADE,tenant TEXT NOT NULL,document TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS trade_invitations(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,endpoint TEXT NOT NULL REFERENCES trade_endpoints(id) ON DELETE CASCADE,secret_hash TEXT NOT NULL,expected_key TEXT NOT NULL,expires_at INTEGER NOT NULL,redeemed TEXT);
CREATE TABLE IF NOT EXISTS trade_routes(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,direction TEXT NOT NULL,peer_key TEXT NOT NULL,endpoint TEXT NOT NULL,document TEXT NOT NULL,credential TEXT NOT NULL,enrollment TEXT);
CREATE TABLE IF NOT EXISTS trade_rotations(route_id TEXT PRIMARY KEY,credential TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS trade_delivery_policies(route_id TEXT PRIMARY KEY,document TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS trade_routes_tenant ON trade_routes(tenant,direction);
CREATE INDEX IF NOT EXISTS trade_routes_endpoint ON trade_routes(endpoint,peer_key);
CREATE INDEX delivery_jobs_received ON delivery_jobs(tenant,json_extract(document,'$.received.link_id')) WHERE json_extract(document,'$.received') IS NOT NULL;
INSERT INTO meta(key,value) VALUES ('schema_version','35'),('tenant_storage_layout','reserved-v1');
