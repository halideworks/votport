use super::*;
use crate::api::outbound::workflows::storage::Storage;
use crate::workflow::{Job, JobRequest, Project};
use rusqlite::params;

pub(super) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS delivery_policy_cache(grant_id TEXT PRIMARY KEY,protected INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS delivery_storage(id TEXT PRIMARY KEY,revision INTEGER NOT NULL,document TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS delivery_projects(tenant TEXT NOT NULL, id TEXT NOT NULL, revision INTEGER NOT NULL, document TEXT NOT NULL, PRIMARY KEY(tenant,id));
CREATE TABLE IF NOT EXISTS delivery_jobs(id TEXT PRIMARY KEY, tenant TEXT NOT NULL, actor TEXT NOT NULL, operation_id TEXT NOT NULL, project_id TEXT NOT NULL, state TEXT NOT NULL, owner TEXT NOT NULL DEFAULT '', not_before INTEGER NOT NULL, deadline INTEGER, escalated INTEGER NOT NULL DEFAULT 0, token TEXT NOT NULL, document TEXT NOT NULL, UNIQUE(tenant,actor,operation_id));
";

pub(super) const INDEXES: &str = "
CREATE INDEX IF NOT EXISTS delivery_jobs_ready ON delivery_jobs(state,not_before);
CREATE INDEX IF NOT EXISTS delivery_jobs_tenant ON delivery_jobs(tenant,id);
CREATE INDEX IF NOT EXISTS delivery_jobs_deadline_pending ON delivery_jobs(deadline) WHERE deadline IS NOT NULL AND escalated=0;
CREATE INDEX IF NOT EXISTS delivery_jobs_retirement_due ON delivery_jobs(COALESCE(json_extract(document,'$.checks.retirement_attempt_at'),0),id) WHERE state IN ('retiring','failed','cancelled','ready','awaiting_approval');
";

#[derive(Debug, PartialEq, Eq)]
pub enum WorkflowMutationError {
    Invalid(String),
    Conflict(String),
    OperationConflict(String),
    Store(String),
}

impl WorkflowMutationError {
    pub(super) fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }

    pub(super) fn conflict(message: impl Into<String>) -> Self {
        Self::Conflict(message.into())
    }

    pub(super) fn operation_conflict(message: impl Into<String>) -> Self {
        Self::OperationConflict(message.into())
    }

    pub(super) fn store(message: impl Into<String>) -> Self {
        Self::Store(message.into())
    }

    #[cfg(test)]
    pub(crate) fn contains(&self, needle: &str) -> bool {
        self.message().contains(needle)
    }

    #[cfg(test)]
    fn message(&self) -> &str {
        match self {
            Self::Invalid(message)
            | Self::Conflict(message)
            | Self::OperationConflict(message)
            | Self::Store(message) => message,
        }
    }
}

#[cfg(test)]
impl PartialEq<&str> for WorkflowMutationError {
    fn eq(&self, other: &&str) -> bool {
        self.message() == *other
    }
}

impl From<String> for WorkflowMutationError {
    fn from(message: String) -> Self {
        Self::Store(message)
    }
}

impl From<WorkflowMutationError> for String {
    fn from(error: WorkflowMutationError) -> Self {
        match error {
            WorkflowMutationError::Invalid(message)
            | WorkflowMutationError::Conflict(message)
            | WorkflowMutationError::OperationConflict(message)
            | WorkflowMutationError::Store(message) => message,
        }
    }
}

pub(super) fn ensure_tenant(
    connection: &Connection,
    tenant: &str,
) -> Result<(), WorkflowMutationError> {
    let exists: bool = connection
        .query_row(
            "SELECT ?1='' OR EXISTS(SELECT 1 FROM tenants WHERE key=?1)",
            [tenant],
            |row| row.get(0),
        )
        .map_err(|e| WorkflowMutationError::store(e.to_string()))?;
    if exists {
        Ok(())
    } else {
        Err(WorkflowMutationError::conflict("tenant missing"))
    }
}

fn decode<T: serde::de::DeserializeOwned>(text: String) -> rusqlite::Result<T> {
    serde_json::from_str(&text).map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
}

fn project_in(
    connection: &Connection,
    tenant: &str,
    id: &str,
) -> rusqlite::Result<Option<Project>> {
    connection
        .prepare_cached("SELECT document FROM delivery_projects WHERE tenant=?1 AND id=?2")?
        .query_row(params![tenant, id], |row| decode(row.get(0)?))
        .optional()
}

fn job_in(connection: &Connection, id: &str) -> rusqlite::Result<Option<Job>> {
    connection
        .prepare_cached("SELECT document FROM delivery_jobs WHERE id=?1")?
        .query_row([id], |row| decode(row.get(0)?))
        .optional()
}

fn save_job(connection: &Connection, job: &Job) -> rusqlite::Result<()> {
    connection.execute(
        "UPDATE delivery_jobs SET state=?2,document=?3 WHERE id=?1",
        params![
            job.id,
            job.state,
            serde_json::to_string(job).expect("job serializes")
        ],
    )?;
    Ok(())
}

pub(super) fn finish_job(
    connection: &Connection,
    signer: &crate::receipt::ReceiptSigner,
    job: &Job,
    grant: &OutboundGrant,
    manifest: &str,
) -> Result<(), String> {
    let mut current = job_in(connection, &job.id)
        .map_err(|e| e.to_string())?
        .ok_or("job missing")?;
    if current.state != "preparing"
        || current.attempts != job.attempts
        || current.project != job.project
    {
        return Err("job changed during preparation".into());
    }
    let project = project_in(connection, &job.tenant, &job.project.id)
        .map_err(|e| e.to_string())?
        .ok_or("project removed")?;
    if project.revision != job.project.revision {
        return Err("project policy changed; submit a new job".into());
    }
    actor_active(connection, job)?;
    check_job_storage(connection, job)?;
    current.manifest = Some(manifest.into());
    current.updated_at = now_unix();
    current.state = if project.require_approval {
        "awaiting_approval"
    } else if !project.destinations.is_empty() {
        "exporting"
    } else {
        "ready"
    }
    .into();
    current.checks = job.checks.clone();
    if !project.require_approval && project.release == crate::workflow::Release::Local {
        current.checks["released_at"] = serde_json::json!(current.updated_at);
    }
    if current.state == "exporting" {
        connection
            .execute("UPDATE delivery_jobs SET owner='' WHERE id=?1", [&job.id])
            .map_err(|e| e.to_string())?;
    }
    save_job(connection, &current).map_err(|e| e.to_string())?;
    evidence::delivery_event(connection, signer, &grant.tenant, &grant.id, &format!("delivery_{}", current.state), &serde_json::json!({"manifest": manifest, "project_id": project.id, "policy_revision": project.revision}), current.updated_at).map_err(|e| e.to_string())
}

fn principal_active(
    connection: &Connection,
    actor: &str,
    credential_version: u64,
) -> rusqlite::Result<bool> {
    connection.query_row("SELECT COALESCE((SELECT blocked=0 AND credential_version=?2 FROM principals WHERE subject=?1), ?2=1)", params![actor,credential_version as i64], |row| row.get(0))
}

fn actor_active(connection: &Connection, job: &Job) -> Result<(), WorkflowMutationError> {
    if let Some(received) = &job.received {
        if !job.project.receive {
            return Err(WorkflowMutationError::conflict(
                "project no longer accepts incoming workflows",
            ));
        }
        if job.actor == format!("reception:{}", received.link_id)
            && job.credential_version == 0
            && job.automation_token_id.is_none()
        {
            return Ok(());
        }
    }
    let active: bool = if let Some(token_id) = &job.automation_token_id {
        connection.query_row("SELECT EXISTS(SELECT 1 FROM automation_tokens WHERE id=?1 AND tenant=?2 AND revoked_at IS NULL AND expires_at>?3 AND EXISTS(SELECT 1 FROM json_each(permissions) WHERE value='jobs:create') AND (directory IS NULL OR directory=?4 OR substr(?4,1,length(directory)+1)=directory||'/'))", params![token_id,job.tenant,now_unix() as i64,job.project.directory], |row| row.get(0))
    } else {
        principal_active(connection, &job.actor, job.credential_version)
    }
    .map_err(|e| WorkflowMutationError::store(e.to_string()))?;
    if active {
        Ok(())
    } else {
        Err(WorkflowMutationError::conflict(
            "submitting identity is no longer authorized",
        ))
    }
}

pub(super) fn check_grant_creation(
    connection: &Connection,
    grant: &OutboundGrant,
    job: Option<&Job>,
) -> Result<(), String> {
    super::routes::require_shareable(connection, &grant.upload_id)?;
    if !grant.link_id.is_empty()
        && received_requires_workflow(connection, &grant.tenant, &grant.link_id, &grant.upload_id)?
    {
        return Err("these incoming files require their project delivery link".into());
    }
    let mut query = connection
        .prepare("SELECT document FROM delivery_projects WHERE tenant=?1")
        .map_err(|e| e.to_string())?;
    let projects = query
        .query_map([&grant.tenant], |row| decode::<Project>(row.get(0)?))
        .map_err(|e| e.to_string())?;
    for project in projects {
        let project = project.map_err(|e| e.to_string())?;
        if grant
            .files
            .iter()
            .any(|file| crate::workflow::within(&project.directory, &file.source))
            && job.is_none_or(|job| job.project.id != project.id)
        {
            return Err("this directory requires a delivery workflow".into());
        }
    }
    if grant
        .files
        .iter()
        .any(|file| file.source.starts_with("received:"))
        && job.is_none_or(|job| job.received.is_none())
    {
        return Err("received sources require their owning workflow".into());
    }
    if let Some(job) = job {
        let received = job
            .received
            .as_ref()
            .map(|received| {
                let upload = read_upload(
                    connection,
                    &job.tenant,
                    &received.link_id,
                    &received.upload_id,
                )
                .map_err(|e| e.to_string())?
                .filter(|upload| !upload.partial && upload.completed_at != 0)
                .ok_or("incoming upload missing")?;
                Ok::<_, String>(
                    upload
                        .files
                        .into_iter()
                        .filter(|file| !file.deleted)
                        .map(|file| (file.path.clone(), file))
                        .collect::<std::collections::BTreeMap<_, _>>(),
                )
            })
            .transpose()?;
        if job.tenant != grant.tenant
            || job.id != grant.id
            || grant.files.is_empty()
            || grant.files.iter().any(|file| {
                file.source
                    != if let Some(received) = &received {
                        received
                            .get(&file.name)
                            .filter(|original| original.bytes == file.bytes)
                            .map(|original| format!("received:{}", original.stored_as))
                            .unwrap_or_default()
                    } else if job.uses_snapshot() {
                        format!("workflow:{}/{}", job.id, file.name)
                    } else {
                        format!("{}/{}", job.project.directory, file.name)
                    }
            })
        {
            return Err("delivery does not match its workflow".into());
        }
    }
    Ok(())
}

fn received_requires_workflow(
    connection: &Connection,
    tenant: &str,
    link: &str,
    upload: &str,
) -> Result<bool, String> {
    connection.prepare_cached("SELECT EXISTS(SELECT 1 FROM receive_workflow_uploads r JOIN links l ON l.id=r.link_id WHERE l.tenant=?1 AND r.link_id=?2 AND r.upload_id=?3)").and_then(|mut statement|statement.query_row(params![tenant,link,upload], |row|row.get(0))).map_err(|e|e.to_string())
}

pub(super) fn receive_pending(
    connection: &Connection,
    tenant: &str,
    link_id: &str,
) -> rusqlite::Result<bool> {
    connection.prepare_cached("SELECT EXISTS(SELECT 1 FROM delivery_jobs WHERE tenant=?1 AND json_extract(document,'$.received.link_id')=?2 AND json_extract(document,'$.received') IS NOT NULL AND state NOT IN ('retired','suspended'))")?.query_row(params![tenant,link_id], |row|row.get(0))
}

pub(super) fn set_receive_workflow(
    connection: &Connection,
    tenant: &str,
    link_id: &str,
    workflow: &crate::workflow::ReceiveWorkflow,
) -> Result<(), String> {
    let exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM links WHERE tenant=?1 AND id=?2)",
            params![tenant, link_id],
            |row| row.get(0),
        )
        .map_err(|e| e.to_string())?;
    if !exists {
        return Err("receive request missing".into());
    }
    if workflow.project_id.is_empty() {
        connection
            .execute("DELETE FROM receive_workflows WHERE link_id=?1", [link_id])
            .map_err(|e| e.to_string())?;
        return Ok(());
    }
    let project = project_in(connection, tenant, &workflow.project_id)
        .map_err(|e| e.to_string())?
        .ok_or("project missing")?;
    if !project.receive {
        return Err("enable incoming files on this project first".into());
    }
    project.validate_job(&workflow.request("validate", "Incoming files"), now_unix())?;
    connection.execute("INSERT INTO receive_workflows(link_id,document) VALUES (?1,?2) ON CONFLICT(link_id) DO UPDATE SET document=excluded.document",params![link_id,serde_json::to_string(workflow).map_err(|e| e.to_string())?]).map_err(|e| e.to_string())?;
    Ok(())
}

fn receive_workflow_in(
    connection: &Connection,
    tenant: &str,
    link_id: &str,
) -> rusqlite::Result<Option<crate::workflow::ReceiveWorkflow>> {
    connection.prepare_cached("SELECT r.document FROM receive_workflows r JOIN links l ON l.id=r.link_id WHERE l.tenant=?1 AND l.id=?2")?
        .query_row(params![tenant,link_id], |row| decode(row.get(0)?)).optional()
}

pub(super) fn queue_received(
    connection: &Connection,
    signer: &crate::receipt::ReceiptSigner,
    tenant: &str,
    link_id: &str,
    upload: &UploadRecord,
) -> Result<(), String> {
    let workflow = receive_workflow_in(connection, tenant, link_id).map_err(|e| e.to_string())?;
    let Some(workflow) = workflow else {
        return Ok(());
    };
    connection
        .execute(
            "INSERT OR IGNORE INTO receive_workflow_uploads(link_id,upload_id) VALUES (?1,?2)",
            params![link_id, upload.id],
        )
        .map_err(|e| e.to_string())?;
    connection.execute("INSERT OR REPLACE INTO delivery_policy_cache(grant_id,protected) SELECT id,1 FROM outbound_grants WHERE tenant=?1 AND link_id=?2 AND upload_id=?3",params![tenant,link_id,upload.id]).map_err(|e|e.to_string())?;
    if upload.partial {
        return Ok(());
    }
    let project = project_in(connection, tenant, &workflow.project_id)
        .map_err(|e| e.to_string())?
        .ok_or("receive project missing")?;
    let actor = format!("reception:{link_id}");
    let exists: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM delivery_jobs WHERE tenant=?1 AND actor=?2 AND operation_id=?3)",params![tenant,actor,upload.id],|row| row.get(0)).map_err(|e| e.to_string())?;
    if exists {
        return Ok(());
    }
    let now = now_unix();
    let label = format!("{} · received", project.label);
    let request = workflow.request(&upload.id, &label[..label.floor_char_boundary(200)]);
    let mut error = project.validate_job(&request, now).err();
    if !project.receive {
        error = Some("project no longer accepts incoming workflows".into());
    }
    let count: i64 = connection.query_row("SELECT COUNT(*) FROM delivery_jobs WHERE tenant=?1 AND state IN ('queued','preparing','awaiting_approval','exporting','retrying')",[tenant],|row|row.get(0)).map_err(|e|e.to_string())?;
    if count >= 1000 {
        error = Some("active job limit reached; retry after other jobs finish".into());
    }
    let checks = trade::snapshot(connection, tenant, &project)?;
    let job = Job {
        id: crate::auth::random_token(),
        tenant: tenant.into(),
        token_generation: 0,
        actor,
        credential_version: 0,
        automation_token_id: None,
        request,
        project,
        state: if error.is_some() { "failed" } else { "queued" }.into(),
        manifest: None,
        approved_by: None,
        attempts: 0,
        created_at: now,
        updated_at: now,
        error,
        checks,
        received: Some(crate::workflow::Received {
            link_id: link_id.into(),
            upload_id: upload.id.clone(),
        }),
        reprocessed_from: None,
        reprocessed_as: None,
    };
    connection.execute("INSERT INTO delivery_jobs(id,tenant,actor,operation_id,project_id,state,not_before,document,token) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",params![job.id,tenant,job.actor,job.request.operation_id,job.project.id,job.state,now as i64,serde_json::to_string(&job).map_err(|e| e.to_string())?,crate::auth::random_token()]).map_err(|e| e.to_string())?;
    evidence::delivery_event(connection,signer,tenant,&job.id,"reception_queued",&serde_json::json!({"project_id":job.project.id,"link_id":link_id,"upload_id":upload.id,"state":job.state,"error":job.error}),now).map_err(|e|e.to_string())
}

impl Store {
    pub fn receive_workflow(
        &self,
        tenant: &str,
        link_id: &str,
    ) -> Result<Option<crate::workflow::ReceiveWorkflow>, String> {
        self.with(|connection| receive_workflow_in(connection, tenant, link_id))
    }

    pub fn set_receive_workflow(
        &self,
        tenant: &str,
        link_id: &str,
        workflow: &crate::workflow::ReceiveWorkflow,
    ) -> Result<(), String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let tx = connection.transaction().map_err(|e| e.to_string())?;
        set_receive_workflow(&tx, tenant, link_id, workflow)?;
        tx.commit().map_err(|e| e.to_string())
    }

    pub fn receive_workflow_pending(&self, tenant: &str, link_id: &str) -> Result<bool, String> {
        self.with(|connection| receive_pending(connection, tenant, link_id))
    }

    pub fn reserve_delivery_snapshot(
        &self,
        id: &str,
        attempt: u64,
        bytes: u64,
        limit: u64,
    ) -> Result<(), String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let tx = connection.transaction().map_err(|e| e.to_string())?;
        let mut job = job_in(&tx, id)
            .map_err(|e| e.to_string())?
            .ok_or("job missing")?;
        if job.state != "preparing" || job.attempts != attempt {
            return Err("job changed during snapshot".into());
        }
        let reserved: i64 = tx.query_row("SELECT COALESCE(SUM(CAST(json_extract(document,'$.checks.snapshot_bytes') AS INTEGER)),0) FROM delivery_jobs WHERE id<>?1",[id],|row| row.get(0)).map_err(|e| e.to_string())?;
        if (reserved as u64)
            .checked_add(bytes)
            .is_none_or(|total| total > limit.min(i64::MAX as u64))
        {
            return Err("delivery snapshot storage budget exhausted; wait for retention cleanup or increase VOTPORT_WORKFLOW_SNAPSHOT_BYTES".into());
        }
        job.checks["snapshot_bytes"] = serde_json::json!(bytes);
        save_job(&tx, &job).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())
    }

    pub fn claim_snapshot_retirement(&self, now: u64) -> Result<Option<Job>, String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let tx = connection.transaction().map_err(|e| e.to_string())?;
        let cutoff = now.saturating_sub(7 * 86400);
        // ponytail: the partial index bounds this ordered scan to live
        // candidates; split the eligibility OR only if measured rows need it.
        let job: Option<Job> = tx.query_row("SELECT j.document FROM delivery_jobs j INDEXED BY delivery_jobs_retirement_due LEFT JOIN outbound_grants g ON g.id=j.id WHERE j.state IN ('retiring','failed','cancelled','ready','awaiting_approval') AND (j.state='retiring' OR (j.state IN ('failed','cancelled') AND CAST(json_extract(j.document,'$.updated_at') AS INTEGER)<=?1 AND (json_extract(j.document,'$.checks.released_at') IS NULL OR g.expires_at<=?1 OR g.revoked_at<=?1)) OR (j.state IN ('ready','awaiting_approval') AND (g.expires_at<=?1 OR g.revoked_at<=?1))) ORDER BY COALESCE(json_extract(j.document,'$.checks.retirement_attempt_at'),0),j.id LIMIT 1",[cutoff as i64],|row| decode(row.get(0)?)).optional().map_err(|e| e.to_string())?;
        let Some(mut job) = job else {
            return Ok(None);
        };
        if job.state != "retiring" {
            job.checks["retired_from"] = serde_json::json!(job.state);
        }
        job.state = "retiring".into();
        job.checks["retirement_attempt_at"] = serde_json::json!(now);
        save_job(&tx, &job).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(Some(job))
    }

    pub fn complete_snapshot_retirement(&self, id: &str, now: u64) -> Result<(), String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let tx = connection.transaction().map_err(|e| e.to_string())?;
        let Some(mut job) = job_in(&tx, id).map_err(|e| e.to_string())? else {
            return Ok(());
        };
        if job.state != "retiring" {
            return Err("job is not retiring".into());
        }
        job.state = "retired".into();
        job.updated_at = now;
        job.checks["snapshot_bytes"] = serde_json::json!(0);
        job.checks["snapshot_purged_at"] = serde_json::json!(now);
        save_job(&tx, &job).map_err(|e| e.to_string())?;
        evidence::delivery_event(
            &tx,
            &self.event_signer,
            &job.tenant,
            id,
            "delivery_retired",
            &serde_json::json!({"manifest": job.manifest,"project_id": job.project.id}),
            now,
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())
    }

    pub fn delivery_storages(
        &self,
    ) -> Result<Vec<crate::api::outbound::workflows::storage::Storage>, String> {
        self.with(|connection| {
            let mut query =
                connection.prepare("SELECT document FROM delivery_storage ORDER BY id")?;
            let rows = query.query_map([], |row| decode(row.get(0)?))?;
            rows.collect()
        })
    }

    pub fn save_delivery_storage(
        &self,
        actor: &str,
        mut storage: crate::api::outbound::workflows::storage::Storage,
        credentials: Option<crate::api::outbound::workflows::storage::Credentials>,
    ) -> Result<crate::api::outbound::workflows::storage::Storage, String> {
        storage.validate()?;
        if let Some(credentials) = &credentials {
            credentials.validate()?;
        }
        let mut connection = self.connection.lock().expect("store poisoned");
        let tx = connection.transaction().map_err(|e| e.to_string())?;
        let paired: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM trade_routes WHERE id=?1)",
                [&storage.id],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        if paired
            || matches!(
                credentials,
                Some(crate::api::outbound::workflows::storage::Credentials::TradeRoute { .. })
            )
        {
            return Err("manage paired connections in Trade routes".into());
        }
        for tenant in &storage.tenants {
            ensure_tenant(&tx, tenant)?;
        }
        let previous: Option<crate::api::outbound::workflows::storage::Storage> = tx
            .query_row(
                "SELECT document FROM delivery_storage WHERE id=?1",
                [&storage.id],
                |row| decode(row.get(0)?),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        if previous.as_ref().map_or(0, |value| value.revision) != storage.revision {
            return Err("storage changed; reload before saving".into());
        }
        if previous
            .as_ref()
            .is_some_and(|value| value.kind != storage.kind)
        {
            return Err("create a new connection to change its storage type".into());
        }
        use crate::api::outbound::workflows::storage::{Credentials, StorageKind};
        match (&storage.kind, &credentials) {
            (StorageKind::S3, Some(Credentials::Votport { .. }))
            | (
                StorageKind::Folder,
                Some(Credentials::AccessKey { .. } | Credentials::Votport { .. }),
            )
            | (StorageKind::Votport, Some(Credentials::Server | Credentials::AccessKey { .. })) => {
                return Err("credentials do not match the connection type".into());
            }
            (StorageKind::Votport, Some(Credentials::Votport { request_url, .. })) => {
                let (origin, _) =
                    crate::api::outbound::workflows::storage::receive_url(request_url)?;
                if origin != storage.endpoint.trim_end_matches('/') {
                    return Err("receive link does not belong to this Votport origin".into());
                }
            }
            (StorageKind::Votport, None) if previous.is_none() => {
                return Err("a Votport connection requires a receive link".into());
            }
            (StorageKind::Votport, None)
                if previous
                    .as_ref()
                    .is_some_and(|value| value.endpoint != storage.endpoint) =>
            {
                return Err("paste a receive link to change the destination port".into());
            }
            _ => {}
        }
        let count: i64 = tx
            .query_row("SELECT COUNT(*) FROM delivery_storage", [], |row| {
                row.get(0)
            })
            .map_err(|e| e.to_string())?;
        if previous.is_none() && count >= 100 {
            return Err("storage connection limit reached".into());
        }
        storage.revision += 1;
        tx.execute("INSERT INTO delivery_storage(id,revision,document) VALUES (?1,?2,?3) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,document=excluded.document",params![storage.id,storage.revision as i64,serde_json::to_string(&storage).expect("storage serializes")]).map_err(|e| e.to_string())?;
        if let Some(credentials) = credentials {
            match credentials {
                Credentials::Server => {
                    tx.execute(
                        "DELETE FROM delivery_storage_credentials WHERE id=?1",
                        [&storage.id],
                    )
                    .map_err(|e| e.to_string())?;
                }
                Credentials::AccessKey { .. }
                | Credentials::Votport { .. }
                | Credentials::TradeRoute { .. } => {
                    tx.execute("INSERT INTO delivery_storage_credentials(id,document) VALUES (?1,?2) ON CONFLICT(id) DO UPDATE SET document=excluded.document", params![storage.id, serde_json::to_string(&credentials).map_err(|e| e.to_string())?]).map_err(|e| e.to_string())?;
                }
            }
        }
        evidence::delivery_event(&tx,&self.event_signer,"","","storage_changed",&serde_json::json!({"actor": actor,"storage_id": storage.id,"revision": storage.revision}),now_unix()).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(storage)
    }

    pub fn delivery_storage_has_credentials(&self, id: &str) -> Result<bool, String> {
        self.with(|connection| {
            connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM delivery_storage_credentials WHERE id=?1)",
                [id],
                |row| row.get(0),
            )
        })
    }

    pub fn delivery_storage_credentials(
        &self,
        id: &str,
        revision: u64,
    ) -> Result<Option<crate::api::outbound::workflows::storage::Credentials>, String> {
        let connection = self.connection.lock().expect("store poisoned");
        let document: Option<Option<String>> = connection.query_row("SELECT c.document FROM delivery_storage s LEFT JOIN delivery_storage_credentials c ON c.id=s.id WHERE s.id=?1 AND s.revision=?2", params![id, revision as i64], |row| row.get(0)).optional().map_err(|e| e.to_string())?;
        document
            .ok_or("storage changed; reload before connecting")?
            .map(|document| {
                serde_json::from_str(&document)
                    .map_err(|_| "invalid saved storage credentials".to_owned())
            })
            .transpose()
    }

    pub fn require_delivery_export(&self, id: &str, attempt: u64) -> Result<Job, String> {
        let connection = self.connection.lock().expect("store poisoned");
        export_in(&connection, id, attempt)
    }

    pub fn require_delivery_destination(
        &self,
        id: &str,
        attempt: u64,
        destination: &str,
    ) -> Result<Storage, String> {
        let connection = self.connection.lock().expect("store poisoned");
        let job = export_in(&connection, id, attempt)?;
        Ok(check_job_destination(&connection, &job, destination)?)
    }

    pub fn complete_delivery_export(
        &self,
        id: &str,
        attempt: u64,
        destination: &str,
        key: &str,
    ) -> Result<(), String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let tx = connection.transaction().map_err(|e| e.to_string())?;
        let mut job = export_in(&tx, id, attempt)?;
        check_job_destination(&tx, &job, destination)?;
        job.checks["destinations"][destination] =
            serde_json::json!({"state":"complete", "location":key, "completed_at":now_unix()});
        if job
            .project
            .destinations
            .iter()
            .all(|id| job.checks["destinations"][id]["state"] == "complete")
        {
            job.state = "ready".into();
        }
        job.updated_at = now_unix();
        save_job(&tx, &job).map_err(|e| e.to_string())?;
        evidence::delivery_event(&tx,&self.event_signer,&job.tenant,id,"destination_completed",&serde_json::json!({"manifest": job.manifest,"project_id": job.project.id,"destination": destination,"location": key}),job.updated_at).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())
    }

    pub fn fail_delivery_destination(
        &self,
        id: &str,
        attempt: u64,
        destination: &str,
        error: &str,
    ) -> Result<(), String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let tx = connection.transaction().map_err(|e| e.to_string())?;
        let mut job = export_in(&tx, id, attempt)?;
        if !job.project.destinations.iter().any(|id| id == destination) {
            return Err("destination is not part of this job".into());
        }
        let error: String = error.chars().take(500).collect();
        job.checks["destinations"][destination] =
            serde_json::json!({"state":"failed", "error":error});
        save_job(&tx, &job).map_err(|e| e.to_string())?;
        evidence::delivery_event(
            &tx,
            &self.event_signer,
            &job.tenant,
            id,
            "destination_failed",
            &serde_json::json!({"destination":destination,"error":error,"attempt":attempt}),
            now_unix(),
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())
    }

    pub fn delivery_projects(&self, tenant: &str) -> Result<Vec<Project>, String> {
        self.with(|connection| {
            let mut query = connection
                .prepare("SELECT document FROM delivery_projects WHERE tenant=?1 ORDER BY id")?;
            let rows = query.query_map([tenant], |row| decode(row.get(0)?))?;
            rows.collect()
        })
    }

    pub fn delivery_project(&self, tenant: &str, id: &str) -> Result<Option<Project>, String> {
        self.with(|connection| project_in(connection, tenant, id))
    }

    pub fn save_delivery_project(
        &self,
        tenant: &str,
        actor: &str,
        mut project: Project,
    ) -> Result<Project, WorkflowMutationError> {
        project.validate().map_err(WorkflowMutationError::invalid)?;
        let mut connection = self.connection.lock().expect("store poisoned");
        let tx = connection.transaction().map_err(|e| e.to_string())?;
        ensure_tenant(&tx, tenant)?;
        let current = project_in(&tx, tenant, &project.id).map_err(|e| e.to_string())?;
        if current.as_ref().map_or(0, |p| p.revision) != project.revision
            || current.as_ref().map_or(0, |p| p.notification_revision)
                != project.notification_revision
        {
            return Err(WorkflowMutationError::conflict(
                "project changed; reload before saving",
            ));
        }
        if current
            .as_ref()
            .is_some_and(|p| p.directory != project.directory)
        {
            return Err(WorkflowMutationError::conflict(
                "a protected project's directory cannot change",
            ));
        }
        let mut query = tx
            .prepare("SELECT document FROM delivery_projects WHERE tenant=?1 AND id<>?2")
            .map_err(|e| e.to_string())?;
        let rows = query
            .query_map(params![tenant, project.id], |row| {
                decode::<Project>(row.get(0)?)
            })
            .map_err(|e| e.to_string())?;
        let mut count = 0;
        for other in rows {
            let other = other.map_err(|e| e.to_string())?;
            count += 1;
            if crate::workflow::within(&other.directory, &project.directory)
                || crate::workflow::within(&project.directory, &other.directory)
            {
                return Err(WorkflowMutationError::conflict(
                    "project directories must not overlap",
                ));
            }
        }
        if count >= 100 {
            return Err(WorkflowMutationError::conflict("project limit reached"));
        }
        drop(query);
        let notifications_only = current.as_ref().is_some_and(|p| {
            p.notifications != project.notifications && p.same_delivery_policy(&project)
        });
        if current
            .as_ref()
            .is_some_and(|p| p.notifications != project.notifications)
        {
            project.notification_revision += 1;
        }
        if !notifications_only {
            project.revision += 1;
        }
        tx.execute("INSERT INTO delivery_projects(tenant,id,revision,document) VALUES (?1,?2,?3,?4) ON CONFLICT(tenant,id) DO UPDATE SET revision=excluded.revision,document=excluded.document", params![tenant,project.id,project.revision as i64,serde_json::to_string(&project).expect("project serializes")]).map_err(|e| e.to_string())?;
        tx.execute("DELETE FROM delivery_policy_cache WHERE grant_id IN (SELECT id FROM outbound_grants WHERE tenant=?1)",[tenant]).map_err(|error| error.to_string())?;
        evidence::delivery_event(&tx, &self.event_signer, tenant, "", "project_policy_changed", &serde_json::json!({"project_id": project.id, "revision": project.revision, "actor": actor}), now_unix()).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(project)
    }

    pub fn enqueue_delivery_job(
        &self,
        tenant: &str,
        actor: &str,
        credential_version: u64,
        automation_token_id: Option<String>,
        project: Project,
        request: JobRequest,
    ) -> Result<Job, WorkflowMutationError> {
        let now = now_unix();
        let mut connection = self.connection.lock().expect("store poisoned");
        let tx = connection.transaction().map_err(|e| e.to_string())?;
        ensure_tenant(&tx, tenant)?;
        let previous: Option<Job> = tx.query_row("SELECT document FROM delivery_jobs WHERE tenant=?1 AND actor=?2 AND operation_id=?3", params![tenant,actor,request.operation_id], |row| decode(row.get(0)?)).optional().map_err(|e| e.to_string())?;
        if let Some(previous) = previous {
            return if previous.request == request {
                Ok(previous)
            } else {
                Err(WorkflowMutationError::operation_conflict(
                    "operation ID already used with a different request",
                ))
            };
        }
        project
            .validate_job(&request, now)
            .map_err(WorkflowMutationError::invalid)?;
        if project_in(&tx, tenant, &project.id)
            .map_err(|e| e.to_string())?
            .as_ref()
            != Some(&project)
        {
            return Err(WorkflowMutationError::conflict(
                "project changed; reload before submitting",
            ));
        }
        let count: i64 = tx.query_row("SELECT COUNT(*) FROM delivery_jobs WHERE tenant=?1 AND state IN ('queued','preparing','awaiting_approval','exporting','retrying')", [tenant], |row| row.get(0)).map_err(|e| e.to_string())?;
        if count >= 1000 {
            return Err(WorkflowMutationError::conflict("active job limit reached"));
        }
        let checks = trade::snapshot(&tx, tenant, &project)?;
        let job = Job {
            id: crate::auth::random_token(),
            tenant: tenant.into(),
            token_generation: 0,
            actor: actor.into(),
            credential_version,
            automation_token_id,
            request,
            project,
            state: "queued".into(),
            manifest: None,
            approved_by: None,
            attempts: 0,
            created_at: now,
            updated_at: now,
            error: None,
            checks,
            received: None,
            reprocessed_from: None,
            reprocessed_as: None,
        };
        actor_active(&tx, &job)?;
        tx.execute("INSERT INTO delivery_jobs(id,tenant,actor,operation_id,project_id,state,not_before,deadline,document,token) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)", params![job.id,tenant,actor,job.request.operation_id,job.project.id,job.state,job.request.not_before.unwrap_or(now) as i64,job.request.deadline.map(|t| t as i64),serde_json::to_string(&job).expect("job serializes"),crate::auth::random_token()]).map_err(|e| e.to_string())?;
        evidence::delivery_event(
            &tx,
            &self.event_signer,
            tenant,
            &job.id,
            "delivery_queued",
            &serde_json::json!({"project_id": job.project.id, "actor": actor}),
            now,
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(job)
    }

    pub fn delivery_job(&self, id: &str) -> Result<Option<Job>, String> {
        self.with(|connection| job_in(connection, id))
    }

    pub fn delivery_jobs(
        &self,
        tenant: &str,
        after: &str,
        limit: usize,
        projects: Option<&[String]>,
        state: &str,
        search: &str,
    ) -> Result<Vec<Job>, String> {
        let projects = projects
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| e.to_string())?;
        self.with(|connection| {
            let mut query = connection.prepare(
                "SELECT document FROM delivery_jobs WHERE tenant=?1 AND id>?2
                 AND (?4 IS NULL OR project_id IN (SELECT value FROM json_each(?4)))
                 AND (?5='' OR state=?5
                    OR (?5='attention' AND state IN ('awaiting_approval','failed','retrying','suspended'))
                    OR (?5='active' AND state IN ('queued','preparing','exporting','retrying')))
                 AND (?6='' OR instr(lower(json_extract(document,'$.request.label')),lower(?6))>0
                    OR instr(lower(json_extract(document,'$.project.label')),lower(?6))>0
                    OR instr(lower(id),lower(?6))>0)
                 ORDER BY id LIMIT ?3",
            )?;
            let rows = query.query_map(
                params![
                    tenant,
                    after,
                    limit.min(101) as i64,
                    projects,
                    state,
                    search
                ],
                |row| decode(row.get(0)?),
            )?;
            rows.collect()
        })
    }

    pub fn claim_delivery_job(&self, owner: &str, now: u64) -> Result<Option<Job>, String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let tx = connection.transaction().map_err(|e| e.to_string())?;
        let job: Option<Job> = tx.query_row("SELECT document FROM delivery_jobs WHERE (state IN ('queued','retrying') AND not_before<=?1) OR (state='preparing' AND owner<>?2) OR (state='exporting' AND owner<>?2) ORDER BY not_before,id LIMIT 1", params![now as i64,owner], |row| decode(row.get(0)?)).optional().map_err(|e| e.to_string())?;
        let Some(mut job) = job else {
            return Ok(None);
        };
        job.state = if job.manifest.is_some() {
            "exporting"
        } else {
            "preparing"
        }
        .into();
        job.attempts += 1;
        job.updated_at = now;
        job.error = None;
        if retry_attempts(&job) > 5 {
            job.state = "failed".into();
            job.error = Some("job recovery limit reached; retry explicitly".into());
        }
        tx.execute(
            "UPDATE delivery_jobs SET owner=?2 WHERE id=?1",
            params![job.id, owner],
        )
        .map_err(|e| e.to_string())?;
        save_job(&tx, &job).map_err(|e| e.to_string())?;
        evidence::delivery_event(
            &tx,
            &self.event_signer,
            &job.tenant,
            &job.id,
            &format!("delivery_{}", job.state),
            &serde_json::json!({"attempt": job.attempts, "error": job.error}),
            now,
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(Some(job))
    }

    pub fn fail_delivery_job(&self, id: &str, attempt: u64, error: &str) -> Result<(), String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let tx = connection.transaction().map_err(|e| e.to_string())?;
        let Some(mut job) = job_in(&tx, id).map_err(|e| e.to_string())? else {
            return Ok(());
        };
        if !["preparing", "exporting"].contains(&job.state.as_str()) || job.attempts != attempt {
            return Ok(());
        }
        job.state = if job.state == "exporting" && retry_attempts(&job) < 5 {
            "retrying"
        } else {
            "failed"
        }
        .into();
        if job.state == "retrying" {
            let retry_at = now_unix().saturating_add(30 * (1u64 << retry_attempts(&job).min(4)));
            job.checks["retry_at"] = serde_json::json!(retry_at);
            tx.execute(
                "UPDATE delivery_jobs SET not_before=?2 WHERE id=?1",
                params![id, retry_at as i64],
            )
            .map_err(|e| e.to_string())?;
        }
        if job.checks["first_failure_at"].is_null() {
            job.checks["first_failure_at"] = serde_json::json!(now_unix());
        }
        job.error = Some(error.chars().take(500).collect());
        job.updated_at = now_unix();
        save_job(&tx, &job).map_err(|e| e.to_string())?;
        evidence::delivery_event(
            &tx,
            &self.event_signer,
            &job.tenant,
            id,
            "delivery_failed",
            &serde_json::json!({"error": job.error}),
            job.updated_at,
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())
    }

    pub fn reprocess_received_job(
        &self,
        identity: &crate::auth::AdminIdentity,
        id: &str,
        manifest: &str,
        project_revision: u64,
    ) -> Result<Job, WorkflowMutationError> {
        if !matches!(identity.role.as_str(), "admin" | "viewer")
            || identity.subject.starts_with("automation:")
        {
            return Err(WorkflowMutationError::conflict(
                "reprocessing requires a human project sender",
            ));
        }
        let mut connection = self.connection.lock().expect("store poisoned");
        let tx = connection.transaction().map_err(|e| e.to_string())?;
        if !principal_active(&tx, &identity.subject, identity.credential_version)
            .map_err(|e| e.to_string())?
        {
            return Err(WorkflowMutationError::conflict(
                "submitting identity is no longer authorized",
            ));
        }
        let mut original = job_in(&tx, id)
            .map_err(|e| e.to_string())?
            .filter(|job| job.tenant == identity.tenant)
            .ok_or_else(|| WorkflowMutationError::conflict("job missing"))?;
        let received = original.received.clone().ok_or_else(|| {
            WorkflowMutationError::conflict("only incoming deliveries can be reprocessed")
        })?;
        let project = project_in(&tx, &identity.tenant, &original.project.id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| WorkflowMutationError::conflict("project missing"))?;
        if !project.allows(&identity.subject, "sender", identity.role == "admin") {
            return Err(WorkflowMutationError::conflict(
                "project sender permission required",
            ));
        }
        if original.manifest.as_deref() != Some(manifest) || manifest.is_empty() {
            return Err(WorkflowMutationError::conflict(
                "delivery manifest changed; reload before reprocessing",
            ));
        }
        if let Some(id) = &original.reprocessed_as {
            return job_in(&tx, id)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| WorkflowMutationError::conflict("replacement delivery missing"));
        }
        if !["failed", "retrying", "awaiting_approval", "ready"].contains(&original.state.as_str())
        {
            return Err(WorkflowMutationError::conflict(
                "only an inactive prepared delivery can be reprocessed",
            ));
        }
        if project.revision != project_revision || project.revision == original.project.revision {
            return Err(WorkflowMutationError::conflict(
                "project policy changed; reload before reprocessing",
            ));
        }
        let workflow = receive_workflow_in(&tx, &identity.tenant, &received.link_id)
            .map_err(|e| e.to_string())?
            .filter(|workflow| workflow.project_id == project.id)
            .ok_or_else(|| {
                WorkflowMutationError::conflict(
                    "the receive request must still select this project",
                )
            })?;
        if !received_requires_workflow(
            &tx,
            &identity.tenant,
            &received.link_id,
            &received.upload_id,
        )? {
            return Err(WorkflowMutationError::conflict(
                "incoming workflow ownership is missing",
            ));
        }
        let upload = read_upload(
            &tx,
            &identity.tenant,
            &received.link_id,
            &received.upload_id,
        )
        .map_err(|e| e.to_string())?
        .filter(|upload| {
            !upload.partial
                && upload.completed_at != 0
                && !upload.files.is_empty()
                && upload.files.iter().all(|file| !file.deleted)
        })
        .ok_or_else(|| {
            WorkflowMutationError::conflict("incoming package is incomplete or unavailable")
        })?;
        if crate::route_protocol::manifest_digest(upload.files.iter().map(|file| {
            (
                file.path.as_str(),
                file.suite.as_str(),
                file.root.as_str(),
                file.bytes,
            )
        })) != manifest
        {
            return Err(WorkflowMutationError::conflict(
                "incoming inventory no longer matches the prepared delivery",
            ));
        }
        super::routes::require_shareable(&tx, &received.upload_id)?;
        let now = now_unix();
        let request = workflow.request(
            &format!("reprocess_{}", original.id),
            &original.request.label,
        );
        project
            .validate_job(&request, now)
            .map_err(WorkflowMutationError::invalid)?;
        let replacement = Job {
            id: crate::auth::random_token(),
            tenant: identity.tenant.clone(),
            token_generation: 0,
            actor: identity.subject.clone(),
            credential_version: identity.credential_version,
            automation_token_id: None,
            request,
            checks: trade::snapshot(&tx, &identity.tenant, &project)?,
            project,
            state: "queued".into(),
            manifest: None,
            approved_by: None,
            attempts: 0,
            created_at: now,
            updated_at: now,
            error: None,
            received: Some(received),
            reprocessed_from: Some(original.id.clone()),
            reprocessed_as: None,
        };
        actor_active(&tx, &replacement)?;
        check_job_source(&tx, &replacement)?;
        original.state = "cancelled".into();
        original.updated_at = now;
        original.reprocessed_as = Some(replacement.id.clone());
        save_job(&tx, &original).map_err(|e| e.to_string())?;
        let count: i64 = tx.query_row("SELECT COUNT(*) FROM delivery_jobs WHERE tenant=?1 AND state IN ('queued','preparing','awaiting_approval','exporting','retrying')",[&identity.tenant],|row| row.get(0)).map_err(|e| e.to_string())?;
        if count >= 1000 {
            return Err(WorkflowMutationError::conflict("active job limit reached"));
        }
        let revoked = tx.execute("UPDATE outbound_grants SET revoked_at=COALESCE(revoked_at,?2) WHERE id=?1 AND tenant=?3",params![original.id,now as i64,identity.tenant]).map_err(|e| e.to_string())?;
        if revoked != 1 {
            return Err(WorkflowMutationError::conflict(
                "prepared delivery link is missing",
            ));
        }
        tx.execute(
            "UPDATE delivery_jobs SET owner='' WHERE id=?1",
            [&original.id],
        )
        .map_err(|e| e.to_string())?;
        tx.execute("INSERT INTO delivery_jobs(id,tenant,actor,operation_id,project_id,state,not_before,document,token) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",params![replacement.id,replacement.tenant,replacement.actor,replacement.request.operation_id,replacement.project.id,replacement.state,now as i64,serde_json::to_string(&replacement).map_err(|e| e.to_string())?,crate::auth::random_token()]).map_err(|e| e.to_string())?;
        evidence::delivery_event(&tx,&self.event_signer,&identity.tenant,&original.id,"delivery_reprocessed",&serde_json::json!({"actor":identity.subject,"manifest":manifest,"project_id":replacement.project.id,"original_revision":original.project.revision,"revision":replacement.project.revision,"replacement_id":replacement.id}),now).map_err(|e| e.to_string())?;
        evidence::delivery_event(&tx,&self.event_signer,&identity.tenant,&replacement.id,"reception_queued",&serde_json::json!({"actor":identity.subject,"project_id":replacement.project.id,"reprocessed_from":original.id,"received":replacement.received}),now).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(replacement)
    }

    pub fn change_delivery_job(
        &self,
        tenant: &str,
        id: &str,
        actor: &str,
        administrator: bool,
        action: &str,
        manifest: Option<&str>,
    ) -> Result<Job, WorkflowMutationError> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let tx = connection.transaction().map_err(|e| e.to_string())?;
        let mut job = job_in(&tx, id)
            .map_err(|e| e.to_string())?
            .filter(|job| job.tenant == tenant)
            .ok_or_else(|| WorkflowMutationError::conflict("job missing"))?;
        let project = project_in(&tx, tenant, &job.project.id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| WorkflowMutationError::conflict("project missing"))?;
        if job.state == "suspended" {
            return Err(WorkflowMutationError::conflict(
                "delivery is held after restore; create a new job",
            ));
        }
        match action {
            "approve" => {
                if actor.starts_with("automation:")
                    || actor == job.actor
                    || !project.allows(actor, "approver", administrator)
                {
                    return Err(WorkflowMutationError::conflict(
                        "approval requires a different authorized human operator",
                    ));
                }
                if job.state != "awaiting_approval"
                    || job.manifest.as_deref() != manifest
                    || manifest.is_none()
                    || project.revision != job.project.revision
                {
                    return Err(WorkflowMutationError::conflict(
                        "approval does not match the pending manifest and policy",
                    ));
                }
                actor_active(&tx, &job)?;
                check_job_storage(&tx, &job)?;
                job.approved_by = Some(actor.into());
                if project.release == crate::workflow::Release::Local {
                    job.checks["released_at"] = serde_json::json!(now_unix());
                }
                job.state = if !project.destinations.is_empty() {
                    "exporting"
                } else {
                    "ready"
                }
                .into();
            }
            "cancel" => {
                if !project.allows(actor, "sender", administrator) && actor != job.actor {
                    return Err(WorkflowMutationError::conflict(
                        "sender permission required",
                    ));
                }
                if ["retiring", "retired"].contains(&job.state.as_str()) {
                    return Err(WorkflowMutationError::conflict(
                        "delivery is retiring or retired",
                    ));
                }
                if job.state == "cancelled" {
                    return Ok(job);
                }
                job.state = "cancelled".into();
            }
            "retry" => {
                if !project.allows(actor, "sender", administrator) && actor != job.actor {
                    return Err(WorkflowMutationError::conflict(
                        "sender permission required",
                    ));
                }
                if !["failed", "retrying"].contains(&job.state.as_str()) {
                    return Err(WorkflowMutationError::conflict(
                        "only a failed job can retry",
                    ));
                }
                if let (Some(received), None) = (&job.received, &job.manifest) {
                    let workflow = receive_workflow_in(&tx, tenant, &received.link_id)
                        .map_err(|e| e.to_string())?
                        .filter(|workflow| workflow.project_id == project.id)
                        .ok_or_else(|| {
                            WorkflowMutationError::conflict(
                                "the receive request must still select this project",
                            )
                        })?;
                    job.request.metadata = workflow.metadata;
                    job.request.recipients = workflow.recipients;
                    job.request.notifications = workflow.notifications;
                    job.project = project.clone();
                    job.checks = trade::snapshot(&tx, tenant, &project)?;
                } else if project.revision != job.project.revision {
                    return Err(WorkflowMutationError::conflict(
                        "this delivery requires its original project policy",
                    ));
                }
                actor_active(&tx, &job)?;
                project
                    .validate_job(&job.request, job.created_at)
                    .map_err(WorkflowMutationError::invalid)?;
                job.attempts += 1;
                job.checks["retry_base"] = serde_json::json!(job.attempts);
                job.checks["first_failure_at"] = serde_json::Value::Null;
                job.checks["retry_at"] = serde_json::Value::Null;
                job.state = if job.manifest.is_some() {
                    "exporting"
                } else {
                    "queued"
                }
                .into();
            }
            _ => return Err(WorkflowMutationError::invalid("unknown job action")),
        }
        job.updated_at = now_unix();
        job.error = None;
        tx.execute("UPDATE delivery_jobs SET owner='' WHERE id=?1", [id])
            .map_err(|e| e.to_string())?;
        save_job(&tx, &job).map_err(|e| e.to_string())?;
        evidence::delivery_event(&tx, &self.event_signer, tenant, id, &format!("delivery_{action}"), &serde_json::json!({"actor": actor, "manifest": job.manifest, "project_id": project.id, "revision": project.revision}), job.updated_at).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(job)
    }

    pub fn delivery_access(&self, grant_id: &str, token_hash: &str) -> Result<Option<Job>, String> {
        let connection = self.connection.lock().expect("store poisoned");
        delivery_access_in(&connection, grant_id, token_hash)
    }

    pub(crate) fn delivery_access_with_audit<E>(
        &self,
        grant_id: &str,
        token_hash: &str,
        tenant: &str,
        detail: &serde_json::Value,
        check: impl FnOnce(Result<Option<Job>, String>) -> Result<(), E>,
    ) -> Result<(), E> {
        let connection = self.connection.lock().expect("store poisoned");
        check(delivery_access_in(&connection, grant_id, token_hash))?;
        if let Err(error) = insert_audit_row(
            &connection,
            now_unix(),
            tenant,
            "",
            "outbound_downloaded",
            grant_id,
            detail,
        ) {
            AUDIT_INSERT_FAILURES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::warn!(%error, event = "outbound_downloaded", "audit row insert failed");
        }
        Ok(())
    }

    pub fn delivery_release(&self, grant_id: &str) -> Result<Option<Job>, String> {
        let connection = self.connection.lock().expect("store poisoned");
        release_in(&connection, grant_id)
    }

    pub(crate) fn delivery_job_token(&self, tenant: &str, id: &str) -> Result<String, String> {
        self.with(|connection| {
            connection.query_row(
                "SELECT token FROM delivery_jobs WHERE tenant=?1 AND id=?2",
                params![tenant, id],
                |row| row.get(0),
            )
        })
    }

    pub fn rotate_delivery_job_token(
        &self,
        tenant: &str,
        id: &str,
        generation: u64,
        token: &str,
    ) -> Result<bool, String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let tx = connection.transaction().map_err(|e| e.to_string())?;
        let mut job = job_in(&tx, id)
            .map_err(|e| e.to_string())?
            .filter(|job| job.tenant == tenant)
            .ok_or("job missing")?;
        if ["retiring", "retired", "suspended"].contains(&job.state.as_str()) {
            return Err("delivery is no longer active; create a new job".into());
        }
        if job.token_generation != generation {
            return Err("delivery changed; reload before rotating".into());
        }
        let token_hash = crate::auth::hash_token(token);
        let changed = tx.execute("UPDATE outbound_grants SET token_hash=?3 WHERE tenant=?1 AND id=?2 AND revoked_at IS NULL",params![tenant,id,token_hash]).map_err(|e| e.to_string())?;
        if changed == 0 {
            return Ok(false);
        }
        job.token_generation += 1;
        job.updated_at = now_unix();
        tx.execute(
            "UPDATE delivery_jobs SET token=?3 WHERE tenant=?1 AND id=?2",
            params![tenant, id, token],
        )
        .map_err(|e| e.to_string())?;
        save_job(&tx, &job).map_err(|e| e.to_string())?;
        evidence::delivery_event(
            &tx,
            &self.event_signer,
            tenant,
            id,
            "delivery_link_rotated",
            &serde_json::json!({"generation": job.token_generation}),
            job.updated_at,
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(true)
    }

    pub fn delivery_token_active(&self, id: &str, token_hash: &str) -> Result<bool, String> {
        self.with(|connection| connection.query_row("SELECT EXISTS(SELECT 1 FROM outbound_grants WHERE id=?1 AND token_hash=?2 AND revoked_at IS NULL AND expires_at>?3)", params![id,token_hash,now_unix() as i64], |row| row.get(0)))
    }
}

fn delivery_access_in(
    connection: &Connection,
    grant_id: &str,
    token_hash: &str,
) -> Result<Option<Job>, String> {
    let row: Option<(Option<String>, Option<i64>, Option<bool>)> = connection
        .prepare_cached("SELECT j.document,p.revision,c.protected FROM outbound_grants g LEFT JOIN delivery_jobs j ON j.id=g.id LEFT JOIN delivery_projects p ON p.tenant=j.tenant AND p.id=j.project_id LEFT JOIN delivery_policy_cache c ON c.grant_id=g.id WHERE g.id=?1 AND g.token_hash=?2 AND g.revoked_at IS NULL AND g.expires_at>?3")
        .and_then(|mut statement| {
            statement.query_row(
                params![grant_id, token_hash, now_unix() as i64],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
        })
        .optional()
        .map_err(|error| error.to_string())?;
    let Some((document, revision, protected)) = row else {
        return Err("delivery link is inactive".into());
    };
    if let Some(document) = document {
        let job: Job = serde_json::from_str(&document).map_err(|error| error.to_string())?;
        if !job.released() || revision != Some(job.project.revision as i64) {
            return Err("delivery is awaiting release under the current project policy".into());
        }
        return Ok(Some(job));
    }
    match protected {
        Some(false) => Ok(None),
        Some(true) => Err("delivery requires a project workflow".into()),
        None => release_in(connection, grant_id),
    }
}

fn check_job_storage(connection: &Connection, job: &Job) -> Result<(), WorkflowMutationError> {
    check_job_source(connection, job)?;
    for id in &job.project.destinations {
        if job.checks["destinations"][id]["state"] != "complete" {
            check_job_destination(connection, job, id)?;
        }
    }
    Ok(())
}

fn check_job_source(connection: &Connection, job: &Job) -> Result<(), WorkflowMutationError> {
    trade::check_export(connection, job)?;
    if let Some(import) = &job.request.import {
        check_storage(
            connection,
            &job.tenant,
            &import.storage_id,
            job.checks["import_storage_revision"].as_u64(),
        )?;
    }
    Ok(())
}

fn check_job_destination(
    connection: &Connection,
    job: &Job,
    destination: &str,
) -> Result<Storage, WorkflowMutationError> {
    if !job.project.destinations.iter().any(|id| id == destination) {
        return Err(WorkflowMutationError::conflict(
            "destination is not part of this job",
        ));
    }
    trade::check_destination(connection, job, destination)?;
    check_storage(
        connection,
        &job.tenant,
        destination,
        job.checks["destination_revisions"][destination].as_u64(),
    )
}

fn check_storage(
    connection: &Connection,
    tenant: &str,
    id: &str,
    revision: Option<u64>,
) -> Result<Storage, WorkflowMutationError> {
    let config: Option<Storage> = connection
        .query_row(
            "SELECT document FROM delivery_storage WHERE id=?1",
            [id],
            |row| decode(row.get(0)?),
        )
        .optional()
        .map_err(|error| WorkflowMutationError::store(error.to_string()))?;
    let Some(config) = config else {
        return Err(WorkflowMutationError::conflict(
            "storage connection missing",
        ));
    };
    if !config.enabled
        || !config.tenants.iter().any(|allowed| allowed == tenant)
        || Some(config.revision) != revision
    {
        return Err(WorkflowMutationError::conflict(
            "storage authorization changed; submit a new job",
        ));
    }
    Ok(config)
}

fn retry_attempts(job: &Job) -> u64 {
    job.attempts
        .saturating_sub(job.checks["retry_base"].as_u64().unwrap_or(0))
}

fn export_in(connection: &Connection, id: &str, attempt: u64) -> Result<Job, String> {
    let job = job_in(connection, id)
        .map_err(|e| e.to_string())?
        .ok_or("job missing")?;
    let project = project_in(connection, &job.tenant, &job.project.id)
        .map_err(|e| e.to_string())?
        .ok_or("project missing")?;
    if job.state != "exporting"
        || job.attempts != attempt
        || !job.project.same_delivery_policy(&project)
        || (project.require_approval && job.approved_by.is_none())
    {
        return Err("export is no longer authorized".into());
    }
    let active: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM outbound_grants WHERE id=?1 AND revoked_at IS NULL AND expires_at>?2)",params![id,now_unix() as i64],|row| row.get(0)).map_err(|e| e.to_string())?;
    if !active {
        return Err("delivery was revoked or expired".into());
    }
    actor_active(connection, &job)?;
    check_job_source(connection, &job)?;
    Ok(job)
}

pub(super) fn remove_storage_tenant(connection: &Connection, tenant: &str) -> Result<(), String> {
    let mut query = connection
        .prepare("SELECT document FROM delivery_storage")
        .map_err(|e| e.to_string())?;
    let rows = query
        .query_map([], |row| {
            decode::<crate::api::outbound::workflows::storage::Storage>(row.get(0)?)
        })
        .map_err(|e| e.to_string())?;
    let rows = rows
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| e.to_string())?;
    drop(query);
    for mut storage in rows {
        if storage.tenants.iter().any(|allowed| allowed == tenant) {
            storage.tenants.retain(|allowed| allowed != tenant);
            storage.revision += 1;
            connection
                .execute(
                    "UPDATE delivery_storage SET revision=?2,document=?3 WHERE id=?1",
                    params![
                        storage.id,
                        storage.revision as i64,
                        serde_json::to_string(&storage).expect("storage serializes")
                    ],
                )
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

pub(super) fn release_in(connection: &Connection, grant_id: &str) -> Result<Option<Job>, String> {
    if let Some(job) = job_in(connection, grant_id).map_err(|e| e.to_string())? {
        let project = project_in(connection, &job.tenant, &job.project.id)
            .map_err(|e| e.to_string())?
            .ok_or("delivery project missing")?;
        if !job.released() || project.revision != job.project.revision {
            return Err("delivery is awaiting release under the current project policy".into());
        }
        return Ok(Some(job));
    }
    let cached: Option<bool> = connection
        .prepare_cached("SELECT protected FROM delivery_policy_cache WHERE grant_id=?1")
        .and_then(|mut statement| statement.query_row([grant_id], |row| row.get(0)).optional())
        .map_err(|error| error.to_string())?;
    let protected = match cached {
        Some(protected) => protected,
        None => {
            let protected: bool = connection.prepare_cached("SELECT EXISTS(SELECT 1 FROM outbound_grants g CROSS JOIN delivery_projects p CROSS JOIN outbound_grant_files f WHERE g.id=?1 AND p.tenant=g.tenant AND f.grant_id=g.id AND votport_within(json_extract(p.document,'$.directory'),f.source)) OR EXISTS(SELECT 1 FROM outbound_grants g JOIN receive_workflow_uploads r ON r.link_id=g.link_id AND r.upload_id=g.upload_id JOIN links l ON l.id=r.link_id AND l.tenant=g.tenant WHERE g.id=?1)").and_then(|mut statement| statement.query_row([grant_id], |row| row.get(0))).map_err(|error| error.to_string())?;
            // Project writes invalidate these immutable-file decisions in the same transaction.
            connection.execute("INSERT OR REPLACE INTO delivery_policy_cache(grant_id,protected) SELECT ?1,?2 WHERE EXISTS(SELECT 1 FROM outbound_grants WHERE id=?1)",params![grant_id,protected]).map_err(|error| error.to_string())?;
            protected
        }
    };
    if protected {
        Err("delivery requires a project workflow".into())
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workflow::tests::{project, request};

    #[test]
    fn unenrolled_route_keeps_the_received_job_recoverable() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let route = crate::store::TradeRoute {
            id: "pending-route".into(),
            revision: 1,
            tenant: String::new(),
            direction: "outgoing".into(),
            name: "Partner".into(),
            peer_name: "Partner".into(),
            peer_key: "ab".repeat(32),
            address: "http://localhost".into(),
            endpoint: "remote-endpoint".into(),
            endpoint_name: "Masters".into(),
            category: "external".into(),
            forwarding: false,
            metadata_keys: vec![],
            state: "pending_approval".into(),
            notifications: Default::default(),
            last_contact: None,
            error: None,
            remote_grant: String::new(),
            remote_state: "enrolling".into(),
            cancel_active: false,
        };
        let invitation = store.event_signer.port_message(
            "invitation",
            "",
            "nonce".into(),
            now_unix() + 300,
            serde_json::json!({}),
        );
        store
            .save_outgoing_trade(&route, &crate::auth::random_token(), &invitation)
            .unwrap();
        let mut policy = project();
        policy.receive = true;
        policy.destinations = vec![route.id.clone()];
        let policy = store.save_delivery_project("", "admin", policy).unwrap();
        let workflow = crate::workflow::ReceiveWorkflow {
            notifications: None,
            project_id: policy.id.clone(),
            metadata: request().metadata,
            recipients: vec![],
        };
        let link = crate::store::tests::test_link("incoming");
        store
            .insert_link_with_workflow(link.clone(), Some(&workflow))
            .unwrap();
        let upload = UploadRecord {
            id: "complete".into(),
            started_at: 1,
            completed_at: 2,
            replayed_chunks: 0,
            rejected_chunks: 0,
            transport: Some("http".into()),
            package_root: "package".into(),
            total_bytes: 1,
            partial: false,
            log: vec![],
            files: vec![FileRecord {
                path: "file.bin".into(),
                stored_as: "file.bin".into(),
                bytes: 1,
                suite: "blake3".into(),
                root: "root".into(),
                receipt: true,
                deleted: false,
            }],
        };
        store.append_upload("", &link.id, upload.clone()).unwrap();
        // The upload is recorded and the job waits with an empty grant that
        // preparation fills in once enrollment finishes.
        let jobs = store.delivery_jobs("", "", 100, None, "", "").unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].state, "queued");
        assert_eq!(
            jobs[0].checks["trade_routes"][&route.id]["permission"]["grant"],
            ""
        );
        store
            .change_delivery_job("", &jobs[0].id, "admin", true, "cancel", None)
            .unwrap();
        let mut updated = policy.clone();
        updated.required_metadata.push("take".into());
        updated.recipients.push(crate::workflow::Recipient {
            email: "editor@example.com".into(),
            holder: store.event_signer.public_hex.clone(),
        });
        let mut updated = store.save_delivery_project("", "admin", updated).unwrap();
        let mut upload = upload;
        upload.id = "missing-metadata".into();
        store.append_upload("", &link.id, upload.clone()).unwrap();
        let failed = store
            .delivery_jobs("", "", 100, None, "", "")
            .unwrap()
            .into_iter()
            .find(|job| job.request.operation_id == upload.id)
            .unwrap();
        assert_eq!(failed.project.revision, updated.revision);
        assert_eq!(failed.state, "failed");
        let retry = || store.change_delivery_job("", &failed.id, "admin", true, "retry", None);
        assert!(retry().unwrap_err().contains("metadata"));
        let mut corrected = workflow.clone();
        corrected.metadata.insert("take".into(), "02".into());
        corrected
            .recipients
            .push(store.event_signer.public_hex.clone());
        corrected.notifications = Some(crate::store::NotificationPolicy {
            mode: crate::store::NotificationMode::Default,
            rules: vec![],
        });
        store
            .set_receive_workflow("", &link.id, &corrected)
            .unwrap();
        store
            .finish_trade_enrollment("", &route.id, "enrolled-grant", "active")
            .unwrap();
        let retried = retry().unwrap();
        assert_eq!(retried.project.revision, failed.project.revision);
        assert_eq!(retried.request.metadata, corrected.metadata);
        assert_eq!(retried.request.recipients, corrected.recipients);
        assert_eq!(retried.request.notifications, corrected.notifications);
        assert_eq!(
            retried.checks["trade_routes"][&route.id]["permission"]["grant"],
            "enrolled-grant"
        );
        let running = store
            .claim_delivery_job("worker", now_unix())
            .unwrap()
            .unwrap();
        assert_eq!(running.id, failed.id);
        store
            .fail_delivery_job(&failed.id, running.attempts, "preparation failed")
            .unwrap();
        assert_eq!(
            store.delivery_job(&failed.id).unwrap().unwrap().state,
            "failed"
        );
        let before =
            serde_json::to_value(store.delivery_job(&failed.id).unwrap().unwrap()).unwrap();
        let mut detached = corrected.clone();
        detached.project_id.clear();
        store.set_receive_workflow("", &link.id, &detached).unwrap();
        assert!(retry().unwrap_err().contains("must still select"));
        let mut other = project();
        other.id = "other".into();
        other.directory = "other".into();
        other.receive = true;
        other.recipients = updated.recipients.clone();
        store.save_delivery_project("", "admin", other).unwrap();
        detached.project_id = "other".into();
        store.set_receive_workflow("", &link.id, &detached).unwrap();
        assert!(retry().unwrap_err().contains("must still select"));
        assert_eq!(
            serde_json::to_value(store.delivery_job(&failed.id).unwrap().unwrap()).unwrap(),
            before
        );
        store
            .set_receive_workflow("", &link.id, &corrected)
            .unwrap();
        updated.receive = false;
        updated = store.save_delivery_project("", "admin", updated).unwrap();
        assert!(retry().unwrap_err().contains("no longer accepts"));
        updated.receive = true;
        updated = store.save_delivery_project("", "admin", updated).unwrap();
        let retried = retry().unwrap();
        assert_eq!(retried.project, updated);
        assert_eq!(retried.id, failed.id);
        assert_eq!(retried.received, failed.received);
        store.append_upload("", &link.id, upload).unwrap();
        assert_eq!(
            store
                .delivery_jobs("", "", 100, None, "", "")
                .unwrap()
                .len(),
            2
        );
        let mut frozen = retried;
        frozen.state = "failed".into();
        frozen.manifest = Some("frozen-manifest".into());
        frozen.approved_by = Some("approver".into());
        frozen.checks["destinations"][&route.id] = serde_json::json!({"state":"complete"});
        store
            .with(|connection| save_job(connection, &frozen))
            .unwrap();
        updated.label = "Changed project".into();
        store.save_delivery_project("", "admin", updated).unwrap();
        assert!(retry().is_err());
        assert_eq!(
            serde_json::to_value(store.delivery_job(&failed.id).unwrap().unwrap()).unwrap(),
            serde_json::to_value(frozen).unwrap()
        );
    }

    #[test]
    fn partial_reception_stays_protected_without_queuing_copies() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut policy = project();
        policy.receive = true;
        let policy = store.save_delivery_project("", "admin", policy).unwrap();
        let workflow = crate::workflow::ReceiveWorkflow {
            notifications: None,
            project_id: policy.id,
            metadata: request().metadata,
            recipients: vec![],
        };
        let link = crate::store::tests::test_link("incoming");
        store
            .insert_link_with_workflow(link.clone(), Some(&workflow))
            .unwrap();
        let mut upload = UploadRecord {
            id: "partial".into(),
            started_at: 1,
            completed_at: 2,
            replayed_chunks: 0,
            rejected_chunks: 0,
            transport: Some("http".into()),
            package_root: "package".into(),
            total_bytes: 1,
            partial: true,
            log: vec![],
            files: vec![FileRecord {
                path: "file.bin".into(),
                stored_as: "file.bin".into(),
                bytes: 1,
                suite: "blake3".into(),
                root: "root".into(),
                receipt: true,
                deleted: false,
            }],
        };
        let mut raw = crate::store::tests::test_outbound_grant("existing", "", 0);
        raw.link_id = link.id.clone();
        raw.upload_id = upload.id.clone();
        store.insert_outbound_grant(raw.clone()).unwrap();
        assert!(store.delivery_release(&raw.id).unwrap().is_none());
        store.append_upload("", &link.id, upload.clone()).unwrap();
        assert!(store
            .delivery_jobs("", "", 100, None, "", "")
            .unwrap()
            .is_empty());
        assert!(!store.receive_workflow_pending("", &link.id).unwrap());
        assert!(store.delivery_release(&raw.id).is_err());
        raw.id = "refused".into();
        raw.token_hash = "refused-token".into();
        assert!(store
            .insert_outbound_grant(raw.clone())
            .unwrap_err()
            .contains("project delivery link"));
        let mut disabled = workflow.clone();
        disabled.project_id.clear();
        store.set_receive_workflow("", &link.id, &disabled).unwrap();
        store
            .with(|connection| connection.execute("DELETE FROM delivery_policy_cache", []))
            .unwrap();
        assert!(store.delivery_release("existing").is_err());
        assert!(store
            .insert_outbound_grant(raw.clone())
            .unwrap_err()
            .contains("project delivery link"));
        upload.id = "ordinary".into();
        store.append_upload("", &link.id, upload.clone()).unwrap();
        raw.id = "ordinary".into();
        raw.token_hash = "ordinary-token".into();
        raw.upload_id = upload.id.clone();
        store.insert_outbound_grant(raw).unwrap();
        assert!(store.delivery_release("ordinary").unwrap().is_none());
        store.set_receive_workflow("", &link.id, &workflow).unwrap();
        upload.partial = false;
        upload.id = "complete".into();
        store.append_upload("", &link.id, upload).unwrap();
        drop(store);
        let reopened = Store::open(directory.path()).unwrap();
        let connection = reopened.connection.lock().unwrap();
        assert!(received_requires_workflow(&connection, "", &link.id, "complete").unwrap());
        assert!(!received_requires_workflow(&connection, "other", &link.id, "complete").unwrap());
    }

    fn prepared_reception(store: &Store) -> (Job, crate::workflow::ReceiveWorkflow) {
        let mut project = project();
        project.receive = true;
        project.require_approval = false;
        let project = store.save_delivery_project("", "local", project).unwrap();
        let workflow = crate::workflow::ReceiveWorkflow {
            notifications: None,
            project_id: project.id.clone(),
            metadata: request().metadata,
            recipients: vec![],
        };
        let mut link = crate::store::tests::test_link("incoming");
        link.active = false;
        link.expires_at = Some(1);
        store
            .insert_link_with_workflow(link, Some(&workflow))
            .unwrap();
        store
            .append_upload(
                "",
                "incoming",
                UploadRecord {
                    id: "received".into(),
                    started_at: 1,
                    completed_at: 2,
                    replayed_chunks: 0,
                    rejected_chunks: 0,
                    transport: Some("http".into()),
                    package_root: "package".into(),
                    total_bytes: 1,
                    partial: false,
                    log: vec![],
                    files: vec![FileRecord {
                        path: "file.bin".into(),
                        stored_as: "file.bin".into(),
                        bytes: 1,
                        suite: "blake3".into(),
                        root: "abc".into(),
                        receipt: true,
                        deleted: false,
                    }],
                },
            )
            .unwrap();
        let job = store
            .claim_delivery_job("worker", now_unix())
            .unwrap()
            .unwrap();
        let mut grant = grant(&job);
        grant.link_id.clear();
        grant.upload_id.clear();
        grant.files[0].source = "received:file.bin".into();
        store
            .insert_workflow_grant(grant, None, Some(&job), None)
            .unwrap();
        (store.delivery_job(&job.id).unwrap().unwrap(), workflow)
    }

    #[test]
    fn reprocess_validates_current_policy_identity_and_inactive_state() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let (original, mut workflow) = prepared_reception(&store);
        let identity = crate::auth::AdminIdentity::local_admin();
        let manifest = original.manifest.as_deref().unwrap();
        assert!(store
            .reprocess_received_job(&identity, &original.id, manifest, original.project.revision)
            .is_err());
        let mut project = original.project.clone();
        project.required_metadata.push("take".into());
        project.recipients.push(crate::workflow::Recipient {
            email: "editor@example.com".into(),
            holder: store.event_signer.public_hex.clone(),
        });
        let project = store.save_delivery_project("", "local", project).unwrap();
        let attempt = |identity: &crate::auth::AdminIdentity| {
            store.reprocess_received_job(identity, &original.id, manifest, project.revision)
        };
        assert!(attempt(&identity).unwrap_err().contains("metadata"));
        workflow.metadata.insert("take".into(), "02".into());
        workflow
            .recipients
            .push(store.event_signer.public_hex.clone());
        workflow.notifications = Some(NotificationPolicy {
            mode: NotificationMode::Default,
            rules: vec![],
        });
        store
            .set_receive_workflow("", "incoming", &workflow)
            .unwrap();
        for (subject, role, tenant, credential_version) in [
            ("observer", "viewer", "", 1),
            ("approver", "viewer", "", 1),
            ("local", "auditor", "", 1),
            ("automation:token", "admin", "", 1),
            ("local", "admin", "other", 1),
            ("sender", "viewer", "", 2),
        ] {
            let mut denied = identity.clone();
            denied.subject = subject.into();
            denied.role = role.into();
            denied.tenant = tenant.into();
            denied.credential_version = credential_version;
            assert!(attempt(&denied).is_err(), "{subject}/{role}/{tenant}");
        }
        assert!(store
            .reprocess_received_job(&identity, &original.id, "changed", project.revision)
            .is_err());
        assert!(store
            .reprocess_received_job(&identity, &original.id, manifest, project.revision + 1)
            .is_err());
        for state in [
            "queued",
            "preparing",
            "exporting",
            "cancelled",
            "retiring",
            "retired",
            "suspended",
        ] {
            let mut busy = original.clone();
            busy.state = state.into();
            store.with(|c| save_job(c, &busy)).unwrap();
            assert!(attempt(&identity).is_err(), "{state}");
            assert_eq!(
                serde_json::to_value(store.delivery_job(&original.id).unwrap().unwrap()).unwrap(),
                serde_json::to_value(&busy).unwrap()
            );
        }
        store.with(|c| save_job(c, &original)).unwrap();
        let mut detached = workflow.clone();
        detached.project_id.clear();
        store
            .set_receive_workflow("", "incoming", &detached)
            .unwrap();
        assert!(attempt(&identity)
            .unwrap_err()
            .contains("must still select"));
        let mut other = project.clone();
        other.id = "other".into();
        other.directory = "other".into();
        other.revision = 0;
        store.save_delivery_project("", "local", other).unwrap();
        detached.project_id = "other".into();
        store
            .set_receive_workflow("", "incoming", &detached)
            .unwrap();
        assert!(attempt(&identity)
            .unwrap_err()
            .contains("must still select"));
        store
            .set_receive_workflow("", "incoming", &workflow)
            .unwrap();
        assert_eq!(
            serde_json::to_value(store.delivery_job(&original.id).unwrap().unwrap()).unwrap(),
            serde_json::to_value(&original).unwrap()
        );
        let replacement = attempt(&identity).unwrap();
        assert_eq!(replacement.request.metadata, workflow.metadata);
        assert_eq!(replacement.request.recipients, workflow.recipients);
        assert_eq!(replacement.request.notifications, workflow.notifications);
        assert!(received_requires_workflow(
            &store.connection.lock().unwrap(),
            "",
            "incoming",
            "received"
        )
        .unwrap());
    }

    #[test]
    fn reprocess_replay_survives_successor_retry_and_fences_old_workers() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let (original, _) = prepared_reception(&store);
        let original_token = store.delivery_job_token("", &original.id).unwrap();
        assert_eq!(hex::decode(&original_token).unwrap().len(), 16);
        let mut project = original.project.clone();
        project.label.push_str(" changed");
        let project = store.save_delivery_project("", "local", project).unwrap();
        let mut identity = crate::auth::AdminIdentity::local_admin();
        identity.subject = "sender".into();
        identity.role = "viewer".into();
        let (replacement, repeated) = std::thread::scope(|threads| {
            let reprocess = || {
                store
                    .reprocess_received_job(
                        &identity,
                        &original.id,
                        original.manifest.as_deref().unwrap(),
                        project.revision,
                    )
                    .unwrap()
            };
            let first = threads.spawn(reprocess);
            let second = threads.spawn(reprocess);
            (first.join().unwrap(), second.join().unwrap())
        });
        assert_eq!(replacement.id, repeated.id);
        let replacement_token = store.delivery_job_token("", &replacement.id).unwrap();
        assert_eq!(hex::decode(&replacement_token).unwrap().len(), 16);
        assert_ne!(replacement_token, original_token);
        assert!(!serde_json::to_string(&replacement)
            .unwrap()
            .contains(&replacement_token));
        assert_eq!(
            replacement.reprocessed_from.as_deref(),
            Some(original.id.as_str())
        );
        assert_eq!(
            store
                .delivery_job(&original.id)
                .unwrap()
                .unwrap()
                .reprocessed_as
                .as_deref(),
            Some(replacement.id.as_str())
        );
        let upload = store
            .link_upload("", "incoming", "received")
            .unwrap()
            .unwrap();
        store.append_upload("", "incoming", upload).unwrap();
        assert_eq!(
            store.delivery_job_token("", &original.id).unwrap(),
            original_token
        );
        assert_eq!(
            store.delivery_job_token("", &replacement.id).unwrap(),
            replacement_token
        );
        assert_eq!(
            store
                .delivery_jobs("", "", 100, None, "", "")
                .unwrap()
                .len(),
            2
        );
        store
            .fail_delivery_job(&original.id, original.attempts, "late failure")
            .unwrap();
        assert!(store
            .complete_delivery_export(&original.id, original.attempts, "old", "late")
            .is_err());
        let mut stale = original.clone();
        stale.state = "preparing".into();
        assert!(store
            .insert_workflow_grant(grant(&stale), None, Some(&stale), None)
            .is_err());
        assert_eq!(
            store.delivery_job(&original.id).unwrap().unwrap().state,
            "cancelled"
        );
        let running = store
            .claim_delivery_job("worker", now_unix())
            .unwrap()
            .unwrap();
        store
            .fail_delivery_job(&running.id, running.attempts, "failed before manifest")
            .unwrap();
        let mut later = project.clone();
        later.label.push_str(" again");
        let later = store.save_delivery_project("", "local", later).unwrap();
        store
            .change_delivery_job("", &replacement.id, "sender", false, "retry", None)
            .unwrap();
        let recovered = store
            .reprocess_received_job(
                &identity,
                &original.id,
                original.manifest.as_deref().unwrap(),
                project.revision,
            )
            .unwrap();
        assert_eq!(recovered.id, replacement.id);
        assert_eq!(
            store.delivery_job_token("", &recovered.id).unwrap(),
            replacement_token
        );
        assert_eq!(recovered.project.revision, later.revision);
        store.provision_principal("sender", None).unwrap();
        store.revoke_principal("sender").unwrap();
        assert!(actor_active(&store.connection.lock().unwrap(), &recovered).is_err());
        let blocked = store
            .claim_delivery_job("worker", now_unix())
            .unwrap()
            .unwrap();
        let mut blocked_grant = grant(&blocked);
        blocked_grant.link_id.clear();
        blocked_grant.upload_id.clear();
        blocked_grant.files[0].source = "received:file.bin".into();
        assert!(store
            .insert_workflow_grant(blocked_grant, None, Some(&blocked), None)
            .unwrap_err()
            .contains("identity"));
        assert!(store
            .outbound_grant_by_id(&replacement.id)
            .unwrap()
            .is_none());
        assert!(store
            .reprocess_received_job(
                &identity,
                &original.id,
                original.manifest.as_deref().unwrap(),
                project.revision
            )
            .is_err());
        assert!(actor_active(&store.connection.lock().unwrap(), &original).is_ok());
        let mut forged = original.clone();
        forged.actor = "reception:another-link".into();
        assert!(actor_active(&store.connection.lock().unwrap(), &forged).is_err());
    }

    #[test]
    fn reprocess_source_and_capacity_refusals_leave_old_delivery_intact() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let (original, _) = prepared_reception(&store);
        let mut project = original.project.clone();
        project.label.push_str(" changed");
        let project = store.save_delivery_project("", "local", project).unwrap();
        let identity = crate::auth::AdminIdentity::local_admin();
        let mut disabled = project.clone();
        disabled.receive = false;
        let disabled = store.save_delivery_project("", "local", disabled).unwrap();
        assert!(store
            .reprocess_received_job(
                &identity,
                &original.id,
                original.manifest.as_deref().unwrap(),
                disabled.revision
            )
            .unwrap_err()
            .contains("no longer accepts"));
        let mut enabled = disabled;
        enabled.receive = true;
        let project = store.save_delivery_project("", "local", enabled).unwrap();
        let attempt = || {
            store.reprocess_received_job(
                &identity,
                &original.id,
                original.manifest.as_deref().unwrap(),
                project.revision,
            )
        };
        store.with(|c| c.execute_batch("INSERT INTO inbound_routes(id,tenant,link_id,issuer,operation_id,source,ancestry,upload_id,revoked_at,created_at) VALUES ('route','','incoming','issuer','operation','{}','[]','received',1,1); INSERT INTO route_uploads(route_id,upload_id,partial) VALUES ('route','received',0)")).unwrap();
        assert!(attempt().unwrap_err().contains("revoked"));
        store
            .with(|c| {
                c.execute_batch(
                    "UPDATE inbound_routes SET revoked_at=NULL; UPDATE route_uploads SET partial=1",
                )
            })
            .unwrap();
        assert!(attempt().unwrap_err().contains("incomplete"));
        store
            .with(|c| c.execute_batch("DELETE FROM route_uploads; DELETE FROM inbound_routes"))
            .unwrap();
        let uploaded = store
            .link_upload("", "incoming", "received")
            .unwrap()
            .unwrap();
        for change in ["partial", "deleted", "content", "name", "empty"] {
            let mut changed = uploaded.clone();
            match change {
                "partial" => changed.partial = true,
                "deleted" => changed.files[0].deleted = true,
                "content" => changed.files[0].root = "different".into(),
                "name" => changed.files[0].path = "different.bin".into(),
                _ => changed.files.clear(),
            }
            store
                .with(|c| {
                    super::write_upload(c, "", "incoming", &changed)?;
                    super::sync_upload_files(c, "incoming", "", &changed)
                })
                .unwrap();
            assert!(attempt().is_err(), "{change}");
        }
        store
            .with(|c| {
                super::write_upload(c, "", "incoming", &uploaded)?;
                super::sync_upload_files(c, "incoming", "", &uploaded)
            })
            .unwrap();
        store.with(|c| c.execute("WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<1000) INSERT INTO delivery_jobs(id,tenant,actor,operation_id,project_id,state,not_before,document,token) SELECT 'busy_'||i,'','sender','busy_'||i,'project','queued',0,'{}','unused' FROM n",[])).unwrap();
        assert!(attempt().unwrap_err().contains("active job limit"));
        assert_eq!(
            serde_json::to_value(store.delivery_job(&original.id).unwrap().unwrap()).unwrap(),
            serde_json::to_value(&original).unwrap()
        );
        assert!(store
            .outbound_grant_by_id(&original.id)
            .unwrap()
            .unwrap()
            .revoked_at
            .is_none());
        store
            .with(|c| c.execute("DELETE FROM delivery_jobs WHERE id='busy_1000'", []))
            .unwrap();
        let mut pending = original.clone();
        pending.state = "awaiting_approval".into();
        store.with(|c| save_job(c, &pending)).unwrap();
        assert!(attempt().is_ok());
    }

    #[test]
    fn reprocess_retains_completed_peer_evidence_and_reports_the_current_successor() {
        let directory = tempfile::tempdir().unwrap();
        let source_directory = tempfile::tempdir().unwrap();
        let peer_directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let signer =
            crate::receipt::ReceiptSigner::load_or_create(source_directory.path()).unwrap();
        let peer = crate::receipt::ReceiptSigner::load_or_create(peer_directory.path()).unwrap();
        let (original, _) = prepared_reception(&store);
        let route = crate::store::TradeRoute {
            id: "incoming-route".into(),
            revision: 1,
            tenant: String::new(),
            direction: "incoming".into(),
            name: "Source".into(),
            peer_name: "Source".into(),
            peer_key: signer.public_hex.clone(),
            address: "http://localhost".into(),
            endpoint: "incoming".into(),
            endpoint_name: "Incoming".into(),
            category: "internal".into(),
            forwarding: true,
            metadata_keys: vec![],
            state: "active".into(),
            notifications: Default::default(),
            last_contact: None,
            error: None,
            remote_grant: String::new(),
            remote_state: "active".into(),
            cancel_active: false,
        };
        let source = signer.sign_route(crate::route_protocol::RouteDocument {
            issuer: signer.public_hex.clone(),
            operation_id: "incoming-operation".into(),
            manifest: original.manifest.clone().unwrap(),
            label: "Received".into(),
            metadata: Default::default(),
            parent_receipt: None,
            visited: vec![signer.public_hex.clone()],
            permission: Some(crate::route_protocol::RoutePermission {
                receiver: store.event_signer.public_hex.clone(),
                grant: route.id.clone(),
                forwarding: true,
            }),
        });
        let receipt = store
            .event_signer
            .route_receipt(source.clone(), "received".into(), 2);
        store.with(|c| {
            c.execute("INSERT INTO inbound_routes(id,tenant,link_id,issuer,operation_id,source,ancestry,upload_id,receipt,created_at) VALUES ('inbound','','incoming',?1,'incoming-operation',?2,'[]','received',?3,1)",params![signer.public_hex,serde_json::to_string(&source).unwrap(),serde_json::to_string(&receipt).unwrap()])?;
            c.execute("INSERT INTO route_uploads(route_id,upload_id,partial) VALUES ('inbound','received',0)",[])
        }).unwrap();
        let config = store.save_delivery_storage("local", serde_json::from_value(serde_json::json!({"id":"downstream","revision":0,"label":"Peer","kind":"votport","endpoint":"http://localhost","tenants":[""],"enabled":true})).unwrap(),Some(crate::api::outbound::workflows::storage::Credentials::Votport { request_url: format!("http://localhost/r/{}", "ab".repeat(16)), password: None })).unwrap();
        let mut project = original.project.clone();
        project.destinations = vec![config.id.clone()];
        let project = store.save_delivery_project("", "local", project).unwrap();
        let identity = crate::auth::AdminIdentity::local_admin();
        let first = store
            .reprocess_received_job(
                &identity,
                &original.id,
                original.manifest.as_deref().unwrap(),
                project.revision,
            )
            .unwrap();
        let mut preparing = store
            .claim_delivery_job("worker", now_unix())
            .unwrap()
            .unwrap();
        preparing.checks["destination_revisions"] =
            serde_json::json!({"downstream":config.revision});
        let mut first_grant = grant(&preparing);
        first_grant.link_id.clear();
        first_grant.upload_id.clear();
        first_grant.files[0].source = "received:file.bin".into();
        store
            .insert_workflow_grant(first_grant, None, Some(&preparing), None)
            .unwrap();
        let exporting = store
            .claim_delivery_job("worker", now_unix())
            .unwrap()
            .unwrap();
        let outgoing = store
            .event_signer
            .sign_route(crate::route_protocol::RouteDocument {
                issuer: store.event_signer.public_hex.clone(),
                operation_id: first.id.clone(),
                manifest: original.manifest.clone().unwrap(),
                label: "Forwarded".into(),
                metadata: Default::default(),
                parent_receipt: Some(receipt.digest()),
                visited: vec![
                    signer.public_hex.clone(),
                    store.event_signer.public_hex.clone(),
                ],
                permission: None,
            });
        let completed = peer.route_receipt(outgoing.clone(), "remote-upload".into(), 3);
        store
            .bind_outbound_route(
                &exporting,
                "downstream",
                "http://localhost",
                "remote-route",
                &peer.public_hex,
                &outgoing,
            )
            .unwrap();
        store
            .record_route_receipt(&exporting, "downstream", &completed)
            .unwrap();
        store
            .complete_delivery_export(
                &first.id,
                exporting.attempts,
                "downstream",
                "receipt:complete",
            )
            .unwrap();
        assert_eq!(
            store.trade_deliveries(&route).unwrap()[0]["workflow"],
            "ready"
        );
        let retained = store.delivery_job(&first.id).unwrap().unwrap();
        let mut current = project;
        current.destinations.clear();
        let current = store.save_delivery_project("", "local", current).unwrap();
        let next = store
            .reprocess_received_job(
                &identity,
                &first.id,
                retained.manifest.as_deref().unwrap(),
                current.revision,
            )
            .unwrap();
        let status = store.trade_deliveries(&route).unwrap();
        assert_eq!(status.as_array().unwrap().len(), 1);
        assert_eq!(status[0]["workflow"], "queued");
        assert_eq!(status[0]["released"], false);
        assert_eq!(
            store.delivery_job(&first.id).unwrap().unwrap().checks,
            retained.checks
        );
        let control = store.claim_route_revocation(now_unix()).unwrap().unwrap();
        assert_eq!(control.job_id, first.id);
        assert_eq!(control.request.document.source, outgoing);
        assert!(control.request.verify());
        let revoke = signer.revoke_route(source, store.event_signer.public_hex.clone(), "inbound");
        store.revoke_inbound_route("inbound", &revoke).unwrap();
        assert_eq!(
            store.delivery_job(&next.id).unwrap().unwrap().state,
            "cancelled"
        );
        assert!(store
            .reprocess_received_job(
                &identity,
                &next.id,
                retained.manifest.as_deref().unwrap(),
                current.revision
            )
            .is_err());
        assert!(store.receive_workflow_pending("", "incoming").unwrap());
    }

    fn grant(job: &Job) -> OutboundGrant {
        let mut grant = crate::store::tests::test_outbound_grant(&job.id, &job.tenant, 0);
        grant.expires_at = now_unix() + 3600;
        grant.bytes = 1;
        grant.files = vec![OutboundGrantFile {
            source: if job.uses_snapshot() {
                format!("workflow:{}/file.bin", job.id)
            } else {
                format!("{}/file.bin", job.project.directory)
            },
            name: "file.bin".into(),
            suite: "blake3".into(),
            root: "abc".into(),
            bytes: 1,
            receipt_b64: "receipt".into(),
            downloads: 0,
            first_download_at: None,
            last_download_at: None,
        }];
        grant
    }

    #[test]
    fn rotated_unadmitted_tickets_release_reservations_but_admitted_tickets_keep_them() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let now = now_unix();
        let mut grant = crate::store::tests::test_outbound_grant("capped", "", 0);
        grant.expires_at = now + 3600;
        grant.max_downloads = Some(1);
        store.insert_outbound_grant(grant.clone()).unwrap();
        let ticket = FetchTicket {
            holder: "first-holder".into(),
            grant_token_hash: grant.token_hash.clone(),
            policy_revision: 0,
            token_id: "first".into(),
            grant_id: grant.id.clone(),
            manifest_root: "root".into(),
            expires_at: now + 600,
            delivered_at: None,
        };
        assert!(store.put_fetch_ticket(&ticket, now).unwrap());
        let mut next = ticket.clone();
        next.token_id = "second".into();
        next.holder = "second-holder".into();
        assert!(!store.put_fetch_ticket(&next, now).unwrap());
        store
            .rotate_outbound_grant_token("", &grant.id, "rotated")
            .unwrap();
        assert!(!store.admit_fetch_ticket(&ticket, now).unwrap());
        next.grant_token_hash = crate::auth::hash_token("rotated");
        assert!(store.put_fetch_ticket(&next, now).unwrap());
        assert!(store.admit_fetch_ticket(&next, now).unwrap());
        store
            .rotate_outbound_grant_token("", &grant.id, "again")
            .unwrap();
        let mut third = next.clone();
        third.token_id = "third".into();
        third.grant_token_hash = crate::auth::hash_token("again");
        assert!(!store.put_fetch_ticket(&third, now).unwrap());
        assert!(!store.admit_fetch_ticket(&next, now).unwrap());
        assert!(!store.admit_fetch_ticket(&third, now).unwrap());
    }

    #[test]
    fn interrupted_fetch_can_be_replaced_by_its_holder_only() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let now = now_unix();
        let mut grant = crate::store::tests::test_outbound_grant("capped", "", 0);
        grant.expires_at = now + 3600;
        grant.max_downloads = Some(1);
        store.insert_outbound_grant(grant.clone()).unwrap();
        let ticket = |token_id: &str, holder: &str| FetchTicket {
            holder: holder.into(),
            grant_token_hash: grant.token_hash.clone(),
            policy_revision: 0,
            token_id: token_id.into(),
            grant_id: grant.id.clone(),
            manifest_root: "root".into(),
            expires_at: now + 600,
            delivered_at: None,
        };
        let first = ticket("first", "holder-a");
        assert!(store.put_fetch_ticket(&first, now).unwrap());
        assert!(
            store
                .put_fetch_ticket(&ticket("retry", "holder-a"), now)
                .unwrap(),
            "an unadmitted interrupted ticket is replaceable by its holder"
        );
        assert!(
            store.fetch_ticket("first").unwrap().is_none(),
            "the replaced ticket cannot remain admissible"
        );
        assert!(
            !store.admit_fetch_ticket(&first, now).unwrap(),
            "the replaced ticket cannot admit after the replacement"
        );
        assert!(
            store
                .admit_fetch_ticket(&ticket("retry", "holder-a"), now)
                .unwrap(),
            "the replacement ticket admits"
        );
        assert!(
            !store
                .put_fetch_ticket(&ticket("after-admission", "holder-a"), now)
                .unwrap(),
            "an admitted ticket cannot be replaced by a retry"
        );
        assert!(
            !store
                .put_fetch_ticket(&ticket("other", "holder-b"), now)
                .unwrap(),
            "another holder cannot bypass the outstanding reservation"
        );
    }

    #[test]
    fn imported_approval_rechecks_storage_authority() {
        use crate::api::outbound::workflows::storage::Storage;
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let config = store
            .save_delivery_storage(
                "admin",
                Storage {
                    id: "s3".into(),
                    revision: 0,
                    label: "S3".into(),
                    kind: Default::default(),
                    directory: String::new(),
                    endpoint: "http://127.0.0.1:9000".into(),
                    bucket: "delivery".into(),
                    region: "us-east-1".into(),
                    prefix: String::new(),
                    path_style: true,
                    kms_key_id: None,
                    tenants: vec![String::new()],
                    enabled: true,
                },
                None,
            )
            .unwrap();
        let mut remaining = config.clone();
        remaining.id = "remaining".into();
        remaining.revision = 0;
        let remaining = store
            .save_delivery_storage("admin", remaining, None)
            .unwrap();
        let mut policy = project();
        policy.destinations = vec![config.id.clone(), remaining.id.clone()];
        policy.release = crate::workflow::Release::Local;
        let project = store.save_delivery_project("", "admin", policy).unwrap();
        let mut request = request();
        request.import = Some(crate::workflow::Import {
            storage_id: "s3".into(),
            prefix: "source".into(),
        });
        store
            .enqueue_delivery_job("", "sender", 1, None, project, request)
            .unwrap();
        let mut job = store
            .claim_delivery_job("boot", now_unix())
            .unwrap()
            .unwrap();
        job.checks["import_storage_revision"] = serde_json::json!(config.revision);
        job.checks["destination_revisions"] =
            serde_json::json!({"s3":config.revision,"remaining":remaining.revision});
        store
            .insert_workflow_grant(grant(&job), None, Some(&job), None)
            .unwrap();
        let pending = store.delivery_job(&job.id).unwrap().unwrap();
        for change in ["disabled", "tenant", "revision"] {
            let mut withdrawn = config.clone();
            match change {
                "disabled" => withdrawn.enabled = false,
                "tenant" => withdrawn.tenants.clear(),
                _ => withdrawn.revision += 1,
            }
            store
                .with(|connection| {
                    connection
                        .execute(
                            "UPDATE delivery_storage SET document=?1 WHERE id='s3'",
                            [serde_json::to_string(&withdrawn).unwrap()],
                        )
                        .map(|_| ())
                })
                .unwrap();
            assert!(
                store
                    .change_delivery_job(
                        "",
                        &job.id,
                        "approver",
                        false,
                        "approve",
                        pending.manifest.as_deref()
                    )
                    .is_err(),
                "{change}"
            );
        }
        store
            .with(|connection| {
                connection
                    .execute(
                        "UPDATE delivery_storage SET document=?1 WHERE id='s3'",
                        [serde_json::to_string(&config).unwrap()],
                    )
                    .map(|_| ())
            })
            .unwrap();
        store
            .change_delivery_job(
                "",
                &job.id,
                "approver",
                false,
                "approve",
                pending.manifest.as_deref(),
            )
            .unwrap();
        assert!(store
            .delivery_access(&job.id, &grant(&job).token_hash)
            .unwrap()
            .is_some());
        let exporting = store
            .claim_delivery_job("worker", now_unix())
            .unwrap()
            .unwrap();
        assert!(store
            .require_delivery_destination(&job.id, exporting.attempts, "remaining")
            .is_ok());
        for (attempt, destination) in [
            (exporting.attempts - 1, "remaining"),
            (exporting.attempts, "foreign"),
        ] {
            assert!(store
                .require_delivery_destination(&job.id, attempt, destination)
                .is_err());
            assert!(store
                .complete_delivery_export(&job.id, attempt, destination, "complete.json")
                .is_err());
            assert!(store
                .fail_delivery_destination(&job.id, attempt, destination, "failed")
                .is_err());
        }
        store
            .complete_delivery_export(&job.id, exporting.attempts, "s3", "complete.json")
            .unwrap();
        let mut withdrawn = config.clone();
        withdrawn.enabled = false;
        store
            .save_delivery_storage("admin", withdrawn, None)
            .unwrap();
        assert!(store
            .require_delivery_export(&job.id, exporting.attempts)
            .unwrap_err()
            .contains("storage authorization"));
        assert!(store
            .require_delivery_destination(&job.id, exporting.attempts, "remaining")
            .is_err());
        assert!(store
            .complete_delivery_export(&job.id, exporting.attempts, "remaining", "complete.json")
            .is_err());
        assert!(store
            .fail_delivery_destination(&job.id, exporting.attempts, "remaining", "failed")
            .is_err());
        store
            .with(|connection| {
                connection.execute(
                    "UPDATE delivery_storage SET revision=?1,document=?2 WHERE id='s3'",
                    params![
                        config.revision as i64,
                        serde_json::to_string(&config).unwrap()
                    ],
                )
            })
            .unwrap();
        store
            .change_delivery_job("", &job.id, "sender", false, "cancel", None)
            .unwrap();
        assert!(store
            .require_delivery_destination(&job.id, exporting.attempts, "remaining")
            .is_err());
        assert!(store
            .complete_delivery_export(&job.id, exporting.attempts, "remaining", "complete.json")
            .is_err());
        assert!(store
            .fail_delivery_destination(&job.id, exporting.attempts, "remaining", "failed")
            .is_err());
    }

    #[test]
    fn cached_policy_checks_skip_files_and_invalidate_on_project_writes() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let project = store.save_delivery_project("", "admin", project()).unwrap();
        let job = store
            .enqueue_delivery_job("", "sender", 1, None, project, request())
            .unwrap();
        let mut legacy = grant(&job);
        legacy.id = "legacy".into();
        legacy.files[0].source = "public/file.bin".into();
        store.insert_outbound_grant(legacy.clone()).unwrap();
        let visits = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&visits);
        store
            .connection
            .lock()
            .unwrap()
            .create_scalar_function(
                "votport_within",
                2,
                rusqlite::functions::FunctionFlags::SQLITE_DETERMINISTIC,
                move |context| {
                    count.fetch_add(1, Ordering::Relaxed);
                    Ok(crate::workflow::within(
                        &context.get::<String>(0)?,
                        &context.get::<String>(1)?,
                    ))
                },
            )
            .unwrap();
        assert!(store
            .delivery_access(&legacy.id, &legacy.token_hash)
            .unwrap()
            .is_none());
        assert!(visits.load(Ordering::Relaxed) > 0);
        visits.store(0, Ordering::Relaxed);
        for _ in 0..100 {
            assert!(store
                .delivery_access(&legacy.id, &legacy.token_hash)
                .unwrap()
                .is_none());
        }
        assert_eq!(
            visits.load(Ordering::Relaxed),
            0,
            "cached admissions must not inspect package files"
        );
        assert!(store.delivery_access(&legacy.id, "wrong-token").is_err());
        let mut protected = crate::workflow::tests::project();
        protected.id = "public".into();
        protected.directory = "PUBLIC".into();
        store.save_delivery_project("", "admin", protected).unwrap();
        assert!(store
            .delivery_access(&legacy.id, &legacy.token_hash)
            .is_err());
        assert!(
            visits.load(Ordering::Relaxed) > 0,
            "new policies must invalidate admitted legacy links"
        );
    }

    #[test]
    fn delivery_audit_decision_precedes_a_concurrent_revocation() {
        use std::sync::mpsc;
        use std::time::Duration;

        let directory = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(Store::open(directory.path()).unwrap());
        let mut grant = crate::store::tests::test_outbound_grant("audited", "", 0);
        grant.expires_at = now_unix() + 3600;
        store.insert_outbound_grant(grant.clone()).unwrap();
        let grant_id = grant.id.clone();
        let detail = serde_json::json!({"mode": "file", "client_ip": "127.0.0.1"});
        let (started_tx, started_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        let revoker = std::thread::spawn({
            let store = std::sync::Arc::clone(&store);
            let grant_id = grant_id.clone();
            move || {
                started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
                store
                    .revoke_outbound_grant("", &grant_id, now_unix())
                    .unwrap();
                finished_tx.send(()).unwrap();
            }
        });

        store
            .delivery_access_with_audit(&grant.id, &grant.token_hash, "", &detail, |access| {
                assert!(access.is_ok());
                assert!(
                    store.connection.try_lock().is_err(),
                    "the access callback must hold the Store connection"
                );
                started_tx.send(()).unwrap();
                assert!(finished_rx.recv_timeout(Duration::from_millis(50)).is_err());
                Ok::<_, ()>(())
            })
            .unwrap();
        assert_eq!(
            store
                .audit_export(None, 0, 0, 100)
                .unwrap()
                .iter()
                .filter(|row| row.event == "outbound_downloaded")
                .count(),
            1
        );
        finished_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        revoker.join().unwrap();
        assert!(store.delivery_access(&grant.id, &grant.token_hash).is_err());
    }

    #[test]
    fn retired_jobs_cannot_extend_or_rotate_and_failed_retirements_do_not_starve() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let project = store.save_delivery_project("", "admin", project()).unwrap();
        let first = store
            .enqueue_delivery_job("", "sender", 1, None, project.clone(), request())
            .unwrap();
        let mut second_request = request();
        second_request.operation_id = "second".into();
        let second = store
            .enqueue_delivery_job("", "sender", 1, None, project, second_request)
            .unwrap();
        for job in [&first, &second] {
            let mut record = job.clone();
            record.state = "retiring".into();
            let connection = store.connection.lock().unwrap();
            save_job(&connection, &record).unwrap();
        }
        let claimed = store
            .claim_snapshot_retirement(now_unix())
            .unwrap()
            .unwrap();
        let next = store
            .claim_snapshot_retirement(now_unix() + 1)
            .unwrap()
            .unwrap();
        assert_ne!(claimed.id, next.id);
        assert!(store
            .rotate_delivery_job_token("", &first.id, 0, "rotated")
            .is_err());
        assert!(store
            .extend_outbound_grant("", &first.id, 86400, now_unix())
            .is_err());
    }

    #[test]
    fn workflow_tokens_survive_retries_and_rotate_atomically() {
        use crate::auth::{hash_token, random_token};

        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let project = store.save_delivery_project("", "admin", project()).unwrap();
        let original = store
            .enqueue_delivery_job("", "sender", 1, None, project.clone(), request())
            .unwrap();
        let token = store.delivery_job_token("", &original.id).unwrap();
        assert_eq!(hex::decode(&token).unwrap().len(), 16);
        assert_ne!(token, original.id);
        assert!(store.delivery_job_token("other", &original.id).is_err());
        assert!(store.delivery_job_token("", "missing").is_err());
        let repeated = store
            .enqueue_delivery_job("", "sender", 1, None, project, request())
            .unwrap();
        assert_eq!(store.delivery_job_token("", &repeated.id).unwrap(), token);
        assert!(!serde_json::to_string(&repeated).unwrap().contains(&token));
        assert!(!store
            .rotate_delivery_job_token("", &original.id, 0, &random_token())
            .unwrap());
        let mut grant = crate::store::tests::test_outbound_grant(&original.id, "", 0);
        grant.token_hash = hash_token(&token);
        grant.expires_at = now_unix() + 3600;
        store.insert_outbound_grant(grant).unwrap();
        assert_eq!(
            store.outbound_share_token("", &original.id).unwrap(),
            Some(token.clone())
        );
        assert!(!store
            .rotate_outbound_grant_token("", &original.id, &random_token())
            .unwrap());
        let snapshot_directory = tempfile::tempdir().unwrap();
        store
            .backup_into(&snapshot_directory.path().join("votport.db"))
            .unwrap();
        let before_events =
            serde_json::to_value(store.delivery_events("", 0, 100).unwrap()).unwrap();
        let before_audit =
            serde_json::to_value(store.audit_export(Some(""), 0, 0, 100).unwrap()).unwrap();
        for trigger in [
            "BEFORE UPDATE OF token_hash ON outbound_grants",
            "BEFORE UPDATE OF token ON delivery_jobs",
            "BEFORE UPDATE OF document ON delivery_jobs",
            "BEFORE INSERT ON delivery_events",
            "BEFORE INSERT ON audit_log",
        ] {
            store.with(|connection| connection.execute_batch(&format!(
                "CREATE TEMP TRIGGER fail_rotation {trigger} BEGIN SELECT RAISE(FAIL,'rotation fixture'); END;"
            ))).unwrap();
            assert!(store
                .rotate_delivery_job_token("", &original.id, 0, &random_token())
                .is_err());
            assert_eq!(store.delivery_job_token("", &original.id).unwrap(), token);
            assert_eq!(
                store
                    .outbound_grant_by_id(&original.id)
                    .unwrap()
                    .unwrap()
                    .token_hash,
                hash_token(&token)
            );
            assert_eq!(
                store
                    .delivery_job(&original.id)
                    .unwrap()
                    .unwrap()
                    .token_generation,
                0
            );
            assert_eq!(
                serde_json::to_value(store.delivery_events("", 0, 100).unwrap()).unwrap(),
                before_events
            );
            assert_eq!(
                serde_json::to_value(store.audit_export(Some(""), 0, 0, 100).unwrap()).unwrap(),
                before_audit
            );
            store
                .with(|connection| connection.execute_batch("DROP TRIGGER fail_rotation"))
                .unwrap();
        }
        assert!(store
            .rotate_delivery_job_token("other", &original.id, 0, &random_token())
            .is_err());
        let candidates = [random_token(), random_token()];
        let results = std::thread::scope(|threads| {
            let workers: Vec<_> = candidates
                .iter()
                .map(|candidate| {
                    let store = &store;
                    let id = &original.id;
                    threads.spawn(move || store.rotate_delivery_job_token("", id, 0, candidate))
                })
                .collect();
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Ok(true)))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| result
                    .as_ref()
                    .is_err_and(|error| error.contains("delivery changed")))
                .count(),
            1
        );
        let current = candidates[results
            .iter()
            .position(|result| matches!(result, Ok(true)))
            .unwrap()]
        .clone();
        assert_eq!(store.delivery_job_token("", &original.id).unwrap(), current);
        assert_eq!(
            store.outbound_share_token("", &original.id).unwrap(),
            Some(current.clone())
        );
        assert_ne!(current, token);
        assert!(store
            .delivery_token_active(&original.id, &hash_token(&current))
            .unwrap());
        assert!(!store
            .delivery_token_active(&original.id, &hash_token(&token))
            .unwrap());
        let events = store.delivery_events("", 0, 100).unwrap();
        assert!(events.iter().all(|event| event.verify()));
        assert_eq!(
            events
                .iter()
                .filter(|event| event.kind == "delivery_link_rotated")
                .count(),
            1
        );
        let rotated = events
            .iter()
            .find(|event| event.kind == "delivery_link_rotated")
            .unwrap();
        let mirrored = store
            .audit_export(Some(""), 0, 0, 100)
            .unwrap()
            .into_iter()
            .filter(|row| row.event == "delivery_link_rotated")
            .collect::<Vec<_>>();
        assert_eq!(mirrored.len(), 1);
        assert_eq!(mirrored[0].detail["delivery_event_id"], rotated.id);
        assert!(!serde_json::to_string(&events).unwrap().contains(&current));
        let snapshot = Store::open(snapshot_directory.path()).unwrap();
        assert_eq!(
            snapshot.delivery_job_token("", &original.id).unwrap(),
            token
        );
        assert_eq!(
            snapshot
                .delivery_job(&original.id)
                .unwrap()
                .unwrap()
                .token_generation,
            0
        );
        drop(store);
        let store = Store::open(directory.path()).unwrap();
        assert_eq!(store.delivery_job_token("", &original.id).unwrap(), current);
        let restored = store.delivery_job(&original.id).unwrap().unwrap();
        assert_eq!(restored.token_generation, 1);
        assert!(!serde_json::to_string(&restored).unwrap().contains(&current));
        store
            .revoke_outbound_grant("", &original.id, now_unix())
            .unwrap();
        assert!(!store
            .rotate_delivery_job_token("", &original.id, 1, &random_token())
            .unwrap());
        assert_eq!(store.delivery_job_token("", &original.id).unwrap(), current);
    }

    #[test]
    fn jobs_recover_idempotently_and_approve_only_the_frozen_manifest() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let project = store.save_delivery_project("", "admin", project()).unwrap();
        let original = store
            .enqueue_delivery_job("", "sender", 1, None, project.clone(), request())
            .unwrap();
        assert_eq!(
            store
                .enqueue_delivery_job("", "sender", 1, None, project.clone(), request())
                .unwrap()
                .id,
            original.id
        );
        let mut changed = request();
        changed.label = "Changed".into();
        assert!(store
            .enqueue_delivery_job("", "sender", 1, None, project.clone(), changed)
            .is_err());
        let first = store
            .claim_delivery_job("boot1", now_unix())
            .unwrap()
            .unwrap();
        assert_eq!(first.attempts, 1);
        assert!(store
            .claim_delivery_job("boot1", now_unix())
            .unwrap()
            .is_none());
        drop(store);
        let store = Store::open(directory.path()).unwrap();
        let job = store
            .claim_delivery_job("boot2", now_unix())
            .unwrap()
            .unwrap();
        assert_eq!(job.id, first.id);
        assert_eq!(job.attempts, 2);
        store
            .fail_delivery_job(&job.id, job.attempts, "fixture interruption")
            .unwrap();
        let retry = store
            .change_delivery_job("", &job.id, "sender", true, "retry", None)
            .unwrap();
        assert!(retry.attempts > job.attempts);
        let stale = job;
        let job = store
            .claim_delivery_job("boot2", now_unix())
            .unwrap()
            .unwrap();
        assert_eq!(retry_attempts(&job), 1);
        store
            .fail_delivery_job(&stale.id, stale.attempts, "stale worker")
            .unwrap();
        assert_eq!(
            store.delivery_job(&job.id).unwrap().unwrap().state,
            "preparing"
        );
        assert!(store
            .insert_workflow_grant(grant(&stale), None, Some(&stale), None)
            .is_err());
        assert!(store
            .insert_workflow_grant(grant(&first), None, Some(&first), None)
            .is_err());
        store
            .insert_workflow_grant(grant(&job), None, Some(&job), None)
            .unwrap();
        let pending = store.delivery_job(&job.id).unwrap().unwrap();
        assert_eq!(pending.state, "awaiting_approval");
        assert!(store.delivery_release(&job.id).is_err());
        let manifest = pending.manifest.as_deref();
        assert!(store
            .change_delivery_job("", &job.id, "sender", true, "approve", manifest)
            .is_err());
        assert!(store
            .change_delivery_job("", &job.id, "observer", false, "approve", manifest)
            .is_err());
        assert!(store
            .change_delivery_job("", &job.id, "approver", false, "approve", Some("different"))
            .is_err());
        let approved = store
            .change_delivery_job("", &job.id, "approver", false, "approve", manifest)
            .unwrap();
        assert_eq!(approved.approved_by.as_deref(), Some("approver"));
        assert_eq!(
            store.delivery_release(&job.id).unwrap().unwrap().state,
            "ready"
        );
        store
            .rotate_delivery_job_token("", &job.id, 0, "rotated")
            .unwrap();
        assert!(store
            .delivery_token_active(&job.id, &crate::auth::hash_token("rotated"))
            .unwrap());
        assert!(!store
            .delivery_token_active(&job.id, &grant(&job).token_hash)
            .unwrap());
        assert!(store
            .rotate_delivery_job_token("", &job.id, 0, "stale")
            .is_err());
        let events = store.delivery_events("", 0, 100).unwrap();
        assert!(!events.is_empty());
        for event in &events {
            assert!(event.verify());
        }
        for pair in events.windows(2) {
            assert_eq!(pair[1].previous_hash, pair[0].hash);
        }
        let mut tampered = events[0].clone();
        tampered.payload["actor"] = serde_json::json!("attacker");
        assert!(!tampered.verify());
        let mut changed = project;
        changed.required_metadata.push("version".into());
        let changed = store.save_delivery_project("", "admin", changed).unwrap();
        assert!(store.delivery_release(&job.id).is_err());
        assert_eq!(
            store
                .enqueue_delivery_job("", "sender", 1, None, changed, request())
                .unwrap()
                .id,
            job.id
        );
    }

    #[test]
    fn cancellations_policy_changes_and_protected_aliases_cannot_publish() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let project = store.save_delivery_project("", "admin", project()).unwrap();
        let job = store
            .enqueue_delivery_job("", "sender", 1, None, project.clone(), request())
            .unwrap();
        let running = store
            .claim_delivery_job("boot", now_unix())
            .unwrap()
            .unwrap();
        store
            .change_delivery_job("", &job.id, "sender", false, "cancel", None)
            .unwrap();
        assert!(store
            .insert_workflow_grant(grant(&running), None, Some(&running), None)
            .is_err());
        assert!(store.outbound_grant_by_id(&job.id).unwrap().is_none());
        for path in [
            "project/file.bin",
            "PROJECT/file.bin",
            "ｐｒｏｊｅｃｔ/file.bin",
        ] {
            let mut grant = grant(&running);
            grant.files[0].source = path.into();
            assert!(store.insert_outbound_grant(grant).is_err());
        }
        let mut overlap = project.clone();
        overlap.id = "overlap".into();
        overlap.revision = 0;
        overlap.directory = "PROJECT/sub".into();
        assert!(store.save_delivery_project("", "admin", overlap).is_err());
        let mut next = request();
        next.operation_id = "next".into();
        store
            .enqueue_delivery_job("", "sender", 1, None, project.clone(), next)
            .unwrap();
        let running = store
            .claim_delivery_job("boot", now_unix())
            .unwrap()
            .unwrap();
        store.save_delivery_project("", "admin", project).unwrap();
        assert!(store
            .insert_workflow_grant(grant(&running), None, Some(&running), None)
            .is_err());
        store
            .fail_delivery_job(&running.id, running.attempts, "changed")
            .unwrap();
        assert!(store
            .change_delivery_job("", &running.id, "sender", false, "retry", None)
            .is_err());
        assert!(store
            .save_delivery_project("missing", "admin", crate::workflow::tests::project())
            .is_err());
    }
}
