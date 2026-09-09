use super::*;
use crate::workflow::{Job, JobRequest, Project};
use rusqlite::params;

pub(super) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS delivery_policy_cache(grant_id TEXT PRIMARY KEY,protected INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS delivery_storage(id TEXT PRIMARY KEY,revision INTEGER NOT NULL,document TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS delivery_projects(tenant TEXT NOT NULL, id TEXT NOT NULL, revision INTEGER NOT NULL, document TEXT NOT NULL, PRIMARY KEY(tenant,id));
CREATE TABLE IF NOT EXISTS delivery_jobs(id TEXT PRIMARY KEY, tenant TEXT NOT NULL, actor TEXT NOT NULL, operation_id TEXT NOT NULL, project_id TEXT NOT NULL, state TEXT NOT NULL, owner TEXT NOT NULL DEFAULT '', not_before INTEGER NOT NULL, deadline INTEGER, escalated INTEGER NOT NULL DEFAULT 0, document TEXT NOT NULL, UNIQUE(tenant,actor,operation_id));
CREATE INDEX IF NOT EXISTS delivery_jobs_ready ON delivery_jobs(state,not_before);
CREATE INDEX IF NOT EXISTS delivery_jobs_tenant ON delivery_jobs(tenant,id);
";

pub(super) fn ensure_tenant(connection: &Connection, tenant: &str) -> Result<(), String> {
    let exists: bool = connection
        .query_row(
            "SELECT ?1='' OR EXISTS(SELECT 1 FROM tenants WHERE key=?1)",
            [tenant],
            |row| row.get(0),
        )
        .map_err(|e| e.to_string())?;
    if exists {
        Ok(())
    } else {
        Err("tenant missing".into())
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
    } else if project.export_storage.is_some() {
        "exporting"
    } else {
        "ready"
    }
    .into();
    current.checks = job.checks.clone();
    if current.state == "exporting" {
        connection
            .execute("UPDATE delivery_jobs SET owner='' WHERE id=?1", [&job.id])
            .map_err(|e| e.to_string())?;
    }
    save_job(connection, &current).map_err(|e| e.to_string())?;
    evidence::delivery_event(connection, signer, &grant.tenant, &grant.id, &format!("delivery_{}", current.state), &serde_json::json!({"manifest": manifest, "project_id": project.id, "policy_revision": project.revision}), current.updated_at).map_err(|e| e.to_string())
}

fn actor_active(connection: &Connection, job: &Job) -> Result<(), String> {
    let active: bool = if let Some(token_id) = &job.automation_token_id {
        connection.query_row("SELECT EXISTS(SELECT 1 FROM automation_tokens WHERE id=?1 AND tenant=?2 AND revoked_at IS NULL AND expires_at>?3 AND EXISTS(SELECT 1 FROM json_each(permissions) WHERE value='jobs:create') AND (directory IS NULL OR directory=?4 OR substr(?4,1,length(directory)+1)=directory||'/'))", params![token_id,job.tenant,now_unix() as i64,job.project.directory], |row| row.get(0))
    } else {
        connection.query_row("SELECT COALESCE((SELECT blocked=0 AND credential_version=?2 FROM principals WHERE subject=?1), ?2=1)", params![job.actor,job.credential_version as i64], |row| row.get(0))
    }.map_err(|e| e.to_string())?;
    if active {
        Ok(())
    } else {
        Err("submitting identity is no longer authorized".into())
    }
}

pub(super) fn check_grant_creation(
    connection: &Connection,
    grant: &OutboundGrant,
    job: Option<&Job>,
) -> Result<(), String> {
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
    if let Some(job) = job {
        if job.tenant != grant.tenant
            || job.id != grant.id
            || grant.files.is_empty()
            || grant.files.iter().any(|file| {
                file.source
                    != if job.uses_snapshot() {
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

impl Store {
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
        let job: Option<Job> = tx.query_row("SELECT j.document FROM delivery_jobs j LEFT JOIN outbound_grants g ON g.id=j.id WHERE j.state='retiring' OR (j.state IN ('failed','cancelled') AND CAST(json_extract(j.document,'$.updated_at') AS INTEGER)<=?1) OR (j.state IN ('ready','awaiting_approval') AND (g.expires_at<=?1 OR g.revoked_at<=?1)) ORDER BY COALESCE(json_extract(j.document,'$.checks.retirement_attempt_at'),0),j.id LIMIT 1",[cutoff as i64],|row| decode(row.get(0)?)).optional().map_err(|e| e.to_string())?;
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
    ) -> Result<crate::api::outbound::workflows::storage::Storage, String> {
        storage.validate()?;
        let mut connection = self.connection.lock().expect("store poisoned");
        let tx = connection.transaction().map_err(|e| e.to_string())?;
        for tenant in &storage.tenants {
            ensure_tenant(&tx, tenant)?;
        }
        let previous: Option<i64> = tx
            .query_row(
                "SELECT revision FROM delivery_storage WHERE id=?1",
                [&storage.id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        if previous.unwrap_or(0) as u64 != storage.revision {
            return Err("storage changed; reload before saving".into());
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
        evidence::delivery_event(&tx,&self.event_signer,"","","storage_changed",&serde_json::json!({"actor": actor,"storage_id": storage.id,"revision": storage.revision}),now_unix()).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(storage)
    }

    pub fn require_delivery_export(&self, id: &str, attempt: u64) -> Result<Job, String> {
        let connection = self.connection.lock().expect("store poisoned");
        export_in(&connection, id, attempt)
    }

    pub fn complete_delivery_export(
        &self,
        id: &str,
        attempt: u64,
        key: &str,
    ) -> Result<(), String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let tx = connection.transaction().map_err(|e| e.to_string())?;
        let mut job = export_in(&tx, id, attempt)?;
        job.state = "ready".into();
        job.updated_at = now_unix();
        job.checks["export_manifest_key"] = serde_json::json!(key);
        save_job(&tx, &job).map_err(|e| e.to_string())?;
        evidence::delivery_event(&tx,&self.event_signer,&job.tenant,id,"delivery_ready",&serde_json::json!({"manifest": job.manifest,"project_id": job.project.id,"export_manifest_key": key}),job.updated_at).map_err(|e| e.to_string())?;
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
    ) -> Result<Project, String> {
        project.validate()?;
        let mut connection = self.connection.lock().expect("store poisoned");
        let tx = connection.transaction().map_err(|e| e.to_string())?;
        ensure_tenant(&tx, tenant)?;
        let current = project_in(&tx, tenant, &project.id).map_err(|e| e.to_string())?;
        if current.as_ref().map_or(0, |p| p.revision) != project.revision {
            return Err("project changed; reload before saving".into());
        }
        if current
            .as_ref()
            .is_some_and(|p| p.directory != project.directory)
        {
            return Err("a protected project's directory cannot change".into());
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
                return Err("project directories must not overlap".into());
            }
        }
        if count >= 100 {
            return Err("project limit reached".into());
        }
        drop(query);
        project.revision += 1;
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
    ) -> Result<Job, String> {
        let now = now_unix();
        let mut connection = self.connection.lock().expect("store poisoned");
        let tx = connection.transaction().map_err(|e| e.to_string())?;
        ensure_tenant(&tx, tenant)?;
        let previous: Option<Job> = tx.query_row("SELECT document FROM delivery_jobs WHERE tenant=?1 AND actor=?2 AND operation_id=?3", params![tenant,actor,request.operation_id], |row| decode(row.get(0)?)).optional().map_err(|e| e.to_string())?;
        if let Some(previous) = previous {
            return if previous.request == request {
                Ok(previous)
            } else {
                Err("operation ID already used with a different request".into())
            };
        }
        project.validate_job(&request, now)?;
        if project_in(&tx, tenant, &project.id)
            .map_err(|e| e.to_string())?
            .as_ref()
            != Some(&project)
        {
            return Err("project changed; reload before submitting".into());
        }
        let count: i64 = tx.query_row("SELECT COUNT(*) FROM delivery_jobs WHERE tenant=?1 AND state IN ('queued','preparing','awaiting_approval','exporting')", [tenant], |row| row.get(0)).map_err(|e| e.to_string())?;
        if count >= 1000 {
            return Err("active job limit reached".into());
        }
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
            checks: serde_json::json!({}),
        };
        actor_active(&tx, &job)?;
        tx.execute("INSERT INTO delivery_jobs(id,tenant,actor,operation_id,project_id,state,not_before,deadline,document) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)", params![job.id,tenant,actor,job.request.operation_id,job.project.id,job.state,job.request.not_before.unwrap_or(now) as i64,job.request.deadline.map(|t| t as i64),serde_json::to_string(&job).expect("job serializes")]).map_err(|e| e.to_string())?;
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
    ) -> Result<Vec<Job>, String> {
        self.with(|connection| {
            let mut query = connection.prepare(
                "SELECT document FROM delivery_jobs WHERE tenant=?1 AND id>?2 ORDER BY id LIMIT ?3",
            )?;
            let rows = query.query_map(params![tenant, after, limit.min(100) as i64], |row| {
                decode(row.get(0)?)
            })?;
            rows.collect()
        })
    }

    pub fn claim_delivery_job(&self, owner: &str, now: u64) -> Result<Option<Job>, String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let tx = connection.transaction().map_err(|e| e.to_string())?;
        let job: Option<Job> = tx.query_row("SELECT document FROM delivery_jobs WHERE (state='queued' AND not_before<=?1) OR (state='preparing' AND owner<>?2) OR (state='exporting' AND owner<>?2) ORDER BY not_before,id LIMIT 1", params![now as i64,owner], |row| decode(row.get(0)?)).optional().map_err(|e| e.to_string())?;
        let Some(mut job) = job else {
            return Ok(None);
        };
        if job.state != "exporting" {
            job.state = "preparing".into();
        }
        job.attempts += 1;
        job.updated_at = now;
        job.error = None;
        if job.attempts > 5 {
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
        job.state = "failed".into();
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

    pub fn change_delivery_job(
        &self,
        tenant: &str,
        id: &str,
        actor: &str,
        administrator: bool,
        action: &str,
        manifest: Option<&str>,
    ) -> Result<Job, String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let tx = connection.transaction().map_err(|e| e.to_string())?;
        let mut job = job_in(&tx, id)
            .map_err(|e| e.to_string())?
            .filter(|job| job.tenant == tenant)
            .ok_or("job missing")?;
        let project = project_in(&tx, tenant, &job.project.id)
            .map_err(|e| e.to_string())?
            .ok_or("project missing")?;
        match action {
            "approve" => {
                if actor.starts_with("automation:")
                    || actor == job.actor
                    || !project.allows(actor, "approver", administrator)
                {
                    return Err("approval requires a different authorized human operator".into());
                }
                if job.state != "awaiting_approval"
                    || job.manifest.as_deref() != manifest
                    || manifest.is_none()
                    || project.revision != job.project.revision
                {
                    return Err("approval does not match the pending manifest and policy".into());
                }
                actor_active(&tx, &job)?;
                check_job_storage(&tx, &job)?;
                job.approved_by = Some(actor.into());
                job.state = if project.export_storage.is_some() {
                    "exporting"
                } else {
                    "ready"
                }
                .into();
            }
            "cancel" => {
                if !project.allows(actor, "sender", administrator) && actor != job.actor {
                    return Err("sender permission required".into());
                }
                if job.state == "cancelled" {
                    return Ok(job);
                }
                job.state = "cancelled".into();
            }
            "retry" => {
                if !project.allows(actor, "sender", administrator) && actor != job.actor {
                    return Err("sender permission required".into());
                }
                if job.state != "failed" || project.revision != job.project.revision {
                    return Err("only a failed job with unchanged policy can retry".into());
                }
                actor_active(&tx, &job)?;
                job.attempts = 0;
                job.state = if job.manifest.is_some() {
                    "exporting"
                } else {
                    "queued"
                }
                .into();
            }
            _ => return Err("unknown job action".into()),
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
        let row: Option<(Option<String>,Option<i64>,Option<bool>)> = connection.prepare_cached("SELECT j.document,p.revision,c.protected FROM outbound_grants g LEFT JOIN delivery_jobs j ON j.id=g.id LEFT JOIN delivery_projects p ON p.tenant=j.tenant AND p.id=j.project_id LEFT JOIN delivery_policy_cache c ON c.grant_id=g.id WHERE g.id=?1 AND g.token_hash=?2 AND g.revoked_at IS NULL AND g.expires_at>?3").and_then(|mut statement| statement.query_row(params![grant_id,token_hash,now_unix() as i64],|row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).optional()).map_err(|error| error.to_string())?;
        let Some((document, revision, protected)) = row else {
            return Err("delivery link is inactive".into());
        };
        if let Some(document) = document {
            let job: Job = serde_json::from_str(&document).map_err(|error| error.to_string())?;
            if job.state != "ready" || revision != Some(job.project.revision as i64) {
                return Err("delivery is awaiting release under the current project policy".into());
            }
            return Ok(Some(job));
        }
        match protected {
            Some(false) => Ok(None),
            Some(true) => Err("delivery requires a project workflow".into()),
            None => release_in(&connection, grant_id),
        }
    }

    pub fn delivery_release(&self, grant_id: &str) -> Result<Option<Job>, String> {
        let connection = self.connection.lock().expect("store poisoned");
        release_in(&connection, grant_id)
    }

    pub fn rotate_delivery_job_token(
        &self,
        tenant: &str,
        id: &str,
        generation: u64,
        token_hash: &str,
    ) -> Result<bool, String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let tx = connection.transaction().map_err(|e| e.to_string())?;
        let mut job = job_in(&tx, id)
            .map_err(|e| e.to_string())?
            .filter(|job| job.tenant == tenant)
            .ok_or("job missing")?;
        if ["retiring", "retired"].contains(&job.state.as_str()) {
            return Err("delivery has been retired; create a new job".into());
        }
        if job.token_generation != generation {
            return Err("delivery changed; reload before rotating".into());
        }
        let changed = tx.execute("UPDATE outbound_grants SET token_hash=?3 WHERE tenant=?1 AND id=?2 AND revoked_at IS NULL",params![tenant,id,token_hash]).map_err(|e| e.to_string())?;
        if changed == 0 {
            return Ok(false);
        }
        job.token_generation += 1;
        job.updated_at = now_unix();
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

fn check_job_storage(connection: &Connection, job: &Job) -> Result<(), String> {
    for (id, field) in [
        (
            job.request
                .import
                .as_ref()
                .map(|value| value.storage_id.as_str()),
            "import_storage_revision",
        ),
        (
            job.project.export_storage.as_deref(),
            "export_storage_revision",
        ),
    ] {
        let Some(id) = id else {
            continue;
        };
        let config = connection
            .query_row(
                "SELECT document FROM delivery_storage WHERE id=?1",
                [id],
                |row| decode::<crate::api::outbound::workflows::storage::Storage>(row.get(0)?),
            )
            .map_err(|_| "storage connection missing")?;
        if !config.enabled
            || !config.tenants.contains(&job.tenant)
            || Some(config.revision) != job.checks[field].as_u64()
        {
            return Err("storage authorization changed; submit a new job".into());
        }
    }
    Ok(())
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
        || job.project != project
        || (project.require_approval && job.approved_by.is_none())
    {
        return Err("export is no longer authorized".into());
    }
    let active: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM outbound_grants WHERE id=?1 AND revoked_at IS NULL AND expires_at>?2)",params![id,now_unix() as i64],|row| row.get(0)).map_err(|e| e.to_string())?;
    if !active {
        return Err("delivery was revoked or expired".into());
    }
    actor_active(connection, &job)?;
    check_job_storage(connection, &job)?;
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
        if job.state != "ready" || project.revision != job.project.revision {
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
            let protected: bool = connection.prepare_cached("SELECT EXISTS(SELECT 1 FROM outbound_grants g CROSS JOIN delivery_projects p CROSS JOIN outbound_grant_files f WHERE g.id=?1 AND p.tenant=g.tenant AND f.grant_id=g.id AND votport_within(json_extract(p.document,'$.directory'),f.source))").and_then(|mut statement| statement.query_row([grant_id], |row| row.get(0))).map_err(|error| error.to_string())?;
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
            holder: String::new(),
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
        assert!(!store.put_fetch_ticket(&next, now).unwrap());
        store
            .rotate_outbound_grant_token("", &grant.id, "rotated")
            .unwrap();
        assert!(!store.admit_fetch_ticket(&ticket, now).unwrap());
        next.grant_token_hash = "rotated".into();
        assert!(store.put_fetch_ticket(&next, now).unwrap());
        assert!(store.admit_fetch_ticket(&next, now).unwrap());
        store
            .rotate_outbound_grant_token("", &grant.id, "again")
            .unwrap();
        let mut third = next.clone();
        third.token_id = "third".into();
        third.grant_token_hash = "again".into();
        assert!(!store.put_fetch_ticket(&third, now).unwrap());
        assert!(!store.admit_fetch_ticket(&next, now).unwrap());
        assert!(!store.admit_fetch_ticket(&third, now).unwrap());
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
                    endpoint: "http://127.0.0.1:9000".into(),
                    bucket: "delivery".into(),
                    region: "us-east-1".into(),
                    prefix: String::new(),
                    path_style: true,
                    kms_key_id: None,
                    tenants: vec![String::new()],
                    enabled: true,
                },
            )
            .unwrap();
        let project = store.save_delivery_project("", "admin", project()).unwrap();
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
        store
            .insert_workflow_grant(grant(&job), None, Some(&job))
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
        assert!(store
            .insert_workflow_grant(grant(&first), None, Some(&first))
            .is_err());
        store
            .insert_workflow_grant(grant(&job), None, Some(&job))
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
        assert!(store.delivery_token_active(&job.id, "rotated").unwrap());
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
            .insert_workflow_grant(grant(&running), None, Some(&running))
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
            .insert_workflow_grant(grant(&running), None, Some(&running))
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
