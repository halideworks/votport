pub mod routes;
pub mod storage;

use super::*;
use crate::workflow::{Job, JobRequest, Project};

struct Actor {
    identity: auth::AdminIdentity,
    token: Option<AutomationToken>,
}

impl Actor {
    fn allows(&self, project: &Project, role: &str) -> bool {
        if let Some(token) = &self.token {
            token
                .directory
                .as_ref()
                .is_none_or(|scope| within_scope(scope, &project.directory))
                && project.allows(&self.identity.subject, role, false)
        } else {
            project.allows(&self.identity.subject, role, self.identity.role == "admin")
        }
    }
}

fn actor(
    app: &App,
    headers: &HeaderMap,
    peer: std::net::SocketAddr,
    permission: &str,
    write: bool,
) -> ApiResult<Actor> {
    if write && !headers.contains_key("x-votport") {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "missing X-Votport header",
        ));
    }
    if headers.contains_key(header::AUTHORIZATION) {
        let (token, _) = automation::authenticate(app, headers, peer, Some(permission))?;
        let identity = auth::AdminIdentity {
            subject: format!("automation:{}", token.id),
            tenant: token.tenant.clone(),
            role: "viewer".into(),
            grants: vec![],
            credential_version: 0,
        };
        Ok(Actor {
            identity,
            token: Some(token),
        })
    } else {
        Ok(Actor {
            identity: admin::require_operator(app, headers)?,
            token: None,
        })
    }
}

fn conflict(error: String) -> ApiError {
    ApiError::new(StatusCode::CONFLICT, error)
}

pub async fn projects(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let actor = actor(&app, &headers, peer, "jobs:read", false)?;
    let projects = app
        .store
        .delivery_projects(&actor.identity.tenant)
        .map_err(crate::api::store_unavailable)?;
    Ok(([(header::CACHE_CONTROL,"no-store")],Json(json!({"projects": projects.into_iter().filter(|p| actor.allows(p,"viewer")).collect::<Vec<_>>()}))).into_response())
}

pub async fn put_project(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(project): Json<Project>,
) -> ApiResult<Response> {
    let identity = admin::require_operator(&app, &headers)?;
    admin::require_admin_write(&headers, &identity)?;
    let _operation = begin_outbound_operation(&app, &identity.tenant)?;
    project
        .validate()
        .map_err(|error| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, error))?;
    safe_library_path(&app, &identity.tenant, &project.directory)?;
    let project = app
        .store
        .save_delivery_project(&identity.tenant, &identity.subject, project)
        .map_err(conflict)?;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(project)).into_response())
}

pub async fn create(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<JobRequest>,
) -> ApiResult<Response> {
    let actor = actor(&app, &headers, peer, "jobs:create", true)?;
    let project = app
        .store
        .delivery_project(&actor.identity.tenant, &request.project_id)
        .map_err(crate::api::store_unavailable)?
        .ok_or_else(ApiError::not_found)?;
    if !actor.allows(&project, "sender") {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "project sender permission required",
        ));
    }
    let _operation = begin_outbound_operation(&app, &actor.identity.tenant)?;
    let job = app
        .store
        .enqueue_delivery_job(
            &actor.identity.tenant,
            &actor.identity.subject,
            actor.identity.credential_version,
            actor.token.map(|token| token.id),
            project,
            request,
        )
        .map_err(conflict)?;
    app.workflow_ready.notify_one();
    Ok((
        StatusCode::ACCEPTED,
        [(header::CACHE_CONTROL, "no-store")],
        Json(public_job(&app, &headers, job)),
    )
        .into_response())
}

fn public_job(app: &App, headers: &HeaderMap, job: Job) -> serde_json::Value {
    let token = app
        .signer
        .delivery_token(&format!("{}:{}", job.id, job.token_generation));
    let url = (job.released()
        && app.store.delivery_release(&job.id).is_ok()
        && app
            .store
            .delivery_token_active(&job.id, &hash_token(&token))
            .unwrap_or(false))
    .then(|| format!("{}/s/{token}", admin::base_url(app, headers)));
    json!({"job": job, "url": url})
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Page {
    after: Option<String>,
    limit: Option<usize>,
}

pub async fn list(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Query(page): Query<Page>,
) -> ApiResult<Response> {
    let actor = actor(&app, &headers, peer, "jobs:read", false)?;
    let limit = page.limit.unwrap_or(50);
    let after = page.after.unwrap_or_default();
    if !(1..=100).contains(&limit) || after.len() > 100 {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid job page",
        ));
    }
    let projects = app
        .store
        .delivery_projects(&actor.identity.tenant)
        .map_err(crate::api::store_unavailable)?;
    let jobs = app
        .store
        .delivery_jobs(&actor.identity.tenant, &after, limit)
        .map_err(crate::api::store_unavailable)?;
    let next = jobs.last().map(|job| job.id.clone());
    let jobs = jobs
        .into_iter()
        .filter(|job| {
            projects
                .iter()
                .any(|p| p.id == job.project.id && actor.allows(p, "viewer"))
        })
        .map(|job| public_job(&app, &headers, job))
        .collect::<Vec<_>>();
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({"jobs": jobs,"next": next})),
    )
        .into_response())
}

pub async fn get(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> ApiResult<Response> {
    let actor = actor(&app, &headers, peer, "jobs:read", false)?;
    let job = app
        .store
        .delivery_job(&id)
        .map_err(crate::api::store_unavailable)?
        .filter(|j| j.tenant == actor.identity.tenant)
        .ok_or_else(ApiError::not_found)?;
    let project = app
        .store
        .delivery_project(&job.tenant, &job.project.id)
        .map_err(crate::api::store_unavailable)?
        .ok_or_else(ApiError::not_found)?;
    if !actor.allows(&project, "viewer") {
        return Err(ApiError::not_found());
    }
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(public_job(&app, &headers, job)),
    )
        .into_response())
}

pub async fn evidence(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Query(page): Query<Page>,
) -> ApiResult<Response> {
    let actor = actor(&app, &headers, peer, "jobs:read", false)?;
    let job = app
        .store
        .delivery_job(&id)
        .map_err(crate::api::store_unavailable)?
        .filter(|j| j.tenant == actor.identity.tenant)
        .ok_or_else(ApiError::not_found)?;
    let project = app
        .store
        .delivery_project(&job.tenant, &job.project.id)
        .map_err(crate::api::store_unavailable)?
        .ok_or_else(ApiError::not_found)?;
    if !actor.allows(&project, "viewer") {
        return Err(ApiError::not_found());
    }
    let limit = page.limit.unwrap_or(50);
    let after = page
        .after
        .unwrap_or_else(|| "0".into())
        .parse::<u64>()
        .map_err(|_| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "invalid evidence cursor"))?;
    if !(1..=100).contains(&limit) || after > i64::MAX as u64 {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid evidence page",
        ));
    }
    let records = app
        .store
        .delivery_evidence(&id, after, limit)
        .map_err(crate::api::store_unavailable)?;
    let next = records
        .last()
        .and_then(|record| record["cursor"].as_u64())
        .unwrap_or(after);
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({"evidence": records,"next": next})),
    )
        .into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Action {
    action: String,
    manifest: Option<String>,
}

pub async fn change(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(action): Json<Action>,
) -> ApiResult<Response> {
    let permission = if action.action == "retry" {
        "jobs:create"
    } else {
        "jobs:cancel"
    };
    let actor = actor(&app, &headers, peer, permission, true)?;
    if actor.token.is_some() && action.action == "approve" {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "automation cannot approve deliveries",
        ));
    }
    let job = app
        .store
        .delivery_job(&id)
        .map_err(crate::api::store_unavailable)?
        .filter(|j| j.tenant == actor.identity.tenant)
        .ok_or_else(ApiError::not_found)?;
    let project = app
        .store
        .delivery_project(&job.tenant, &job.project.id)
        .map_err(crate::api::store_unavailable)?
        .ok_or_else(ApiError::not_found)?;
    if !actor.allows(
        &project,
        if action.action == "approve" {
            "approver"
        } else {
            "sender"
        },
    ) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "project permission required",
        ));
    }
    let job = app
        .store
        .change_delivery_job(
            &job.tenant,
            &id,
            &actor.identity.subject,
            actor.token.is_none() && actor.identity.role == "admin",
            &action.action,
            action.manifest.as_deref(),
        )
        .map_err(conflict)?;
    app.workflow_ready.notify_one();
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(public_job(&app, &headers, job)),
    )
        .into_response())
}

pub async fn events(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Query(page): Query<Page>,
) -> ApiResult<Response> {
    let actor = actor(&app, &headers, peer, "jobs:read", false)?;
    let limit = page.limit.unwrap_or(50);
    let after = page
        .after
        .unwrap_or_else(|| "0".into())
        .parse::<u64>()
        .map_err(|_| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "invalid event cursor"))?;
    if !(1..=100).contains(&limit) || after > i64::MAX as u64 {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid event page",
        ));
    }
    let projects = app
        .store
        .delivery_projects(&actor.identity.tenant)
        .map_err(crate::api::store_unavailable)?;
    let events = app
        .store
        .delivery_events(&actor.identity.tenant, after, limit)
        .map_err(crate::api::store_unavailable)?;
    let next = events.last().map_or(after, |event| event.id);
    let mut visible = vec![];
    for event in events {
        let job = app
            .store
            .delivery_job(&event.grant_id)
            .map_err(crate::api::store_unavailable)?;
        let project_id = job
            .as_ref()
            .map(|job| job.project.id.as_str())
            .or_else(|| event.payload.get("project_id").and_then(|v| v.as_str()));
        if (actor.token.is_none() && actor.identity.role == "admin")
            || projects
                .iter()
                .any(|p| Some(p.id.as_str()) == project_id && actor.allows(p, "viewer"))
        {
            visible.push(event);
        }
    }
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({"events": visible,"next": next})),
    )
        .into_response())
}

pub async fn worker(app: Arc<App>) {
    loop {
        if app.lease_lost.load(std::sync::atomic::Ordering::Relaxed) {
            return;
        }
        if let Ok(operation) = begin_outbound_operation(&app, "") {
            match app.store.claim_delivery_job(&app.lease_holder, now_unix()) {
                Ok(Some(job)) if job.state == "preparing" || job.state == "exporting" => {
                    let result = match begin_outbound_operation(&app, &job.tenant) {
                        Ok(_tenant_operation) => prepare(&app, job.clone()).await,
                        Err(error) => Err(error),
                    };
                    if let Err(error) = result {
                        while let Err(store_error) =
                            app.store
                                .fail_delivery_job(&job.id, job.attempts, &error.message)
                        {
                            tracing::error!(%store_error,job_id=%job.id,"record delivery job failure");
                            tokio::select! { _ = app.shutdown.notified() => return, _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {} }
                        }
                    }
                    if let Ok(Some(current)) = app.store.delivery_job(&job.id) {
                        if current.state == "failed"
                            || (current.state == "retrying"
                                && job.checks["first_failure_at"].is_null())
                        {
                            let notify_app = Arc::clone(&app);
                            tokio::spawn(async move {
                                crate::notify::workflow_failed(notify_app, current).await;
                            });
                        }
                    }
                    drop(operation);
                    continue;
                }
                Err(error) => tracing::error!(%error,"claim delivery job"),
                _ => {}
            }
        }
        tokio::select! { _ = app.shutdown.notified() => return, _ = app.workflow_ready.notified() => {}, _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {} }
    }
}

async fn prepare(app: &Arc<App>, mut job: Job) -> ApiResult<()> {
    if job.state == "exporting" {
        return storage::export(app, &job).await;
    }
    let project = app
        .store
        .delivery_project(&job.tenant, &job.project.id)
        .map_err(crate::api::store_unavailable)?
        .ok_or_else(ApiError::not_found)?;
    if job.received.is_some() {
        if !project.receive {
            return Err(conflict(
                "project no longer accepts incoming workflows".into(),
            ));
        }
        project
            .validate_job(&job.request, job.created_at)
            .map_err(conflict)?;
    }
    if project != job.project {
        return Err(conflict("project changed; submit a new job".into()));
    }
    if job.uses_snapshot() {
        create_library_dirs(&library_root(app, &job.tenant))?;
    }
    let import_revision = if job.request.import.is_some() {
        storage::import(app, &job).await?
    } else {
        None
    };
    let mut paths = if job.uses_snapshot() {
        freeze_files(app, &job).await?
    } else {
        let root = library_root(app, &job.tenant);
        let directory = automation_directory(app, &job.tenant, &job.project.directory)?;
        tokio::task::spawn_blocking(move || {
            enumerate_automation_files(&root, &directory, MAX_LIBRARY_PROJECT_FILES)
        })
        .await
        .map_err(|_| ApiError::internal("enumerate job files failed"))??
    };
    // Custody digests use filename order, independently of the transport's case-folded order.
    paths.sort();
    if let Some(sequence) = &job.project.sequence {
        let prefix = format!("{}/", job.project.directory);
        let names: std::collections::BTreeSet<_> = paths
            .iter()
            .map(|path| {
                if job.uses_snapshot() {
                    path.as_str()
                } else {
                    path.strip_prefix(&prefix).unwrap_or(path)
                }
            })
            .collect();
        for index in sequence.first..=sequence.last {
            let name = format!(
                "{}{:0width$}{}",
                sequence.prefix,
                index,
                sequence.suffix,
                width = sequence.padding
            );
            if !names.contains(name.as_str()) {
                return Err(conflict(format!("sequence is missing {name}")));
            }
        }
    }
    job.checks = app
        .store
        .delivery_job(&job.id)
        .map_err(crate::api::store_unavailable)?
        .ok_or_else(ApiError::not_found)?
        .checks;
    if let Some(received) = &job.received {
        if let Some(route) = app
            .store
            .received_route(&job.tenant, &received.upload_id)
            .map_err(crate::api::store_unavailable)?
        {
            job.checks["source_receipt"] = json!(route.receipt);
            job.checks["source_ancestry"] = json!(route.ancestry);
        }
    }
    if let Some(revision) = import_revision {
        job.checks["import_storage_revision"] = json!(revision);
    }
    job.checks["metadata"] = json!("passed");
    job.checks["sequence"] = json!(if job.project.sequence.is_some() {
        "passed"
    } else {
        "not_required"
    });
    for id in &job.project.destinations {
        job.checks["destination_revisions"][id] =
            json!(storage::authorized_storage(app, &job.tenant, id)?.revision);
    }
    check_media(app, &job, &paths).await?;
    job.checks["media"] = json!(if job.project.media.is_some() {
        "passed"
    } else {
        "not_required"
    });
    job.checks["malware_scan"] = json!(if job.project.scan_required {
        "passed"
    } else {
        "not_required"
    });
    let identity = auth::AdminIdentity {
        subject: job.actor.clone(),
        tenant: job.tenant.clone(),
        role: "viewer".into(),
        grants: vec![],
        credential_version: job.credential_version,
    };
    create_library_grant(
        app,
        &HeaderMap::new(),
        &identity,
        &paths,
        MAX_LIBRARY_PROJECT_FILES,
        GrantOptions {
            label: Some(job.request.label.clone()),
            expires_days: job.request.expires_days,
            password_hash: None,
            max_downloads: None,
            notify_on_download: false,
            automation: None,
            workflow: Some(job),
        },
    )
    .await?;
    Ok(())
}

pub(super) fn payload_root(app: &App, tenant: &str, id: &str) -> PathBuf {
    library_root(app, tenant)
        .join(".votport-workflows")
        .join(id)
        .join("files")
}

pub(super) fn payload_path(app: &App, tenant: &str, id: &str, name: &str) -> ApiResult<PathBuf> {
    if !crate::workflow::valid_id(id) || !crate::workflow::valid_path(name) {
        return Err(ApiError::not_found());
    }
    for component in name.split('/') {
        crate::paths::admit_component(component, app.config.allow_hidden)
            .map_err(|_| ApiError::not_found())?;
    }
    let path = payload_root(app, tenant, id).join(name);
    if !library_components_safe(&library_root(app, tenant), &path) {
        return Err(ApiError::not_found());
    }
    Ok(path)
}

async fn freeze_files(app: &Arc<App>, job: &Job) -> ApiResult<Vec<String>> {
    let app = Arc::clone(app);
    let job = job.clone();
    tokio::task::spawn_blocking(move || {
        let root = payload_root(&app, &job.tenant, &job.id);
        let parent = root.parent().ok_or_else(ApiError::not_found)?;
        let inventory = parent.join("inventory.json");
        if !library_components_safe(&library_root(&app, &job.tenant), &inventory) {
            return Err(ApiError::not_found());
        }
        if let Ok(file) = std::fs::File::open(&inventory) {
            let paths: Vec<String> =
                serde_json::from_reader(std::io::Read::take(file, 64 * 1024 * 1024))
                    .map_err(|_| conflict("frozen inventory is corrupt".into()))?;
            if paths.is_empty() || paths.len() > MAX_LIBRARY_PROJECT_FILES {
                return Err(conflict("invalid frozen inventory".into()));
            }
            for path in &paths {
                payload_path(&app, &job.tenant, &job.id, path)?;
            }
            return Ok(paths);
        }
        if job.request.import.is_some() {
            return Err(conflict("storage import has not completed".into()));
        }
        let source_root = if job.received.is_some() {
            app.config.receive_dir.clone()
        } else {
            library_root(&app, &job.tenant)
        };
        let sources: Vec<(String, PathBuf)> = if let Some(received) = &job.received {
            let upload = app
                .store
                .link_upload(&job.tenant, &received.link_id, &received.upload_id)
                .map_err(crate::api::store_unavailable)?
                .ok_or_else(ApiError::not_found)?;
            if upload.partial
                || upload.files.is_empty()
                || upload.files.len() > MAX_LIBRARY_PROJECT_FILES
            {
                return Err(conflict(
                    "incoming package is incomplete or exceeds the workflow file limit".into(),
                ));
            }
            upload
                .files
                .into_iter()
                .map(|file| {
                    if file.deleted {
                        return Err(conflict("incoming file was deleted".into()));
                    }
                    let path = admin::stored_path(&app, &job.tenant, &file.stored_as)
                        .ok_or_else(ApiError::not_found)?;
                    Ok((file.path, path))
                })
                .collect::<ApiResult<_>>()?
        } else {
            let directory = automation_directory(&app, &job.tenant, &job.project.directory)?;
            enumerate_automation_files(&source_root, &directory, MAX_LIBRARY_PROJECT_FILES)?
                .into_iter()
                .map(|source| {
                    let path = safe_library_path(&app, &job.tenant, &source)?;
                    let name = path
                        .strip_prefix(&directory)
                        .map_err(|_| ApiError::not_found())?
                        .to_str()
                        .ok_or_else(ApiError::not_found)?
                        .replace('\\', "/");
                    Ok((name, path))
                })
                .collect::<ApiResult<_>>()?
        };
        let reserved = sources.iter().try_fold(0u64, |total, (_, path)| {
            let size = std::fs::symlink_metadata(path)
                .map_err(|_| ApiError::not_found())?
                .len();
            total
                .checked_add(size)
                .filter(|total| *total <= app.config.max_upload_bytes)
                .ok_or_else(|| conflict("job exceeds delivery size limit".into()))
        })?;
        app.store
            .reserve_delivery_snapshot(
                &job.id,
                job.attempts,
                reserved,
                app.config.workflow_snapshot_bytes,
            )
            .map_err(conflict)?;
        if root.exists() {
            std::fs::remove_dir_all(&root)
                .map_err(|_| conflict("remove incomplete job snapshot failed".into()))?;
        }
        create_library_dirs(&root)?;
        crate::paths::tighten_private_dir(parent).map_err(ApiError::internal)?;
        let mut paths = Vec::with_capacity(sources.len());
        let mut total = 0u64;
        for (name, path) in sources {
            if !library_components_safe(&source_root, &path) {
                return Err(ApiError::not_found());
            }
            let destination = payload_path(&app, &job.tenant, &job.id, &name)?;
            let before = std::fs::symlink_metadata(&path).map_err(|_| ApiError::not_found())?;
            if !before.file_type().is_file() {
                return Err(ApiError::not_found());
            }
            total = total
                .checked_add(before.len())
                .filter(|total| *total <= reserved)
                .ok_or_else(|| conflict("job exceeds delivery size limit".into()))?;
            create_library_dirs(destination.parent().ok_or_else(ApiError::not_found)?)?;
            let source = std::fs::File::open(&path).map_err(|_| ApiError::not_found())?;
            let mut destination_file = std::fs::File::create(&destination)
                .map_err(|_| conflict("create delivery snapshot failed".into()))?;
            let copied = copy_snapshot(&source, &mut destination_file, before.len())
                .map_err(|_| conflict("copy delivery snapshot failed; check free space".into()))?;
            if copied != before.len() {
                return Err(conflict("source size changed during snapshot".into()));
            }
            let after = std::fs::symlink_metadata(&path).map_err(|_| ApiError::not_found())?;
            if !after.file_type().is_file()
                || before.len() != after.len()
                || before.modified().ok() != after.modified().ok()
            {
                return Err(conflict("source changed during delivery snapshot".into()));
            }
            destination_file
                .sync_all()
                .map_err(|_| conflict("sync delivery snapshot failed".into()))?;
            paths.push(name);
        }
        storage::publish_inventory(&app, &job.tenant, &job.id, &paths)?;
        Ok(paths)
    })
    .await
    .map_err(|_| ApiError::internal("freeze delivery files failed"))?
}

fn copy_snapshot(
    source: &std::fs::File,
    destination: &mut std::fs::File,
    length: u64,
) -> std::io::Result<u64> {
    #[cfg(target_os = "linux")]
    if rustix::fs::ioctl_ficlone(&*destination, source).is_ok() {
        return Ok(destination.metadata()?.len());
    }
    std::io::copy(
        &mut std::io::Read::take(source, length.saturating_add(1)),
        destination,
    )
}

async fn check_media(app: &App, job: &Job, names: &[String]) -> ApiResult<()> {
    if job.project.media.is_none() && !job.project.scan_required {
        return Ok(());
    }
    for name in names {
        let path = payload_path(app, &job.tenant, &job.id, name)?;
        if let Some(check) = &job.project.media {
            let binary = std::env::var_os("VOTPORT_FFPROBE").unwrap_or_else(|| "ffprobe".into());
            let output = run_check(
                binary,
                &[
                    "-v",
                    "error",
                    "-protocol_whitelist",
                    "file,pipe",
                    "-show_entries",
                    "stream=codec_type,codec_name,width,height,avg_frame_rate",
                    "-of",
                    "json",
                ],
                &path,
            )
            .await?;
            let document: serde_json::Value = serde_json::from_slice(&output)
                .map_err(|_| conflict("ffprobe returned invalid media data".into()))?;
            let video = document
                .get("streams")
                .and_then(|v| v.as_array())
                .and_then(|streams| {
                    streams.iter().find(|stream| {
                        stream.get("codec_type").and_then(|v| v.as_str()) == Some("video")
                    })
                });
            if video.is_none_or(|stream| {
                check.video_codec.as_ref().is_some_and(|codec| {
                    stream.get("codec_name").and_then(|v| v.as_str()) != Some(codec.as_str())
                }) || check.width.is_some_and(|width| {
                    stream.get("width").and_then(|v| v.as_u64()) != Some(width as u64)
                }) || check.height.is_some_and(|height| {
                    stream.get("height").and_then(|v| v.as_u64()) != Some(height as u64)
                }) || check.frame_rate.as_ref().is_some_and(|rate| {
                    stream
                        .get("avg_frame_rate")
                        .and_then(|v| v.as_str())
                        .is_none_or(|actual| !crate::workflow::same_frame_rate(rate, actual))
                })
            }) {
                return Err(conflict(format!("media checks failed for {name}")));
            }
        }
        if job.project.scan_required {
            let binary =
                std::env::var_os("VOTPORT_CLAMDSCAN").unwrap_or_else(|| "clamdscan".into());
            run_check(binary, &["--no-summary", "--fdpass", "--"], &path)
                .await
                .map_err(|_| {
                    conflict(format!(
                        "malware scan did not clear {name}; delivery remains quarantined"
                    ))
                })?;
        }
    }
    Ok(())
}

async fn run_check(binary: std::ffi::OsString, args: &[&str], path: &Path) -> ApiResult<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut child = tokio::process::Command::new(binary)
        .args(args)
        .arg(path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| conflict("required media or malware checker is unavailable".into()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ApiError::internal("checker stdout missing"))?;
    let result = tokio::time::timeout(std::time::Duration::from_secs(300), async {
        let mut output = vec![];
        stdout
            .take(65537)
            .read_to_end(&mut output)
            .await
            .map_err(|_| conflict("checker output failed".into()))?;
        if output.len() > 65536 {
            return Err(conflict("checker output exceeds limit".into()));
        }
        if !child
            .wait()
            .await
            .map_err(|_| conflict("checker failed".into()))?
            .success()
        {
            return Err(conflict("checker did not clear the file".into()));
        }
        Ok(output)
    })
    .await
    .map_err(|_| conflict("required checker timed out".into()))?;
    result
}

pub(crate) fn release(app: &App, grant: &OutboundGrant) -> ApiResult<Option<Job>> {
    app.store
        .delivery_access(&grant.id, &grant.token_hash)
        .map_err(|error| {
            if error == "delivery link is inactive" {
                ApiError::not_found()
            } else {
                ApiError::new(StatusCode::FORBIDDEN, error).with_code("delivery_pending")
            }
        })
}

fn recipient_cookie_name(id: &str) -> String {
    format!("votport_recipient_{id}")
}

pub(crate) fn require_recipient(
    app: &App,
    grant: &OutboundGrant,
    headers: &HeaderMap,
) -> ApiResult<Option<String>> {
    let Some(job) = release(app, grant)? else {
        return Ok(None);
    };
    if job.request.recipients.is_empty() {
        return Ok(None);
    }
    let holder = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| auth::cookie_value(cookies, &recipient_cookie_name(&grant.id)))
        .and_then(|cookie| cookie.split_once('.'))
        .filter(|(holder, token)| {
            job.request.recipients.iter().any(|key| key == holder)
                && auth::verify_recipient(
                    &app.secret,
                    &grant.id,
                    &grant.token_hash,
                    job.project.revision,
                    holder,
                    token,
                )
        })
        .map(|(holder, _)| holder.to_owned());
    holder.map(Some).ok_or_else(|| {
        ApiError::new(
            StatusCode::FORBIDDEN,
            "this delivery requires an enrolled recipient device",
        )
        .with_code("recipient_required")
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientChallenge {
    holder: String,
}

pub async fn recipient_challenge(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    AxumPath(token): AxumPath<String>,
    Json(request): Json<RecipientChallenge>,
) -> ApiResult<Response> {
    recipient_rate(&app, &headers, &peer)?;
    let grant = readable_grant(&app, &token)?;
    let job = release(&app, &grant)?.ok_or_else(ApiError::not_found)?;
    if !job.request.recipients.contains(&request.holder) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "ask the sender to enroll this device for the delivery",
        ));
    }
    let now = now_unix();
    let challenge = app
        .signer
        .evidence_challenge(crate::delivery_protocol::Challenge {
            origin: admin::base_url(&app, &headers),
            grant_id: grant.id,
            manifest: job.manifest.ok_or_else(ApiError::not_found)?,
            holder: request.holder,
            nonce: format!(
                "{}.{}.{}",
                grant.token_hash,
                job.project.revision,
                auth::random_token()
            ),
            issued_at: now,
            expires_at: now + 300,
        });
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(challenge)).into_response())
}

pub async fn recipient_verify(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    AxumPath(token): AxumPath<String>,
    Json(proof): Json<crate::delivery_protocol::AccessProof>,
) -> ApiResult<Response> {
    recipient_rate(&app, &headers, &peer)?;
    let grant = readable_grant(&app, &token)?;
    let job = release(&app, &grant)?.ok_or_else(ApiError::not_found)?;
    let challenge = &proof.authorization.challenge;
    let now = now_unix();
    if !proof.verify(&app.signer.public_hex)
        || challenge.grant_id != grant.id
        || Some(&challenge.manifest) != job.manifest.as_ref()
        || !job.request.recipients.contains(&challenge.holder)
        || challenge.origin != admin::base_url(&app, &headers)
        || challenge.issued_at > now
        || challenge.expires_at <= now
        || challenge.expires_at.saturating_sub(challenge.issued_at) > 300
        || !challenge
            .nonce
            .starts_with(&format!("{}.{}.", grant.token_hash, job.project.revision))
    {
        return Err(ApiError::unauthorized());
    }
    let cookie = format!(
        "{}={}.{}",
        recipient_cookie_name(&grant.id),
        challenge.holder,
        auth::issue_recipient(
            &app.secret,
            &grant.id,
            &grant.token_hash,
            job.project.revision,
            &challenge.holder
        )
    );
    let secure = if admin::base_url(&app, &headers).starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    Ok(([(header::CACHE_CONTROL,"no-store".into()),(header::SET_COOKIE,format!("{cookie}; Path=/api/s/{token}; Max-Age=86400; HttpOnly; SameSite=Strict{secure}"))],Json(json!({"authorized": true}))).into_response())
}

fn recipient_rate(app: &App, headers: &HeaderMap, peer: &std::net::SocketAddr) -> ApiResult<()> {
    let ip = crate::api::client_ip(headers, peer, &app.config.trusted_proxies);
    if app.automation_read_rate.allow(&ip) {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many recipient authentication requests",
        )
        .with_retry_after(600))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookRequest {
    url: String,
    enabled: bool,
    revision: u64,
}

pub async fn webhook(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult<Response> {
    let identity = admin::require_operator(&app, &headers)?;
    if identity.role != "admin" {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "administrator required",
        ));
    }
    let hook = app
        .store
        .delivery_webhook(&identity.tenant)
        .map_err(crate::api::store_unavailable)?;
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({"webhook": hook})),
    )
        .into_response())
}

pub async fn put_webhook(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(request): Json<WebhookRequest>,
) -> ApiResult<Response> {
    let identity = admin::require_operator(&app, &headers)?;
    admin::require_admin_write(&headers, &identity)?;
    let _operation = begin_outbound_operation(&app, &identity.tenant)?;
    let url =
        reqwest::Url::parse(&request.url).map_err(|_| conflict("invalid webhook URL".into()))?;
    if request.url.len() > 2048
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || !(url.scheme() == "https"
            || (url.scheme() == "http"
                && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))))
    {
        return Err(conflict(
            "webhook URL must use HTTPS, except loopback, without embedded credentials".into(),
        ));
    }
    let hook = app
        .store
        .save_delivery_webhook(
            &identity.tenant,
            &identity.subject,
            &request.url,
            request.enabled,
            request.revision,
        )
        .map_err(conflict)?;
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({"webhook": hook,"signing_secret": hook.secret})),
    )
        .into_response())
}

pub async fn webhook_attempts(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(page): Query<Page>,
) -> ApiResult<Response> {
    let identity = admin::require_operator(&app, &headers)?;
    if identity.role != "admin" {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "administrator required",
        ));
    }
    let after = page
        .after
        .unwrap_or_else(|| "0".into())
        .parse::<u64>()
        .map_err(|_| conflict("invalid webhook cursor".into()))?;
    let limit = page.limit.unwrap_or(50);
    if after > i64::MAX as u64 || !(1..=100).contains(&limit) {
        return Err(conflict("invalid webhook page".into()));
    }
    let attempts = app
        .store
        .delivery_webhook_attempts(&identity.tenant, after, limit)
        .map_err(crate::api::store_unavailable)?;
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({"attempts": attempts})),
    )
        .into_response())
}

pub async fn replay_webhook(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<u64>,
) -> ApiResult<Response> {
    let identity = admin::require_operator(&app, &headers)?;
    admin::require_admin_write(&headers, &identity)?;
    let _operation = begin_outbound_operation(&app, &identity.tenant)?;
    if id > i64::MAX as u64
        || !app
            .store
            .replay_delivery_webhook(&identity.tenant, id)
            .map_err(crate::api::store_unavailable)?
    {
        return Err(ApiError::not_found());
    }
    app.store.audit(
        &identity.tenant,
        &identity.subject,
        "delivery_webhook_replayed",
        &id.to_string(),
        &json!({}),
    );
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"event_id": id,"queued": true})),
    )
        .into_response())
}

pub async fn event_worker(app: Arc<App>) {
    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            tracing::error!(%error,"build delivery webhook client");
            return;
        }
    };
    loop {
        if app.lease_lost.load(std::sync::atomic::Ordering::Relaxed) {
            return;
        }
        if let Err(error) = dispatch_events(&app, &client).await {
            tracing::error!(%error,"dispatch delivery events");
        }
        if let Err(error) = retire_snapshot(&app).await {
            tracing::error!(%error,"retire delivery snapshot");
        }
        tokio::select! { _ = app.shutdown.notified() => return, _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {} }
    }
}

async fn dispatch_events(app: &App, client: &reqwest::Client) -> Result<(), String> {
    use hmac::{Hmac, Mac};
    app.store.escalate_delivery_jobs(now_unix())?;
    app.store.queue_delivery_webhooks(now_unix())?;
    for attempt in app.store.due_delivery_webhooks(now_unix())? {
        let Some(hook) = app
            .store
            .delivery_webhook(&attempt.tenant)?
            .filter(|hook| hook.enabled && hook.revision == attempt.revision)
        else {
            continue;
        };
        let event = app
            .store
            .delivery_events(&attempt.tenant, attempt.event_id.saturating_sub(1), 1)?
            .into_iter()
            .find(|event| event.id == attempt.event_id);
        let Some(event) = event.filter(|event| event.verify()) else {
            app.store.finish_delivery_webhook(
                &attempt,
                Some("event missing or signature invalid"),
                now_unix(),
            )?;
            continue;
        };
        let body = serde_json::to_vec(&event).map_err(|e| e.to_string())?;
        let timestamp = now_unix().to_string();
        let mut mac =
            Hmac::<sha2::Sha256>::new_from_slice(hook.secret.as_bytes()).expect("HMAC key");
        mac.update(timestamp.as_bytes());
        mac.update(b".");
        mac.update(&body);
        let signature = hex::encode(mac.finalize().into_bytes());
        let response = client
            .post(&hook.url)
            .header(header::CONTENT_TYPE, "application/json")
            .header("X-Votport-Event-Id", event.id.to_string())
            .header("X-Votport-Timestamp", timestamp)
            .header("X-Votport-Signature", format!("sha256={signature}"))
            .body(body)
            .send()
            .await;
        let error = match response {
            Ok(response) if response.status().is_success() => None,
            Ok(response) => Some(format!("receiver returned {}", response.status().as_u16())),
            Err(_) => Some("receiver unavailable or timed out".into()),
        };
        app.store
            .finish_delivery_webhook(&attempt, error.as_deref(), now_unix())?;
    }
    Ok(())
}

async fn retire_snapshot(app: &Arc<App>) -> Result<(), String> {
    let Some(job) = app.store.claim_snapshot_retirement(now_unix())? else {
        return Ok(());
    };
    let _operation = begin_outbound_operation(app, &job.tenant).map_err(|error| error.message)?;
    let root = payload_root(app, &job.tenant, &job.id);
    let path = root.parent().ok_or("invalid snapshot path")?.to_owned();
    if !library_components_safe(&library_root(app, &job.tenant), &path) {
        return Err("invalid snapshot directory".into());
    }
    tokio::task::spawn_blocking(move || match std::fs::remove_dir_all(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("remove retired snapshot failed".to_owned()),
    })
    .await
    .map_err(|_| "retire snapshot task failed")??;
    app.store.complete_snapshot_retirement(&job.id, now_unix())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery_protocol::{AccessProof, Evidence, EvidenceKind, SignedChallenge};
    use axum::http::{Method, Request};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn call(
        app: &Arc<App>,
        method: Method,
        path: &str,
        cookie: Option<&str>,
        payload: Option<serde_json::Value>,
    ) -> (StatusCode, HeaderMap, Vec<u8>) {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .extension(ConnectInfo(
                "127.0.0.1:34567".parse::<std::net::SocketAddr>().unwrap(),
            ))
            .header("X-Votport", "1");
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, cookie);
        }
        let body = if let Some(payload) = payload {
            request = request.header(header::CONTENT_TYPE, "application/json");
            Body::from(payload.to_string())
        } else {
            Body::empty()
        };
        let response = crate::app::router(Arc::clone(app))
            .oneshot(request.body(body).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        (
            status,
            headers,
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
    }

    fn admin_cookie(app: &App) -> String {
        format!(
            "votport_admin={}",
            auth::issue_admin_token(
                &app.secret,
                &auth::AdminIdentity::local_admin(),
                &app.config.admin_token_tag
            )
        )
    }

    #[tokio::test]
    async fn reception_snapshots_gate_multiple_copies_and_retry_lost_completion() {
        for release in [
            crate::workflow::Release::AllDestinations,
            crate::workflow::Release::Local,
        ] {
            let directory = tempfile::tempdir().unwrap();
            let app = crate::api::testing::build(directory.path());
            let cookie = admin_cookie(&app);
            for id in ["offline", "online"] {
                let path = directory.path().join(id);
                if id == "online" {
                    std::fs::create_dir(&path).unwrap();
                }
                let config = serde_json::from_value(json!({"id":id,"revision":0,"label":id,"kind":"folder","directory":path,"tenants":[""],"enabled":true})).unwrap();
                app.store
                    .save_delivery_storage("local", config, None)
                    .unwrap();
            }
            let mut project = crate::workflow::tests::project();
            project.receive = true;
            project.require_approval = false;
            project.release = release;
            project.destinations = vec!["offline".into(), "online".into()];
            let project = app
                .store
                .save_delivery_project("", "local", project)
                .unwrap();
            let workflow = crate::workflow::ReceiveWorkflow {
                project_id: project.id.clone(),
                metadata: crate::workflow::tests::request().metadata,
                recipients: vec![],
            };
            let link = crate::store::Link {
                id: "incoming".into(),
                tenant: String::new(),
                label: "Incoming".into(),
                dest: String::new(),
                password_hash: None,
                created_at: now_unix(),
                expires_at: None,
                max_bytes: None,
                active: true,
                legal_hold: false,
                notify_on_upload: false,
                uploads: vec![],
                events: vec![],
            };
            app.store
                .insert_link_with_workflow(link.clone(), Some(&workflow))
                .unwrap();
            std::fs::create_dir_all(&app.config.receive_dir).unwrap();
            let bytes = b"original";
            std::fs::write(app.config.receive_dir.join("file.bin"), bytes).unwrap();
            let mut builder = InMemoryObjectBuilder::new(
                Suite::Blake3Bao64,
                Some(bytes.len() as u64),
                bytes.len() as u64,
            )
            .unwrap();
            builder.update(bytes).unwrap();
            let root = hex::encode(builder.finish().unwrap().object_id().root);
            let mut upload = crate::store::UploadRecord {
                id: "upload".into(),
                started_at: now_unix(),
                completed_at: now_unix(),
                replayed_chunks: 0,
                rejected_chunks: 0,
                transport: Some("http".into()),
                package_root: "package".into(),
                total_bytes: bytes.len() as u64,
                files: vec![crate::store::FileRecord {
                    path: "file.bin".into(),
                    stored_as: "file.bin".into(),
                    bytes: bytes.len() as u64,
                    suite: "blake3".into(),
                    root,
                    receipt: true,
                    deleted: false,
                }],
                partial: true,
                log: vec![],
            };
            app.store
                .append_upload("", &link.id, upload.clone())
                .unwrap();
            assert!(app.store.delivery_jobs("", "", 100).unwrap().is_empty());
            upload.partial = false;
            upload.id = "complete".into();
            app.store.append_upload("", &link.id, upload).unwrap();
            assert!(app.store.receive_workflow_pending("", &link.id).unwrap());
            assert!(app.store.remove_link("", &link.id).is_err());
            assert!(app
                .store
                .update_link_uploads("", &link.id, |link| link.uploads.clear())
                .is_err());
            assert_eq!(
                call(
                    &app,
                    Method::DELETE,
                    "/api/admin/links/incoming/uploads/complete",
                    Some(&cookie),
                    None
                )
                .await
                .0,
                StatusCode::CONFLICT
            );
            let job = app
                .store
                .claim_delivery_job("worker", now_unix())
                .unwrap()
                .unwrap();
            prepare(&app, job.clone()).await.unwrap();
            assert_eq!(
                std::fs::read(payload_root(&app, "", &job.id).join("file.bin")).unwrap(),
                bytes
            );
            assert!(!app.store.receive_workflow_pending("", &link.id).unwrap());
            std::fs::write(app.config.receive_dir.join("file.bin"), b"changed!").unwrap();
            let exporting = app
                .store
                .claim_delivery_job("worker", now_unix())
                .unwrap()
                .unwrap();
            assert_eq!(exporting.state, "exporting");
            assert_eq!(
                exporting.released(),
                release == crate::workflow::Release::Local
            );
            let error = prepare(&app, exporting.clone()).await.unwrap_err();
            let progress = app.store.delivery_job(&job.id).unwrap().unwrap();
            assert_eq!(
                progress.checks["destinations"]["offline"]["state"],
                "failed"
            );
            assert_eq!(
                progress.checks["destinations"]["online"]["state"],
                "complete"
            );
            app.store
                .fail_delivery_job(&job.id, exporting.attempts, &error.message)
                .unwrap();
            let retrying = app.store.delivery_job(&job.id).unwrap().unwrap();
            assert_eq!(retrying.state, "retrying");
            assert!(retrying.checks["first_failure_at"].is_u64());
            assert_eq!(
                app.store.delivery_release(&job.id).is_ok(),
                release == crate::workflow::Release::Local
            );
            let key = progress.checks["destinations"]["online"]["location"]
                .as_str()
                .unwrap();
            let completion = directory.path().join("online").join(key);
            let signed = std::fs::read(&completion).unwrap();
            assert_eq!(
                std::fs::read(completion.parent().unwrap().join("files/file.bin")).unwrap(),
                bytes
            );
            // A completion response can be lost after the remote filesystem commits it.
            let connection =
                rusqlite::Connection::open(app.config.data_dir.join("votport.db")).unwrap();
            connection.execute("UPDATE delivery_jobs SET document=json_remove(document,'$.checks.destinations.online') WHERE id=?1",[&job.id]).unwrap();
            std::fs::create_dir(directory.path().join("offline")).unwrap();
            let retry = app
                .store
                .claim_delivery_job("worker", retrying.checks["retry_at"].as_u64().unwrap())
                .unwrap()
                .unwrap();
            prepare(&app, retry).await.unwrap();
            assert_eq!(std::fs::read(&completion).unwrap(), signed);
            let ready = app.store.delivery_job(&job.id).unwrap().unwrap();
            assert_eq!(ready.state, "ready");
            assert!(app.store.delivery_release(&job.id).is_ok());
            assert!(app
                .store
                .delivery_events("", 0, 100)
                .unwrap()
                .iter()
                .any(|event| event.kind == "destination_failed" && event.verify()));
            let mut changed = app
                .store
                .link_upload("", &link.id, "complete")
                .unwrap()
                .unwrap();
            changed.id = "changed".into();
            app.store
                .append_upload("", &link.id, changed.clone())
                .unwrap();
            let queued = app
                .store
                .claim_delivery_job("worker", now_unix())
                .unwrap()
                .unwrap();
            assert!(prepare(&app, queued.clone())
                .await
                .unwrap_err()
                .message
                .contains("changed since verification"));
            assert!(app
                .store
                .outbound_grant_by_id(&queued.id)
                .unwrap()
                .is_none());
            app.store
                .change_delivery_job("", &queued.id, "local", true, "cancel", None)
                .unwrap();
            let mut disabled = project.clone();
            disabled.receive = false;
            app.store
                .save_delivery_project("", "local", disabled)
                .unwrap();
            changed.id = "disabled".into();
            app.store.append_upload("", &link.id, changed).unwrap();
            let refused = app
                .store
                .delivery_jobs("", "", 100)
                .unwrap()
                .into_iter()
                .find(|job| job.request.operation_id == "disabled")
                .unwrap();
            assert_eq!(refused.state, "failed");
            assert!(app
                .store
                .change_delivery_job("", &refused.id, "local", true, "retry", None)
                .is_err());
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn peer_routes_transfer_signed_custody_and_acknowledge_revocation() {
        for push in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let source = crate::api::testing::build(&directory.path().join("la"));
            let mut config = crate::api::testing::config(&directory.path().join("nyc"));
            if push {
                config.push_bind = Some("127.0.0.1:0".parse().unwrap());
            }
            let receiver = crate::app::build(config).unwrap();
            crate::app::start_push_receiver(Arc::clone(&receiver));
            let mut tenant = crate::store::Tenant {
                key: "nyc".into(),
                label: "Independent NYC tenant".into(),
                admin_group: None,
                max_total_bytes: Some(300_000),
                max_links: None,
                max_sessions: None,
                created_at: now_unix(),
            };
            receiver.store.insert_tenant(tenant.clone()).unwrap();
            let mut reception = crate::workflow::tests::project();
            reception.id = "receiving".into();
            reception.directory = "reception".into();
            reception.receive = true;
            reception.require_approval = false;
            let reception = receiver
                .store
                .save_delivery_project("nyc", "local", reception)
                .unwrap();
            let token = auth::random_token();
            receiver
                .store
                .insert_link(crate::store::Link {
                    id: token.clone(),
                    tenant: "nyc".into(),
                    label: "NYC reception".into(),
                    dest: String::new(),
                    password_hash: None,
                    created_at: now_unix(),
                    expires_at: None,
                    max_bytes: None,
                    active: true,
                    legal_hold: false,
                    notify_on_upload: false,
                    uploads: vec![],
                    events: vec![],
                })
                .unwrap();
            receiver
                .store
                .set_receive_workflow(
                    "nyc",
                    &token,
                    &crate::workflow::ReceiveWorkflow {
                        project_id: reception.id.clone(),
                        metadata: crate::workflow::tests::request().metadata,
                        recipients: vec![],
                    },
                )
                .unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin = format!("http://{}", listener.local_addr().unwrap());
            let router = crate::app::router(Arc::clone(&receiver));
            let server = tokio::spawn(async move {
                axum::serve(
                    listener,
                    router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
                )
                .await
                .unwrap();
            });
            let config:storage::Storage = serde_json::from_value(json!({"id":"nyc","revision":0,"label":"NYC","kind":"votport","endpoint":origin,"enabled":true,"tenants":[""]})).unwrap();
            source
                .store
                .save_delivery_storage(
                    "local",
                    config,
                    Some(storage::Credentials::Votport {
                        request_url: format!("{origin}/r/{token}"),
                        password: None,
                    }),
                )
                .unwrap();
            let mut project = crate::workflow::tests::project();
            project.require_approval = false;
            project.destinations = vec!["nyc".into()];
            let library = source.config.outbound_dir.join(&project.directory);
            std::fs::create_dir_all(&library).unwrap();
            let bytes = vec![71u8; 200_000];
            for name in ["Z.bin", "a.bin"] {
                std::fs::write(library.join(name), &bytes).unwrap();
            }
            let project = source
                .store
                .save_delivery_project("", "local", project)
                .unwrap();
            source
                .store
                .enqueue_delivery_job(
                    "",
                    "sender",
                    1,
                    None,
                    project,
                    crate::workflow::tests::request(),
                )
                .unwrap();
            let preparing = source
                .store
                .claim_delivery_job("test", now_unix())
                .unwrap()
                .unwrap();
            prepare(&source, preparing.clone()).await.unwrap();
            let exporting = source
                .store
                .claim_delivery_job("test", now_unix())
                .unwrap()
                .unwrap();
            assert!(source.store.delivery_release(&exporting.id).is_err());
            assert!(prepare(&source, exporting.clone())
                .await
                .unwrap_err()
                .message
                .contains("destination refused the transfer"));
            assert!(receiver
                .store
                .link("nyc", &token)
                .unwrap()
                .unwrap()
                .uploads
                .is_empty());
            tenant.max_total_bytes = Some(1024 * 1024);
            receiver.store.update_tenant(&tenant).unwrap();
            let resumed = if !push {
                let connection =
                    rusqlite::Connection::open(source.config.data_dir.join("votport.db")).unwrap();
                let route_id: String = connection
                    .query_row(
                        "SELECT route_id FROM outbound_routes WHERE job_id=?1",
                        [&exporting.id],
                        |row| row.get(0),
                    )
                    .unwrap();
                let sender = Arc::clone(&source);
                let job = exporting.clone();
                let base = origin.clone();
                let request_token = token.clone();
                Some(
                    tokio::task::spawn_blocking(move || {
                        let grant = sender.store.outbound_grant_by_id(&job.id).unwrap().unwrap();
                        let package =
                            crate::api::serve::prepare_route_package(&sender, &grant).unwrap();
                        let client =
                            votport_client_core::api::Client::for_route(base, route_id.clone())
                                .unwrap();
                        let session = client
                            .create_session(
                                &request_token,
                                None,
                                votport_client_core::api::PackageAnnouncement {
                                    suite: "blake3".into(),
                                    root: hex::encode(package.summary.root),
                                    length: package.summary.logical_length,
                                },
                            )
                            .unwrap();
                        client
                            .seal(&session.session, package.seal_bytes.clone())
                            .unwrap();
                        for page in &package.page_bytes {
                            client.page(&session.session, page.clone()).unwrap();
                        }
                        assert_eq!(client.begin(&session.session).unwrap()[0].covered_bytes, 0);
                        let proof = package.objects[0]
                            .prover()
                            .unwrap()
                            .prove(0, 65536)
                            .unwrap();
                        client
                            .chunk(&session.session, 0, 0, proof.proof(), &vec![71; 65536])
                            .unwrap();
                        assert_eq!(
                            client.begin(&session.session).unwrap()[0].covered_bytes,
                            65536
                        );
                        (route_id, session.session)
                    })
                    .await
                    .unwrap(),
                )
            } else {
                None
            };
            tokio::time::timeout(
                std::time::Duration::from_secs(30),
                prepare(&source, exporting.clone()),
            )
            .await
            .unwrap()
            .unwrap();
            let ready = source.store.delivery_job(&exporting.id).unwrap().unwrap();
            assert_eq!(ready.state, "ready");
            let receipt: crate::route_protocol::RouteReceipt =
                serde_json::from_value(ready.checks["route_receipts"]["nyc"].clone()).unwrap();
            assert!(receipt.verify(&receiver.signer.public_hex));
            assert_eq!(
                receipt.document.source.document.issuer,
                source.signer.public_hex
            );
            assert_eq!(
                Some(&receipt.document.source.document.manifest),
                ready.manifest.as_ref()
            );
            let upload = receiver
                .store
                .link_upload("nyc", &token, &receipt.document.upload_id)
                .unwrap()
                .unwrap();
            assert_eq!(
                std::fs::read(
                    admin::stored_path(&receiver, "nyc", &upload.files[0].stored_as).unwrap()
                )
                .unwrap(),
                bytes
            );
            assert_eq!(
                upload.transport.as_deref(),
                Some(if push { "push" } else { "http" })
            );
            if let Some((route_id, session_id)) = &resumed {
                assert_eq!(
                    receiver
                        .store
                        .inbound_route(route_id)
                        .unwrap()
                        .unwrap()
                        .session_id
                        .as_ref(),
                    Some(session_id)
                );
            }
            assert_eq!(
                receiver
                    .store
                    .received_route_receipt("nyc", &upload.id)
                    .unwrap(),
                Some(receipt.clone())
            );
            assert!(receiver
                .store
                .received_route_receipt("", &upload.id)
                .unwrap()
                .is_none());
            let received_job = receiver
                .store
                .claim_delivery_job("test", now_unix())
                .unwrap()
                .unwrap();
            prepare(&receiver, received_job.clone()).await.unwrap();
            let forwarded = receiver
                .store
                .delivery_job(&received_job.id)
                .unwrap()
                .unwrap();
            assert_eq!(forwarded.checks["source_receipt"], json!(receipt));
            assert_eq!(forwarded.checks["source_ancestry"], json!([]));
            assert_eq!(forwarded.manifest, ready.manifest);
            // The receiver's completed operation survives a lost sender-side completion update.
            let connection =
                rusqlite::Connection::open(source.config.data_dir.join("votport.db")).unwrap();
            connection.execute("UPDATE delivery_jobs SET state='exporting',document=json_set(json_remove(document,'$.checks.destinations.nyc','$.checks.route_receipts.nyc'),'$.state','exporting') WHERE id=?1",[&ready.id]).unwrap();
            prepare(&source, exporting.clone()).await.unwrap();
            assert_eq!(
                receiver
                    .store
                    .link("nyc", &token)
                    .unwrap()
                    .unwrap()
                    .uploads
                    .len(),
                1
            );
            assert!(source
                .store
                .claim_route_revocation(now_unix())
                .unwrap()
                .is_none());
            source
                .store
                .change_delivery_job("", &ready.id, "local", true, "cancel", None)
                .unwrap();
            let control = source
                .store
                .claim_route_revocation(now_unix())
                .unwrap()
                .unwrap();
            let mut forged = control.request.clone();
            forged.document.source.document.label = "different".into();
            assert_eq!(
                call(
                    &receiver,
                    Method::POST,
                    &format!("/api/route/{}/revoke", control.route_id),
                    None,
                    Some(json!(forged))
                )
                .await
                .0,
                StatusCode::CONFLICT
            );
            let path = format!("/api/route/{}/revoke", control.route_id);
            let (status, _, body) = call(
                &receiver,
                Method::POST,
                &path,
                None,
                Some(json!(control.request)),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let ack: crate::route_protocol::RouteRevoked = serde_json::from_slice(&body).unwrap();
            assert!(ack.verify(&control.request));
            source
                .store
                .finish_route_revocation(&control, Some(&ack), now_unix())
                .unwrap();
            assert!(source
                .store
                .claim_route_revocation(now_unix() + 10000)
                .unwrap()
                .is_none());
            assert_eq!(
                call(
                    &receiver,
                    Method::POST,
                    &path,
                    None,
                    Some(json!(control.request))
                )
                .await
                .2,
                body
            );
            assert_eq!(
                source
                    .store
                    .delivery_job(&ready.id)
                    .unwrap()
                    .unwrap()
                    .checks["route_revocations"]["nyc"]["state"],
                "acknowledged"
            );
            assert!(receiver
                .store
                .inbound_route(&control.route_id)
                .unwrap()
                .unwrap()
                .revoked_at
                .is_some());
            assert_eq!(
                receiver
                    .store
                    .delivery_job(&received_job.id)
                    .unwrap()
                    .unwrap()
                    .state,
                "cancelled"
            );
            assert!(receiver.store.delivery_release(&received_job.id).is_err());
            receiver.store.remove_link("nyc", &token).unwrap();
            assert_eq!(
                receiver.store.remove_tenant("nyc").unwrap(),
                crate::store::TenantRemoval::Deleted
            );
            let (status, _, absence) = call(
                &receiver,
                Method::POST,
                &path,
                None,
                Some(json!(control.request)),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let absence: crate::route_protocol::RouteRevoked =
                serde_json::from_slice(&absence).unwrap();
            assert!(absence.verify(&control.request));
            assert_eq!(
                call(
                    &receiver,
                    Method::POST,
                    &format!("/api/route/{}/revoke", auth::random_token()),
                    None,
                    Some(json!(control.request))
                )
                .await
                .0,
                StatusCode::CONFLICT
            );
            server.abort();
        }
    }

    #[tokio::test]
    async fn storage_kinds_bind_private_credentials_and_validate_paths() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let cookie = admin_cookie(&app);
        let folder = json!({"id":"shared", "revision":0, "label":"Shared folder", "kind":"folder", "directory":directory.path().join("shared"), "tenants":[""], "enabled":true});
        for changes in [
            json!({"directory":"relative"}),
            json!({"directory":"/shared/../elsewhere"}),
            json!({"directory":"/shared/\u{0}"}),
            json!({"endpoint":"https://s3.example"}),
            json!({"kms_key_id":"key"}),
        ] {
            let mut invalid = folder.clone();
            invalid
                .as_object_mut()
                .unwrap()
                .extend(changes.as_object().unwrap().clone());
            assert_eq!(
                call(
                    &app,
                    Method::PUT,
                    "/api/workflows/storage",
                    Some(&cookie),
                    Some(json!({"storage":invalid}))
                )
                .await
                .0,
                StatusCode::CONFLICT
            );
        }
        let (status, _, body) = call(
            &app,
            Method::PUT,
            "/api/workflows/storage",
            Some(&cookie),
            Some(json!({"storage":folder})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let saved: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(saved["kind"], "folder");
        let port = json!({"id":"west", "revision":0, "label":"West coast", "kind":"votport", "endpoint":"https://west.example", "tenants":[""], "enabled":true});
        assert_eq!(
            call(
                &app,
                Method::PUT,
                "/api/workflows/storage",
                Some(&cookie),
                Some(json!({"storage":port}))
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        for url in [
            "https://west.example/s/0123456789abcdef0123456789abcdef",
            "https://west.example/r/short",
            "https://user:secret@west.example/r/0123456789abcdef0123456789abcdef",
            "https://other.example/r/0123456789abcdef0123456789abcdef",
            "https://west.example/r/0123456789abcdef0123456789abcdef?secret=1",
        ] {
            assert_eq!(call(&app, Method::PUT, "/api/workflows/storage", Some(&cookie), Some(json!({"storage":port, "credentials":{"mode":"votport", "request_url":url, "password":null}}))).await.0, StatusCode::CONFLICT);
        }
        let credentials = json!({"mode":"votport", "request_url":"https://west.example/r/0123456789abcdef0123456789abcdef", "password":"private-request-password"});
        let (status, _, body) = call(
            &app,
            Method::PUT,
            "/api/workflows/storage",
            Some(&cookie),
            Some(json!({"storage":port, "credentials":credentials})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let mut saved: serde_json::Value = serde_json::from_slice(&body).unwrap();
        for kind in ["s3", "folder"] {
            let mut changed = saved.clone();
            changed["kind"] = json!(kind);
            assert_ne!(
                call(
                    &app,
                    Method::PUT,
                    "/api/workflows/storage",
                    Some(&cookie),
                    Some(json!({"storage":changed}))
                )
                .await
                .0,
                StatusCode::OK
            );
        }
        let mut changed = saved.clone();
        changed["endpoint"] = json!("https://other.example");
        assert_eq!(
            call(
                &app,
                Method::PUT,
                "/api/workflows/storage",
                Some(&cookie),
                Some(json!({"storage":changed}))
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        saved["label"] = json!("West renamed");
        assert_eq!(
            call(
                &app,
                Method::PUT,
                "/api/workflows/storage",
                Some(&cookie),
                Some(json!({"storage":saved}))
            )
            .await
            .0,
            StatusCode::OK
        );
        let (status, _, body) = call(
            &app,
            Method::GET,
            "/api/workflows/storage",
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let text = std::str::from_utf8(&body).unwrap();
        assert!(
            !text.contains("private-request-password")
                && !text.contains("0123456789abcdef")
                && !text.contains("request_url")
        );
        assert!(app.store.delivery_storage_has_credentials("west").unwrap());
    }

    #[tokio::test]
    async fn shared_folder_and_votport_connection_checks_use_saved_credentials() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let cookie = admin_cookie(&app);
        let root = directory.path().join("shared");
        std::fs::create_dir(&root).unwrap();
        let save = |storage, credentials| json!({"storage": storage, "credentials": credentials});
        let folder = json!({"id":"shared", "revision":0, "label":"Shared folder", "kind":"folder", "directory":root, "tenants":[""], "enabled":true});
        assert_eq!(
            call(
                &app,
                Method::PUT,
                "/api/workflows/storage",
                Some(&cookie),
                Some(save(folder, serde_json::Value::Null))
            )
            .await
            .0,
            StatusCode::OK
        );
        let check = json!({"revision":1});
        assert_eq!(
            call(
                &app,
                Method::POST,
                "/api/workflows/storage/shared/test",
                Some(&cookie),
                Some(check.clone())
            )
            .await
            .0,
            StatusCode::OK
        );
        assert_eq!(
            call(
                &app,
                Method::POST,
                "/api/workflows/storage/shared/test",
                Some(&cookie),
                Some(json!({"revision":0}))
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        std::fs::remove_dir(&root).unwrap();
        assert_eq!(
            call(
                &app,
                Method::POST,
                "/api/workflows/storage/shared/test",
                Some(&cookie),
                Some(check.clone())
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(directory.path(), &root).unwrap();
            assert_eq!(
                call(
                    &app,
                    Method::POST,
                    "/api/workflows/storage/shared/test",
                    Some(&cookie),
                    Some(check.clone())
                )
                .await
                .0,
                StatusCode::CONFLICT
            );
        }
        let receiver_dir = tempfile::tempdir().unwrap();
        let receiver = crate::api::testing::build(receiver_dir.path());
        let receiver_cookie = admin_cookie(&receiver);
        let (status, _, bytes) = call(
            &receiver,
            Method::POST,
            "/api/admin/links",
            Some(&receiver_cookie),
            Some(json!({"label":"Incoming masters", "password":"receive-secret"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let link: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let router = crate::app::router(receiver);
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let request_url = format!("{origin}/r/{}", link["link"]["id"].as_str().unwrap());
        let port = json!({"id":"west", "revision":0, "label":"West", "kind":"votport", "endpoint":origin, "tenants":[""], "enabled":true});
        assert_eq!(call(&app, Method::PUT, "/api/workflows/storage", Some(&cookie), Some(save(port, json!({"mode":"votport", "request_url":request_url, "password":"receive-secret"})))).await.0, StatusCode::OK);
        let (status, _, bytes) = call(
            &app,
            Method::POST,
            "/api/workflows/storage/west/test",
            Some(&cookie),
            Some(check.clone()),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&bytes)
        );
        for (index, password) in [serde_json::Value::Null, json!("wrong")]
            .into_iter()
            .enumerate()
        {
            let mut port = app
                .store
                .delivery_storages()
                .unwrap()
                .into_iter()
                .find(|s| s.id == "west")
                .unwrap();
            port.revision = index as u64 + 1;
            assert_eq!(
                call(
                    &app,
                    Method::PUT,
                    "/api/workflows/storage",
                    Some(&cookie),
                    Some(save(
                        json!(port),
                        json!({"mode":"votport", "request_url":request_url, "password":password})
                    ))
                )
                .await
                .0,
                StatusCode::OK
            );
            assert_eq!(
                call(
                    &app,
                    Method::POST,
                    "/api/workflows/storage/west/test",
                    Some(&cookie),
                    Some(json!({"revision":index+2}))
                )
                .await
                .0,
                StatusCode::CONFLICT
            );
        }
        server.abort();
    }

    #[tokio::test]
    async fn storage_credentials_stay_private_and_change_with_the_revision() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let cookie = admin_cookie(&app);
        let config = json!({"id":"archive","revision":0,"label":"Archive","endpoint":"http://127.0.0.1:1","bucket":"archive","region":"us-east-1","prefix":"","path_style":true,"kms_key_id":null,"tenants":[""],"enabled":true});
        let keys = json!({"mode":"access_key","access_key_id":"fixture-access","secret_access_key":"fixture-secret","session_token":"fixture-session"});
        let payload = json!({"storage":config,"credentials":keys});
        assert_eq!(
            call(
                &app,
                Method::PUT,
                "/api/workflows/storage",
                None,
                Some(payload.clone())
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        let mut viewer = auth::AdminIdentity::local_admin();
        viewer.role = "viewer".into();
        let viewer_cookie = format!(
            "votport_admin={}",
            auth::issue_admin_token(&app.secret, &viewer, &app.config.admin_token_tag)
        );
        assert_eq!(
            call(
                &app,
                Method::PUT,
                "/api/workflows/storage",
                Some(&viewer_cookie),
                Some(payload.clone())
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(
                &app,
                Method::POST,
                "/api/workflows/storage/archive/test",
                Some(&viewer_cookie),
                Some(json!({"revision":0}))
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        let saved = call(
            &app,
            Method::PUT,
            "/api/workflows/storage",
            Some(&cookie),
            Some(payload.clone()),
        )
        .await;
        assert_eq!(
            saved.0,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&saved.2)
        );
        let mut config: serde_json::Value = serde_json::from_slice(&saved.2).unwrap();
        assert_eq!(config["revision"], 1);
        let listing = call(
            &app,
            Method::GET,
            "/api/workflows/storage",
            Some(&cookie),
            None,
        )
        .await;
        let public: serde_json::Value = serde_json::from_slice(&listing.2).unwrap();
        assert_eq!(public["storage"][0]["credential_source"], "saved");
        for body in [&saved.2, &listing.2] {
            let body = String::from_utf8_lossy(body);
            for secret in ["fixture-access", "fixture-secret", "fixture-session"] {
                assert!(!body.contains(secret));
            }
        }
        assert!(app
            .store
            .delivery_storage_has_credentials("archive")
            .unwrap());
        let stored = app
            .store
            .delivery_storage_credentials("archive", 1)
            .unwrap()
            .unwrap();
        assert_eq!(serde_json::to_value(stored).unwrap(), keys);
        assert!(app
            .store
            .delivery_storage_credentials("archive", 0)
            .is_err());
        assert_eq!(
            call(
                &app,
                Method::PUT,
                "/api/workflows/storage",
                Some(&cookie),
                Some(payload)
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        let invalid = json!({"mode":"access_key","access_key_id":"fixture-access","secret_access_key":"","session_token":null});
        assert_eq!(
            call(
                &app,
                Method::PUT,
                "/api/workflows/storage",
                Some(&cookie),
                Some(json!({"storage":config,"credentials":invalid}))
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            serde_json::to_value(
                app.store
                    .delivery_storage_credentials("archive", 1)
                    .unwrap()
                    .unwrap()
            )
            .unwrap(),
            keys
        );
        config["label"] = json!("Archive renamed");
        let renamed = call(
            &app,
            Method::PUT,
            "/api/workflows/storage",
            Some(&cookie),
            Some(json!({"storage":config})),
        )
        .await;
        assert_eq!(renamed.0, StatusCode::OK);
        config = serde_json::from_slice(&renamed.2).unwrap();
        assert_eq!(config["revision"], 2);
        assert_eq!(
            serde_json::to_value(
                app.store
                    .delivery_storage_credentials("archive", 2)
                    .unwrap()
                    .unwrap()
            )
            .unwrap(),
            keys
        );
        assert!(app
            .store
            .delivery_storage_credentials("archive", 1)
            .is_err());
        assert_eq!(
            call(
                &app,
                Method::POST,
                "/api/workflows/storage/archive/test",
                Some(&cookie),
                Some(json!({"revision":1}))
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        let cleared = call(
            &app,
            Method::PUT,
            "/api/workflows/storage",
            Some(&cookie),
            Some(json!({"storage":config,"credentials":{"mode":"server"}})),
        )
        .await;
        assert_eq!(cleared.0, StatusCode::OK);
        assert!(!app
            .store
            .delivery_storage_has_credentials("archive")
            .unwrap());
        assert!(app
            .store
            .delivery_storage_credentials("archive", 3)
            .unwrap()
            .is_none());
        assert!(app
            .store
            .delivery_storage_credentials("archive", 2)
            .is_err());
        let events = app.store.delivery_events("", 0, 100).unwrap();
        let events = serde_json::to_string(&events).unwrap();
        assert!(!events.contains("fixture-secret") && !events.contains("fixture-session"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn required_checkers_fail_closed_and_bound_output() {
        let path = Path::new("fixture");
        assert_eq!(
            run_check("/bin/sh".into(), &["-c", "printf checked"], path)
                .await
                .unwrap(),
            b"checked"
        );
        for script in ["exit 1", "head -c 65537 /dev/zero"] {
            assert!(tokio::time::timeout(
                std::time::Duration::from_secs(5),
                run_check("/bin/sh".into(), &["-c", script], path)
            )
            .await
            .expect("checker limit must not hang")
            .is_err());
        }
        assert!(run_check("/nonexistent-votport-checker".into(), &[], path)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn workflow_reuses_library_bytes_and_enforces_recipient_approval_and_evidence() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        std::fs::create_dir_all(app.config.outbound_dir.join("project")).unwrap();
        std::fs::write(
            app.config.outbound_dir.join("project/file.bin"),
            b"original",
        )
        .unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[2; 32]);
        let holder = hex::encode(key.verifying_key().to_bytes());
        let mut project = crate::workflow::tests::project();
        project.recipients.push(crate::workflow::Recipient {
            email: "recipient@example.com".into(),
            holder: holder.clone(),
        });
        let project = app
            .store
            .save_delivery_project("", "local", project)
            .unwrap();
        let mut request = crate::workflow::tests::request();
        request.recipients = vec![holder.clone()];
        let job = app
            .store
            .enqueue_delivery_job("", "sender", 1, None, project, request)
            .unwrap();
        let running = app
            .store
            .claim_delivery_job("boot", now_unix())
            .unwrap()
            .unwrap();
        prepare(&app, running).await.unwrap();
        let token = app.signer.delivery_token(&format!("{}:0", job.id));
        let path = format!("/api/s/{token}");
        for suffix in [
            "",
            "?offset=0&limit=1",
            "/file",
            "/bundle",
            "/batch",
            "/receipt",
            "/logo",
        ] {
            let response = call(&app, Method::GET, &format!("{path}{suffix}"), None, None).await;
            assert_eq!(
                response.0,
                StatusCode::FORBIDDEN,
                "{suffix}: {}",
                String::from_utf8_lossy(&response.2)
            );
        }
        let pending = app.store.delivery_job(&job.id).unwrap().unwrap();
        app.store
            .change_delivery_job(
                "",
                &job.id,
                "approver",
                false,
                "approve",
                pending.manifest.as_deref(),
            )
            .unwrap();
        let response = call(&app, Method::GET, &path, None, None).await;
        assert_eq!(response.0, StatusCode::FORBIDDEN);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&response.2).unwrap()["code"],
            "recipient_required"
        );
        let response = call(
            &app,
            Method::POST,
            &format!("{path}/recipient-challenge"),
            None,
            Some(json!({"holder": holder})),
        )
        .await;
        assert_eq!(
            response.0,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&response.2)
        );
        let authorization: SignedChallenge = serde_json::from_slice(&response.2).unwrap();
        let proof = AccessProof::sign(authorization, &key);
        let mut forged = proof.clone();
        forged.authorization.challenge.manifest = "changed".into();
        assert_eq!(
            call(
                &app,
                Method::POST,
                &format!("{path}/recipient-verify"),
                None,
                Some(json!(forged))
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        let response = call(
            &app,
            Method::POST,
            &format!("{path}/recipient-verify"),
            None,
            Some(json!(proof)),
        )
        .await;
        assert_eq!(response.0, StatusCode::OK);
        let cookie = response
            .1
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        assert!(!payload_root(&app, "", &job.id).exists());
        let response = call(
            &app,
            Method::GET,
            &format!("{path}/file"),
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(
            response.0,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&response.2)
        );
        assert_eq!(response.2, b"original");
        let lease = response
            .1
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        let with_lease = format!("{cookie}; {lease}");
        let response = call(
            &app,
            Method::POST,
            &format!("{path}/evidence-challenge"),
            Some(&cookie),
            Some(json!({"holder": holder})),
        )
        .await;
        assert_eq!(response.0, StatusCode::OK);
        let authorization: SignedChallenge = serde_json::from_slice(&response.2).unwrap();
        let accepted = Evidence::sign(authorization.clone(), EvidenceKind::Accepted, &key);
        assert_eq!(
            call(
                &app,
                Method::POST,
                "/api/evidence",
                None,
                Some(json!(accepted))
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        let verified = Evidence::sign(authorization, EvidenceKind::Verified, &key);
        let response = call(
            &app,
            Method::POST,
            "/api/evidence",
            None,
            Some(json!(verified)),
        )
        .await;
        assert_eq!(response.0, StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&response.2).unwrap()["id"],
            verified.id()
        );
        assert_eq!(
            call(
                &app,
                Method::POST,
                "/api/evidence",
                None,
                Some(json!(accepted))
            )
            .await
            .0,
            StatusCode::OK
        );
        for (subject, role, expected) in [
            ("outside", "viewer", StatusCode::NOT_FOUND),
            ("observer", "viewer", StatusCode::OK),
            ("local", "admin", StatusCode::OK),
        ] {
            let mut identity = auth::AdminIdentity::local_admin();
            identity.subject = subject.into();
            identity.role = role.into();
            let cookie = format!(
                "votport_admin={}",
                auth::issue_admin_token(&app.secret, &identity, &app.config.admin_token_tag)
            );
            for route in [
                format!("/api/admin/outbound/{}/evidence", job.id),
                format!("/api/workflows/jobs/{}/evidence", job.id),
            ] {
                assert_eq!(
                    call(&app, Method::GET, &route, Some(&cookie), None).await.0,
                    expected,
                    "{subject}: {route}"
                );
            }
        }
        let rotated = call(
            &app,
            Method::PATCH,
            &format!("/api/admin/outbound-grants/{}", job.id),
            Some(&admin_cookie(&app)),
            Some(json!({"rotate": true})),
        )
        .await;
        assert_eq!(
            rotated.0,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&rotated.2)
        );
        let rotated_url = serde_json::from_slice::<serde_json::Value>(&rotated.2).unwrap()["url"]
            .as_str()
            .unwrap()
            .to_owned();
        let displayed = public_job(
            &app,
            &HeaderMap::new(),
            app.store.delivery_job(&job.id).unwrap().unwrap(),
        );
        assert_eq!(displayed["url"], rotated_url);
        assert_eq!(
            call(
                &app,
                Method::GET,
                &format!("{path}/file"),
                Some(&with_lease),
                None
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
        let project = app.store.delivery_project("", "project").unwrap().unwrap();
        app.store
            .save_delivery_project("", "local", project)
            .unwrap();
        assert!(public_job(
            &app,
            &HeaderMap::new(),
            app.store.delivery_job(&job.id).unwrap().unwrap()
        )["url"]
            .is_null());
    }

    #[tokio::test]
    async fn snapshot_budget_and_retirement_preserve_signed_history() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        std::fs::create_dir_all(app.config.outbound_dir.join("project")).unwrap();
        std::fs::write(
            app.config.outbound_dir.join("project/file.bin"),
            b"snapshot",
        )
        .unwrap();
        let project = app
            .store
            .save_delivery_project("", "local", crate::workflow::tests::project())
            .unwrap();
        let job = app
            .store
            .enqueue_delivery_job(
                "",
                "sender",
                1,
                None,
                project,
                crate::workflow::tests::request(),
            )
            .unwrap();
        let running = app
            .store
            .claim_delivery_job("boot", now_unix())
            .unwrap()
            .unwrap();
        assert!(app
            .store
            .reserve_delivery_snapshot(&job.id, running.attempts, 10, 9)
            .is_err());
        freeze_files(&app, &running).await.unwrap();
        let root = payload_root(&app, "", &job.id);
        assert!(root.join("file.bin").is_file());
        let cancelled = app
            .store
            .change_delivery_job("", &job.id, "sender", false, "cancel", None)
            .unwrap();
        assert!(app
            .store
            .claim_snapshot_retirement(cancelled.updated_at + 7 * 86400 - 1)
            .unwrap()
            .is_none());
        assert_eq!(
            app.store
                .claim_snapshot_retirement(cancelled.updated_at + 7 * 86400)
                .unwrap()
                .unwrap()
                .id,
            job.id
        );
        retire_snapshot(&app).await.unwrap();
        assert!(!root.exists());
        let retired = app.store.delivery_job(&job.id).unwrap().unwrap();
        assert_eq!(retired.state, "retired");
        assert_eq!(retired.checks["snapshot_bytes"], 0);
        assert!(app
            .store
            .delivery_events("", 0, 100)
            .unwrap()
            .iter()
            .all(|event| event.verify()));
        app.store
            .fail_delivery_job("missing", 1, "already removed")
            .unwrap();
    }
}
