use super::*;
use futures_util::StreamExt;
use object_store::{
    aws::{AmazonS3Builder, AmazonS3ConfigKey},
    path::Path as ObjectPath,
    GetOptions, ObjectStore, ObjectStoreExt, PutMode,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Storage {
    pub id: String,
    pub revision: u64,
    pub label: String,
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub prefix: String,
    pub path_style: bool,
    pub kms_key_id: Option<String>,
    pub tenants: Vec<String>,
    pub enabled: bool,
}

impl Storage {
    pub fn validate(&self) -> Result<(), String> {
        if !crate::workflow::valid_id(&self.id)
            || !self
                .id
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
            || self.label.trim().is_empty()
            || self.label.len() > 200
            || self.region.is_empty()
            || self.region.len() > 100
            || (!self.prefix.is_empty() && !crate::workflow::valid_path(&self.prefix))
            || self.tenants.len() > 500
            || self.kms_key_id.as_ref().is_some_and(|key| {
                key.is_empty() || key.len() > 2048 || key.chars().any(char::is_control)
            })
        {
            return Err("invalid storage ID, label, region, prefix, tenant list or KMS key".into());
        }
        crate::backup::validate_endpoint(&self.endpoint)?;
        crate::backup::validate_bucket(&self.bucket)?;
        Ok(())
    }

    fn connect(&self) -> Result<Arc<dyn ObjectStore>, String> {
        let prefix = format!("VOTPORT_STORAGE_{}", self.id.to_ascii_uppercase());
        let mut builder = match (
            std::env::var(format!("{prefix}_ACCESS_KEY_ID")).ok(),
            std::env::var(format!("{prefix}_SECRET_ACCESS_KEY")).ok(),
        ) {
            (Some(access), Some(secret)) => AmazonS3Builder::new()
                .with_access_key_id(access)
                .with_secret_access_key(secret),
            (None, None) => AmazonS3Builder::from_env(),
            _ => return Err("storage credentials are incomplete".into()),
        }
        .with_config(AmazonS3ConfigKey::S3Endpoint, &self.endpoint)
        .with_bucket_name(&self.bucket)
        .with_region(&self.region)
        .with_virtual_hosted_style_request(!self.path_style)
        .with_allow_http(self.endpoint.starts_with("http://"));
        if let Ok(token) = std::env::var(format!("{prefix}_SESSION_TOKEN")) {
            builder = builder.with_token(token);
        }
        if let Some(key) = &self.kms_key_id {
            builder = builder.with_sse_kms_encryption(key);
        }
        builder
            .build()
            .map(|store| Arc::new(store) as Arc<dyn ObjectStore>)
            .map_err(|_| "invalid storage connection".into())
    }

    fn key(&self, relative: &str) -> ApiResult<ObjectPath> {
        ObjectPath::parse(if self.prefix.is_empty() {
            relative.into()
        } else {
            format!("{}/{relative}", self.prefix)
        })
        .map_err(|_| conflict("invalid S3 object key".into()))
    }
}

pub async fn list(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult<Response> {
    let identity = admin::require_operator(&app, &headers)?;
    let platform_admin = identity.tenant.is_empty() && identity.role == "admin";
    let storage = app
        .store
        .delivery_storages()
        .map_err(crate::api::store_unavailable)?
        .into_iter()
        .filter(|storage| {
            platform_admin || (storage.enabled && storage.tenants.contains(&identity.tenant))
        })
        .collect::<Vec<_>>();
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({"storage": storage})),
    )
        .into_response())
}

pub async fn put(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(storage): Json<Storage>,
) -> ApiResult<Response> {
    let identity = admin::require_operator(&app, &headers)?;
    admin::require_admin_write(&headers, &identity)?;
    if !identity.tenant.is_empty() {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "platform administrator required for storage connections",
        ));
    }
    storage.validate().map_err(conflict)?;
    let storage = app
        .store
        .save_delivery_storage(&identity.subject, storage)
        .map_err(conflict)?;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(storage)).into_response())
}

pub(super) fn authorized_storage(app: &App, tenant: &str, id: &str) -> ApiResult<Storage> {
    app.store
        .delivery_storages()
        .map_err(crate::api::store_unavailable)?
        .into_iter()
        .find(|storage| {
            storage.id == id
                && storage.enabled
                && storage.tenants.iter().any(|allowed| allowed == tenant)
        })
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::FORBIDDEN,
                "storage is unavailable for this tenant",
            )
        })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SourceObject {
    name: String,
    key: String,
    size: u64,
    etag: Option<String>,
    version: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct SourceInventory {
    storage_id: String,
    revision: u64,
    objects: Vec<SourceObject>,
}

pub(super) async fn import(app: &Arc<App>, job: &Job) -> ApiResult<Option<u64>> {
    let Some(import) = &job.request.import else {
        return Ok(None);
    };
    let config = authorized_storage(app, &job.tenant, &import.storage_id)?;
    let store = config.connect().map_err(conflict)?;
    let root = payload_root(app, &job.tenant, &job.id);
    let parent = root.parent().ok_or_else(ApiError::not_found)?;
    create_library_dirs(&library_root(app, &job.tenant))?;
    if !library_components_safe(&library_root(app, &job.tenant), parent) {
        return Err(ApiError::not_found());
    }
    create_library_dirs(parent)?;
    crate::paths::tighten_private_dir(parent).map_err(ApiError::internal)?;
    let source_inventory = parent.join("source-inventory.json");
    let objects: Vec<SourceObject> = if source_inventory.exists() {
        let bytes = read_inventory(&source_inventory)?;
        let inventory: SourceInventory = serde_json::from_slice(&bytes)
            .map_err(|_| conflict("source inventory is corrupt".into()))?;
        if inventory.storage_id != config.id || inventory.revision != config.revision {
            return Err(conflict(
                "storage configuration changed; submit a new delivery".into(),
            ));
        }
        inventory.objects
    } else {
        let prefix = config.key(&import.prefix)?;
        let prefix_string = format!("{}/", prefix.as_ref().trim_end_matches('/'));
        let mut list = store.list(Some(&prefix));
        let mut objects = vec![];
        let mut total = 0u64;
        while let Some(object) = list.next().await {
            let object = object.map_err(|_| conflict("S3 object listing failed".into()))?;
            let Some(name) = object
                .location
                .as_ref()
                .strip_prefix(&prefix_string)
                .filter(|name| !name.is_empty() && !name.ends_with('/'))
            else {
                continue;
            };
            payload_path(app, &job.tenant, &job.id, name)?;
            if object.e_tag.is_none() && object.version.is_none() {
                return Err(conflict(
                    "S3 source must provide an ETag or version for conditional reads".into(),
                ));
            }
            total = total
                .checked_add(object.size)
                .filter(|total| *total <= app.config.max_upload_bytes)
                .ok_or_else(|| conflict("S3 source exceeds delivery size limit".into()))?;
            objects.push(SourceObject {
                name: name.into(),
                key: object.location.to_string(),
                size: object.size,
                etag: object.e_tag,
                version: object.version,
            });
            if objects.len() > MAX_LIBRARY_PROJECT_FILES {
                return Err(conflict("S3 source has too many files".into()));
            }
        }
        if objects.is_empty() {
            return Err(conflict("S3 prefix contains no files".into()));
        }
        objects.sort_by(|a, b| a.name.cmp(&b.name));
        let inventory = SourceInventory {
            storage_id: config.id.clone(),
            revision: config.revision,
            objects,
        };
        let bytes = serde_json::to_vec(&inventory)
            .map_err(|_| ApiError::internal("serialize source inventory"))?;
        if bytes.len() > 64 * 1024 * 1024 {
            return Err(conflict("source inventory exceeds 64 MiB".into()));
        }
        crate::backup::atomic_write_private(&source_inventory, &bytes)
            .map_err(|_| conflict("persist S3 source inventory failed".into()))?;
        sync_directory(parent)?;
        inventory.objects
    };
    if parent.join("inventory.json").is_file() {
        return Ok(Some(config.revision));
    }
    if objects.is_empty() || objects.len() > MAX_LIBRARY_PROJECT_FILES {
        return Err(conflict("invalid S3 inventory".into()));
    }
    let mut portable_names = std::collections::HashSet::new();
    for object in &objects {
        if !portable_names.insert(bundle_collision_key(&object.name)) {
            return Err(conflict(
                "S3 filenames collide on recipient filesystems".into(),
            ));
        }
    }
    let reserved = objects
        .iter()
        .try_fold(0u64, |total, object| total.checked_add(object.size))
        .filter(|total| *total <= app.config.max_upload_bytes)
        .ok_or_else(|| conflict("S3 source exceeds delivery size limit".into()))?;
    app.store
        .reserve_delivery_snapshot(
            &job.id,
            job.attempts,
            reserved,
            app.config.workflow_snapshot_bytes,
        )
        .map_err(conflict)?;
    let mut total = 0u64;
    let mut names = vec![];
    for object in objects {
        if authorized_storage(app, &job.tenant, &config.id)?.revision != config.revision {
            return Err(conflict(
                "storage configuration changed during import".into(),
            ));
        }
        let path = payload_path(app, &job.tenant, &job.id, &object.name)?;
        total = total
            .checked_add(object.size)
            .filter(|total| *total <= app.config.max_upload_bytes)
            .ok_or_else(|| conflict("S3 source exceeds delivery size limit".into()))?;
        create_library_dirs(path.parent().ok_or_else(ApiError::not_found)?)?;
        let response = store
            .get_opts(
                &ObjectPath::parse(object.key)
                    .map_err(|_| conflict("invalid persisted S3 object key".into()))?,
                GetOptions {
                    if_match: object.etag,
                    version: object.version,
                    ..Default::default()
                },
            )
            .await
            .map_err(|_| conflict("S3 source changed or conditional read failed".into()))?;
        let mut stream = response.into_stream();
        let mut file = tokio::fs::File::create(&path)
            .await
            .map_err(|_| conflict("create imported payload failed".into()))?;
        let mut received = 0u64;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| conflict("S3 download interrupted".into()))?;
            received = received
                .checked_add(chunk.len() as u64)
                .filter(|bytes| *bytes <= object.size)
                .ok_or_else(|| conflict("S3 object size changed".into()))?;
            file.write_all(&chunk)
                .await
                .map_err(|_| conflict("write imported payload failed; check free space".into()))?;
        }
        if received != object.size {
            return Err(conflict("S3 object size changed".into()));
        }
        file.sync_all()
            .await
            .map_err(|_| conflict("sync imported payload failed".into()))?;
        names.push(object.name);
    }
    publish_inventory(app, &job.tenant, &job.id, &names)?;
    Ok(Some(config.revision))
}

fn read_inventory(path: &Path) -> ApiResult<Vec<u8>> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| ApiError::not_found())?;
    if !meta.is_file() || meta.len() > 64 * 1024 * 1024 {
        return Err(conflict("invalid workflow inventory".into()));
    }
    std::fs::read(path).map_err(|_| conflict("read workflow inventory failed".into()))
}

pub(super) fn publish_inventory(
    app: &App,
    tenant: &str,
    id: &str,
    names: &[String],
) -> ApiResult<()> {
    let root = payload_root(app, tenant, id);
    let mut directories = std::collections::BTreeSet::new();
    let library = library_root(app, tenant);
    for name in names {
        let path = payload_path(app, tenant, id, name)?;
        let mut parent = path.parent();
        while let Some(directory) = parent {
            directories.insert(directory.to_owned());
            if directory == library {
                break;
            }
            parent = directory.parent();
        }
    }
    for directory in directories.iter().rev() {
        sync_directory(directory)?;
    }
    let bytes =
        serde_json::to_vec(names).map_err(|_| ApiError::internal("serialize frozen inventory"))?;
    if bytes.len() > 64 * 1024 * 1024 {
        return Err(conflict("frozen inventory exceeds 64 MiB".into()));
    }
    let parent = root.parent().ok_or_else(ApiError::not_found)?;
    crate::backup::atomic_write_private(&parent.join("inventory.json"), &bytes)
        .map_err(|_| conflict("persist frozen inventory failed".into()))?;
    sync_directory(parent)
}

fn sync_directory(path: &Path) -> ApiResult<()> {
    std::fs::File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| conflict("sync workflow directory failed".into()))
}

pub(super) async fn export(app: &Arc<App>, job: &Job) -> ApiResult<()> {
    let config = authorized_storage(
        app,
        &job.tenant,
        job.project
            .export_storage
            .as_deref()
            .ok_or_else(|| conflict("export storage missing".into()))?,
    )?;
    if job
        .checks
        .get("export_storage_revision")
        .and_then(|value| value.as_u64())
        != Some(config.revision)
    {
        return Err(conflict(
            "storage configuration changed; submit a new delivery".into(),
        ));
    }
    let store = config.connect().map_err(conflict)?;
    let grant = app
        .store
        .outbound_grant_by_id(&job.id)
        .map_err(crate::api::store_unavailable)?
        .ok_or_else(ApiError::not_found)?;
    let manifest = job
        .manifest
        .as_deref()
        .ok_or_else(|| conflict("frozen manifest missing".into()))?;
    let prefix = format!("deliveries/{}/{manifest}", job.id);
    let mut files = vec![];
    for (index, file) in grant.files.iter().enumerate() {
        app.store
            .require_delivery_export(&job.id, job.attempts)
            .map_err(conflict)?;
        let key = config.key(&format!("{prefix}/files/{}", file.name))?;
        let path = source_info_indexed_with_file(app, &grant, index, Some(file))?.path;
        upload_file(&*store, &key, &path, file).await?;
        files.push(json!({"name": file.name,"suite": file.suite,"root": file.root,"bytes": file.bytes,"key": key.to_string(),"receipt": file.receipt_b64}));
    }
    app.store
        .require_delivery_export(&job.id, job.attempts)
        .map_err(conflict)?;
    let document = json!({"format": "votport-delivery-export-v1","job_id": job.id,"manifest": manifest,"metadata": job.request.metadata,"project_id": job.project.id,"policy_revision": job.project.revision,"approved_by": job.approved_by,"checks": job.checks,"files": files,"issuer": app.signer.public_hex});
    let attestation =
        json!({"document": document,"signature": app.signer.sign_delivery_export(&document)});
    let bytes = serde_json::to_vec(&attestation)
        .map_err(|_| ApiError::internal("serialize export manifest"))?;
    let completion = config.key(&format!("{prefix}/complete.json"))?;
    match store
        .put_opts(&completion, bytes.clone().into(), PutMode::Create.into())
        .await
    {
        Ok(_) => {}
        Err(
            object_store::Error::AlreadyExists { .. } | object_store::Error::Precondition { .. },
        ) => {
            let result = store
                .get(&completion)
                .await
                .map_err(|_| conflict("read existing export manifest failed".into()))?;
            if result.meta.size != bytes.len() as u64
                || result
                    .bytes()
                    .await
                    .map_err(|_| conflict("read existing export manifest failed".into()))?
                    .as_ref()
                    != bytes
            {
                return Err(conflict(
                    "existing export manifest does not match this delivery".into(),
                ));
            }
        }
        Err(_) => {
            return Err(conflict(
                "publish immutable S3 completion manifest failed".into(),
            ))
        }
    }
    app.store
        .complete_delivery_export(&job.id, job.attempts, completion.as_ref())
        .map_err(conflict)?;
    Ok(())
}

async fn upload_file(
    store: &dyn ObjectStore,
    key: &ObjectPath,
    path: &Path,
    expected: &OutboundGrantFile,
) -> ApiResult<()> {
    let part_size = expected.bytes.div_ceil(10_000).max(8 * 1024 * 1024);
    // ponytail: at most 128 MiB per part; larger than 1.25 TiB needs a streaming multipart adapter.
    if part_size > 128 * 1024 * 1024 {
        return Err(conflict("S3 export supports files up to 1.25 TiB".into()));
    }
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|_| conflict("open export payload failed".into()))?;
    let mut builder = InMemoryObjectBuilder::new(
        Suite::try_from(1).map_err(|_| ApiError::internal("object suite"))?,
        Some(expected.bytes),
        expected.bytes,
    )
    .map_err(|_| conflict("build export verifier failed".into()))?;
    let mut upload = store
        .put_multipart(key)
        .await
        .map_err(|_| conflict("start S3 multipart upload failed".into()))?;
    let result = async {
        let mut total = 0u64;
        loop {
            let mut bytes = vec![0u8; part_size as usize];
            let mut used = 0;
            while used < bytes.len() {
                let count = file
                    .read(&mut bytes[used..])
                    .await
                    .map_err(|_| conflict("read export payload failed".into()))?;
                if count == 0 {
                    break;
                }
                used += count;
            }
            bytes.truncate(used);
            if used == 0 && total > 0 {
                break;
            }
            total = total
                .checked_add(used as u64)
                .filter(|bytes| *bytes <= expected.bytes)
                .ok_or_else(|| conflict("export payload size changed".into()))?;
            builder
                .update(&bytes)
                .map_err(|_| conflict("verify export payload failed".into()))?;
            upload
                .put_part(bytes.into())
                .await
                .map_err(|_| conflict("S3 multipart upload interrupted".into()))?;
            if used == 0 {
                break;
            }
        }
        let object = builder
            .finish()
            .map_err(|_| conflict("verify export payload failed".into()))?;
        if total != expected.bytes || hex::encode(object.object_id().root) != expected.root {
            return Err(conflict(
                "export payload does not match the frozen manifest".into(),
            ));
        }
        upload
            .complete()
            .await
            .map_err(|_| conflict("complete S3 multipart upload failed".into()))?;
        Ok(())
    }
    .await;
    if result.is_err() {
        let _ = upload.abort().await;
    }
    result
}
