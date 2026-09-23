use super::*;
use futures_util::StreamExt;
use object_store::{
    aws::{AmazonS3Builder, AmazonS3ConfigKey},
    path::Path as ObjectPath,
    GetOptions, ObjectStore, ObjectStoreExt, PutMode,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageKind {
    #[default]
    S3,
    Folder,
    Votport,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Storage {
    pub id: String,
    pub revision: u64,
    pub label: String,
    #[serde(default)]
    pub kind: StorageKind,
    #[serde(default)]
    pub directory: String,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub bucket: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub prefix: String,
    #[serde(default)]
    pub path_style: bool,
    pub kms_key_id: Option<String>,
    pub tenants: Vec<String>,
    pub enabled: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum Credentials {
    Server,
    AccessKey {
        access_key_id: String,
        secret_access_key: String,
        session_token: Option<String>,
    },
    TradeRoute {
        route_id: String,
    },
    Votport {
        request_url: String,
        password: Option<String>,
    },
}

impl Credentials {
    pub fn validate(&self) -> Result<(), String> {
        if let Self::AccessKey {
            access_key_id,
            secret_access_key,
            session_token,
        } = self
        {
            for value in [
                Some(access_key_id),
                Some(secret_access_key),
                session_token.as_ref(),
            ]
            .into_iter()
            .flatten()
            {
                if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
                    return Err("storage credentials must be nonempty, at most 4096 characters and contain no control characters".into());
                }
            }
        }
        if let Self::Votport {
            request_url,
            password,
        } = self
        {
            receive_url(request_url)?;
            if password.as_ref().is_some_and(|value| value.len() > 256) {
                return Err("request password must be at most 256 bytes".into());
            }
        }
        Ok(())
    }
}

pub(crate) fn receive_url(value: &str) -> Result<(String, String), String> {
    let error = "enter a Votport receive link such as https://port.example/r/TOKEN";
    if value.len() > 4096 || value.chars().any(char::is_control) {
        return Err(error.into());
    }
    let url = reqwest::Url::parse(value).map_err(|_| error)?;
    let token = url.path().strip_prefix("/r/").ok_or(error)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !crate::auth::valid_hex(token, 32)
    {
        return Err(error.into());
    }
    Ok((url.origin().ascii_serialization(), token.to_owned()))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SaveStorage {
    storage: Storage,
    credentials: Option<Credentials>,
}

/// Client settings for delivery storage and backup S3. The default 30 second
/// total timeout covers the body too, so an import or restore of a
/// multi-gigabyte object failed on every retry; a stall is caught by the
/// read timeout instead. It restarts per downloaded chunk, but on an upload it
/// spans the whole part until the response headers: 15 minutes lets a 128 MiB
/// export part through at 150 KB/s. Set key by key: with_client_options would
/// replace the whole set, including any AWS_* client settings from_env read.
pub(crate) fn client_settings(builder: AmazonS3Builder, endpoint: &str) -> AmazonS3Builder {
    use object_store::ClientConfigKey;
    builder
        .with_allow_http(endpoint.starts_with("http://"))
        .with_config(AmazonS3ConfigKey::Client(ClientConfigKey::Timeout), "30d")
        .with_config(
            AmazonS3ConfigKey::Client(ClientConfigKey::ConnectTimeout),
            "30s",
        )
        .with_config(
            AmazonS3ConfigKey::Client(ClientConfigKey::ReadTimeout),
            "900s",
        )
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
            || (!self.prefix.is_empty() && !crate::workflow::valid_path(&self.prefix))
            || self.tenants.len() > 500
            || self.kms_key_id.as_ref().is_some_and(|key| {
                key.is_empty() || key.len() > 2048 || key.chars().any(char::is_control)
            })
        {
            return Err("invalid storage ID, label, prefix, tenant list or KMS key".into());
        }
        match self.kind {
            StorageKind::S3 => {
                if self.region.is_empty() || self.region.len() > 100 || !self.directory.is_empty() {
                    return Err("S3 storage requires a region and no shared folder path".into());
                }
                crate::backup::validate_endpoint(&self.endpoint)?;
                crate::backup::validate_bucket(&self.bucket)?;
            }
            StorageKind::Folder => {
                if self.directory.len() > 4096
                    || self.directory.chars().any(char::is_control)
                    || !Path::new(&self.directory).is_absolute()
                    || Path::new(&self.directory)
                        .components()
                        .any(|part| matches!(part, std::path::Component::ParentDir))
                    || !self.endpoint.is_empty()
                    || !self.bucket.is_empty()
                    || !self.region.is_empty()
                    || self.kms_key_id.is_some()
                {
                    return Err(
                        "shared storage requires an absolute folder path and no S3 settings".into(),
                    );
                }
            }
            StorageKind::Votport => {
                let url =
                    reqwest::Url::parse(&self.endpoint).map_err(|_| "invalid Votport origin")?;
                if !matches!(url.scheme(), "http" | "https")
                    || url.host_str().is_none()
                    || !url.username().is_empty()
                    || url.password().is_some()
                    || url.query().is_some()
                    || url.fragment().is_some()
                    || !matches!(url.path(), "" | "/")
                    || !self.directory.is_empty()
                    || !self.bucket.is_empty()
                    || !self.region.is_empty()
                    || self.kms_key_id.is_some()
                    || !self.prefix.is_empty()
                {
                    return Err(
                        "Votport storage requires a server origin and no S3 or folder settings"
                            .into(),
                    );
                }
            }
        }
        Ok(())
    }

    fn connect(&self, store: &crate::store::Store) -> Result<Arc<dyn ObjectStore>, String> {
        if self.kind == StorageKind::Folder {
            let root = folder_root(self).map_err(|error| error.message)?;
            return object_store::local::LocalFileSystem::new_with_prefix(root)
                .map(|store| Arc::new(store.with_fsync(true)) as Arc<dyn ObjectStore>)
                .map_err(|_| "shared folder is unavailable".into());
        }
        if self.kind != StorageKind::S3 {
            return Err("this connection is not S3 storage".into());
        }
        let prefix = format!("VOTPORT_STORAGE_{}", self.id.to_ascii_uppercase());
        let saved = store.delivery_storage_credentials(&self.id, self.revision)?;
        let explicit = matches!(saved, Some(Credentials::AccessKey { .. }));
        let mut builder = if let Some(Credentials::AccessKey {
            access_key_id,
            secret_access_key,
            session_token,
        }) = saved
        {
            let mut builder = AmazonS3Builder::new()
                .with_access_key_id(access_key_id)
                .with_secret_access_key(secret_access_key);
            if let Some(token) = session_token {
                builder = builder.with_token(token);
            }
            builder
        } else {
            match (
                std::env::var(format!("{prefix}_ACCESS_KEY_ID")).ok(),
                std::env::var(format!("{prefix}_SECRET_ACCESS_KEY")).ok(),
            ) {
                (Some(access), Some(secret)) => AmazonS3Builder::new()
                    .with_access_key_id(access)
                    .with_secret_access_key(secret),
                (None, None) => AmazonS3Builder::from_env(),
                _ => return Err("storage credentials are incomplete".into()),
            }
        }
        .with_config(AmazonS3ConfigKey::S3Endpoint, &self.endpoint)
        .with_bucket_name(&self.bucket)
        .with_region(&self.region)
        .with_virtual_hosted_style_request(!self.path_style);
        builder = client_settings(builder, &self.endpoint);
        if !explicit {
            if let Ok(token) = std::env::var(format!("{prefix}_SESSION_TOKEN")) {
                builder = builder.with_token(token);
            }
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
        let key = ObjectPath::parse(if self.prefix.is_empty() {
            relative.into()
        } else {
            format!("{}/{relative}", self.prefix)
        })
        .map_err(|_| conflict("invalid S3 object key".into()))?;
        if self.kind == StorageKind::S3 && key.as_ref().len() > 1024 {
            return Err(conflict(
                "S3 object key exceeds 1024 bytes including the storage prefix".into(),
            ));
        }
        Ok(key)
    }
}

pub async fn list(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    // Readable by an operator session or, like the other automation-readable
    // GETs, by a bearer token; a bearer needs jobs:create because the listing
    // exists to pick an S3 import source for job creation.
    let actor = actor(&app, &headers, peer, "jobs:create", false)?;
    let identity = &actor.identity;
    let platform_admin = identity.tenant.is_empty() && identity.role == "admin";
    let configs = app
        .store
        .delivery_storages()
        .map_err(crate::api::store_unavailable)?
        .into_iter()
        .filter(|storage| {
            platform_admin || (storage.enabled && storage.tenants.contains(&identity.tenant))
        })
        .collect::<Vec<_>>();
    let mut storage = Vec::with_capacity(configs.len());
    for config in configs {
        let saved = app
            .store
            .delivery_storage_has_credentials(&config.id)
            .map_err(crate::api::store_unavailable)?;
        let paired = app
            .store
            .is_trade_route(&config.id)
            .map_err(crate::api::store_unavailable)?;
        let mut public =
            serde_json::to_value(config).map_err(|e| ApiError::internal(e.to_string()))?;
        public["trade_route"] = json!(paired);
        public["credential_source"] = json!(if saved { "saved" } else { "server" });
        storage.push(public);
    }
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({"storage": storage})),
    )
        .into_response())
}

pub async fn put(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(body): Json<SaveStorage>,
) -> ApiResult<Response> {
    let identity = admin::require_operator_write(&app, &headers)?;
    if !identity.tenant.is_empty() {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "platform administrator required for storage connections",
        ));
    }
    if app
        .store
        .is_trade_route(&body.storage.id)
        .map_err(crate::api::store_unavailable)?
        || matches!(body.credentials, Some(Credentials::TradeRoute { .. }))
    {
        return Err(conflict("Manage paired routes in Trade routes".into()));
    }
    body.storage.validate().map_err(conflict)?;
    let previous = app
        .store
        .delivery_storages()
        .map_err(crate::api::store_unavailable)?
        .into_iter()
        .find(|config| config.id == body.storage.id);
    let credentials_saved = matches!(
        body.credentials,
        Some(Credentials::AccessKey { .. } | Credentials::Votport { .. })
    );
    let storage = app
        .store
        .save_delivery_storage(&identity.subject, body.storage, body.credentials)
        .map_err(conflict)?;
    // Value-free row: S3 endpoints may embed query credentials, so only the
    // origin and which fields changed are recorded.
    let changed: Vec<&str> = match &previous {
        None => vec![
            "label",
            "kind",
            "endpoint",
            "bucket",
            "region",
            "prefix",
            "path_style",
            "kms_key_id",
            "directory",
            "tenants",
            "enabled",
        ],
        Some(prev) => {
            let mut changed = Vec::new();
            if prev.label != storage.label {
                changed.push("label");
            }
            if prev.kind != storage.kind {
                changed.push("kind");
            }
            if prev.endpoint != storage.endpoint {
                changed.push("endpoint");
            }
            if prev.bucket != storage.bucket {
                changed.push("bucket");
            }
            if prev.region != storage.region {
                changed.push("region");
            }
            if prev.prefix != storage.prefix {
                changed.push("prefix");
            }
            if prev.path_style != storage.path_style {
                changed.push("path_style");
            }
            if prev.kms_key_id != storage.kms_key_id {
                changed.push("kms_key_id");
            }
            if prev.directory != storage.directory {
                changed.push("directory");
            }
            if prev.tenants != storage.tenants {
                changed.push("tenants");
            }
            if prev.enabled != storage.enabled {
                changed.push("enabled");
            }
            changed
        }
    };
    let detail = json!({
        "changed": changed,
        "endpoint": crate::api::audit_url(&storage.endpoint),
        "tenants": storage.tenants.clone(),
        "credentials_saved": credentials_saved,
        "revision": storage.revision,
    });
    let audiences: Vec<String> = if storage.tenants.is_empty() {
        vec![String::new()]
    } else {
        storage.tenants.clone()
    };
    for tenant in audiences {
        app.store.audit(
            &tenant,
            &identity.subject,
            "storage_changed",
            &storage.id,
            &detail,
        );
    }
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(storage)).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestStorage {
    revision: u64,
}
pub async fn test_connection(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<TestStorage>,
) -> ApiResult<Response> {
    let identity = admin::require_operator_write(&app, &headers)?;
    if !identity.tenant.is_empty() {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "platform administrator required",
        ));
    }
    let config = app
        .store
        .delivery_storages()
        .map_err(crate::api::store_unavailable)?
        .into_iter()
        .find(|config| config.id == id)
        .ok_or_else(ApiError::not_found)?;
    if config.revision != body.revision {
        return Err(conflict(
            "Storage changed. Save or reload it before testing.".into(),
        ));
    }
    // Both probe outcomes are audited, so each arm yields its result instead
    // of returning early.
    let attempt: Result<ConnectionProbe, ApiError> = match config.kind {
        StorageKind::S3 => async {
            let store = config.connect(&app.store).map_err(conflict)?;
            let prefix = if config.prefix.is_empty() {
                None
            } else {
                Some(config.key("")?)
            };
            let result = tokio::time::timeout(std::time::Duration::from_secs(10), async {
                store.list(prefix.as_ref()).next().await.transpose()
            })
            .await;
            if !matches!(result, Ok(Ok(_))) {
                return Err(conflict("Could not list this storage location. Check the endpoint, bucket, credentials and list permission, then try again.".into()));
            }
            Ok(ConnectionProbe::Verified("Connection verified. Bucket listing works; exports also require permission to write objects."))
        }
        .await,
        StorageKind::Folder => {
            let config = config.clone();
            tokio::task::spawn_blocking(move || {
                let root = folder_root(&config)?;
                std::fs::read_dir(root).map_err(|_| {
                    conflict("The shared folder cannot be read by the server.".into())
                })?;
                Ok::<_, ApiError>(())
            })
            .await
            .map_err(|_| ApiError::internal("shared folder check failed"))?
            .map(|_| ConnectionProbe::Verified("Connection verified. The server can read this shared folder; mirroring also requires write permission."))
        }
        StorageKind::Votport => async {
            let Some(Credentials::Votport {
                request_url,
                password,
            }) = app
                .store
                .delivery_storage_credentials(&id, body.revision)
                .map_err(conflict)?
            else {
                return Err(conflict(
                    "Save a receive link for this Votport connection.".into(),
                ));
            };
            let (origin, token) = receive_url(&request_url).map_err(conflict)?;
            let response = match app
                .http
                .get(format!("{origin}/api/r/{token}"))
                .send()
                .await
            {
                Ok(response) => response,
                Err(error) => {
                    return Ok(ConnectionProbe::Unreachable(
                        crate::notify::notification_connection_failure(&error),
                    ))
                }
            };
            if !response.status().is_success() {
                return Err(conflict(
                    "The destination did not return a usable receive request.".into(),
                ));
            }
            let info = port_json(response).await?;
            if info["usable"] != true {
                return Err(conflict(
                    "The destination receive request is expired or disabled.".into(),
                ));
            }
            if info["needs_password"] == true {
                let password = password.ok_or_else(|| {
                    conflict(
                        "This receive request needs a password. Save it with the connection."
                            .into(),
                    )
                })?;
                let response = match app
                    .http
                    .post(format!("{origin}/api/r/{token}/verify"))
                    .header("X-Votport", "1")
                    .json(&json!({"password":password}))
                    .send()
                    .await
                {
                    Ok(response) => response,
                    Err(error) => {
                        return Ok(ConnectionProbe::Unreachable(
                            crate::notify::notification_connection_failure(&error),
                        ))
                    }
                };
                if !response.status().is_success() {
                    return Err(conflict(
                        "The destination rejected the receive-request password.".into(),
                    ));
                }
            }
            Ok(ConnectionProbe::Verified("Connection verified. The destination port is accepting files into this receive request."))
        }
        .await,
    };
    // Origin-only address: S3 endpoints may embed credentials in the query.
    let address = if matches!(config.kind, StorageKind::Folder) {
        config.directory.clone()
    } else {
        crate::api::audit_url(&config.endpoint)
    };
    let verified = matches!(&attempt, Ok(ConnectionProbe::Verified(_)));
    app.store.audit(
        &identity.tenant,
        &identity.subject,
        "storage_connection_tested",
        &config.id,
        &json!({
            "kind": config.kind,
            "address": address,
            "outcome": if verified { "success" } else { "failure" }
        }),
    );
    // Audit finding 337: an unreachable destination is a probe outcome, so
    // it answers 200 with the connection failure class inside the normal
    // envelope; only refused probes keep an error status. `message` mirrors
    // the reason so the storage page renders both outcomes unchanged.
    match attempt {
        Ok(ConnectionProbe::Unreachable(reason)) => Ok((
            [(header::CACHE_CONTROL, "no-store")],
            Json(json!({"delivered": false, "reason": reason, "message": reason})),
        )
            .into_response()),
        Ok(ConnectionProbe::Verified(message)) => {
            app.store
                .delivery_storage_credentials(&id, body.revision)
                .map_err(conflict)?;
            Ok((
                [(header::CACHE_CONTROL, "no-store")],
                Json(json!({"ok": true, "message": message})),
            )
                .into_response())
        }
        Err(error) => Err(error),
    }
}

/// Audit finding 337: outcome of a destination connection probe. Verified
/// carries the success message; Unreachable carries the connection failure
/// class instead of an API error.
enum ConnectionProbe {
    Verified(&'static str),
    Unreachable(&'static str),
}

/// Audit finding 381: a delivery storage connection was undeletable. Remove
/// the connection and its stored credentials, refusing while a non-retired
/// delivery job still references it or a trade route owns the id.
pub async fn remove(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> ApiResult<Response> {
    let identity = admin::require_operator_write(&app, &headers)?;
    if !identity.tenant.is_empty() {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "platform administrator required for storage connections",
        ));
    }
    // Read the label before deletion for a value-free audit row.
    let removed_config = app
        .store
        .delivery_storages()
        .map_err(crate::api::store_unavailable)?
        .into_iter()
        .find(|config| config.id == id);
    use crate::store::DeliveryStorageRemoval;
    match app
        .store
        .delete_delivery_storage(&id)
        .map_err(crate::api::store_unavailable)?
    {
        DeliveryStorageRemoval::Deleted => {}
        DeliveryStorageRemoval::Absent => return Err(ApiError::not_found()),
        DeliveryStorageRemoval::PairedTradeRoute => {
            return Err(conflict("Manage paired routes in Trade routes".into()))
        }
        DeliveryStorageRemoval::JobsAttached => {
            return Err(conflict(
                "Deliveries still use this connection. Retire them before removing it.".into(),
            ))
        }
    }
    let audiences: Vec<String> = match &removed_config {
        Some(config) if !config.tenants.is_empty() => config.tenants.clone(),
        _ => vec![String::new()],
    };
    let detail = json!({
        "label": removed_config.as_ref().map(|config| config.label.clone()),
        "kind": removed_config.as_ref().map(|config| config.kind),
    });
    for tenant in audiences {
        app.store
            .audit(&tenant, &identity.subject, "storage_deleted", &id, &detail);
    }
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({"ok": true})),
    )
        .into_response())
}

fn folder_root(config: &Storage) -> ApiResult<PathBuf> {
    let root = Path::new(&config.directory);
    for ancestor in root.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor).map_err(|_| {
            conflict("The shared folder must exist and be accessible to the server.".into())
        })?;
        if !metadata.file_type().is_dir() {
            return Err(conflict(
                "The shared folder path must contain directories, without symlinks.".into(),
            ));
        }
    }
    Ok(root.to_owned())
}

async fn port_json(mut response: reqwest::Response) -> ApiResult<serde_json::Value> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| conflict("The destination response was interrupted.".into()))?
    {
        if bytes.len() + chunk.len() > 65536 {
            return Err(conflict("The destination response was too large.".into()));
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| conflict("The destination did not return Votport request details.".into()))
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

fn skip_directory_markers(
    mut listed: Vec<(object_store::ObjectMeta, String)>,
) -> Vec<(object_store::ObjectMeta, String)> {
    // Audit finding 557: object_store normalises keys without the trailing
    // delimiter, so a 0-byte directory marker (what the AWS console, aws s3
    // sync and rclone create) survives the `ends_with('/')` filter and the
    // inventory would store a key that does not exist; the conditional GET
    // then 404s and the whole job fails blaming the source. A 0-byte object
    // whose key is a directory prefix of a sibling key is such a marker, the
    // sibling naming the directory: skip it. A lone 0-byte file is a real
    // object and stays.
    // Only 0-byte keys can be markers; each key's directory prefixes are
    // looked up in that set, so memory scales with the empty objects.
    let empty: std::collections::HashSet<String> = listed
        .iter()
        .filter(|(object, _)| object.size == 0)
        .map(|(object, _)| object.location.as_ref().to_owned())
        .collect();
    let mut markers = std::collections::HashSet::new();
    for (object, _) in &listed {
        let key = object.location.as_ref();
        for (at, _) in key.match_indices('/') {
            if let Some(marker) = empty.get(&key[..at]) {
                markers.insert(marker.as_str());
            }
        }
    }
    listed.retain(|(object, _)| !markers.contains(object.location.as_ref()));
    listed
}

pub(super) async fn import(app: &Arc<App>, job: &Job) -> ApiResult<Option<u64>> {
    let Some(import) = &job.request.import else {
        return Ok(None);
    };
    let config = authorized_storage(app, &job.tenant, &import.storage_id)?;
    if config.kind != StorageKind::S3 {
        return Err(conflict("imports require an S3 connection".into()));
    }
    let store = config.connect(&app.store).map_err(conflict)?;
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
            .map_err(|_| conflict("the saved list of source files could not be read; check the storage connection, then retry the delivery".into()))?;
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
        let mut listed: Vec<(object_store::ObjectMeta, String)> = Vec::new();
        while let Some(object) = list.next().await {
            let object = object.map_err(|_| conflict("S3 object listing failed".into()))?;
            let Some(name) = object
                .location
                .as_ref()
                .strip_prefix(&prefix_string)
                .filter(|name| !name.is_empty() && !name.ends_with('/'))
                .map(str::to_owned)
            else {
                continue;
            };
            listed.push((object, name));
            // Stop reading a prefix that cannot fit, instead of listing
            // millions of keys first; markers are at most one per folder.
            if listed.len() > 2 * MAX_LIBRARY_PROJECT_FILES {
                return Err(conflict("S3 source has too many files".into()));
            }
        }
        let mut objects = vec![];
        let mut total = 0u64;
        for (object, name) in skip_directory_markers(listed) {
            payload_path(app, &job.tenant, &job.id, &name)?;
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
                name,
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
            return Err(conflict("the saved list of source files is too large to read; submit a new delivery with fewer files".into()));
        }
        crate::backup::atomic_write_private(&source_inventory, &bytes)
            .map_err(|_| conflict("the server could not save the list of source files; check free space on the server, then retry the delivery".into()))?;
        sync_directory(parent)?;
        inventory.objects
    };
    if objects.is_empty() || objects.len() > MAX_LIBRARY_PROJECT_FILES {
        return Err(conflict(
            "the saved list of source files is unusable; retry the delivery".into(),
        ));
    }
    crate::paths::admit_portable_paths(objects.iter().map(|object| object.name.as_str()))
        .map_err(conflict)?;
    if parent.join("inventory.json").is_file() {
        return Ok(Some(config.revision));
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
        return Err(conflict(
            "this delivery's saved file list is unusable; retry the delivery".into(),
        ));
    }
    std::fs::read(path).map_err(|_| {
        conflict("this delivery's saved file list could not be read; retry the delivery".into())
    })
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
        return Err(conflict("this delivery's file list is too large to save; submit a new delivery with fewer files".into()));
    }
    let parent = root.parent().ok_or_else(ApiError::not_found)?;
    crate::backup::atomic_write_private(&parent.join("inventory.json"), &bytes)
        .map_err(|_| conflict("the server could not save this delivery's file list; check free space on the server, then retry the delivery".into()))?;
    sync_directory(parent)
}

fn sync_directory(path: &Path) -> ApiResult<()> {
    std::fs::File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| conflict("sync workflow directory failed".into()))
}

pub(super) async fn export(app: &Arc<App>, job: &Job) -> ApiResult<()> {
    app.store
        .require_delivery_export(&job.id, job.attempts)
        .map_err(conflict)?;
    let mut failures = vec![];
    let pending: Vec<_> = job
        .project
        .destinations
        .iter()
        .filter(|id| job.checks["destinations"][*id]["state"] != "complete")
        .cloned()
        .collect();
    let mut transfers = futures_util::stream::iter(pending.into_iter().map(|id| async move {
        let (label, result) =
            match app
                .store
                .require_delivery_destination(&job.id, job.attempts, &id)
            {
                Ok(config) => (
                    config.label.clone(),
                    export_destination(app, job, &config).await,
                ),
                Err(error) => (id.clone(), Err(conflict(error))),
            };
        (id, label, result)
    }))
    .buffer_unordered(2);
    while let Some((id, label, result)) = transfers.next().await {
        if let Err(error) = result {
            // Record the leg failure without returning early: the sibling
            // leg may still hold an in-flight multipart upload, and a
            // dropped future never aborts it (object_store has no Drop
            // abort), so already-uploaded parts stay billable until a
            // lifecycle rule expires them. Draining both legs is also the
            // only shape that helps here: the server's SIGTERM path exits
            // the process, which skips destructors, so an abort-on-drop
            // guard would not fire on shutdown either.
            if let Err(record) =
                app.store
                    .fail_delivery_destination(&job.id, job.attempts, &id, &error.message)
            {
                tracing::warn!(
                    job_id = %job.id,
                    destination = %id,
                    %record,
                    "record delivery destination failure"
                );
                failures.push(format!("{}: {}", label, record));
                continue;
            }
            if job.checks["destinations"][&id]["state"] != "failed" {
                if let (Ok(Some(route)), Ok(policy)) = (
                    app.store.trade_route(&job.tenant, &id),
                    serde_json::from_value(
                        job.checks["trade_routes"][&id]["notifications"].clone(),
                    ),
                ) {
                    crate::notify::trade_event(
                        app,
                        &route,
                        &policy,
                        "route_failed",
                        Some(error.message.as_str()),
                    )
                    .await;
                }
            }
            failures.push(format!("{}: {}", label, error.message));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(conflict(failures.join("; ")))
    }
}

async fn export_destination(app: &Arc<App>, job: &Job, config: &Storage) -> ApiResult<()> {
    let grant = Arc::new(
        app.store
            .outbound_grant_by_id(&job.id)
            .map_err(crate::api::store_unavailable)?
            .ok_or_else(ApiError::not_found)?,
    );
    grant.validate_names().map_err(conflict)?;
    if config.kind == StorageKind::Votport {
        return super::routes::export(app, job, config).await;
    }
    let store = config.connect(&app.store).map_err(conflict)?;
    let manifest = job.manifest.as_deref().ok_or_else(|| {
        conflict("this job's approved file list is missing; submit a new delivery".into())
    })?;
    let prefix = format!("deliveries/{}/{manifest}", job.id);
    let mut files = vec![];
    let mut operation = begin_outbound_operation_owned(app, &job.tenant)?;
    for (index, file) in grant.files.iter().enumerate() {
        app.store
            .require_delivery_destination(&job.id, job.attempts, &config.id)
            .map_err(conflict)?;
        let key = config.key(&format!("{prefix}/files/{}", file.name))?;
        guard_folder_key(config, &key)?;
        let (source, retained) = source_info_async(
            app,
            Arc::clone(&grant),
            index,
            Some(file.clone()),
            operation,
            Some("storage"),
        )
        .await?;
        operation = retained;
        upload_file(&*store, &key, &source.path, &source.object).await?;
        let receipt = source
            .receipt
            .map(|bytes| base64::prelude::BASE64_STANDARD.encode(bytes));
        files.push(json!({"name": file.name,"suite": file.suite,"root": file.root,"bytes": file.bytes,"key": key.to_string(),"receipt": receipt}));
    }
    app.store
        .require_delivery_destination(&job.id, job.attempts, &config.id)
        .map_err(conflict)?;
    let document = json!({"format": "votport-delivery-export-v1","created_at": grant.created_at,"expires_at": grant.expires_at,"job_id": job.id,"manifest": manifest,"metadata": job.request.metadata,"project_id": job.project.id,"policy_revision": job.project.revision,"approved_by": job.approved_by,"checks": export_checks(job),"files": files,"issuer": app.signer.public_hex});
    let attestation =
        json!({"document": document,"signature": app.signer.sign_delivery_export(&document)});
    let bytes = serde_json::to_vec(&attestation)
        .map_err(|_| ApiError::internal("serialize export manifest"))?;
    let completion = config.key(&format!("{prefix}/complete.json"))?;
    guard_folder_key(config, &completion)?;
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
                "publish immutable storage completion manifest failed".into(),
            ))
        }
    }
    app.store
        .complete_delivery_export(&job.id, job.attempts, &config.id, completion.as_ref())
        .map_err(conflict)?;
    Ok(())
}

/// Audit finding 375: a completed export whose delivery was retired,
/// cancelled or revoked is indistinguishable from a live one. At retirement
/// the server writes a signed marker beside each completed external export,
/// so the destination itself records the delivery's state.
pub(super) async fn mark_exports_retired(app: &Arc<App>, job: &Job) -> Result<(), String> {
    let mut targets = Vec::new();
    for id in &job.project.destinations {
        let state = &job.checks["destinations"][id];
        let Some(location) = state["location"].as_str() else {
            continue;
        };
        if state["state"] != "complete" || location.starts_with("receipt:") {
            continue;
        }
        let revision = job.checks["destination_revisions"][id].as_u64();
        targets.push((id.clone(), revision));
    }
    if targets.is_empty() {
        return Ok(());
    }
    let storages = app.store.delivery_storages().map_err(|e| e.to_string())?;
    for (id, revision) in targets {
        let Some(config) = storages
            .iter()
            .find(|config| config.id == id && Some(config.revision) == revision)
        else {
            return Err(format!(
                "retired export marker skipped: destination {id} changed since export"
            ));
        };
        let store = config.connect(&app.store).map_err(|e| e.to_string())?;
        let manifest = job
            .manifest
            .as_deref()
            .ok_or("retired export marker needs the frozen manifest")?;
        let key = config
            .key(&format!("deliveries/{}/{manifest}/retired.json", job.id))
            .map_err(|error| error.message)?;
        guard_folder_key(config, &key).map_err(|error| error.message)?;
        let document = json!({
            "format": "votport-delivery-retired-v1",
            "job_id": job.id,
            "manifest": manifest,
            "retired_at": crate::store::now_unix(),
        });
        let attestation =
            json!({"document": document,"signature": app.signer.sign_delivery_export(&document)});
        let bytes = serde_json::to_vec(&attestation)
            .map_err(|_| "serialize retired export marker".to_owned())?;
        // Overwrite, not Create: retirement retries after a crash must not
        // fail on their own marker.
        store
            .put(&key, bytes.into())
            .await
            .map_err(|_| "retired export marker upload failed".to_owned())?;
    }
    Ok(())
}

fn export_checks(job: &Job) -> serde_json::Value {
    let mut checks = serde_json::Map::new();
    for key in [
        "metadata",
        "sequence",
        "media",
        "malware_scan",
        "import_storage_revision",
        "destination_revisions",
        "source_receipt",
        "source_ancestry",
    ] {
        if let Some(value) = job.checks.get(key) {
            checks.insert(key.into(), value.clone());
        }
    }
    checks.into()
}

fn guard_folder_key(config: &Storage, key: &ObjectPath) -> ApiResult<()> {
    if config.kind == StorageKind::Folder {
        let root = folder_root(config)?;
        if !library_components_safe(&root, &root.join(key.as_ref())) {
            return Err(conflict(
                "shared folder contains a symlink or invalid directory".into(),
            ));
        }
    }
    Ok(())
}

/// Class of a storage multipart failure: object_store Display strings carry
/// the object path and endpoint URL, so only the failure class reaches the
/// job-visible message. A rotated policy reads differently from a dropped
/// connection, and neither is confounded with a key the store refused
/// (audit finding 560, matching backup's abort failure classes).
fn multipart_failure_class(error: &object_store::Error) -> &'static str {
    match error {
        object_store::Error::NotFound { .. }
        | object_store::Error::AlreadyExists { .. }
        | object_store::Error::NotModified { .. }
        | object_store::Error::Precondition { .. } => {
            "the store answered with a conflicting object state"
        }
        object_store::Error::PermissionDenied { .. }
        | object_store::Error::Unauthenticated { .. } => "the store refused the credentials",
        object_store::Error::InvalidPath { .. } => "the store refused the object key",
        object_store::Error::NotSupported { .. } | object_store::Error::NotImplemented { .. } => {
            "the store cannot multipart-upload"
        }
        _ => "the store request failed",
    }
}

async fn upload_file(
    store: &dyn ObjectStore,
    key: &ObjectPath,
    path: &Path,
    expected: &ObjectId,
) -> ApiResult<()> {
    // Audit finding 560: an assembled key over the store's 1024-byte limit is
    // named here, before the put, instead of surfacing as the anonymous
    // multipart failure that shares a 120 s backoff with refused credentials
    // and dropped connections.
    if key.as_ref().len() > 1024 {
        return Err(conflict(format!(
            "the assembled object key is {} bytes, over the store's 1024-byte limit",
            key.as_ref().len()
        )));
    }
    let part_size = expected.length.div_ceil(10_000).max(8 * 1024 * 1024);
    // ponytail: at most 128 MiB per part; larger than 1.25 TiB needs a streaming multipart adapter.
    if part_size > 128 * 1024 * 1024 {
        return Err(conflict(
            "storage export supports files up to 1.25 TiB".into(),
        ));
    }
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|_| conflict("open export payload failed".into()))?;
    let mut builder = InMemoryObjectBuilder::new(
        Suite::try_from(expected.suite).map_err(|_| ApiError::internal("object suite"))?,
        Some(expected.length),
        expected.length,
    )
    .map_err(|_| conflict("build export verifier failed".into()))?;
    let mut upload = store.put_multipart(key).await.map_err(|error| {
        conflict(format!(
            "start storage multipart upload failed ({})",
            multipart_failure_class(&error)
        ))
    })?;
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
                .filter(|bytes| *bytes <= expected.length)
                .ok_or_else(|| conflict("export payload size changed".into()))?;
            builder
                .update(&bytes)
                .map_err(|_| conflict("verify export payload failed".into()))?;
            upload
                .put_part(bytes.into())
                .await
                .map_err(|error| {
                    conflict(format!(
                        "storage multipart upload interrupted ({})",
                        multipart_failure_class(&error)
                    ))
                })?;
            if used == 0 {
                break;
            }
        }
        let object = builder
            .finish()
            .map_err(|_| conflict("verify export payload failed".into()))?;
        if object.object_id() != expected {
            return Err(conflict(
                "the delivered files do not match this delivery's approved file list; submit a new delivery".into(),
            ));
        }
        upload
            .complete()
            .await
            .map_err(|error| {
                conflict(format!(
                    "complete storage multipart upload failed ({})",
                    multipart_failure_class(&error)
                ))
            })?;
        Ok(())
    }
    .await;
    if result.is_err() {
        let _ = upload.abort().await;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Audit finding 560: an assembled key over the store's 1024-byte limit
    /// is refused by name before the put, so an in-memory store that would
    /// happily accept it never sees the upload and the refusal cannot be
    /// confused with the anonymous multipart failures.
    #[tokio::test]
    async fn an_oversized_assembled_key_is_refused_before_the_multipart_put() {
        let directory = tempfile::tempdir().unwrap();
        let expected = ObjectId {
            suite: 1,
            root: [9; 32],
            length: 8,
        };
        let source = directory.path().join("payload.bin");
        std::fs::write(&source, vec![0u8; 8]).unwrap();
        let key = ObjectPath::parse(format!("deliveries/{}", "k".repeat(1020))).unwrap();
        assert!(key.as_ref().len() > 1024);
        let store = object_store::memory::InMemory::new();
        let error = upload_file(&store, &key, &source, &expected)
            .await
            .expect_err("an oversized assembled key is refused");
        assert_eq!(error.status, StatusCode::CONFLICT);
        assert_eq!(
            error.message,
            "the assembled object key is 1031 bytes, over the store's 1024-byte limit"
        );
        let listed = store.list(None).next().await;
        assert!(listed.is_none(), "the put never happened: {listed:?}");
    }

    /// Audit finding 557: a 0-byte directory marker (console, aws s3 sync,
    /// rclone) is listed without its trailing delimiter, so it must be
    /// recognised by being a directory prefix of a sibling key instead of by
    /// its delimiter, while a lone 0-byte file stays in the inventory.
    #[test]
    fn zero_byte_directory_markers_are_skipped_from_the_source_inventory() {
        let meta = |key: &str, size: u64| object_store::ObjectMeta {
            location: ObjectPath::parse(key).unwrap(),
            last_modified: chrono::Utc::now(),
            size,
            e_tag: Some("test-etag".into()),
            version: None,
        };
        let kept = skip_directory_markers(vec![
            (meta("source/folder", 0), "folder".into()),
            (meta("source/folder/file.mov", 5), "folder/file.mov".into()),
            (meta("source/empty.mov", 0), "empty.mov".into()),
        ]);
        let keys: Vec<&str> = kept
            .iter()
            .map(|(object, _)| object.location.as_ref())
            .collect();
        assert_eq!(keys, ["source/folder/file.mov", "source/empty.mov"]);
    }

    /// Audit 436: delivery-card refusals never name the internal artefacts
    /// (frozen manifest, snapshot, inventory); each refusal is one
    /// recoverable sentence in the delivery card's own vocabulary.
    #[test]
    fn delivery_refusals_never_name_internal_artefacts() {
        for (file, source) in [
            ("outbound/workflows.rs", include_str!("../workflows.rs")),
            ("outbound/workflows/routes.rs", include_str!("routes.rs")),
            ("outbound/workflows/storage.rs", include_str!("storage.rs")),
        ] {
            for (number, line) in source.lines().enumerate() {
                let bare = line.trim_start();
                let same_line = line
                    .find("conflict(\"")
                    .map(|at| &line[at + "conflict(\"".len()..]);
                let parts: Vec<&str> = match same_line {
                    Some(rest) => vec![rest.split('"').next().unwrap_or_default()],
                    None if bare.starts_with('"') => {
                        vec![bare.trim_end_matches(',').trim_end_matches('"')]
                    }
                    None => continue,
                };
                for literal in parts {
                    for artefact in ["frozen manifest", "snapshot", "inventory"] {
                        assert!(
                            !literal.contains(artefact),
                            "{file}:{number} names the internal artefact {artefact:?}: {literal}"
                        );
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn connection_test_reports_unreachable_votport_port_with_reason_and_no_error_envelope() {
        // Audit finding 337: an unreachable destination port is a probe
        // outcome (200, delivered false, reason), not a 409 conflict.
        use http_body_util::BodyExt as _;
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = closed.local_addr().unwrap();
        drop(closed);
        let config: Storage = serde_json::from_value(json!({
            "id":"destination","revision":0,"label":"Destination","kind":"votport",
            "endpoint":format!("http://{address}"),"tenants":[""],"enabled":true
        }))
        .unwrap();
        let config = app
            .store
            .save_delivery_storage(
                "local",
                config,
                Some(Credentials::Votport {
                    request_url: format!("http://{address}/r/{}", "a".repeat(32)),
                    password: None,
                }),
            )
            .unwrap();
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            format!(
                "votport_admin={}",
                crate::auth::issue_admin_token(
                    &app.secret,
                    &crate::auth::AdminIdentity::local_admin(),
                    &app.config.admin_token_tag
                )
            )
            .parse()
            .unwrap(),
        );
        headers.insert("x-votport", "1".parse().unwrap());
        let response = test_connection(
            State(app.clone()),
            headers,
            axum::extract::Path(config.id),
            Json(TestStorage {
                revision: config.revision,
            }),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["delivered"], false);
        assert!(
            body["reason"]
                .as_str()
                .is_some_and(|reason| !reason.is_empty()),
            "{}",
            body
        );
        assert!(
            body.get("error").is_none()
                && body.get("code").is_none()
                && body.get("retryable").is_none(),
            "{}",
            body
        );
    }

    #[test]
    fn s3_keys_limit_complete_utf8_bytes_for_all_operation_paths() {
        let mut config: Storage = serde_json::from_value(json!({
            "id":"destination","revision":0,"label":"Destination","kind":"s3",
            "endpoint":"https://s3.example.com","bucket":"test","region":"us-east-1",
            "tenants":[""],"enabled":true
        }))
        .unwrap();
        let delivery = format!("deliveries/{}/{}", "a".repeat(32), "b".repeat(64));
        for relative in [
            format!("{delivery}/files/folder/納品.mov"),
            format!("{delivery}/complete.json"),
            "incoming/é".into(),
        ] {
            config.prefix = "p".repeat(1024 - relative.len() - 1);
            config.validate().unwrap();
            let key = config.key(&relative).unwrap();
            assert_eq!(key.as_ref().len(), 1024);

            config.prefix.push('p');
            config.validate().unwrap();
            let error = config.key(&relative).unwrap_err();
            assert_eq!(error.status, StatusCode::CONFLICT);
            assert_eq!(
                error.message,
                "S3 object key exceeds 1024 bytes including the storage prefix"
            );
        }

        config.prefix = "p".repeat(1024);
        config.validate().unwrap();
        assert_eq!(config.key("").unwrap().as_ref(), config.prefix);
        config.prefix.clear();
        let relative = format!("{}éab", "é/".repeat(340));
        assert_eq!(relative.len(), 1024);
        assert!(crate::workflow::valid_path(&relative));
        assert_eq!(config.key(&relative).unwrap().as_ref(), relative);
        let oversized = format!("{relative}a");
        assert_eq!(oversized.chars().count(), 684);
        assert!(config.key(&oversized).is_err());

        config.kind = StorageKind::Folder;
        config.directory = std::env::current_dir().unwrap().display().to_string();
        config.prefix = "folder".into();
        config.endpoint.clear();
        config.bucket.clear();
        config.region.clear();
        config.validate().unwrap();
        assert_eq!(
            config.key(&relative).unwrap().as_ref(),
            format!("folder/{relative}")
        );
    }

    #[test]
    fn client_settings_keep_other_client_options() {
        use object_store::ClientConfigKey;
        let client = |key| AmazonS3ConfigKey::Client(key);
        let builder = client_settings(
            AmazonS3Builder::new()
                .with_config(client(ClientConfigKey::ProxyUrl), "http://proxy:3128"),
            "https://s3.example.test",
        );
        assert_eq!(
            builder
                .get_config_value(&client(ClientConfigKey::ProxyUrl))
                .as_deref(),
            Some("http://proxy:3128")
        );
        assert_eq!(
            builder
                .get_config_value(&client(ClientConfigKey::ReadTimeout))
                .as_deref(),
            Some("900s")
        );
        assert_eq!(
            builder
                .get_config_value(&client(ClientConfigKey::AllowHttp))
                .as_deref(),
            Some("false")
        );
    }

    #[tokio::test]
    async fn an_http_s3_endpoint_is_contacted() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let config: Storage = serde_json::from_value(json!({
            "id":"plain","revision":0,"label":"Plain","kind":"s3",
            "endpoint":format!("http://{}", listener.local_addr().unwrap()),
            "bucket":"test","region":"us-east-1","path_style":true,"tenants":[""],"enabled":true
        }))
        .unwrap();
        let config = app
            .store
            .save_delivery_storage(
                "local",
                config,
                Some(Credentials::AccessKey {
                    access_key_id: "test-access".into(),
                    secret_access_key: "test-secret".into(),
                    session_token: None,
                }),
            )
            .unwrap();
        let store = config.connect(&app.store).unwrap();
        let request = tokio::spawn(async move {
            let _ = store.head(&object_store::path::Path::from("probe")).await;
        });
        let accepted =
            tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept()).await;
        request.abort();
        assert!(accepted.is_ok(), "an http:// endpoint must be allowed");
    }

    #[tokio::test]
    async fn cached_s3_inventory_still_requires_portable_names() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let config: Storage = serde_json::from_value(json!({
            "id":"source","revision":0,"label":"Source","kind":"s3",
            "endpoint":"http://127.0.0.1:1","bucket":"test","region":"us-east-1",
            "path_style":true,"tenants":[""],"enabled":true
        }))
        .unwrap();
        let config = app
            .store
            .save_delivery_storage(
                "local",
                config,
                Some(Credentials::AccessKey {
                    access_key_id: "test-access".into(),
                    secret_access_key: "test-secret".into(),
                    session_token: None,
                }),
            )
            .unwrap();
        let mut request = crate::workflow::tests::request();
        request.import = Some(crate::workflow::Import {
            storage_id: config.id.clone(),
            prefix: "source".into(),
        });
        let job: Job = serde_json::from_value(json!({
            "id":"cached","tenant":"","token_generation":0,"actor":"local","credential_version":0,
            "request":request,"project":crate::workflow::tests::project(),
            "state":"preparing","attempts":1,"created_at":1,"updated_at":1,"checks":{}
        }))
        .unwrap();
        let root = payload_root(&app, "", &job.id);
        let parent = root.parent().unwrap();
        std::fs::create_dir_all(parent).unwrap();
        std::fs::write(parent.join("inventory.json"), b"[]").unwrap();
        let mut inventory = SourceInventory {
            storage_id: config.id.clone(),
            revision: config.revision,
            objects: ["Café.mov", "Cafe\u{301}.mov"]
                .into_iter()
                .map(|name| SourceObject {
                    name: name.into(),
                    key: format!("source/{name}"),
                    size: 1,
                    etag: Some("test".into()),
                    version: None,
                })
                .collect(),
        };
        for cached in [true, false] {
            if !cached {
                std::fs::remove_file(parent.join("inventory.json")).unwrap();
            }
            std::fs::write(
                parent.join("source-inventory.json"),
                serde_json::to_vec(&inventory).unwrap(),
            )
            .unwrap();
            let error = tokio::time::timeout(std::time::Duration::from_secs(5), import(&app, &job))
                .await
                .unwrap()
                .unwrap_err();
            assert_eq!(error.status, StatusCode::CONFLICT);
            assert!(error.message.contains("collide"), "{}", error.message);
            assert!(!root.exists());
        }
        inventory.objects[1].name = "second.mov".into();
        std::fs::write(
            parent.join("source-inventory.json"),
            serde_json::to_vec(&inventory).unwrap(),
        )
        .unwrap();
        std::fs::write(parent.join("inventory.json"), b"[]").unwrap();
        assert_eq!(import(&app, &job).await.unwrap(), Some(config.revision));
    }

    #[tokio::test]
    async fn existing_ambiguous_grants_are_refused_before_destination_access() {
        let directory = tempfile::tempdir().unwrap();
        let data = directory.path().join("data");
        let mut grant = crate::store::tests::test_outbound_grant("existing", "", 0);
        grant.files = ["Café.mov", "second.mov"]
            .into_iter()
            .map(|name| crate::store::OutboundGrantFile {
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
        {
            let store = crate::store::Store::open(&data).unwrap();
            store.insert_outbound_grant(grant.clone()).unwrap();
        }
        // The closed scratch database represents a grant admitted before portable-name checks.
        {
            grant.files[1].name = "Cafe\u{301}.mov".into();
            let db = rusqlite::Connection::open(data.join("votport.db")).unwrap();
            db.execute(
                "UPDATE outbound_grants SET files_json = ?1 WHERE id = ?2",
                rusqlite::params![serde_json::to_string(&grant.files).unwrap(), grant.id],
            )
            .unwrap();
            db.execute(
                "UPDATE outbound_grant_files SET name = ?1 WHERE grant_id = ?2 AND file_index = 1",
                rusqlite::params![grant.files[1].name, grant.id],
            )
            .unwrap();
        }
        let app = crate::api::testing::build(directory.path());
        let job: Job = serde_json::from_value(json!({
            "id":grant.id,"tenant":"","token_generation":0,"actor":"local","credential_version":0,
            "request":crate::workflow::tests::request(),"project":crate::workflow::tests::project(),
            "state":"exporting","manifest":"frozen","attempts":1,"created_at":1,"updated_at":1,"checks":{}
        })).unwrap();
        for kind in ["folder", "s3", "votport"] {
            let config: Storage = serde_json::from_value(json!({
                "id":"destination","revision":1,"label":"Destination","kind":kind,
                "directory":directory.path().join("destination"),"tenants":[""],"enabled":true
            }))
            .unwrap();
            let error = export_destination(&app, &job, &config).await.unwrap_err();
            assert_eq!(error.status, StatusCode::CONFLICT);
            assert!(
                error.message.contains("collide"),
                "{kind}: {}",
                error.message
            );
            assert!(!directory.path().join("destination").exists());
        }
        let error = crate::api::serve::grant_entries(&app, &grant)
            .err()
            .unwrap();
        assert_eq!(error.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(error.message.contains("collide"));
    }

    // Audit finding 375: the export attestation carries the grant window,
    // and retirement writes a signed marker beside the completed export.
    #[tokio::test]
    async fn export_attestation_carries_the_window_and_retirement_writes_a_marker() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let mut grant = crate::store::tests::test_outbound_grant("existing", "", 0);
        let now = crate::store::now_unix();
        grant.created_at = now;
        grant.expires_at = now + 3_600;
        app.store.insert_outbound_grant(grant.clone()).unwrap();
        let mut project = crate::workflow::tests::project();
        project.require_approval = false;
        project.destinations = vec!["destination".into()];
        let mut job: Job = serde_json::from_value(json!({
            "id":grant.id,"tenant":"","token_generation":0,"actor":"local","credential_version":1,
            "request":crate::workflow::tests::request(),"project":project,
            "state":"exporting","manifest":"frozen","attempts":1,"created_at":1,"updated_at":1,
            "checks":{"destination_revisions":{"destination":0}}
        }))
        .unwrap();
        app.store
            .with(|connection| {
                connection.execute(
                    "INSERT INTO principals(subject, credential_version, blocked, created_at)
                     VALUES ('local',1,0,0)
                     ON CONFLICT(subject) DO UPDATE SET credential_version=1, blocked=0",
                    [],
                )?;
                connection.execute(
                    "INSERT INTO delivery_projects(tenant,id,revision,document)
                     VALUES ('','project',0,?1)",
                    rusqlite::params![serde_json::to_string(&project).unwrap()],
                )?;
                connection.execute(
                    "INSERT INTO delivery_jobs(id,tenant,actor,operation_id,project_id,state,not_before,created_at,deadline,document,token)
                     VALUES (?1,'','local','op','project','exporting',0,1,0,?2,'token')",
                    rusqlite::params![job.id, serde_json::to_string(&job).unwrap()],
                )
            })
            .unwrap();
        let config: Storage = serde_json::from_value(json!({
            "id":"destination","revision":0,"label":"Destination","kind":"folder",
            "directory":directory.path().join("destination"),"tenants":[""],"enabled":true
        }))
        .unwrap();
        std::fs::create_dir(directory.path().join("destination")).unwrap();
        let config = app
            .store
            .save_delivery_storage("local", config, None)
            .unwrap();
        job.checks["destination_revisions"]["destination"] = json!(config.revision);
        app.store
            .with(|connection| {
                connection.execute(
                    "UPDATE delivery_jobs SET document=?2 WHERE id=?1",
                    rusqlite::params![job.id, serde_json::to_string(&job).unwrap()],
                )
            })
            .unwrap();
        export_destination(&app, &job, &config).await.unwrap();
        let completion = directory
            .path()
            .join("destination/deliveries/existing/frozen/complete.json");
        let attestation: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&completion).unwrap()).unwrap();
        assert_eq!(
            attestation["document"]["format"],
            "votport-delivery-export-v1"
        );
        assert_eq!(attestation["document"]["created_at"], grant.created_at);
        assert_eq!(attestation["document"]["expires_at"], grant.expires_at);

        let stored = app.store.delivery_job(&job.id).unwrap().unwrap();
        assert_eq!(
            stored.checks["destinations"]["destination"]["state"],
            "complete"
        );
        mark_exports_retired(&app, &stored).await.unwrap();
        let marker = directory
            .path()
            .join("destination/deliveries/existing/frozen/retired.json");
        let marker: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&marker).unwrap()).unwrap();
        assert_eq!(marker["document"]["format"], "votport-delivery-retired-v1");
        assert_eq!(marker["document"]["job_id"], grant.id);
        assert_eq!(marker["document"]["manifest"], "frozen");
        assert!(marker["document"]["retired_at"].as_u64().is_some());
        assert!(marker["signature"]
            .as_str()
            .is_some_and(|signature| !signature.is_empty()));
        // Retirement retries after a crash must not fail on their own marker.
        mark_exports_retired(&app, &stored).await.unwrap();

        // A reception job has no snapshot to remove, but its exports are
        // retired through the same sweep.
        let marker_path = directory
            .path()
            .join("destination/deliveries/existing/frozen/retired.json");
        std::fs::remove_file(&marker_path).unwrap();
        let mut reception = stored.clone();
        reception.received = Some(crate::workflow::Received {
            link_id: "link".into(),
            upload_id: "upload".into(),
        });
        reception.state = crate::workflow::JobState::Retiring;
        app.store
            .with(|connection| {
                connection.execute(
                    "UPDATE delivery_jobs SET state='retiring', document=?2 WHERE id=?1",
                    rusqlite::params![reception.id, serde_json::to_string(&reception).unwrap()],
                )
            })
            .unwrap();
        assert!(super::super::retire_snapshot(&app).await.unwrap());
        assert!(
            marker_path.exists(),
            "the reception job's export is marked retired"
        );
    }
}
