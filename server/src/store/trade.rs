use super::*;
use crate::route_protocol::{RouteReceipt, SignedPortMessage, SignedRoute};
use rusqlite::params;
use sha2::{Digest, Sha256};

pub(super) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS trade_endpoints(id TEXT PRIMARY KEY REFERENCES links(id) ON DELETE CASCADE,tenant TEXT NOT NULL,document TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS trade_invitations(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,endpoint TEXT NOT NULL REFERENCES trade_endpoints(id) ON DELETE CASCADE,secret_hash TEXT NOT NULL,expected_key TEXT NOT NULL,expires_at INTEGER NOT NULL,redeemed TEXT);
CREATE TABLE IF NOT EXISTS trade_routes(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,direction TEXT NOT NULL,peer_key TEXT NOT NULL,endpoint TEXT NOT NULL,document TEXT NOT NULL,credential TEXT NOT NULL,enrollment TEXT);
CREATE TABLE IF NOT EXISTS trade_rotations(route_id TEXT PRIMARY KEY,credential TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS trade_delivery_policies(route_id TEXT PRIMARY KEY,document TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS trade_routes_tenant ON trade_routes(tenant,direction);
CREATE INDEX IF NOT EXISTS trade_routes_endpoint ON trade_routes(endpoint,peer_key);
";

pub const TRADE_EVENTS: [&str; 6] = [
    "route_approval_requested",
    "route_approved",
    "route_identity_changed",
    "route_failed",
    "route_recovered",
    "route_received",
];

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TradeEndpoint {
    pub id: String,
    pub name: String,
    pub category: String,
    pub forwarding: bool,
    pub metadata_keys: Vec<String>,
    pub notifications: NotificationPolicy,
}

impl TradeEndpoint {
    pub fn validate(&self) -> Result<(), String> {
        if !crate::workflow::valid_id(&self.id)
            || self.name.trim().is_empty()
            || self.name.len() > 200
            || !matches!(self.category.as_str(), "internal" | "external")
            || self.metadata_keys.len() > 50
            || self
                .metadata_keys
                .iter()
                .any(|key| !crate::workflow::valid_id(key))
        {
            return Err("invalid endpoint name, category or metadata allowlist".into());
        }
        self.notifications.validate(&TRADE_EVENTS)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TradeRoute {
    pub id: String,
    pub revision: u64,
    pub tenant: String,
    pub direction: String,
    pub name: String,
    pub peer_name: String,
    pub peer_key: String,
    pub address: String,
    pub endpoint: String,
    pub endpoint_name: String,
    pub category: String,
    pub forwarding: bool,
    pub metadata_keys: Vec<String>,
    pub state: String,
    pub notifications: NotificationPolicy,
    pub last_contact: Option<u64>,
    pub error: Option<String>,
    pub remote_grant: String,
    pub remote_state: String,
    pub cancel_active: bool,
}

pub fn trade_secret_hash(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}

fn decode<T: serde::de::DeserializeOwned>(row: &rusqlite::Row<'_>) -> rusqlite::Result<T> {
    parse_json(&row.get::<_, String>(0)?, 0)
}
fn route_in(connection: &Connection, id: &str) -> Result<TradeRoute, String> {
    connection
        .query_row(
            "SELECT document FROM trade_routes WHERE id=?1",
            [id],
            decode,
        )
        .optional()
        .map_err(|e| e.to_string())?
        .ok_or("route not found".into())
}
fn write_route(connection: &Connection, route: &TradeRoute) -> Result<(), String> {
    connection
        .execute(
            "UPDATE trade_routes SET document=?2 WHERE id=?1",
            params![
                route.id,
                serde_json::to_string(route).expect("route serializes")
            ],
        )
        .map(|_| ())
        .map_err(|e| e.to_string())
}

impl Store {
    pub fn trade_endpoints(&self, tenant: &str) -> Result<Vec<TradeEndpoint>, String> {
        self.with(|c| {
            c.prepare("SELECT document FROM trade_endpoints WHERE tenant=?1 ORDER BY id")?
                .query_map([tenant], decode)?
                .collect()
        })
    }
    pub fn is_trade_endpoint(&self, id: &str) -> Result<bool, String> {
        self.with(|c| {
            c.query_row(
                "SELECT EXISTS(SELECT 1 FROM trade_endpoints WHERE id=?1)",
                [id],
                |r| r.get(0),
            )
        })
    }
    pub fn create_trade_endpoint(
        &self,
        tenant: &str,
        endpoint: &TradeEndpoint,
    ) -> Result<(), String> {
        endpoint.validate()?;
        let mut c = self.connection.lock().expect("store poisoned");
        let tx = c.transaction().map_err(|e| e.to_string())?;
        let eligible: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM links WHERE id=?1 AND tenant=?2 AND password_hash IS NULL AND active=1 AND json_array_length(uploads_json)=0) AND NOT EXISTS(SELECT 1 FROM inbound_routes WHERE link_id=?1)", params![endpoint.id, tenant], |r|r.get(0)).map_err(|e|e.to_string())?;
        if !eligible {
            return Err(
                "choose a new, active receive request without a password or previous uploads"
                    .into(),
            );
        }
        tx.execute(
            "INSERT INTO trade_endpoints(id,tenant,document) VALUES (?1,?2,?3)",
            params![
                endpoint.id,
                tenant,
                serde_json::to_string(endpoint).expect("endpoint serializes")
            ],
        )
        .map_err(|_| "this request is already a trade endpoint")?;
        tx.commit().map_err(|e| e.to_string())
    }
    pub fn create_trade_invitation(
        &self,
        tenant: &str,
        endpoint: &str,
        expected_key: &str,
        expires_at: u64,
    ) -> Result<(String, String), String> {
        if expires_at <= now_unix()
            || expires_at > now_unix() + 7 * 86400
            || (!expected_key.is_empty() && !valid_peer_key(expected_key))
        {
            return Err("invitations need a valid peer key and expiry within seven days".into());
        }
        let id = crate::auth::random_token();
        let secret = crate::auth::random_token();
        self.with(|c|c.execute("INSERT INTO trade_invitations(id,tenant,endpoint,secret_hash,expected_key,expires_at) SELECT ?1,?2,id,?4,?5,?6 FROM trade_endpoints WHERE id=?3 AND tenant=?2",params![id,tenant,endpoint,trade_secret_hash(&secret),expected_key,expires_at as i64]))
            .and_then(|count| if count == 1 {Ok((id,secret))} else {Err("endpoint not found".into())})
    }
    pub fn redeem_trade_invitation(
        &self,
        message: &SignedPortMessage,
    ) -> Result<(TradeRoute, bool), String> {
        let now = now_unix();
        if !message.verify("enroll", &self.event_signer.public_hex, now)
            || message.document.expires_at > now + 600
        {
            return Err("invalid enrollment proof".into());
        }
        let body = &message.document.body;
        let secret = body["secret"].as_str().ok_or("missing invitation secret")?;
        let credential = body["credential"]
            .as_str()
            .filter(|v| v.len() == 32 && v.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or("invalid route credential")?;
        let peer_name = body["name"]
            .as_str()
            .filter(|v| !v.trim().is_empty() && v.len() <= 200)
            .ok_or("invalid port name")?;
        if message.document.issuer == self.event_signer.public_hex {
            return Err("cannot pair a port with itself".into());
        }
        let hash = trade_secret_hash(credential);
        let mut c = self.connection.lock().expect("store poisoned");
        let tx = c.transaction().map_err(|e| e.to_string())?;
        let (tenant,endpoint,secret_hash,expected,expires,redeemed): (String,String,String,String,i64,Option<String>) = tx.query_row("SELECT tenant,endpoint,secret_hash,expected_key,expires_at,redeemed FROM trade_invitations WHERE id=?1", [&message.document.nonce], |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).optional().map_err(|e|e.to_string())?.ok_or("invitation unavailable")?;
        if secret_hash != trade_secret_hash(secret)
            || (!expected.is_empty() && expected != message.document.issuer)
        {
            return Err("invitation does not authorize this peer".into());
        }
        if let Some(id) = redeemed {
            let route = route_in(&tx, &id)?;
            let same: bool = tx
                .query_row(
                    "SELECT credential=?2 FROM trade_routes WHERE id=?1",
                    params![id, hash],
                    |r| r.get(0),
                )
                .map_err(|e| e.to_string())?;
            return if same && route.peer_key == message.document.issuer {
                Ok((route, false))
            } else {
                Err("invitation has already been redeemed".into())
            };
        }
        if expires <= now as i64 {
            return Err("invitation expired".into());
        }
        let count: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM trade_routes WHERE tenant=?1",
                [&tenant],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        if count >= 100 {
            return Err("route limit reached".into());
        }
        let endpoint: TradeEndpoint = tx
            .query_row(
                "SELECT document FROM trade_endpoints WHERE id=?1",
                [endpoint],
                decode,
            )
            .map_err(|_| "endpoint unavailable")?;
        let route = TradeRoute {
            id: crate::auth::random_token(),
            revision: 1,
            tenant: tenant.clone(),
            direction: "incoming".into(),
            name: endpoint.name.clone(),
            peer_name: peer_name.into(),
            peer_key: message.document.issuer.clone(),
            address: body["address"]
                .as_str()
                .filter(|v| !v.is_empty())
                .map(crate::api::trade::address)
                .transpose()?
                .unwrap_or_default(),
            endpoint: endpoint.id,
            endpoint_name: endpoint.name,
            category: endpoint.category,
            forwarding: endpoint.forwarding,
            metadata_keys: endpoint.metadata_keys,
            state: if expected.is_empty() {
                "pending_approval"
            } else {
                "active"
            }
            .into(),
            notifications: endpoint.notifications,
            last_contact: Some(now),
            error: None,
            remote_grant: String::new(),
            remote_state: String::new(),
            cancel_active: false,
        };
        tx.execute("INSERT INTO trade_routes(id,tenant,direction,peer_key,endpoint,document,credential) VALUES (?1,?2,'incoming',?3,?4,?5,?6)",params![route.id,tenant,route.peer_key,route.endpoint,serde_json::to_string(&route).expect("route serializes"),hash]).map_err(|e|e.to_string())?;
        tx.execute(
            "UPDATE trade_invitations SET redeemed=?2 WHERE id=?1",
            params![message.document.nonce, route.id],
        )
        .map_err(|e| e.to_string())?;
        evidence::delivery_event(
            &tx,
            &self.event_signer,
            &tenant,
            "",
            "route_enrolled",
            &serde_json::json!({"route":route.id,"peer":route.peer_key,"state":route.state}),
            now,
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok((route, true))
    }
    pub fn trade_routes(&self, tenant: Option<&str>) -> Result<Vec<TradeRoute>, String> {
        self.with(|c| {
            c.prepare(
                "SELECT document FROM trade_routes WHERE (?1 IS NULL OR tenant=?1) ORDER BY id",
            )?
            .query_map([tenant], decode)?
            .collect()
        })
    }
    pub fn trade_route(&self, tenant: &str, id: &str) -> Result<TradeRoute, String> {
        let c = self.connection.lock().expect("store poisoned");
        let route = route_in(&c, id)?;
        if route.tenant != tenant {
            return Err("route not found".into());
        }
        Ok(route)
    }
    pub fn trade_credential(&self, tenant: &str, id: &str) -> Result<String, String> {
        self.with(|c|c.query_row("SELECT credential FROM trade_routes WHERE tenant=?1 AND id=?2 AND direction='outgoing'",params![tenant,id],|r|r.get(0)))
    }
    pub fn authenticate_trade(
        &self,
        message: &SignedPortMessage,
        purpose: &str,
    ) -> Result<TradeRoute, String> {
        let now = now_unix();
        if !message.verify(purpose, &self.event_signer.public_hex, now)
            || message.document.expires_at > now + 600
        {
            return Err("invalid peer proof".into());
        }
        let id = message.document.body["grant"]
            .as_str()
            .ok_or("missing grant")?;
        let credential = message.document.body["credential"]
            .as_str()
            .ok_or("missing credential")?;
        let c = self.connection.lock().expect("store poisoned");
        let route = route_in(&c, id)?;
        let accepted:bool=c.query_row("SELECT direction='incoming' AND (credential=?2 OR (?3='rotate' AND credential=?4)) FROM trade_routes WHERE id=?1",params![id,trade_secret_hash(credential),purpose,trade_secret_hash(message.document.body["next"].as_str().unwrap_or_default())],|r|r.get(0)).map_err(|e|e.to_string())?;
        if !accepted || route.peer_key != message.document.issuer {
            return Err("route credential or peer identity is invalid".into());
        }
        Ok(route)
    }
    pub fn save_outgoing_trade(
        &self,
        route: &TradeRoute,
        credential: &str,
        invitation: &SignedPortMessage,
    ) -> Result<(), String> {
        let mut c = self.connection.lock().expect("store poisoned");
        let tx = c.transaction().map_err(|e| e.to_string())?;
        workflows::ensure_tenant(&tx, &route.tenant)?;
        let changed_address:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM trade_routes WHERE tenant=?1 AND peer_key=?2 AND direction='outgoing' AND json_extract(document,'$.address')<>?3)",params![route.tenant,route.peer_key,route.address],|r|r.get(0)).map_err(|e|e.to_string())?;
        if changed_address {
            return Err("this peer has a different saved address; verify and change its connection address first".into());
        }

        let count: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM trade_routes WHERE tenant=?1",
                [&route.tenant],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        if count >= 100 {
            return Err("route limit reached".into());
        }
        let storage = crate::api::outbound::workflows::storage::Storage {
            id: route.id.clone(),
            revision: 1,
            label: route.name.clone(),
            kind: crate::api::outbound::workflows::storage::StorageKind::Votport,
            directory: String::new(),
            endpoint: route.address.clone(),
            bucket: String::new(),
            region: String::new(),
            prefix: String::new(),
            path_style: false,
            kms_key_id: None,
            tenants: vec![route.tenant.clone()],
            enabled: true,
        };
        tx.execute("INSERT INTO trade_routes(id,tenant,direction,peer_key,endpoint,document,credential,enrollment) VALUES (?1,?2,'outgoing',?3,?4,?5,?6,?7)",params![route.id,route.tenant,route.peer_key,route.endpoint,serde_json::to_string(route).expect("route serializes"),credential,serde_json::to_string(invitation).expect("invitation serializes")]).map_err(|e|e.to_string())?;
        tx.execute(
            "INSERT INTO delivery_storage(id,revision,document) VALUES (?1,1,?2)",
            params![
                route.id,
                serde_json::to_string(&storage).expect("storage serializes")
            ],
        )
        .map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT INTO delivery_storage_credentials(id,document) VALUES (?1,?2)",
            params![
                route.id,
                serde_json::json!({"mode":"trade_route","route_id":route.id}).to_string()
            ],
        )
        .map_err(|e| e.to_string())?;
        evidence::delivery_event(
            &tx,
            &self.event_signer,
            &route.tenant,
            "",
            "route_accepted",
            &serde_json::json!({"route":route.id,"peer":route.peer_key,"address":route.address,"endpoint":route.endpoint}),
            now_unix(),
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())
    }
    pub fn prune_trade_invitations(&self) -> Result<usize, String> {
        self.with(|c| {
            c.execute(
                "DELETE FROM trade_invitations WHERE redeemed IS NULL AND expires_at<=?1",
                [now_unix() as i64],
            )
        })
    }
    pub fn trade_enrollment(
        &self,
        tenant: &str,
        id: &str,
    ) -> Result<Option<SignedPortMessage>, String> {
        self.with(|c| {
            c.query_row(
                "SELECT enrollment FROM trade_routes WHERE tenant=?1 AND id=?2",
                params![tenant, id],
                |r| r.get::<_, Option<String>>(0),
            )
        })?
        .map(|v| serde_json::from_str(&v).map_err(|e| e.to_string()))
        .transpose()
    }
    pub fn finish_trade_enrollment(
        &self,
        tenant: &str,
        id: &str,
        grant: &str,
        state: &str,
    ) -> Result<(), String> {
        self.with(|c|c.execute("UPDATE trade_routes SET document=json_set(document,'$.remote_grant',?3,'$.remote_state',?4,'$.state',CASE WHEN json_extract(document,'$.state') IN ('paused','revoked') THEN json_extract(document,'$.state') ELSE ?4 END),enrollment=NULL WHERE tenant=?1 AND id=?2 AND json_extract(document,'$.remote_grant')=''",params![tenant,id,grant,state])).map(|_|())
    }
    pub fn update_trade_route(
        &self,
        tenant: &str,
        id: &str,
        revision: u64,
        state: &str,
        cancel_active: bool,
        policy: &NotificationPolicy,
    ) -> Result<TradeRoute, String> {
        if !matches!(state, "active" | "paused" | "revoked" | "pending_approval") {
            return Err("choose active, paused or revoked".into());
        }
        policy.validate(&TRADE_EVENTS)?;
        let mut c = self.connection.lock().expect("store poisoned");
        let tx = c.transaction().map_err(|e| e.to_string())?;
        let mut route = route_in(&tx, id)?;
        if route.tenant != tenant || route.revision != revision {
            return Err("route changed or unavailable; reload before saving".into());
        }
        if route.state == "revoked" && state != "revoked" {
            return Err("revoked routes require a new invitation".into());
        }
        if route.direction == "outgoing" && route.remote_grant.is_empty() && state == "active" {
            return Err("finish enrollment first".into());
        }
        if state == "pending_approval" && route.state != "pending_approval" {
            return Err("an existing approval cannot be changed back to pending".into());
        }
        route.revision += 1;
        route.state = state.into();
        route.cancel_active = cancel_active;
        route.notifications = policy.clone();
        write_route(&tx, &route)?;
        queue_cancelled(&tx, &self.event_signer, id)?;
        if route.direction == "incoming" && state != "active" && cancel_active {
            tx.execute("UPDATE inbound_routes SET revoked_at=COALESCE(revoked_at,?2) WHERE receipt IS NULL AND json_extract(source,'$.document.permission.grant')=?1",params![id,now_unix() as i64]).map_err(|e|e.to_string())?;
        }
        evidence::delivery_event(
            &tx,
            &self.event_signer,
            tenant,
            "",
            "route_permission_changed",
            &serde_json::json!({"route":id,"state":state,"cancel_active":cancel_active}),
            now_unix(),
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(route)
    }
    pub fn trade_contact(
        &self,
        tenant: &str,
        id: &str,
        remote_state: &str,
        error: Option<&str>,
    ) -> Result<bool, String> {
        let mut c = self.connection.lock().expect("store poisoned");
        let tx = c.transaction().map_err(|e| e.to_string())?;
        let mut route = route_in(&tx, id)?;
        if route.tenant != tenant {
            return Err("route unavailable".into());
        }
        let changed = route.remote_state != remote_state || route.error.as_deref() != error;
        route.remote_state = remote_state.into();
        route.error = error.map(str::to_owned);
        if error.is_none() {
            route.last_contact = Some(now_unix());
        }
        if route.direction == "outgoing"
            && route.state == "pending_approval"
            && remote_state == "active"
        {
            route.state = "active".into();
        }
        write_route(&tx, &route)?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(changed)
    }
    pub fn rotate_trade_credential(
        &self,
        id: &str,
        previous: &str,
        next: &str,
        incoming: bool,
    ) -> Result<(), String> {
        if next.len() != 32 || !next.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("invalid credential".into());
        }
        let (previous, next) = if incoming {
            (trade_secret_hash(previous), trade_secret_hash(next))
        } else {
            (previous.into(), next.into())
        };
        self.with(|c|c.execute("UPDATE trade_routes SET credential=?3 WHERE id=?1 AND (credential=?2 OR credential=?3)",params![id,previous,next])).and_then(|n|if n==1 {Ok(())}else{Err("credential changed; retry with current credentials".into())})
    }
}

pub fn valid_peer_key(key: &str) -> bool {
    hex::decode(key)
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .and_then(|v| ed25519_dalek::VerifyingKey::from_bytes(&v).ok())
        .is_some()
        && key.len() == 64
        && key
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
}

pub(super) fn admit(
    connection: &Connection,
    source: &SignedRoute,
    ancestry: &[RouteReceipt],
    link_id: &str,
    credential: Option<&str>,
    existing: bool,
) -> Result<(), String> {
    let paired: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM trade_endpoints WHERE id=?1)",
            [link_id],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    if !paired {
        return if source.document.permission.is_none() {
            Ok(())
        } else {
            Err("route permission names an unmanaged endpoint".into())
        };
    }
    let permission = source
        .document
        .permission
        .as_ref()
        .ok_or("this endpoint requires an enrolled route")?;
    let route = route_in(connection, &permission.grant)?;
    let accepted: bool = connection
        .query_row(
            "SELECT credential=?2 FROM trade_routes WHERE id=?1",
            params![
                route.id,
                trade_secret_hash(credential.ok_or("route credential required")?)
            ],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    if !accepted
        || route.direction != "incoming"
        || route.endpoint != link_id
        || route.peer_key != source.document.issuer
        || (route.state != "active" && !existing)
        || (permission.forwarding && !route.forwarding)
        || source
            .document
            .metadata
            .keys()
            .any(|key| !route.metadata_keys.contains(key))
        || ancestry.iter().any(|receipt| {
            receipt
                .document
                .source
                .document
                .metadata
                .keys()
                .any(|key| !route.metadata_keys.contains(key))
        })
    {
        return Err(
            "route permission, forwarding terms or metadata policy denied admission".into(),
        );
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TradeDeliveryStatus {
    route: String,
    received: bool,
    revoked: bool,
    workflow: Option<String>,
    released: bool,
}

impl Store {
    pub fn trade_deliveries(&self, route: &TradeRoute) -> Result<serde_json::Value, String> {
        self.with(|c| {
            if route.direction=="incoming" {
                c.prepare("SELECT r.id,r.receipt,r.revoked_at,j.state,json_extract(j.document,'$.checks.released_at') FROM inbound_routes r LEFT JOIN delivery_jobs j ON j.tenant=r.tenant AND json_extract(j.document,'$.received.upload_id')=r.upload_id WHERE json_extract(r.source,'$.document.permission.grant')=?1 ORDER BY r.created_at DESC LIMIT 50")?.query_map([&route.id],|r|{
                    let receipt:Option<String>=r.get(1)?;let state:Option<String>=r.get(3)?;let released:Option<i64>=r.get(4)?;
                    Ok(serde_json::json!({"route":r.get::<_,String>(0)?,"received":receipt.is_some(),"revoked":r.get::<_,Option<i64>>(2)?.is_some(),"workflow":state,"released":state.as_deref()==Some("ready") || (released.is_some() && matches!(state.as_deref(),Some("exporting"|"retrying"|"failed")))}))
                })?.collect::<rusqlite::Result<Vec<_>>>().map(serde_json::Value::from)
            } else {
                c.prepare("SELECT j.id,j.state,json_extract(j.document,'$.request.label'),json_extract(j.document,?2) FROM delivery_jobs j JOIN json_each(j.document,'$.project.destinations') d ON d.value=?1 WHERE j.tenant=?3 ORDER BY j.rowid DESC LIMIT 50")?.query_map(params![route.id,format!("$.checks.remote_status.{}",route.id),route.tenant],|r|{
                    let status:Option<String>=r.get(3)?;
                    Ok(serde_json::json!({"job":r.get::<_,String>(0)?,"state":r.get::<_,String>(1)?,"label":r.get::<_,String>(2)?,"remote":status.map(|s|serde_json::from_str::<serde_json::Value>(&s)).transpose().map_err(|e|rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?}))
                })?.collect::<rusqlite::Result<Vec<_>>>().map(serde_json::Value::from)
            }
        })
    }
    pub fn record_trade_status(
        &self,
        route: &TradeRoute,
        deliveries: &serde_json::Value,
    ) -> Result<(), String> {
        let rows: Vec<TradeDeliveryStatus> = serde_json::from_value(deliveries.clone())
            .map_err(|_| "invalid peer delivery status")?;
        if rows.len() > 50
            || rows.iter().any(|row| {
                !crate::workflow::valid_id(&row.route)
                    || row.workflow.as_ref().is_some_and(|state| {
                        !matches!(
                            state.as_str(),
                            "queued"
                                | "preparing"
                                | "awaiting_approval"
                                | "exporting"
                                | "retrying"
                                | "failed"
                                | "ready"
                                | "cancelled"
                                | "retiring"
                                | "retired"
                        )
                    })
            })
        {
            return Err("invalid peer delivery status".into());
        }
        self.with(|c| {
            for mut row in rows {
                let proof:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM delivery_jobs j JOIN outbound_routes r ON r.job_id=j.id WHERE j.tenant=?1 AND r.destination_id=?2 AND r.route_id=?3 AND json_extract(j.document,?4) IS NOT NULL)",params![route.tenant,route.id,row.route,format!("$.checks.route_receipts.{}",route.id)],|r|r.get(0))?;
                row.received &= proof;
                row.released &= row.received && !row.revoked;
                c.execute("UPDATE delivery_jobs SET document=json_set(document,?3,json(?4)) WHERE tenant=?1 AND id IN (SELECT job_id FROM outbound_routes WHERE destination_id=?2 AND route_id=?5)",params![route.tenant,route.id,format!("$.checks.remote_status.{}",route.id),serde_json::to_string(&row).expect("status serializes"),row.route])?;
            } Ok(())
        })
    }
}

pub(super) fn snapshot(
    connection: &Connection,
    tenant: &str,
    project: &crate::workflow::Project,
) -> Result<serde_json::Value, String> {
    let mut routes = serde_json::Map::new();
    for id in &project.destinations {
        let route:Option<TradeRoute>=connection.query_row("SELECT document FROM trade_routes WHERE tenant=?1 AND id=?2 AND direction='outgoing'",params![tenant,id],decode).optional().map_err(|e|e.to_string())?;
        if let Some(route) = route {
            routes.insert(id.clone(),serde_json::json!({"notifications":route.notifications,"metadata_keys":route.metadata_keys,"permission":{"receiver":route.peer_key,"grant":route.remote_grant,"forwarding":route.forwarding}}));
        }
    }
    Ok(serde_json::json!({"trade_routes":routes}))
}

pub(super) fn check_export(
    connection: &Connection,
    job: &crate::workflow::Job,
) -> Result<(), String> {
    if !job.project.destinations.is_empty() {
        if let Some(received) = &job.received {
            let prohibited:bool=connection.query_row("SELECT EXISTS(SELECT 1 FROM inbound_routes WHERE tenant=?1 AND upload_id=?2 AND json_extract(source,'$.document.permission.forwarding')=0)",params![job.tenant,received.upload_id],|r|r.get(0)).map_err(|e|e.to_string())?;
            if prohibited {
                return Err("source port does not permit managed forwarding".into());
            }
        }
    }
    for id in &job.project.destinations {
        let route: Option<TradeRoute> = connection
            .query_row(
                "SELECT document FROM trade_routes WHERE id=?1",
                [id],
                decode,
            )
            .optional()
            .map_err(|e| e.to_string())?;
        if route
            .as_ref()
            .is_some_and(|route| route.tenant != job.tenant || route.direction != "outgoing")
        {
            return Err("trade route is unavailable to this tenant".into());
        }
    }
    Ok(())
}

impl Store {
    pub fn pending_trade_rotation(&self, tenant: &str, id: &str) -> Result<String, String> {
        let mut c = self.connection.lock().expect("store poisoned");
        let tx = c.transaction().map_err(|e| e.to_string())?;
        let route = route_in(&tx, id)?;
        if route.tenant != tenant || route.direction != "outgoing" {
            return Err("route unavailable".into());
        }
        tx.execute(
            "INSERT OR IGNORE INTO trade_rotations(route_id,credential) VALUES (?1,?2)",
            params![id, crate::auth::random_token()],
        )
        .map_err(|e| e.to_string())?;
        let next = tx
            .query_row(
                "SELECT credential FROM trade_rotations WHERE route_id=?1",
                [id],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(next)
    }
    pub fn clear_trade_rotation(&self, id: &str, next: &str) -> Result<(), String> {
        self.with(|c| {
            c.execute(
                "DELETE FROM trade_rotations WHERE route_id=?1 AND credential=?2",
                params![id, next],
            )
        })
        .map(|_| ())
    }
    pub fn trade_sessions(&self, id: &str) -> Result<Vec<String>, String> {
        self.with(|c|c.prepare("SELECT session_id FROM inbound_routes WHERE json_extract(source,'$.document.permission.grant')=?1 AND receipt IS NULL AND session_id IS NOT NULL")?.query_map([id],|r|r.get(0))?.collect())
    }
}

impl Store {
    pub fn is_trade_route(&self, id: &str) -> Result<bool, String> {
        self.with(|c| {
            c.query_row(
                "SELECT EXISTS(SELECT 1 FROM trade_routes WHERE id=?1)",
                [id],
                |r| r.get(0),
            )
        })
    }
    pub fn change_trade_address(
        &self,
        tenant: &str,
        id: &str,
        revision: u64,
        address: &str,
    ) -> Result<(), String> {
        let mut c = self.connection.lock().expect("store poisoned");
        let tx = c.transaction().map_err(|e| e.to_string())?;
        let route = route_in(&tx, id)?;
        if route.tenant != tenant || route.revision != revision || route.direction != "outgoing" {
            return Err("route changed or unavailable".into());
        }
        let active:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM delivery_jobs j JOIN json_each(j.document,'$.project.destinations') d JOIN trade_routes r ON r.id=d.value WHERE r.tenant=?1 AND r.peer_key=?2 AND j.state IN ('queued','preparing','awaiting_approval','exporting','retrying'))",params![tenant,route.peer_key],|r|r.get(0)).map_err(|e|e.to_string())?;
        if active {
            return Err(
                "finish or cancel active deliveries to this peer before changing its address"
                    .into(),
            );
        }
        tx.execute("UPDATE trade_routes SET document=json_set(document,'$.address',?3,'$.revision',json_extract(document,'$.revision')+1) WHERE tenant=?1 AND peer_key=?2 AND direction='outgoing'",params![tenant,route.peer_key,address]).map_err(|e|e.to_string())?;
        tx.execute("UPDATE delivery_storage SET document=json_set(document,'$.endpoint',?3) WHERE id IN (SELECT id FROM trade_routes WHERE tenant=?1 AND peer_key=?2 AND direction='outgoing')",params![tenant,route.peer_key,address]).map_err(|e|e.to_string())?;
        tx.execute("UPDATE outbound_routes SET origin=?3 WHERE destination_id IN (SELECT id FROM trade_routes WHERE tenant=?1 AND peer_key=?2 AND direction='outgoing') AND peer_key=?2",params![tenant,route.peer_key,address]).map_err(|e|e.to_string())?;
        evidence::delivery_event(
            &tx,
            &self.event_signer,
            tenant,
            "",
            "route_address_changed",
            &serde_json::json!({"peer":route.peer_key,"address":address}),
            now_unix(),
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())
    }
}

impl Store {
    pub fn trade_delivery_policy(&self, id: &str) -> Result<Option<NotificationPolicy>, String> {
        self.with(|c| {
            c.query_row(
                "SELECT document FROM trade_delivery_policies WHERE route_id=?1",
                [id],
                decode,
            )
            .optional()
        })
    }
}

pub(super) fn check_destination(
    c: &Connection,
    job: &crate::workflow::Job,
    id: &str,
) -> Result<(), String> {
    if job.checks["destinations"][id]["state"] == "complete" {
        return Ok(());
    }
    let route: Option<TradeRoute> = c
        .query_row(
            "SELECT document FROM trade_routes WHERE id=?1",
            [id],
            decode,
        )
        .optional()
        .map_err(|e| e.to_string())?;
    let Some(route) = route else {
        return Ok(());
    };
    let cancelled: bool = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM outbound_routes WHERE job_id=?1 AND destination_id=?2 AND (revocation IS NOT NULL OR ack IS NOT NULL))",
        params![job.id, id], |row| row.get(0),
    ).map_err(|e| e.to_string())?;
    if cancelled {
        return Err(
            "this delivery was permanently revoked; submit a new job for the resumed route".into(),
        );
    }
    let admitted: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM outbound_routes WHERE job_id=?1 AND destination_id=?2)",
            params![job.id, id],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    if route.tenant != job.tenant
        || route.direction != "outgoing"
        || route.remote_grant.is_empty()
        || (route.state != "active" && (!admitted || route.cancel_active))
    {
        return Err("trade route is not approved or has been paused or revoked".into());
    }
    Ok(())
}

pub(super) fn queue_cancelled(
    c: &Connection,
    signer: &crate::receipt::ReceiptSigner,
    id: &str,
) -> Result<(), String> {
    let rows=c.prepare("SELECT r.job_id,r.route_id,r.peer_key,r.source FROM outbound_routes r JOIN trade_routes t ON t.id=r.destination_id JOIN delivery_jobs j ON j.id=r.job_id WHERE t.id=?1 AND t.direction='outgoing' AND json_extract(t.document,'$.state')<>'active' AND json_extract(t.document,'$.cancel_active')=1 AND COALESCE(json_extract(j.document,?2),'')<>'complete' AND r.revocation IS NULL AND r.ack IS NULL").map_err(|e|e.to_string())?.query_map(params![id,format!("$.checks.destinations.{id}.state")],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,parse_json::<SignedRoute>(&r.get::<_,String>(3)?,3)?))).map_err(|e|e.to_string())?.collect::<rusqlite::Result<Vec<_>>>().map_err(|e|e.to_string())?;
    for (job, route, key, source) in rows {
        let request = signer.revoke_route(source, key, &route);
        c.execute("UPDATE outbound_routes SET revocation=?3,next_attempt=0 WHERE job_id=?1 AND destination_id=?2",params![job,id,serde_json::to_string(&request).expect("revocation serializes")]).map_err(|e|e.to_string())?;
    }
    Ok(())
}

impl Store {
    pub fn require_trade_destination(
        &self,
        job: &crate::workflow::Job,
        id: &str,
    ) -> Result<(), String> {
        check_destination(&self.connection.lock().expect("store poisoned"), job, id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route_protocol::{RouteDocument, RoutePermission};

    #[test]
    fn enrollment_permissions_replay_and_rotation_stay_scoped() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let sender_dir = tempfile::tempdir().unwrap();
        let sender = crate::receipt::ReceiptSigner::load_or_create(sender_dir.path()).unwrap();
        let endpoint = TradeEndpoint {
            id: crate::auth::random_token(),
            name: "Masters".into(),
            category: "external".into(),
            forwarding: false,
            metadata_keys: vec!["episode".into()],
            notifications: NotificationPolicy::default(),
        };
        let link:Link=serde_json::from_value(serde_json::json!({"id":endpoint.id,"label":"Masters","dest":"","tenant":"","created_at":now_unix(),"active":true})).unwrap();
        store.insert_link(link).unwrap();
        store.create_trade_endpoint("", &endpoint).unwrap();
        assert!(store
            .create_trade_invitation("other", &endpoint.id, "", now_unix() + 300)
            .is_err());
        let (id, secret) = store
            .create_trade_invitation("", &endpoint.id, "", now_unix() + 300)
            .unwrap();
        let credential = crate::auth::random_token();
        let proof = sender.port_message(
            "enroll",
            &store.event_signer.public_hex,
            id.clone(),
            now_unix() + 300,
            serde_json::json!({"name":"Sender","secret":secret,"credential":credential}),
        );
        let (pending, created) = store.redeem_trade_invitation(&proof).unwrap();
        assert!(created);
        assert_eq!(pending.state, "pending_approval");
        assert!(!store.redeem_trade_invitation(&proof).unwrap().1);
        let mut different = proof.document.body.clone();
        different["credential"] = serde_json::json!(crate::auth::random_token());
        let replay = sender.port_message(
            "enroll",
            &store.event_signer.public_hex,
            id,
            now_unix() + 300,
            different,
        );
        assert!(store.redeem_trade_invitation(&replay).is_err());
        let status = sender.port_message(
            "status",
            &store.event_signer.public_hex,
            crate::auth::random_token(),
            now_unix() + 300,
            serde_json::json!({"grant":pending.id,"credential":credential}),
        );
        assert!(store.authenticate_trade(&status, "status").is_ok());
        let other_dir = tempfile::tempdir().unwrap();
        let other = crate::receipt::ReceiptSigner::load_or_create(other_dir.path()).unwrap();
        let wrong_peer = other.port_message(
            "status",
            &store.event_signer.public_hex,
            crate::auth::random_token(),
            now_unix() + 300,
            status.document.body.clone(),
        );
        assert!(store.authenticate_trade(&wrong_peer, "status").is_err());

        store
            .trade_contact("", &pending.id, "active", None)
            .unwrap();
        assert_eq!(
            store.trade_route("", &pending.id).unwrap().state,
            "pending_approval"
        );
        let mut document = RouteDocument {
            issuer: sender.public_hex.clone(),
            operation_id: "operation".into(),
            manifest: "ab".repeat(32),
            label: "Delivery".into(),
            metadata: Default::default(),
            visited: vec![sender.public_hex.clone()],
            parent_receipt: None,
            permission: Some(RoutePermission {
                receiver: store.event_signer.public_hex.clone(),
                grant: pending.id.clone(),
                forwarding: false,
            }),
        };
        let signed = sender.sign_route(document.clone());
        assert!(store
            .receive_route_authorized("", &endpoint.id, &signed, &[], Some(&credential))
            .is_err());
        assert!(store
            .update_trade_route(
                "other",
                &pending.id,
                1,
                "active",
                false,
                &pending.notifications
            )
            .is_err());
        let active = store
            .update_trade_route("", &pending.id, 1, "active", false, &pending.notifications)
            .unwrap();
        assert!(store.receive_route("", &endpoint.id, &signed, &[]).is_err());
        let admitted = store
            .receive_route_authorized("", &endpoint.id, &signed, &[], Some(&credential))
            .unwrap();
        assert_eq!(
            admitted.id,
            store
                .receive_route_authorized("", &endpoint.id, &signed, &[], Some(&credential))
                .unwrap()
                .id
        );
        document.operation_id = "wrong-metadata".into();
        document.metadata.insert("private".into(), "secret".into());
        assert!(store
            .receive_route_authorized(
                "",
                &endpoint.id,
                &sender.sign_route(document.clone()),
                &[],
                Some(&credential)
            )
            .is_err());
        document.metadata.clear();
        document.permission.as_mut().unwrap().forwarding = true;
        assert!(store
            .receive_route_authorized(
                "",
                &endpoint.id,
                &sender.sign_route(document.clone()),
                &[],
                Some(&credential)
            )
            .is_err());
        let paused = store
            .update_trade_route(
                "",
                &active.id,
                active.revision,
                "paused",
                false,
                &active.notifications,
            )
            .unwrap();
        assert!(store
            .receive_route_authorized("", &endpoint.id, &signed, &[], Some(&credential))
            .is_ok());
        document.permission.as_mut().unwrap().forwarding = false;
        document.operation_id = "new".into();
        assert!(store
            .receive_route_authorized(
                "",
                &endpoint.id,
                &sender.sign_route(document),
                &[],
                Some(&credential)
            )
            .is_err());
        store
            .update_trade_route(
                "",
                &paused.id,
                paused.revision,
                "revoked",
                true,
                &paused.notifications,
            )
            .unwrap();
        assert!(store
            .inbound_route(&admitted.id)
            .unwrap()
            .unwrap()
            .revoked_at
            .is_some());
        assert!(store
            .update_trade_route(
                "",
                &paused.id,
                paused.revision + 1,
                "active",
                false,
                &paused.notifications
            )
            .is_err());
        let next = crate::auth::random_token();
        store
            .rotate_trade_credential(&active.id, &credential, &next, true)
            .unwrap();
        store
            .rotate_trade_credential(&active.id, &credential, &next, true)
            .unwrap();
        assert!(store.authenticate_trade(&status, "status").is_err());
        let rotation = sender.port_message(
            "rotate",
            &store.event_signer.public_hex,
            crate::auth::random_token(),
            now_unix() + 300,
            serde_json::json!({"grant":active.id,"credential":credential,"next":next}),
        );
        assert!(store.authenticate_trade(&rotation, "rotate").is_ok());
        let (expired, secret) = store
            .create_trade_invitation("", &endpoint.id, &sender.public_hex, now_unix() + 100)
            .unwrap();
        store
            .with(|c| {
                c.execute(
                    "UPDATE trade_invitations SET expires_at=1 WHERE id=?1",
                    [&expired],
                )
            })
            .unwrap();
        let proof = sender.port_message(
            "enroll",
            &store.event_signer.public_hex,
            expired,
            now_unix() + 300,
            serde_json::json!({"name":"Sender","secret":secret,"credential":credential}),
        );
        assert!(store.redeem_trade_invitation(&proof).is_err());
        let custody =
            store
                .event_signer
                .route_receipt(signed.clone(), "received".into(), now_unix());
        let forward = store.event_signer.sign_route(RouteDocument {
            issuer: store.event_signer.public_hex.clone(),
            operation_id: "forward".into(),
            manifest: signed.document.manifest.clone(),
            label: "Forward".into(),
            metadata: Default::default(),
            visited: vec![
                sender.public_hex.clone(),
                store.event_signer.public_hex.clone(),
            ],
            parent_receipt: Some(custody.digest()),
            permission: None,
        });
        assert!(!crate::route_protocol::verify_ancestry(
            &forward,
            &[custody]
        ));
        assert!(store.record_trade_status(&pending,&serde_json::json!([{"route":"delivery","received":true,"revoked":false,"workflow":{},"released":true}])).is_err());
        let mut outgoing = pending.clone();
        outgoing.id = crate::auth::random_token();
        outgoing.direction = "outgoing".into();
        outgoing.state = "active".into();
        outgoing.address = "http://localhost".into();
        outgoing.remote_grant = pending.id.clone();
        store
            .save_outgoing_trade(&outgoing, &crate::auth::random_token(), &proof)
            .unwrap();
        let mut project = crate::workflow::tests::project();
        project.destinations = vec![outgoing.id.clone()];
        let project = store.save_delivery_project("", "local", project).unwrap();
        let job = store
            .enqueue_delivery_job(
                "",
                "sender",
                1,
                None,
                project,
                crate::workflow::tests::request(),
            )
            .unwrap();
        assert!(store.require_trade_destination(&job, &outgoing.id).is_ok());
        let remote = crate::auth::random_token();
        store
            .bind_outbound_route(
                &job,
                &outgoing.id,
                &outgoing.address,
                &remote,
                &outgoing.peer_key,
                &signed,
            )
            .unwrap();
        store.with(|c|c.execute("UPDATE outbound_routes SET revocation=?3 WHERE job_id=?1 AND destination_id=?2",params![job.id,outgoing.id,serde_json::to_string(&store.event_signer.revoke_route(signed.clone(),outgoing.peer_key.clone(),&remote)).unwrap()])).unwrap();
        assert!(store.require_trade_destination(&job, &outgoing.id).is_err());
        let mut completed = job.clone();
        completed.checks["destinations"][&outgoing.id] = serde_json::json!({"state":"complete"});
        assert!(store
            .require_trade_destination(&completed, &outgoing.id)
            .is_ok());
        drop(store);
        std::fs::remove_file(dir.path().join("receipt.key")).unwrap();
        assert!(Store::open(dir.path())
            .err()
            .unwrap()
            .contains("receipt.key is missing"));
    }

    #[test]
    fn ancestry_metadata_and_link_removal() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let sender_dir = tempfile::tempdir().unwrap();
        let sender = crate::receipt::ReceiptSigner::load_or_create(sender_dir.path()).unwrap();
        let origin_dir = tempfile::tempdir().unwrap();
        let origin = crate::receipt::ReceiptSigner::load_or_create(origin_dir.path()).unwrap();
        let endpoint = TradeEndpoint {
            id: crate::auth::random_token(),
            name: "Masters".into(),
            category: "external".into(),
            forwarding: false,
            metadata_keys: vec!["episode".into()],
            notifications: NotificationPolicy::default(),
        };
        let link:Link=serde_json::from_value(serde_json::json!({"id":endpoint.id,"label":"Masters","dest":"","tenant":"","created_at":now_unix(),"active":true})).unwrap();
        store.insert_link(link).unwrap();
        store.create_trade_endpoint("", &endpoint).unwrap();
        let (id, secret) = store
            .create_trade_invitation("", &endpoint.id, "", now_unix() + 300)
            .unwrap();
        let credential = crate::auth::random_token();
        let proof = sender.port_message(
            "enroll",
            &store.event_signer.public_hex,
            id,
            now_unix() + 300,
            serde_json::json!({"name":"Sender","secret":secret,"credential":credential}),
        );
        let (pending, _) = store.redeem_trade_invitation(&proof).unwrap();
        let active = store
            .update_trade_route("", &pending.id, 1, "active", false, &pending.notifications)
            .unwrap();
        store
            .create_trade_invitation("", &endpoint.id, "", now_unix() + 300)
            .unwrap();
        store
            .with(|c| {
                c.execute(
                    "UPDATE trade_invitations SET expires_at=1 WHERE redeemed IS NULL",
                    [],
                )
            })
            .unwrap();
        assert_eq!(store.prune_trade_invitations().unwrap(), 1);
        let manifest = "ab".repeat(32);
        // A forwarded delivery: the origin's metadata rides in the signed
        // ancestry, not in the forwarding port's own document.
        let forwarded = |metadata: &[(&str, &str)]| {
            let upstream = origin.sign_route(RouteDocument {
                issuer: origin.public_hex.clone(),
                operation_id: "origin".into(),
                manifest: manifest.clone(),
                label: "Origin".into(),
                metadata: metadata
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                visited: vec![origin.public_hex.clone()],
                parent_receipt: None,
                permission: None,
            });
            let receipt = sender.route_receipt(upstream, "upload".into(), now_unix());
            let forward = sender.sign_route(RouteDocument {
                issuer: sender.public_hex.clone(),
                operation_id: format!("forward-{}", metadata.len()),
                manifest: manifest.clone(),
                label: "Forward".into(),
                metadata: Default::default(),
                visited: vec![origin.public_hex.clone(), sender.public_hex.clone()],
                parent_receipt: Some(receipt.digest()),
                permission: Some(RoutePermission {
                    receiver: store.event_signer.public_hex.clone(),
                    grant: pending.id.clone(),
                    forwarding: false,
                }),
            });
            (forward, vec![receipt])
        };
        let (forward, ancestry) = forwarded(&[("private", "secret")]);
        assert!(crate::route_protocol::verify_ancestry(&forward, &ancestry));
        assert!(store
            .receive_route_authorized("", &endpoint.id, &forward, &ancestry, Some(&credential))
            .is_err());
        let (forward, ancestry) = forwarded(&[("episode", "1")]);
        assert!(store
            .receive_route_authorized("", &endpoint.id, &forward, &ancestry, Some(&credential))
            .is_ok());

        assert!(store.remove_link("", &endpoint.id).is_err());
        store
            .update_trade_route(
                "",
                &active.id,
                active.revision,
                "revoked",
                false,
                &active.notifications,
            )
            .unwrap();
        assert!(store.remove_link("", &endpoint.id).unwrap());
        assert!(store.trade_endpoints("").unwrap().is_empty());
        assert!(store.trade_routes(Some("")).unwrap().is_empty());
        let invitations: i64 = store
            .with(|c| c.query_row("SELECT COUNT(*) FROM trade_invitations", [], |r| r.get(0)))
            .unwrap();
        assert_eq!(invitations, 0);
    }
}
