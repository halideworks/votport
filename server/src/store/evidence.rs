use super::*;
use crate::delivery_protocol::{manifest_digest, Evidence, EvidenceKind};
use rusqlite::params;

pub(super) const SCHEMA: &str = "
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
";

pub(crate) fn grant_digest(grant: &OutboundGrant) -> String {
    if grant.files.is_empty() {
        manifest_digest([(&*grant.name, &*grant.suite, &*grant.root, grant.bytes)])
    } else {
        manifest_digest(
            grant
                .files
                .iter()
                .map(|f| (&*f.name, &*f.suite, &*f.root, f.bytes)),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeliveryEvent {
    pub id: u64,
    pub tenant: String,
    pub grant_id: String,
    pub kind: String,
    pub created_at: u64,
    pub payload: serde_json::Value,
    pub previous_hash: String,
    pub hash: String,
    pub issuer: String,
    pub signature: String,
}

impl DeliveryEvent {
    pub fn verify(&self) -> bool {
        use sha2::{Digest, Sha256};
        let document = self.document();
        let key = hex::decode(&self.issuer)
            .ok()
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
            .and_then(|v| ed25519_dalek::VerifyingKey::from_bytes(&v).ok());
        let signature = hex::decode(&self.signature)
            .ok()
            .and_then(|v| ed25519_dalek::Signature::from_slice(&v).ok());
        let mut message = b"votport-delivery-event-v1\0".to_vec();
        message.extend(serde_json::to_vec(&document).expect("event serializes"));
        let hash = hex::encode(Sha256::digest(
            serde_json::to_vec(
                &serde_json::json!({"document": document,"signature": self.signature}),
            )
            .expect("event serializes"),
        ));
        hash == self.hash
            && key
                .zip(signature)
                .is_some_and(|(key, signature)| key.verify_strict(&message, &signature).is_ok())
    }

    pub fn document(&self) -> serde_json::Value {
        serde_json::json!({"id": self.id,"tenant": self.tenant,"grant_id": self.grant_id,"kind": self.kind,"created_at": self.created_at,"payload": self.payload,"previous_hash": self.previous_hash,"issuer": self.issuer})
    }
}

pub(crate) fn delivery_event(
    connection: &Connection,
    signer: &crate::receipt::ReceiptSigner,
    tenant: &str,
    grant_id: &str,
    kind: &str,
    payload: &serde_json::Value,
    now: u64,
) -> rusqlite::Result<()> {
    use sha2::{Digest, Sha256};
    let previous: Option<String> = connection
        .query_row(
            "SELECT hash FROM delivery_events WHERE tenant=?1 ORDER BY id DESC LIMIT 1",
            [tenant],
            |row| row.get(0),
        )
        .optional()?;
    let previous_hash = previous.unwrap_or_default();
    connection.execute("INSERT INTO delivery_events(tenant,grant_id,kind,created_at,payload,previous_hash,hash,issuer,signature) VALUES (?1,?2,?3,?4,?5,?6,'',?7,'')", params![tenant,grant_id,kind,now as i64,payload.to_string(),previous_hash,signer.public_hex])?;
    let id = connection.last_insert_rowid();
    let document = serde_json::json!({"id": id,"tenant": tenant,"grant_id": grant_id,"kind": kind,"created_at": now,"payload": payload,"previous_hash": previous_hash,"issuer": signer.public_hex});
    let signature = signer.sign_delivery_event(&document);
    let hash = hex::encode(Sha256::digest(
        serde_json::to_vec(&serde_json::json!({"document": document,"signature": signature}))
            .expect("event serializes"),
    ));
    connection.execute(
        "UPDATE delivery_events SET hash=?2,signature=?3 WHERE id=?1",
        params![id, hash, signature],
    )?;
    Ok(())
}

impl Store {
    pub fn delivery_manifest(&self, grant_id: &str) -> Result<String, String> {
        if let Some(digest) = self.with(|connection| {
            connection
                .query_row(
                    "SELECT digest FROM delivery_manifests WHERE grant_id=?1",
                    [grant_id],
                    |row| row.get(0),
                )
                .optional()
        })? {
            return Ok(digest);
        }
        let grant = self
            .outbound_grant_by_id(grant_id)?
            .ok_or("delivery not found")?;
        let digest = grant_digest(&grant);
        self.with(|connection| {
            connection.execute(
                "INSERT OR IGNORE INTO delivery_manifests(grant_id,digest) SELECT ?1,?2 WHERE EXISTS(SELECT 1 FROM outbound_grants WHERE id=?1)",
                params![grant_id, digest],
            )
        })?;
        Ok(digest)
    }

    pub fn record_delivery_evidence(&self, evidence: &Evidence, now: u64) -> Result<bool, String> {
        let challenge = &evidence.authorization.challenge;
        let id = evidence.id();
        let kind = match evidence.kind {
            EvidenceKind::Verified => "verified",
            EvidenceKind::Accepted => "accepted",
        };
        let mut connection = self.connection.lock().expect("store poisoned");
        let tx = connection.transaction().map_err(|e| e.to_string())?;
        let tenant: String = tx
            .query_row(
                "SELECT tenant FROM outbound_grants WHERE id=?1",
                [&challenge.grant_id],
                |row| row.get(0),
            )
            .map_err(|_| "delivery not found")?;
        let manifest: String = tx
            .query_row(
                "SELECT digest FROM delivery_manifests WHERE grant_id=?1",
                [&challenge.grant_id],
                |row| row.get(0),
            )
            .map_err(|_| "delivery manifest missing")?;
        if manifest != challenge.manifest {
            return Err("delivery manifest changed".into());
        }
        let previous: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM delivery_evidence WHERE grant_id=?1 AND holder=?2 AND kind=?3)", params![challenge.grant_id, challenge.holder, kind], |row| row.get(0)).map_err(|e| e.to_string())?;
        let duplicate: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM delivery_evidence WHERE id=?1)",
                [&id],
                |row| row.get(0),
            )
            .map_err(|e| e.to_string())?;
        if duplicate {
            return Ok(false);
        }
        if evidence.kind == EvidenceKind::Accepted {
            let verified: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM delivery_evidence WHERE grant_id=?1 AND holder=?2 AND kind='verified')", params![challenge.grant_id, challenge.holder], |row| row.get(0)).map_err(|e| e.to_string())?;
            if !verified {
                return Err("this device must report verification before acceptance".into());
            }
        }
        let count: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM delivery_evidence WHERE grant_id=?1",
                [&challenge.grant_id],
                |row| row.get(0),
            )
            .map_err(|e| e.to_string())?;
        if count >= 2000 {
            return Err("delivery evidence limit reached".into());
        }
        tx.execute("INSERT INTO delivery_evidence(id,grant_id,holder,kind,received_at,document) VALUES (?1,?2,?3,?4,?5,?6)", params![id, challenge.grant_id, challenge.holder, kind, now as i64, serde_json::to_string(evidence).map_err(|e| e.to_string())?]).map_err(|e| e.to_string())?;
        if !previous {
            delivery_event(&tx, &self.event_signer, &tenant, &challenge.grant_id, &format!("recipient_{kind}"), &serde_json::json!({"evidence_id": id, "manifest": manifest, "holder": challenge.holder}), now).map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(true)
    }

    pub fn delivery_evidence_recorded(&self, id: &str) -> Result<bool, String> {
        self.with(|connection| {
            connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM delivery_evidence WHERE id=?1)",
                [id],
                |row| row.get(0),
            )
        })
    }

    pub fn delivery_evidence(
        &self,
        grant_id: &str,
        after: u64,
        limit: usize,
    ) -> Result<Vec<serde_json::Value>, String> {
        self.with(|connection| {
            let mut query = connection.prepare("SELECT rowid,received_at,document FROM delivery_evidence WHERE grant_id=?1 AND rowid>?2 ORDER BY rowid LIMIT ?3")?;
            let rows = query.query_map(params![grant_id, after as i64, limit.min(100) as i64], |row| {
                let document: String = row.get(2)?;
                Ok(serde_json::json!({"cursor": row.get::<_,i64>(0)?, "received_at": row.get::<_,i64>(1)?, "evidence": serde_json::from_str::<serde_json::Value>(&document).map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?}))
            })?;
            rows.collect()
        })
    }

    pub fn delivery_events(
        &self,
        tenant: &str,
        after: u64,
        limit: usize,
    ) -> Result<Vec<DeliveryEvent>, String> {
        self.with(|connection| {
            let mut query = connection.prepare("SELECT id,tenant,grant_id,kind,created_at,payload,previous_hash,hash,issuer,signature FROM delivery_events WHERE tenant=?1 AND id>?2 ORDER BY id LIMIT ?3")?;
            let rows = query.query_map(params![tenant, after as i64, limit.min(100) as i64], |row| {
                let payload: String = row.get(5)?;
                Ok(DeliveryEvent { previous_hash: row.get(6)?, hash: row.get(7)?, issuer: row.get(8)?, signature: row.get(9)?, id: row.get::<_,i64>(0)? as u64, tenant: row.get(1)?, grant_id: row.get(2)?, kind: row.get(3)?, created_at: row.get::<_,i64>(4)? as u64, payload: serde_json::from_str(&payload).map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))? })
            })?;
            rows.collect()
        })
    }
}
