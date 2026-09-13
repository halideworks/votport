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
    fn verify_for(&self, issuer: &str, tenant: &str) -> bool {
        self.issuer == issuer && self.tenant == tenant && self.id > 0 && self.verify()
    }

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

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventCheckpoint {
    pub id: u64,
    pub hash: String,
}

impl EventCheckpoint {
    fn of(event: &DeliveryEvent) -> Self {
        Self {
            id: event.id,
            hash: event.hash.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct EventExport {
    pub format: &'static str,
    pub issuer: String,
    pub tenant: String,
    pub start: EventCheckpoint,
    pub end: EventCheckpoint,
    pub terminal: EventCheckpoint,
    pub complete: bool,
    pub events: Vec<DeliveryEvent>,
}

const EVENT_COLUMNS: &str =
    "id,tenant,grant_id,kind,created_at,payload,previous_hash,hash,issuer,signature";
pub const MAX_EVENT_PAGE_BYTES: usize = 16 * 1024 * 1024;

fn invalid_chain() -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure("invalid or incomplete delivery event chain".into())
}

fn event_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<DeliveryEvent> {
    for column in [1, 2, 3, 5, 6, 7, 8, 9] {
        if matches!(row.get_ref(column)?, rusqlite::types::ValueRef::Text(bytes) if bytes.len() > MAX_EVENT_PAGE_BYTES)
        {
            return Err(invalid_chain());
        }
    }
    let payload: String = row.get(5)?;
    Ok(DeliveryEvent {
        id: row.get::<_, i64>(0)? as u64,
        tenant: row.get(1)?,
        grant_id: row.get(2)?,
        kind: row.get(3)?,
        created_at: row.get::<_, i64>(4)? as u64,
        payload: serde_json::from_str(&payload).map_err(|_| invalid_chain())?,
        previous_hash: row.get(6)?,
        hash: row.get(7)?,
        issuer: row.get(8)?,
        signature: row.get(9)?,
    })
}

fn predecessor(
    connection: &Connection,
    issuer: &str,
    tenant: &str,
    through: u64,
) -> rusqlite::Result<EventCheckpoint> {
    let event = connection.query_row(&format!("SELECT {EVENT_COLUMNS} FROM delivery_events WHERE tenant=?1 AND id<=?2 ORDER BY id DESC LIMIT 1"), params![tenant, through as i64], event_row).optional()?;
    match event {
        Some(event) if event.verify_for(issuer, tenant) => Ok(EventCheckpoint::of(&event)),
        Some(_) => Err(invalid_chain()),
        None => Ok(EventCheckpoint::default()),
    }
}

fn require_checkpoint(
    connection: &Connection,
    issuer: &str,
    tenant: &str,
    checkpoint: &EventCheckpoint,
) -> rusqlite::Result<()> {
    if checkpoint.id > i64::MAX as u64
        || predecessor(connection, issuer, tenant, checkpoint.id)? != *checkpoint
    {
        return Err(invalid_chain());
    }
    Ok(())
}

fn event_page(
    connection: &Connection,
    issuer: &str,
    tenant: &str,
    start: &EventCheckpoint,
    through: u64,
    limit: usize,
    byte_budget: usize,
) -> rusqlite::Result<Vec<DeliveryEvent>> {
    let mut query = connection.prepare(&format!("SELECT {EVENT_COLUMNS} FROM delivery_events WHERE tenant=?1 AND id>?2 AND id<=?3 ORDER BY id LIMIT ?4"))?;
    let rows = query.query_map(
        params![
            tenant,
            start.id as i64,
            through as i64,
            limit.min(100) as i64
        ],
        event_row,
    )?;
    let mut previous = start.clone();
    let mut events = vec![];
    let mut bytes = 0;
    for row in rows {
        let event = row?;
        if !event.verify_for(issuer, tenant)
            || event.id <= previous.id
            || event.previous_hash != previous.hash
        {
            return Err(invalid_chain());
        }
        bytes += serde_json::to_vec(&event)
            .map_err(|_| invalid_chain())?
            .len()
            + 1;
        if bytes > byte_budget {
            if events.is_empty() {
                return Err(invalid_chain());
            }
            break;
        }
        previous = EventCheckpoint::of(&event);
        events.push(event);
    }
    Ok(events)
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
            if after > i64::MAX as u64 {
                return Err(invalid_chain());
            }
            let start = predecessor(connection, &self.event_signer.public_hex, tenant, after)?;
            event_page(
                connection,
                &self.event_signer.public_hex,
                tenant,
                &start,
                i64::MAX as u64,
                limit,
                MAX_EVENT_PAGE_BYTES - 128,
            )
        })
    }

    pub fn delivery_event_export(
        &self,
        tenant: &str,
        start: EventCheckpoint,
        terminal: Option<EventCheckpoint>,
        limit: usize,
    ) -> Result<EventExport, String> {
        self.with(|connection| {
            let issuer = &self.event_signer.public_hex;
            if !(1..=100).contains(&limit) {
                return Err(invalid_chain());
            }
            require_checkpoint(connection, issuer, tenant, &start)?;
            let terminal = match terminal {
                Some(terminal) => {
                    require_checkpoint(connection, issuer, tenant, &terminal)?;
                    terminal
                }
                None => predecessor(connection, issuer, tenant, i64::MAX as u64)?,
            };
            if start.id > terminal.id {
                return Err(invalid_chain());
            }
            let mut export = EventExport {
                format: "votport-delivery-events-v1",
                issuer: issuer.clone(),
                tenant: tenant.into(),
                start,
                end: terminal.clone(),
                terminal,
                complete: false,
                events: vec![],
            };
            let envelope_bytes = serde_json::to_vec(&export)
                .map_err(|_| invalid_chain())?
                .len();
            let budget = MAX_EVENT_PAGE_BYTES
                .checked_sub(envelope_bytes)
                .ok_or_else(invalid_chain)?;
            export.events = event_page(
                connection,
                issuer,
                tenant,
                &export.start,
                export.terminal.id,
                limit,
                budget,
            )?;
            export.end = export
                .events
                .last()
                .map_or_else(|| export.start.clone(), EventCheckpoint::of);
            export.complete = export.end == export.terminal;
            if !export.complete && export.events.is_empty() {
                return Err(invalid_chain());
            }
            Ok(export)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn append(store: &Store, tenant: &str, index: usize) {
        let mut connection = store.connection.lock().unwrap();
        let tx = connection.transaction().unwrap();
        delivery_event(
            &tx,
            &store.event_signer,
            tenant,
            "",
            "fixture",
            &serde_json::json!({"index":index}),
            1,
        )
        .unwrap();
        tx.commit().unwrap();
    }

    #[test]
    fn delivery_events_reject_tampering_before_returning_rows() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        append(&store, "", 1);
        store
            .with(|c| c.execute("UPDATE delivery_events SET payload='{}'", []))
            .unwrap();
        assert!(store.delivery_events("", 0, 100).is_err());
    }

    #[test]
    fn event_exports_keep_checkpoints_across_pages_append_and_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        {
            let mut connection = store.connection.lock().unwrap();
            let tx = connection.transaction().unwrap();
            for index in 0..205 {
                for tenant in ["tenant", "other"] {
                    delivery_event(
                        &tx,
                        &store.event_signer,
                        tenant,
                        "",
                        "fixture",
                        &serde_json::json!({"index":index}),
                        1,
                    )
                    .unwrap();
                }
            }
            tx.commit().unwrap();
        }
        let first = store
            .delivery_event_export("tenant", EventCheckpoint::default(), None, 100)
            .unwrap();
        assert_eq!(store.delivery_events("tenant", 2, 1).unwrap()[0].id, 3);
        assert_eq!(store.delivery_events("tenant", 4, 1).unwrap()[0].id, 5);
        assert_eq!(first.events.len(), 100);
        assert!(!first.complete);
        assert!(first
            .events
            .windows(2)
            .all(|pair| pair[1].id == pair[0].id + 2));
        assert!(store
            .delivery_event_export(
                "other",
                first.end.clone(),
                Some(first.terminal.clone()),
                100
            )
            .is_err());
        append(&store, "tenant", 206);
        drop(store);
        let store = Store::open(directory.path()).unwrap();
        let second = store
            .delivery_event_export("tenant", first.end, Some(first.terminal.clone()), 100)
            .unwrap();
        assert_eq!(second.events.len(), 100);
        assert!(!second.complete);
        let last = store
            .delivery_event_export("tenant", second.end, Some(first.terminal.clone()), 100)
            .unwrap();
        assert_eq!(last.events.len(), 5);
        assert_eq!(last.end, first.terminal);
        assert!(last.complete);
        let empty = store
            .delivery_event_export("tenant", last.end.clone(), Some(last.terminal.clone()), 100)
            .unwrap();
        assert!(empty.complete && empty.events.is_empty());
        let next = store
            .delivery_event_export("tenant", last.end, None, 100)
            .unwrap();
        assert_eq!(next.events.len(), 1);
        assert!(next.complete);
    }

    #[test]
    fn event_exports_reject_deleted_interior_and_retained_tail() {
        for removed in [2, 3, 0] {
            let directory = tempfile::tempdir().unwrap();
            let store = Store::open(directory.path()).unwrap();
            for index in 1..=3 {
                append(&store, "", index);
            }
            let first = store
                .delivery_event_export("", EventCheckpoint::default(), None, 1)
                .unwrap();
            store
                .with(|c| c.execute("DELETE FROM delivery_events WHERE id=?1 OR ?1=0", [removed]))
                .unwrap();
            drop(store);
            let store = Store::open(directory.path()).unwrap();
            assert!(store
                .delivery_event_export("", first.end, Some(first.terminal.clone()), 100)
                .is_err());
            assert!(store
                .delivery_event_export("", EventCheckpoint::default(), Some(first.terminal), 100)
                .is_err());
            if removed != 2 {
                // A new observation alone cannot reveal a previously removed valid tail.
                assert!(store
                    .delivery_event_export("", EventCheckpoint::default(), None, 100)
                    .is_ok());
            } else {
                assert!(store.delivery_events("", 1, 100).is_err());
            }
        }
    }

    #[test]
    fn event_checkpoints_reject_mismatch_and_invalid_ranges() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let empty = store
            .delivery_event_export("", EventCheckpoint::default(), None, 100)
            .unwrap();
        assert!(empty.complete && empty.events.is_empty());
        append(&store, "", 1);
        append(&store, "other", 2);
        append(&store, "", 3);
        let all = store
            .delivery_event_export("", EventCheckpoint::default(), None, 100)
            .unwrap();
        for point in [
            EventCheckpoint {
                id: 0,
                hash: "not-genesis".into(),
            },
            EventCheckpoint {
                id: 1,
                hash: "0".repeat(64),
            },
            EventCheckpoint {
                id: 2,
                hash: all.events[0].hash.clone(),
            },
            EventCheckpoint {
                id: u64::MAX,
                hash: all.terminal.hash.clone(),
            },
        ] {
            assert!(store
                .delivery_event_export("", point.clone(), None, 100)
                .is_err());
            assert!(store
                .delivery_event_export("", EventCheckpoint::default(), Some(point), 100)
                .is_err());
        }
        assert!(store
            .delivery_event_export(
                "",
                all.terminal,
                Some(EventCheckpoint::of(&all.events[0])),
                100
            )
            .is_err());
        for limit in [0, 101] {
            assert!(store
                .delivery_event_export("", EventCheckpoint::default(), None, limit)
                .is_err());
        }
        assert!(store.delivery_events("", u64::MAX, 1).is_err());
    }

    #[test]
    fn ordinary_appends_do_not_authenticate_a_corrupt_predecessor() {
        for foreign_key in [true, false] {
            let directory = tempfile::tempdir().unwrap();
            let foreign = tempfile::tempdir().unwrap();
            let store = Store::open(directory.path()).unwrap();
            append(&store, "", 0);
            let trusted = store
                .delivery_event_export("", EventCheckpoint::default(), None, 100)
                .unwrap()
                .terminal;
            let signer = crate::receipt::ReceiptSigner::load_or_create(foreign.path()).unwrap();
            {
                let mut connection = store.connection.lock().unwrap();
                let tx = connection.transaction().unwrap();
                delivery_event(
                    &tx,
                    if foreign_key {
                        &signer
                    } else {
                        &store.event_signer
                    },
                    "",
                    "",
                    "fixture",
                    &serde_json::json!({"original": true}),
                    1,
                )
                .unwrap();
                if !foreign_key {
                    tx.execute(
                        "UPDATE delivery_events SET payload='{}' WHERE id=?1",
                        [tx.last_insert_rowid()],
                    )
                    .unwrap();
                }
                tx.commit().unwrap();
            }
            assert!(store.delivery_events("", trusted.id, 100).is_err());
            let project = store
                .save_delivery_project("", "local", crate::workflow::tests::project())
                .unwrap();
            let now = now_unix();
            let mut request = crate::workflow::tests::request();
            request.deadline = Some(now + 60);
            let job = store
                .enqueue_delivery_job("", "local", 1, None, project, request)
                .unwrap();
            assert_eq!(
                store.claim_delivery_job("worker", now).unwrap().unwrap().id,
                job.id
            );
            store.escalate_delivery_jobs(now + 120).unwrap();
            let last = store
                .with(|c| {
                    c.query_row(
                        &format!(
                            "SELECT {EVENT_COLUMNS} FROM delivery_events ORDER BY id DESC LIMIT 1"
                        ),
                        [],
                        event_row,
                    )
                })
                .unwrap();
            assert_eq!(last.kind, "delivery_deadline_missed");
            assert!(last.verify_for(&store.event_signer.public_hex, ""));
            let terminal = EventCheckpoint::of(&last);
            for start in [EventCheckpoint::default(), trusted] {
                assert!(store
                    .delivery_event_export("", start, Some(terminal.clone()), 100)
                    .is_err());
            }
        }
    }

    #[test]
    fn event_append_rollback_leaves_previous_checkpoint_unchanged() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        append(&store, "", 1);
        let before = store
            .delivery_event_export("", EventCheckpoint::default(), None, 100)
            .unwrap();
        {
            let mut connection = store.connection.lock().unwrap();
            let tx = connection.transaction().unwrap();
            delivery_event(
                &tx,
                &store.event_signer,
                "",
                "",
                "fixture",
                &serde_json::json!({}),
                1,
            )
            .unwrap();
        }
        drop(store);
        let store = Store::open(directory.path()).unwrap();
        let after = store
            .delivery_event_export("", EventCheckpoint::default(), Some(before.terminal), 100)
            .unwrap();
        assert_eq!(after.events.len(), 1);
        append(&store, "", 2);
        assert_eq!(store.delivery_events("", 0, 100).unwrap().len(), 2);
    }

    #[test]
    fn event_export_bounds_encoded_page_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        {
            let mut connection = store.connection.lock().unwrap();
            let tx = connection.transaction().unwrap();
            let payload = serde_json::json!({"text":"x".repeat(MAX_EVENT_PAGE_BYTES / 2)});
            for _ in 0..2 {
                delivery_event(&tx, &store.event_signer, "", "", "fixture", &payload, 1).unwrap();
            }
            tx.commit().unwrap();
        }
        let first = store
            .delivery_event_export("", EventCheckpoint::default(), None, 100)
            .unwrap();
        assert_eq!(first.events.len(), 1);
        assert!(serde_json::to_vec(&first).unwrap().len() <= MAX_EVENT_PAGE_BYTES);
        let last = store
            .delivery_event_export("", first.end, Some(first.terminal), 100)
            .unwrap();
        assert!(last.complete);
        assert_eq!(last.events.len(), 1);
        assert!(serde_json::to_vec(&last).unwrap().len() <= MAX_EVENT_PAGE_BYTES);
    }
}
