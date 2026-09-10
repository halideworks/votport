use super::*;
use crate::route_protocol::{RouteReceipt, RouteRevocation, RouteRevoked, SignedRoute};
use rusqlite::params;

pub(super) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS inbound_routes(id TEXT PRIMARY KEY, tenant TEXT NOT NULL, link_id TEXT NOT NULL, issuer TEXT NOT NULL, operation_id TEXT NOT NULL, source TEXT NOT NULL, ancestry TEXT NOT NULL, session_id TEXT UNIQUE, transport TEXT, upload_id TEXT UNIQUE, receipt TEXT, revoked_at INTEGER, created_at INTEGER NOT NULL, UNIQUE(link_id,issuer,operation_id));
CREATE TABLE IF NOT EXISTS outbound_routes(job_id TEXT NOT NULL, destination_id TEXT NOT NULL, origin TEXT NOT NULL, route_id TEXT NOT NULL, peer_key TEXT NOT NULL, source TEXT NOT NULL, next_attempt INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0, revocation TEXT, ack TEXT, PRIMARY KEY(job_id,destination_id));
CREATE TABLE IF NOT EXISTS route_uploads(route_id TEXT NOT NULL, upload_id TEXT PRIMARY KEY, partial INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS inbound_routes_link ON inbound_routes(tenant,link_id);
";

#[derive(Clone, Debug)]
pub struct InboundRoute {
    pub id: String,
    pub tenant: String,
    pub link_id: String,
    pub source: SignedRoute,
    pub ancestry: Vec<RouteReceipt>,
    pub session_id: Option<String>,
    pub transport: Option<String>,
    pub receipt: Option<RouteReceipt>,
    pub revoked_at: Option<u64>,
}

fn row_route(row: &rusqlite::Row<'_>) -> rusqlite::Result<InboundRoute> {
    let receipt: Option<String> = row.get(7)?;
    Ok(InboundRoute {
        id: row.get(0)?,
        tenant: row.get(1)?,
        link_id: row.get(2)?,
        source: parse_json(&row.get::<_, String>(3)?, 3)?,
        ancestry: parse_json(&row.get::<_, String>(9)?, 9)?,
        session_id: row.get(4)?,
        transport: row.get(5)?,
        receipt: receipt.map(|text| parse_json(&text, 7)).transpose()?,
        revoked_at: row.get::<_, Option<i64>>(8)?.map(|value| value as u64),
    })
}

const COLUMNS: &str =
    "id,tenant,link_id,source,session_id,transport,upload_id,receipt,revoked_at,ancestry";

impl Store {
    pub fn route_progress(
        &self,
        job: &crate::workflow::Job,
        destination: &str,
        moved: u64,
    ) -> Result<(), String> {
        self.with(|connection| connection.execute("UPDATE delivery_jobs SET document=json_set(document,?3,json(?4)) WHERE id=?1 AND state='exporting' AND json_extract(document,'$.attempts')=?2",params![job.id,job.attempts as i64,format!("$.checks.destinations.{destination}"),serde_json::json!({"state":"sending","transferred":moved}).to_string()])).map(|_|())
    }

    pub fn bind_outbound_route(
        &self,
        job: &crate::workflow::Job,
        destination: &str,
        origin: &str,
        route: &str,
        peer_key: &str,
        source: &SignedRoute,
    ) -> Result<(), String> {
        let source = serde_json::to_string(source).map_err(|e| e.to_string())?;
        let mut connection = self.connection.lock().expect("store poisoned");
        let tx = connection.transaction().map_err(|e| e.to_string())?;
        tx.execute("INSERT OR IGNORE INTO outbound_routes(job_id,destination_id,origin,route_id,peer_key,source) VALUES (?1,?2,?3,?4,?5,?6)",params![job.id,destination,origin,route,peer_key,source]).map_err(|e|e.to_string())?;
        let same:bool = tx.query_row("SELECT origin=?3 AND route_id=?4 AND peer_key=?5 AND source=?6 FROM outbound_routes WHERE job_id=?1 AND destination_id=?2",params![job.id,destination,origin,route,peer_key,source],|row|row.get(0)).map_err(|e|e.to_string())?;
        if !same {
            return Err("peer identity or route changed; delivery remains held".into());
        }
        tx.commit().map_err(|e| e.to_string())
    }

    pub fn record_route_receipt(
        &self,
        job: &crate::workflow::Job,
        destination: &str,
        receipt: &RouteReceipt,
    ) -> Result<(), String> {
        self.with(|connection| connection.execute("UPDATE delivery_jobs SET document=json_set(document,?3,json(?4)) WHERE id=?1 AND state='exporting' AND json_extract(document,'$.attempts')=?2",params![job.id,job.attempts as i64,format!("$.checks.route_receipts.{destination}"),serde_json::to_string(receipt).expect("route receipt serializes")]))
            .and_then(|count|if count == 1 { Ok(()) } else { Err("delivery changed while recording its peer receipt".into()) })
    }

    pub fn inbound_route(&self, id: &str) -> Result<Option<InboundRoute>, String> {
        self.with(|connection| {
            connection
                .prepare_cached(&format!("SELECT {COLUMNS} FROM inbound_routes WHERE id=?1"))?
                .query_row([id], row_route)
                .optional()
        })
    }

    pub fn receive_route(
        &self,
        tenant: &str,
        link_id: &str,
        source: &SignedRoute,
        ancestry: &[RouteReceipt],
    ) -> Result<InboundRoute, String> {
        if !source.admits(&self.event_signer.public_hex)
            || !crate::route_protocol::verify_ancestry(source, ancestry)
        {
            return Err("invalid route evidence, forwarding loop or hop limit".into());
        }
        let mut connection = self.connection.lock().expect("store poisoned");
        let tx = connection.transaction().map_err(|e| e.to_string())?;
        let usable: bool = tx.query_row("SELECT active=1 AND (expires_at IS NULL OR expires_at>?3) FROM links WHERE tenant=?1 AND id=?2",params![tenant,link_id,now_unix() as i64],|row|row.get(0)).optional().map_err(|e|e.to_string())?.ok_or("receive request missing")?;
        let previous = tx.query_row(&format!("SELECT {COLUMNS} FROM inbound_routes WHERE link_id=?1 AND issuer=?2 AND operation_id=?3"),params![link_id,source.document.issuer,source.document.operation_id],row_route).optional().map_err(|e|e.to_string())?;
        if let Some(previous) = previous {
            return if &previous.source == source && previous.ancestry == ancestry {
                Ok(previous)
            } else {
                Err("route operation already names a different delivery".into())
            };
        }
        if !usable {
            return Err("request is no longer accepting routes".into());
        }
        let pending:i64 = tx.query_row("SELECT COUNT(*) FROM inbound_routes r JOIN links l ON l.id=r.link_id WHERE r.tenant=?1 AND r.receipt IS NULL AND r.revoked_at IS NULL AND l.active=1 AND (l.expires_at IS NULL OR l.expires_at>?2)",params![tenant,now_unix() as i64],|row|row.get(0)).map_err(|e|e.to_string())?;
        if pending >= 1000 {
            return Err("incoming route limit reached".into());
        }
        let id = crate::auth::random_token();
        tx.execute("INSERT INTO inbound_routes(id,tenant,link_id,issuer,operation_id,source,created_at,ancestry) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",params![id,tenant,link_id,source.document.issuer,source.document.operation_id,serde_json::to_string(source).map_err(|e|e.to_string())?,now_unix() as i64,serde_json::to_string(ancestry).expect("ancestry serializes")]).map_err(|e|e.to_string())?;
        evidence::delivery_event(&tx,&self.event_signer,tenant,"","route_admitted",&serde_json::json!({"source":source.document.issuer,"operation_id":source.document.operation_id,"manifest":source.document.manifest}),now_unix()).map_err(|e|e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(InboundRoute {
            id,
            tenant: tenant.into(),
            link_id: link_id.into(),
            source: source.clone(),
            ancestry: ancestry.to_vec(),
            session_id: None,
            transport: None,
            receipt: None,
            revoked_at: None,
        })
    }

    pub fn bind_route_session(
        &self,
        route: &InboundRoute,
        session: &str,
        transport: &str,
    ) -> Result<(), String> {
        self.with(|connection| connection.execute("UPDATE inbound_routes SET session_id=?2,transport=?3 WHERE id=?1 AND link_id=?4 AND session_id IS ?5 AND receipt IS NULL AND revoked_at IS NULL",params![route.id,session,transport,route.link_id,route.session_id]))
            .and_then(|count| if count == 1 { Ok(()) } else { Err("route session changed or route was revoked".into()) })
    }

    pub fn check_route_manifest(
        &self,
        session: &str,
        manifest: impl FnOnce() -> String,
    ) -> Result<(), String> {
        self.with(|connection| {
            connection
                .query_row(
                    "SELECT source,revoked_at FROM inbound_routes WHERE session_id=?1",
                    [session],
                    |row| {
                        Ok((
                            parse_json::<SignedRoute>(&row.get::<_, String>(0)?, 0)?,
                            row.get::<_, Option<i64>>(1)?,
                        ))
                    },
                )
                .optional()
        })?
        .map_or(Ok(()), |(source, revoked)| {
            if revoked.is_none() && source.document.manifest == manifest() {
                Ok(())
            } else {
                Err("route manifest does not match its source evidence or route was revoked".into())
            }
        })
    }

    pub fn received_route_receipt(
        &self,
        tenant: &str,
        upload: &str,
    ) -> Result<Option<RouteReceipt>, String> {
        self.with(|connection| connection.query_row("SELECT receipt FROM inbound_routes WHERE tenant=?1 AND upload_id=?2 AND receipt IS NOT NULL",params![tenant,upload],|row| parse_json(&row.get::<_,String>(0)?,0)).optional())
    }

    pub fn received_route(
        &self,
        tenant: &str,
        upload: &str,
    ) -> Result<Option<InboundRoute>, String> {
        self.with(|connection| {
            connection
                .query_row(
                    &format!(
                        "SELECT {COLUMNS} FROM inbound_routes WHERE tenant=?1 AND upload_id=?2"
                    ),
                    params![tenant, upload],
                    row_route,
                )
                .optional()
        })
    }

    pub fn received_route_statuses(
        &self,
        tenant: &str,
        link: &str,
    ) -> Result<std::collections::BTreeMap<String, serde_json::Value>, String> {
        self.with(|connection| {
            let mut query = connection.prepare_cached("SELECT upload_id,issuer,revoked_at FROM inbound_routes WHERE tenant=?1 AND link_id=?2 AND receipt IS NOT NULL")?;
            let rows = query.query_map(params![tenant,link],|row| Ok((row.get::<_,String>(0)?,serde_json::json!({"issuer":row.get::<_,String>(1)?,"revoked_at":row.get::<_,Option<i64>>(2)?}))))?;
            rows.collect()
        })
    }

    pub fn revoke_inbound_route(
        &self,
        id: &str,
        request: &RouteRevocation,
    ) -> Result<Option<InboundRoute>, String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let tx = connection.transaction().map_err(|e| e.to_string())?;
        use sha2::{Digest, Sha256};
        if request.document.receiver != self.event_signer.public_hex
            || !request.verify()
            || request.document.route_digest != hex::encode(Sha256::digest(id.as_bytes()))
        {
            return Err("invalid route revocation proof".into());
        }
        let route = tx
            .query_row(
                &format!("SELECT {COLUMNS} FROM inbound_routes WHERE id=?1"),
                [id],
                row_route,
            )
            .optional()
            .map_err(|e| e.to_string())?;
        let Some(mut route) = route else {
            return Ok(None);
        };
        if request.document.source != route.source {
            return Err("invalid route revocation proof".into());
        }
        if route.revoked_at.is_some() {
            return Ok(Some(route));
        }
        let now = now_unix();
        tx.execute(
            "UPDATE inbound_routes SET revoked_at=?2 WHERE id=?1",
            params![id, now as i64],
        )
        .map_err(|e| e.to_string())?;
        tx.execute("UPDATE outbound_grants SET revoked_at=COALESCE(revoked_at,?2) WHERE upload_id IN (SELECT upload_id FROM route_uploads WHERE route_id=?1) OR id IN (SELECT j.id FROM delivery_jobs j JOIN route_uploads u ON u.upload_id=json_extract(j.document,'$.received.upload_id') WHERE u.route_id=?1)",params![id,now as i64]).map_err(|e|e.to_string())?;
        tx.execute("UPDATE delivery_jobs SET state='cancelled',document=json_set(document,'$.state','cancelled','$.updated_at',?2,'$.error','Source port revoked this route') WHERE json_extract(document,'$.received.upload_id') IN (SELECT upload_id FROM route_uploads WHERE route_id=?1)",params![id,now as i64]).map_err(|e|e.to_string())?;
        evidence::delivery_event(&tx,&self.event_signer,&route.tenant,"","route_revoked",&serde_json::json!({"source":route.source.document.issuer,"operation_id":route.source.document.operation_id,"manifest":route.source.document.manifest}),now).map_err(|e|e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        route.revoked_at = Some(now);
        Ok(Some(route))
    }
}

pub(super) fn complete_route(
    connection: &Connection,
    signer: &crate::receipt::ReceiptSigner,
    tenant: &str,
    link_id: &str,
    session: &str,
    upload: &UploadRecord,
) -> Result<(), String> {
    let route = connection
        .query_row(
            &format!("SELECT {COLUMNS} FROM inbound_routes WHERE session_id=?1"),
            [session],
            row_route,
        )
        .optional()
        .map_err(|e| e.to_string())?;
    let Some(route) = route else {
        return Ok(());
    };
    if route.tenant != tenant || route.link_id != link_id {
        return Err("route belongs to a different receive request".into());
    }
    connection
        .execute(
            "INSERT INTO route_uploads(route_id,upload_id,partial) VALUES (?1,?2,?3)",
            params![route.id, upload.id, upload.partial],
        )
        .map_err(|e| e.to_string())?;
    if upload.partial {
        return Ok(());
    }
    let manifest = crate::route_protocol::manifest_digest(upload.files.iter().map(|file| {
        (
            file.path.as_str(),
            file.suite.as_str(),
            file.root.as_str(),
            file.bytes,
        )
    }));
    if route.tenant != tenant
        || route.link_id != link_id
        || route.revoked_at.is_some()
        || route.receipt.is_some()
        || manifest != route.source.document.manifest
    {
        return Err(
            "incoming route is revoked, already complete or does not match its signed manifest"
                .into(),
        );
    }
    let receipt = signer.route_receipt(route.source, upload.id.clone(), upload.completed_at);
    connection
        .execute(
            "UPDATE inbound_routes SET upload_id=?2,receipt=?3 WHERE id=?1",
            params![
                route.id,
                upload.id,
                serde_json::to_string(&receipt).map_err(|e| e.to_string())?
            ],
        )
        .map_err(|e| e.to_string())?;
    evidence::delivery_event(
        connection,
        signer,
        tenant,
        "",
        "route_received",
        &serde_json::json!({"receipt":receipt}),
        upload.completed_at,
    )
    .map_err(|e| e.to_string())
}

pub(super) fn require_shareable(
    connection: &Connection,
    grant: &OutboundGrant,
) -> Result<(), String> {
    let blocked:bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM route_uploads u JOIN inbound_routes r ON r.id=u.route_id WHERE u.upload_id=?1 AND (u.partial=1 OR r.revoked_at IS NOT NULL))",[&grant.upload_id],|row|row.get(0)).map_err(|e|e.to_string())?;
    if blocked {
        Err("incoming route is incomplete or revoked".into())
    } else {
        Ok(())
    }
}

pub struct OutboundControl {
    pub job_id: String,
    pub destination: String,
    pub origin: String,
    pub route_id: String,
    pub request: RouteRevocation,
    pub attempts: u64,
}

impl Store {
    pub fn claim_route_revocation(&self, now: u64) -> Result<Option<OutboundControl>, String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let tx = connection.transaction().map_err(|e| e.to_string())?;
        let row = tx.query_row("SELECT r.job_id,r.destination_id,r.origin,r.route_id,r.source,r.peer_key,r.revocation,r.attempts FROM outbound_routes r LEFT JOIN delivery_jobs j ON j.id=r.job_id LEFT JOIN outbound_grants g ON g.id=r.job_id WHERE r.ack IS NULL AND r.next_attempt<=?1 AND (r.revocation IS NOT NULL OR j.state IN ('cancelled','retiring','retired') OR g.id IS NULL OR g.revoked_at IS NOT NULL OR g.expires_at<=?1) ORDER BY r.next_attempt,r.job_id,r.destination_id LIMIT 1",[now as i64],|row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,String>(3)?,parse_json::<SignedRoute>(&row.get::<_,String>(4)?,4)?,row.get::<_,String>(5)?,row.get::<_,Option<String>>(6)?,row.get::<_,i64>(7)?))).optional().map_err(|e|e.to_string())?;
        let Some((job_id, destination, origin, route_id, source, receiver, request, attempts)) =
            row
        else {
            return Ok(None);
        };
        let request = request
            .map(|text| serde_json::from_str(&text).map_err(|e| e.to_string()))
            .transpose()?
            .unwrap_or_else(|| self.event_signer.revoke_route(source, receiver, &route_id));
        let attempts = (attempts as u64).saturating_add(1);
        tx.execute("UPDATE outbound_routes SET revocation=?3,next_attempt=?4,attempts=?5 WHERE job_id=?1 AND destination_id=?2",params![job_id,destination,serde_json::to_string(&request).expect("revocation serializes"),now.saturating_add(300) as i64,attempts as i64]).map_err(|e|e.to_string())?;
        tx.execute(
            "UPDATE delivery_jobs SET document=json_set(document,?2,json(?3)) WHERE id=?1",
            params![
                job_id,
                format!("$.checks.route_revocations.{destination}"),
                serde_json::json!({"state":"pending","attempts":attempts}).to_string()
            ],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(Some(OutboundControl {
            job_id,
            destination,
            origin,
            route_id,
            request,
            attempts,
        }))
    }

    pub fn finish_route_revocation(
        &self,
        control: &OutboundControl,
        acknowledgement: Option<&RouteRevoked>,
        now: u64,
    ) -> Result<(), String> {
        if acknowledgement.is_some_and(|ack| !ack.verify(&control.request)) {
            return Err("invalid destination revocation acknowledgement".into());
        }
        let mut connection = self.connection.lock().expect("store poisoned");
        let tx = connection.transaction().map_err(|e| e.to_string())?;
        let next = now.saturating_add((30 * (1u64 << control.attempts.min(7))).min(3600));
        let changed = tx.execute("UPDATE outbound_routes SET ack=?3,next_attempt=?4 WHERE job_id=?1 AND destination_id=?2 AND ack IS NULL AND attempts=?5",params![control.job_id,control.destination,acknowledgement.map(|ack|serde_json::to_string(ack).expect("ack serializes")),next as i64,control.attempts as i64]).map_err(|e|e.to_string())?;
        if changed == 0 {
            return Ok(());
        }
        let status = serde_json::json!({"state":if acknowledgement.is_some() { "acknowledged" } else { "pending" },"attempts":control.attempts,"retry_at":if acknowledgement.is_none() { Some(next) } else { None },"acknowledgement":acknowledgement});
        tx.execute(
            "UPDATE delivery_jobs SET document=json_set(document,?2,json(?3)) WHERE id=?1",
            params![
                control.job_id,
                format!("$.checks.route_revocations.{}", control.destination),
                status.to_string()
            ],
        )
        .map_err(|e| e.to_string())?;
        let tenant: Option<String> = tx
            .query_row(
                "SELECT tenant FROM delivery_jobs WHERE id=?1",
                [&control.job_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        if let Some(tenant) = tenant {
            evidence::delivery_event(
                &tx,
                &self.event_signer,
                &tenant,
                &control.job_id,
                if acknowledgement.is_some() {
                    "route_revocation_acknowledged"
                } else {
                    "route_revocation_pending"
                },
                &serde_json::json!({"destination":control.destination,"status":status}),
                now,
            )
            .map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())
    }
}
