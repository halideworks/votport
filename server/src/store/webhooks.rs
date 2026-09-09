use super::*;
use rusqlite::params;

pub(super) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS delivery_webhooks(tenant TEXT PRIMARY KEY,url TEXT NOT NULL,secret TEXT NOT NULL,revision INTEGER NOT NULL,enabled INTEGER NOT NULL,cursor INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS delivery_webhook_attempts(id INTEGER PRIMARY KEY AUTOINCREMENT,tenant TEXT NOT NULL,event_id INTEGER NOT NULL,revision INTEGER NOT NULL,status TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,next_try INTEGER NOT NULL,error TEXT,UNIQUE(tenant,event_id,revision));
CREATE INDEX IF NOT EXISTS delivery_webhook_due ON delivery_webhook_attempts(status,next_try);
";

#[derive(Clone, Debug, Serialize)]
pub struct DeliveryWebhook {
    pub tenant: String,
    pub url: String,
    #[serde(skip)]
    pub secret: String,
    pub revision: u64,
    pub enabled: bool,
    pub cursor: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct WebhookAttempt {
    pub id: u64,
    pub tenant: String,
    pub event_id: u64,
    pub revision: u64,
    pub status: String,
    pub attempts: u64,
    pub next_try: u64,
    pub error: Option<String>,
}

fn hook_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<DeliveryWebhook> {
    Ok(DeliveryWebhook {
        tenant: row.get(0)?,
        url: row.get(1)?,
        secret: row.get(2)?,
        revision: row.get::<_, i64>(3)? as u64,
        enabled: row.get(4)?,
        cursor: row.get::<_, i64>(5)? as u64,
    })
}

fn attempt_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<WebhookAttempt> {
    Ok(WebhookAttempt {
        id: row.get::<_, i64>(7)? as u64,
        tenant: row.get(0)?,
        event_id: row.get::<_, i64>(1)? as u64,
        revision: row.get::<_, i64>(2)? as u64,
        status: row.get(3)?,
        attempts: row.get::<_, i64>(4)? as u64,
        next_try: row.get::<_, i64>(5)? as u64,
        error: row.get(6)?,
    })
}

impl Store {
    pub fn delivery_webhook(&self, tenant: &str) -> Result<Option<DeliveryWebhook>, String> {
        self.with(|connection| connection.query_row("SELECT tenant,url,secret,revision,enabled,cursor FROM delivery_webhooks WHERE tenant=?1", [tenant], hook_row).optional())
    }

    pub fn save_delivery_webhook(
        &self,
        tenant: &str,
        actor: &str,
        url: &str,
        enabled: bool,
        revision: u64,
    ) -> Result<DeliveryWebhook, String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let tx = connection.transaction().map_err(|e| e.to_string())?;
        workflows::ensure_tenant(&tx, tenant)?;
        let previous: Option<DeliveryWebhook> = tx.query_row("SELECT tenant,url,secret,revision,enabled,cursor FROM delivery_webhooks WHERE tenant=?1",[tenant],hook_row).optional().map_err(|e| e.to_string())?;
        if previous.as_ref().map_or(0, |hook| hook.revision) != revision {
            return Err("webhook changed; reload before saving".into());
        }
        let cursor: i64 = tx
            .query_row(
                "SELECT COALESCE(MAX(id),0) FROM delivery_events WHERE tenant=?1",
                [tenant],
                |row| row.get(0),
            )
            .map_err(|e| e.to_string())?;
        let secret = format!(
            "{}{}",
            crate::auth::random_token(),
            crate::auth::random_token()
        );
        let hook = DeliveryWebhook {
            tenant: tenant.into(),
            url: url.into(),
            secret,
            enabled,
            revision: revision + 1,
            cursor: cursor as u64,
        };
        tx.execute("UPDATE delivery_webhook_attempts SET status='superseded',error='webhook configuration changed' WHERE tenant=?1 AND status='pending'",[tenant]).map_err(|e| e.to_string())?;
        tx.execute("INSERT INTO delivery_webhooks(tenant,url,secret,revision,enabled,cursor) VALUES (?1,?2,?3,?4,?5,?6) ON CONFLICT(tenant) DO UPDATE SET url=excluded.url,secret=excluded.secret,revision=excluded.revision,enabled=excluded.enabled,cursor=excluded.cursor",params![tenant,url,hook.secret,hook.revision as i64,enabled,cursor]).map_err(|e| e.to_string())?;
        evidence::delivery_event(
            &tx,
            &self.event_signer,
            tenant,
            "",
            "webhook_changed",
            &serde_json::json!({"actor": actor,"revision": hook.revision,"enabled": enabled}),
            now_unix(),
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(hook)
    }

    pub fn queue_delivery_webhooks(&self, now: u64) -> Result<(), String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let tx = connection.transaction().map_err(|e| e.to_string())?;
        let hooks = {
            let mut query = tx.prepare("SELECT tenant,url,secret,revision,enabled,cursor FROM delivery_webhooks WHERE enabled=1").map_err(|e| e.to_string())?;
            let rows = query.query_map([], hook_row).map_err(|e| e.to_string())?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|e| e.to_string())?
        };
        for hook in hooks {
            tx.execute("INSERT OR IGNORE INTO delivery_webhook_attempts(tenant,event_id,revision,status,next_try) SELECT tenant,id,?3,'pending',?4 FROM delivery_events WHERE tenant=?1 AND id>?2 ORDER BY id LIMIT 100",params![hook.tenant,hook.cursor as i64,hook.revision as i64,now as i64]).map_err(|e| e.to_string())?;
            tx.execute("UPDATE delivery_webhooks SET cursor=MAX(cursor,COALESCE((SELECT MAX(id) FROM (SELECT id FROM delivery_events WHERE tenant=?1 AND id>?2 ORDER BY id LIMIT 100)),0)) WHERE tenant=?1",params![hook.tenant,hook.cursor as i64]).map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())
    }

    pub fn due_delivery_webhooks(&self, now: u64) -> Result<Vec<WebhookAttempt>, String> {
        self.with(|connection| {
            let mut query = connection.prepare("SELECT a.tenant,a.event_id,a.revision,a.status,a.attempts,a.next_try,a.error,a.id FROM delivery_webhook_attempts a JOIN delivery_webhooks h ON h.tenant=a.tenant AND h.revision=a.revision WHERE h.enabled=1 AND a.status='pending' AND a.next_try<=?1 ORDER BY a.next_try,a.event_id LIMIT 16")?;
            let rows = query.query_map([now as i64],attempt_row)?; rows.collect()
        })
    }

    pub fn finish_delivery_webhook(
        &self,
        attempt: &WebhookAttempt,
        error: Option<&str>,
        now: u64,
    ) -> Result<(), String> {
        let count = attempt.attempts + 1;
        let status = if error.is_none() {
            "delivered"
        } else if count >= 12 {
            "dead"
        } else {
            "pending"
        };
        let next = now.saturating_add(webhook_retry_delay(count));
        self.with(|connection| connection.execute("UPDATE delivery_webhook_attempts SET status=?4,attempts=?5,next_try=?6,error=?7 WHERE tenant=?1 AND event_id=?2 AND revision=?3 AND status='pending' AND attempts=?8",params![attempt.tenant,attempt.event_id as i64,attempt.revision as i64,status,count as i64,next as i64,error,attempt.attempts as i64]).map(|_| ()))
    }

    pub fn delivery_webhook_attempts(
        &self,
        tenant: &str,
        after: u64,
        limit: usize,
    ) -> Result<Vec<WebhookAttempt>, String> {
        self.with(|connection| {
            let mut query = connection.prepare("SELECT tenant,event_id,revision,status,attempts,next_try,error,id FROM delivery_webhook_attempts WHERE tenant=?1 AND id>?2 ORDER BY id LIMIT ?3")?;
            let rows = query.query_map(params![tenant,after as i64,limit.min(100) as i64],attempt_row)?; rows.collect()
        })
    }

    pub fn replay_delivery_webhook(&self, tenant: &str, id: u64) -> Result<bool, String> {
        self.with(|connection| connection.execute("INSERT INTO delivery_webhook_attempts(tenant,event_id,revision,status,attempts,next_try) SELECT h.tenant,e.id,h.revision,'pending',0,?3 FROM delivery_webhooks h JOIN delivery_events e ON e.tenant=h.tenant WHERE h.tenant=?1 AND h.enabled=1 AND e.id=?2 ON CONFLICT(tenant,event_id,revision) DO UPDATE SET status='pending',attempts=0,next_try=excluded.next_try,error=NULL",params![tenant,id as i64,now_unix() as i64]).map(|count| count == 1))
    }

    pub fn escalate_delivery_jobs(&self, now: u64) -> Result<(), String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let tx = connection.transaction().map_err(|e| e.to_string())?;
        let due = {
            let mut query = tx.prepare("SELECT j.id,j.tenant FROM delivery_jobs j WHERE j.deadline<=?1 AND j.escalated=0 AND COALESCE(json_extract(j.document,'$.checks.retired_from'),j.state)<>'cancelled' AND (CASE WHEN json_array_length(json_extract(j.document,'$.request.recipients'))=0 THEN NOT EXISTS(SELECT 1 FROM delivery_evidence e WHERE e.grant_id=j.id AND e.kind='accepted') ELSE EXISTS(SELECT 1 FROM json_each(json_extract(j.document,'$.request.recipients')) r WHERE NOT EXISTS(SELECT 1 FROM delivery_evidence e WHERE e.grant_id=j.id AND e.kind='accepted' AND e.holder=r.value)) END) ORDER BY j.deadline LIMIT 100").map_err(|e| e.to_string())?;
            let rows = query
                .query_map([now as i64], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(|e| e.to_string())?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|e| e.to_string())?
        };
        for (id, tenant) in due {
            tx.execute("UPDATE delivery_jobs SET escalated=1 WHERE id=?1", [&id])
                .map_err(|e| e.to_string())?;
            evidence::delivery_event(
                &tx,
                &self.event_signer,
                &tenant,
                &id,
                "delivery_deadline_missed",
                &serde_json::json!({"job_id": id}),
                now,
            )
            .map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())
    }
}

pub fn webhook_retry_delay(attempt: u64) -> u64 {
    5u64.saturating_mul(1 << attempt.min(7)).min(600)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_ahead_preserves_queue_pages_and_rotations_preserve_attempt_pages() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let hook = store
            .save_delivery_webhook("", "admin", "http://localhost/hook", true, 0)
            .unwrap();
        {
            let mut connection = store.connection.lock().unwrap();
            let tx = connection.transaction().unwrap();
            for index in 0..205 {
                evidence::delivery_event(
                    &tx,
                    &store.event_signer,
                    "",
                    "",
                    "fixture",
                    &serde_json::json!({"index":index}),
                    1,
                )
                .unwrap();
            }
            tx.commit().unwrap();
        }
        let events = store.delivery_events("", 200, 100).unwrap();
        let last = events.last().unwrap().id;
        assert!(store.replay_delivery_webhook("", last).unwrap());
        store.queue_delivery_webhooks(1).unwrap();
        assert_eq!(store.delivery_webhook("").unwrap().unwrap().cursor, 100);
        for _ in 0..3 {
            store.queue_delivery_webhooks(1).unwrap();
        }
        let mut all = vec![];
        let mut after = 0;
        for _ in 0..4 {
            let page = store.delivery_webhook_attempts("", after, 100).unwrap();
            after = page.last().map_or(after, |row| row.id);
            all.extend(page);
        }
        assert_eq!(all.len() as u64, last);
        let ids: std::collections::HashSet<_> = all.iter().map(|row| row.event_id).collect();
        assert_eq!(ids.len(), all.len());
        assert_eq!(store.delivery_webhook("").unwrap().unwrap().cursor, last);
        let old = store.due_delivery_webhooks(1).unwrap().remove(0);
        let changed = store
            .save_delivery_webhook("", "admin", "http://localhost/changed", true, hook.revision)
            .unwrap();
        assert_ne!(hook.secret, changed.secret);
        assert!(!serde_json::to_string(&changed)
            .unwrap()
            .contains(&changed.secret));
        assert!(store.replay_delivery_webhook("", old.event_id).unwrap());
        store.finish_delivery_webhook(&old, None, 2).unwrap();
        let replay = store
            .delivery_webhook_attempts("", after, 1)
            .unwrap()
            .remove(0);
        assert_eq!(replay.event_id, old.event_id);
        assert_eq!(replay.revision, changed.revision);
        assert_eq!(replay.status, "pending");
        assert!(store
            .delivery_webhook_attempts("other", 0, 100)
            .unwrap()
            .is_empty());
        assert!(!store.replay_delivery_webhook("other", last).unwrap());
        let mut attempt = replay;
        for count in 1..=12 {
            let before = attempt.clone();
            store
                .finish_delivery_webhook(&attempt, Some("503"), 1000 + count)
                .unwrap();
            attempt = store
                .delivery_webhook_attempts("", attempt.id - 1, 1)
                .unwrap()
                .remove(0);
            assert_eq!(attempt.attempts, count);
            assert_eq!(attempt.status, if count == 12 { "dead" } else { "pending" });
            assert_eq!(attempt.next_try, 1000 + count + webhook_retry_delay(count));
            store.finish_delivery_webhook(&before, None, 9999).unwrap();
            assert_eq!(
                store
                    .delivery_webhook_attempts("", attempt.id - 1, 1)
                    .unwrap()[0]
                    .status,
                attempt.status
            );
        }
        assert!(store.replay_delivery_webhook("", attempt.event_id).unwrap());
        let attempt = store
            .delivery_webhook_attempts("", attempt.id - 1, 1)
            .unwrap()
            .remove(0);
        assert_eq!((attempt.attempts, attempt.status.as_str()), (0, "pending"));
        store.finish_delivery_webhook(&attempt, None, 2000).unwrap();
        assert_eq!(
            store
                .delivery_webhook_attempts("", attempt.id - 1, 1)
                .unwrap()[0]
                .status,
            "delivered"
        );
        assert_eq!(
            [0, 1, 6, 7, u64::MAX].map(webhook_retry_delay),
            [5, 10, 320, 600, 600]
        );
    }

    #[test]
    fn deadlines_require_all_recipients_but_ignore_completed_and_cancelled_retirement() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let project = store
            .save_delivery_project("", "admin", crate::workflow::tests::project())
            .unwrap();
        for (index, accepted, cancelled, expected) in [
            (0, 0, false, true),
            (1, 1, false, true),
            (2, 2, false, false),
            (3, 0, true, false),
        ] {
            let mut request = crate::workflow::tests::request();
            request.operation_id = format!("deadline-{index}");
            request.deadline = Some(now_unix() + 60);
            let job = store
                .enqueue_delivery_job("", "sender", 1, None, project.clone(), request)
                .unwrap();
            store.with(|connection| {
                connection.execute("UPDATE delivery_jobs SET state='retired',document=json_set(document,'$.state','retired','$.checks.retired_from',?2,'$.request.recipients',json('[\"one\",\"two\"]')) WHERE id=?1", params![job.id, if cancelled {"cancelled"} else {"ready"}])?;
                for holder in ["one", "two"].iter().take(accepted) {
                    connection.execute("INSERT INTO delivery_evidence(id,grant_id,holder,kind,received_at,document) VALUES (?1,?2,?3,'accepted',1,'{}')",params![format!("{index}-{holder}"),job.id,holder])?;
                }
                Ok(())
            }).unwrap();
            store.escalate_delivery_jobs(now_unix() + 120).unwrap();
            store.escalate_delivery_jobs(now_unix() + 120).unwrap();
            let events = store.delivery_events("", 0, 100).unwrap();
            assert_eq!(
                events
                    .iter()
                    .filter(|event| event.grant_id == job.id
                        && event.kind == "delivery_deadline_missed")
                    .count(),
                usize::from(expected)
            );
        }
    }
}
