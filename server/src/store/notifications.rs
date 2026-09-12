use super::*;
use rusqlite::params;

pub(super) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS notification_destinations (
    id TEXT PRIMARY KEY, tenant TEXT NOT NULL, document TEXT NOT NULL,
    last_at INTEGER, last_delivered INTEGER
);
CREATE INDEX IF NOT EXISTS notification_destinations_tenant ON notification_destinations(tenant);
CREATE TABLE IF NOT EXISTS notification_defaults (tenant TEXT PRIMARY KEY, document TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS notification_job_overrides (job_id TEXT PRIMARY KEY REFERENCES delivery_jobs(id) ON DELETE CASCADE, document TEXT NOT NULL);
";

pub const NOTIFICATION_EVENTS: [&str; 12] = [
    "route_approval_requested",
    "route_approved",
    "route_identity_changed",
    "route_failed",
    "route_recovered",
    "route_received",
    "upload_complete",
    "upload_failed",
    "outbound_download_started",
    "outbound_delivery_complete",
    "workflow_retry_scheduled",
    "workflow_failed",
];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationMode {
    #[default]
    Off,
    Default,
    Custom,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationPolicy {
    pub mode: NotificationMode,
    #[serde(default)]
    pub rules: Vec<NotificationRule>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationRule {
    pub destination_id: String,
    pub events: Vec<String>,
}

impl NotificationPolicy {
    pub fn enabled(&self) -> bool {
        self.mode != NotificationMode::Off
    }

    pub fn validate(&self, events: &[&str]) -> Result<(), String> {
        if self.mode != NotificationMode::Custom {
            return if self.rules.is_empty() {
                Ok(())
            } else {
                Err("Only custom notifications accept rules".into())
            };
        }
        if self.rules.is_empty() || self.rules.len() > 32 {
            return Err("Choose 1 to 32 notification destinations".into());
        }
        let mut ids = std::collections::HashSet::new();
        for rule in &self.rules {
            if !ids.insert(&rule.destination_id) {
                return Err("Choose each destination once".into());
            }
            if rule.events.is_empty()
                || rule.events.len() > events.len()
                || rule
                    .events
                    .iter()
                    .any(|event| !events.contains(&event.as_str()))
                || rule
                    .events
                    .iter()
                    .collect::<std::collections::HashSet<_>>()
                    .len()
                    != rule.events.len()
            {
                return Err("Choose supported events for each destination".into());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationDestination {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub revision: u64,
    pub label: String,
    pub channel: String,
    pub target: String,
    pub enabled: bool,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub recipients: Vec<String>,
    #[serde(default)]
    pub thread_id: String,
}

impl NotificationDestination {
    pub fn public(&self) -> serde_json::Value {
        serde_json::json!({"id":self.id, "revision":self.revision, "label":self.label,
            "channel":self.channel, "target":self.target, "enabled":self.enabled,
            "url_set":!self.url.is_empty(), "token_set":!self.token.is_empty(),
            "user_set":!self.user.is_empty(), "recipients":self.recipients, "thread_id":self.thread_id})
    }
}

impl Store {
    pub fn notification_destinations(
        &self,
        tenant: &str,
    ) -> Result<Vec<NotificationDestination>, String> {
        self.with(|connection| {
            let mut query = connection.prepare("SELECT document FROM notification_destinations WHERE tenant=?1 ORDER BY id LIMIT 100")?;
            let rows = query.query_map([tenant], |row| parse_json(&row.get::<_, String>(0)?, 0))?;
            rows.collect()
        })
    }

    pub fn notification_destination(
        &self,
        tenant: &str,
        id: &str,
    ) -> Result<Option<NotificationDestination>, String> {
        self.with(|connection| {
            connection
                .query_row(
                    "SELECT document FROM notification_destinations WHERE tenant=?1 AND id=?2",
                    params![tenant, id],
                    |row| parse_json(&row.get::<_, String>(0)?, 0),
                )
                .optional()
        })
    }

    pub fn save_notification_destination(
        &self,
        tenant: &str,
        destination: &mut NotificationDestination,
    ) -> Result<(), String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let tx = connection.transaction().map_err(|e| e.to_string())?;
        workflows::ensure_tenant(&tx, tenant)?;
        let current: Option<String> = tx
            .query_row(
                "SELECT document FROM notification_destinations WHERE tenant=?1 AND id=?2",
                params![tenant, destination.id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        if current
            .as_ref()
            .map(|document| {
                serde_json::from_str::<NotificationDestination>(document).map(|d| d.revision)
            })
            .transpose()
            .map_err(|e| e.to_string())?
            .unwrap_or(0)
            != destination.revision
        {
            return Err("Connection changed; reload before saving".into());
        }
        if current.is_none() {
            let count: i64 = tx
                .query_row(
                    "SELECT COUNT(*) FROM notification_destinations WHERE tenant=?1",
                    [tenant],
                    |row| row.get(0),
                )
                .map_err(|e| e.to_string())?;
            if count >= 100 {
                return Err("A tenant can have at most 100 notification destinations".into());
            }
        }
        destination.revision += 1;
        let document = serde_json::to_string(destination).map_err(|e| e.to_string())?;
        tx.execute("INSERT INTO notification_destinations(id,tenant,document) VALUES (?1,?2,?3) ON CONFLICT(id) DO UPDATE SET document=excluded.document,last_at=NULL,last_delivered=NULL WHERE notification_destinations.tenant=excluded.tenant", params![destination.id,tenant,document]).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())
    }

    pub fn notification_defaults(&self, tenant: &str) -> Result<NotificationPolicy, String> {
        self.with(|connection| {
            connection
                .query_row(
                    "SELECT document FROM notification_defaults WHERE tenant=?1",
                    [tenant],
                    |row| parse_json(&row.get::<_, String>(0)?, 0),
                )
                .optional()
        })
        .map(|policy| policy.unwrap_or_default())
    }

    pub fn save_notification_defaults(
        &self,
        tenant: &str,
        policy: &NotificationPolicy,
    ) -> Result<(), String> {
        let document = serde_json::to_string(policy).map_err(|e| e.to_string())?;
        let mut connection = self.connection.lock().expect("store poisoned");
        let tx = connection.transaction().map_err(|e| e.to_string())?;
        workflows::ensure_tenant(&tx, tenant)?;
        tx.execute("INSERT INTO notification_defaults(tenant,document) VALUES (?1,?2) ON CONFLICT(tenant) DO UPDATE SET document=excluded.document", params![tenant,document]).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())
    }

    pub fn notification_outcomes(&self, tenant: &str) -> Result<serde_json::Value, String> {
        self.with(|connection| {
            let mut query = connection.prepare("SELECT id,last_at,last_delivered FROM notification_destinations WHERE tenant=?1 AND last_at IS NOT NULL")?;
            let pairs = query.query_map([tenant], |row| Ok((row.get::<_, String>(0)?,serde_json::json!({"at":row.get::<_, i64>(1)?,"delivered":row.get::<_, bool>(2)?}))))?.collect::<rusqlite::Result<serde_json::Map<String,serde_json::Value>>>()?;
            Ok(serde_json::Value::Object(pairs))
        })
    }

    pub fn record_notification_outcome(
        &self,
        tenant: &str,
        destination: &NotificationDestination,
        delivered: bool,
    ) -> Result<(), String> {
        self.with(|connection| connection.execute("UPDATE notification_destinations SET last_at=?3,last_delivered=?4 WHERE tenant=?1 AND id=?2 AND json_extract(document,'$.revision')=?5", params![tenant,destination.id,now_unix() as i64,delivered,destination.revision as i64]).map(|_| ()))
    }

    pub fn set_outbound_notifications(
        &self,
        tenant: &str,
        id: &str,
        policy: &NotificationPolicy,
    ) -> Result<bool, String> {
        let document = serde_json::to_string(policy).map_err(|e| e.to_string())?;
        self.with(|connection| {
            connection
                .execute(
                    "UPDATE outbound_grants SET notifications_json=?3 WHERE tenant=?1 AND id=?2",
                    params![tenant, id, document],
                )
                .map(|count| count > 0)
        })
    }
}

impl Store {
    pub fn notification_job_override(
        &self,
        tenant: &str,
        id: &str,
    ) -> Result<Option<NotificationPolicy>, String> {
        self.with(|connection| notification_job_override_in(connection, tenant, id))
    }

    pub fn set_job_notifications(
        &self,
        tenant: &str,
        id: &str,
        policy: Option<&NotificationPolicy>,
    ) -> Result<bool, String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let tx = connection.transaction().map_err(|e| e.to_string())?;
        let job: Option<crate::workflow::Job> = tx
            .query_row(
                "SELECT document FROM delivery_jobs WHERE tenant=?1 AND id=?2",
                params![tenant, id],
                |row| parse_json(&row.get::<_, String>(0)?, 0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        let Some(job) = job else {
            return Ok(false);
        };
        if let Some(policy) = policy {
            tx.execute("INSERT INTO notification_job_overrides(job_id,document) VALUES (?1,?2) ON CONFLICT(job_id) DO UPDATE SET document=excluded.document", params![id,serde_json::to_string(policy).map_err(|e|e.to_string())?]).map_err(|e|e.to_string())?;
        } else {
            tx.execute(
                "DELETE FROM notification_job_overrides WHERE job_id=?1",
                [id],
            )
            .map_err(|e| e.to_string())?;
        }
        let effective = policy
            .or(job.request.notifications.as_ref())
            .or(job.project.notifications.as_ref());
        tx.execute(
            "UPDATE outbound_grants SET notifications_json=?3 WHERE tenant=?1 AND id=?2",
            params![
                tenant,
                id,
                serde_json::to_string(&effective).map_err(|e| e.to_string())?
            ],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(true)
    }

    pub fn delivery_operation_exists(
        &self,
        tenant: &str,
        actor: &str,
        operation_id: &str,
    ) -> Result<bool, String> {
        self.with(|connection| connection.query_row("SELECT EXISTS(SELECT 1 FROM delivery_jobs WHERE tenant=?1 AND actor=?2 AND operation_id=?3)",params![tenant,actor,operation_id],|row|row.get(0)))
    }
}

pub(super) fn notification_job_override_in(
    connection: &Connection,
    tenant: &str,
    id: &str,
) -> rusqlite::Result<Option<NotificationPolicy>> {
    connection.query_row("SELECT n.document FROM notification_job_overrides n JOIN delivery_jobs j ON j.id=n.job_id WHERE j.tenant=?1 AND j.id=?2",params![tenant,id],|row|parse_json(&row.get::<_,String>(0)?,0)).optional()
}

#[cfg(test)]
mod cleanup_tests {
    use super::*;

    #[test]
    fn upgrade_removes_broadcast_configuration_and_preserves_named_destinations() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut destination: NotificationDestination = serde_json::from_value(serde_json::json!({
            "id":"named", "label":"Incoming", "channel":"webhook", "target":"Operations",
            "enabled":true, "url":"https://example.test/private"
        }))
        .unwrap();
        store
            .save_notification_destination("", &mut destination)
            .unwrap();
        let policy = NotificationPolicy {
            mode: NotificationMode::Custom,
            rules: vec![NotificationRule {
                destination_id: destination.id.clone(),
                events: vec!["upload_complete".into()],
            }],
        };
        store.save_notification_defaults("", &policy).unwrap();
        for id in ["disabled", "enabled"] {
            store
                .insert_link(Link {
                    id: id.into(),
                    tenant: String::new(),
                    label: id.into(),
                    dest: String::new(),
                    password_hash: None,
                    created_at: 1,
                    expires_at: None,
                    max_bytes: None,
                    active: true,
                    legal_hold: false,
                    notifications: Some(policy.clone()),
                    uploads: vec![],
                    events: vec![],
                })
                .unwrap();
        }
        let mut grant = crate::notify::tests::test_grant(vec![]);
        grant.notifications = Some(policy.clone());
        store.insert_outbound_grant(grant).unwrap();
        store.with(|connection| connection.execute_batch("ALTER TABLE links ADD COLUMN notify_on_upload INTEGER NOT NULL DEFAULT 0;
            ALTER TABLE outbound_grants ADD COLUMN notify_on_download INTEGER NOT NULL DEFAULT 0;
            UPDATE links SET notify_on_upload=1 WHERE id='enabled';
            INSERT INTO settings(key,value,updated_at) VALUES ('notify_slack','old-secret',1),('smtp_to','old@example.test',1),('smtp_host','smtp.example.test',1);
            UPDATE meta SET value='34' WHERE key='schema_version';")).unwrap();
        drop(store);
        let store = Store::open(directory.path()).unwrap();
        assert!(store.setting("notify_slack").unwrap().is_none());
        assert!(store.setting("smtp_to").unwrap().is_none());
        assert_eq!(
            store.setting("smtp_host").unwrap().as_deref(),
            Some("smtp.example.test")
        );
        assert_eq!(store.notification_defaults("").unwrap(), policy);
        assert_eq!(
            store.link("", "disabled").unwrap().unwrap().notifications,
            Some(NotificationPolicy::default())
        );
        assert_eq!(
            store.link("", "enabled").unwrap().unwrap().notifications,
            Some(policy.clone())
        );
        assert_eq!(
            store.outbound_grants("").unwrap()[0].notifications,
            Some(NotificationPolicy::default())
        );
        assert_eq!(
            store
                .notification_destination("", "named")
                .unwrap()
                .unwrap()
                .url,
            destination.url
        );
        for (table, column) in [
            ("links", "notify_on_upload"),
            ("outbound_grants", "notify_on_download"),
        ] {
            let present: bool = store.with(|connection| connection.query_row(&format!("SELECT EXISTS(SELECT 1 FROM pragma_table_info('{table}') WHERE name='{column}')"), [], |row| row.get(0))).unwrap();
            assert!(!present);
        }
    }
}
