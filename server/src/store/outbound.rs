//! Outbound grants, file counters, and native fetch reservations.

use super::*;

/// Compared without ASCII case: on a case-insensitive library volume another
/// spelling of a served path names the same file.
pub(crate) const ACTIVE_LIBRARY_GRANT: &str = "SELECT EXISTS (
    SELECT 1 FROM outbound_grant_files f JOIN outbound_grants g ON g.id = f.grant_id
    WHERE f.source = ?2 COLLATE NOCASE AND g.tenant = ?1 AND g.revoked_at IS NULL)";

impl Store {
    pub fn insert_outbound_grant(&self, grant: OutboundGrant) -> Result<(), String> {
        self.insert_outbound_grant_with_operation(grant, None)
    }

    pub fn insert_outbound_grant_with_operation(
        &self,
        grant: OutboundGrant,
        operation: Option<&AutomationOperation>,
    ) -> Result<(), String> {
        self.insert_workflow_grant(grant, operation, None, None)
            .map_err(String::from)
    }

    /// Inserts a grant, and for a workflow job records it finished. Policy
    /// refusals (a protected directory, a project edited meanwhile) come back
    /// as conflicts, not as a store failure the caller would retry.
    pub fn insert_workflow_grant(
        &self,
        mut grant: OutboundGrant,
        operation: Option<&AutomationOperation>,
        job: Option<&crate::workflow::Job>,
        share_token: Option<&str>,
    ) -> Result<(), WorkflowMutationError> {
        if share_token.is_some_and(|token| crate::auth::hash_token(token) != grant.token_hash) {
            return Err(WorkflowMutationError::invalid(
                "download token does not match grant",
            ));
        }
        grant
            .validate_names()
            .map_err(WorkflowMutationError::invalid)?;
        let delivery_digest = evidence::grant_digest(&grant);
        let (bytes_hi, bytes_lo) = split_bytes(grant.bytes);
        let files_json = serde_json::to_string(&grant.files).unwrap_or_else(|_| "[]".to_owned());
        let file_count = i64::try_from(grant.files.len().max(1)).unwrap_or(i64::MAX);
        let grant_id = grant.id.clone();
        let mut connection = self.connection.lock().expect("store poisoned");
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        workflows::check_grant_creation(&transaction, &grant, job)?;
        if let Some(policy) =
            notifications::notification_job_override_in(&transaction, &grant.tenant, &grant.id)
                .map_err(|e| e.to_string())?
        {
            grant.notifications = Some(policy);
        }
        if let Some(job) = job {
            workflows::finish_job(
                &transaction,
                &self.event_signer,
                job,
                &grant,
                &delivery_digest,
            )?;
        }
        transaction.execute(
                "INSERT INTO outbound_grants
                 (id, token_hash, password_hash, tenant, link_id, upload_id, package_root, name, suite,
                  root, file_index, bytes_hi, bytes_lo, label, created_at, expires_at, revoked_at,
                  downloads, max_downloads, first_download_at, last_download_at,
                  files_json, file_count, notifications_json, share_token)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25)",
                rusqlite::params![
                    &grant_id,
                    grant.token_hash,
                    grant.password_hash,
                    grant.tenant,
                    grant.link_id,
                    grant.upload_id,
                    grant.package_root,
                    grant.name,
                    grant.suite,
                    grant.root,
                    i64::try_from(grant.file_index).unwrap_or(i64::MAX),
                    bytes_hi,
                    bytes_lo,
                    grant.label,
                    i64::try_from(grant.created_at).unwrap_or(i64::MAX),
                    i64::try_from(grant.expires_at).unwrap_or(i64::MAX),
                    grant.revoked_at.map(|at| i64::try_from(at).unwrap_or(i64::MAX)),
                    i64::try_from(grant.downloads).unwrap_or(i64::MAX),
                    grant
                        .max_downloads
                        .map(|count| i64::try_from(count).unwrap_or(i64::MAX)),
                    grant
                        .first_download_at
                        .map(|at| i64::try_from(at).unwrap_or(i64::MAX)),
                    grant
                        .last_download_at
                        .map(|at| i64::try_from(at).unwrap_or(i64::MAX)),
                    files_json,
                    file_count,
                    serde_json::to_string(&grant.notifications).map_err(|e| e.to_string())?,
                    share_token.filter(|_| job.is_none()),
                ],
            )
            .map_err(|error| error.to_string())?;
        let mut child = transaction
            .prepare(
                "INSERT INTO outbound_grant_files
             (grant_id, file_index, source, name, suite, root, bytes_hi, bytes_lo,
              receipt_b64, downloads, first_download_at, last_download_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            )
            .map_err(|error| error.to_string())?;
        for (index, file) in grant.files.into_iter().enumerate() {
            let (file_bytes_hi, file_bytes_lo) = split_bytes(file.bytes);
            child
                .execute(rusqlite::params![
                    &grant_id,
                    i64::try_from(index).unwrap_or(i64::MAX),
                    file.source,
                    file.name,
                    file.suite,
                    file.root,
                    file_bytes_hi,
                    file_bytes_lo,
                    file.receipt_b64,
                    i64::try_from(file.downloads).unwrap_or(i64::MAX),
                    file.first_download_at
                        .map(|at| i64::try_from(at).unwrap_or(i64::MAX)),
                    file.last_download_at
                        .map(|at| i64::try_from(at).unwrap_or(i64::MAX)),
                ])
                .map_err(|error| error.to_string())?;
        }
        drop(child);
        transaction
            .execute(
                "INSERT INTO delivery_manifests(grant_id,digest) VALUES (?1,?2)",
                rusqlite::params![grant_id, delivery_digest],
            )
            .map_err(|e| e.to_string())?;
        if let Some(operation) = operation {
            let active: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM automation_tokens WHERE id = ?1 AND revoked_at IS NULL AND expires_at > ?2)",
                rusqlite::params![operation.token_id, now_unix() as i64], |row| row.get(0),
            ).map_err(|error| error.to_string())?;
            if !active {
                return Err(WorkflowMutationError::conflict(
                    "automation token expired or revoked",
                ));
            }
            transaction.execute(
                "INSERT INTO automation_operations (token_id, operation_id, request_hash, grant_id) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![operation.token_id, operation.operation_id, operation.request_hash, grant_id],
            ).map_err(|error| error.to_string())?;
        }
        transaction
            .commit()
            .map_err(|error| WorkflowMutationError::store(error.to_string()))
    }

    pub fn outbound_grants(&self, tenant: &str) -> Result<Vec<OutboundGrant>, String> {
        self.with(|connection| {
            let mut statement = connection.prepare(
                "SELECT id, token_hash, password_hash, tenant, link_id, upload_id, package_root,
                        name, suite, root, file_index, bytes_hi, bytes_lo, label, created_at,
                        expires_at, revoked_at, downloads, max_downloads, notifications_json, first_download_at,
                        last_download_at,
                        files_json
                 FROM outbound_grants WHERE tenant = ?1 ORDER BY created_at, rowid",
            )?;
            let rows = statement.query_map([tenant], map_outbound_grant)?;
            let mut grants = rows.collect::<Result<Vec<_>, _>>()?;
            for grant in &mut grants {
                overlay_outbound_file_counters(connection, grant)?;
            }
            Ok(grants)
        })
    }

    pub fn outbound_grants_page(
        &self,
        tenant: &str,
        limit: usize,
        offset: usize,
        file_preview_limit: usize,
    ) -> Result<(Vec<(OutboundGrant, usize)>, u64), String> {
        self.with(|connection| {
            let grants = outbound_grant_previews(
                connection,
                tenant,
                None,
                limit,
                offset,
                file_preview_limit,
            )?;
            let total = connection
                .query_row(
                    "SELECT COUNT(*) FROM outbound_grants WHERE tenant = ?1",
                    [tenant],
                    |row| row.get::<_, i64>(0),
                )?
                .max(0) as u64;
            Ok((grants, total))
        })
    }

    pub fn outbound_grant_preview(
        &self,
        tenant: &str,
        id: &str,
        file_preview_limit: usize,
    ) -> Result<Option<(OutboundGrant, usize)>, String> {
        self.with(|connection| {
            Ok(
                outbound_grant_previews(connection, tenant, Some(id), 1, 0, file_preview_limit)?
                    .pop(),
            )
        })
    }

    pub fn outbound_grant_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<OutboundGrant>, String> {
        self.outbound_grant("token_hash", token_hash)
    }

    /// Whether the grant keyed by this token hash still admits downloads:
    /// present, unrevoked and unexpired. Reads two columns, not the file list.
    pub fn outbound_grant_admits(&self, token_hash: &str, now: u64) -> Result<bool, String> {
        self.with(|connection| {
            connection
                .query_row(
                    "SELECT revoked_at IS NULL AND expires_at > ?2 FROM outbound_grants WHERE token_hash = ?1",
                    rusqlite::params![token_hash, now as i64],
                    |row| row.get::<_, bool>(0),
                )
                .optional()
                .map(|admits| admits.unwrap_or(false))
        })
    }

    /// The manifest root recorded for a grant's VOT package, if one was built.
    pub fn outbound_grant_manifest_root(&self, grant_id: &str) -> Result<Option<String>, String> {
        self.with(|connection| {
            connection
                .query_row(
                    "SELECT manifest_root FROM outbound_grant_manifests WHERE grant_id = ?1",
                    [grant_id],
                    |row| row.get(0),
                )
                .optional()
        })
    }

    pub(crate) fn outbound_grant_is_non_revoked(&self, grant_id: &str) -> Result<bool, String> {
        self.with(|connection| {
            connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM outbound_grants WHERE id = ?1 AND revoked_at IS NULL)",
                [grant_id],
                |row| row.get(0),
            )
        })
    }

    pub fn put_outbound_grant_manifest(
        &self,
        grant_id: &str,
        manifest_root: &str,
        now: u64,
    ) -> Result<(), String> {
        self.with(|connection| {
            connection
                .execute(
                    "INSERT INTO outbound_grant_manifests (grant_id, manifest_root, created_at)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT(grant_id) DO UPDATE SET manifest_root = excluded.manifest_root,
                                                         created_at = excluded.created_at",
                    rusqlite::params![grant_id, manifest_root, now as i64],
                )
                .map(|_| ())
        })
    }

    /// One grant by id, for fetch admission through its ticket.
    pub fn outbound_grant_by_id(&self, id: &str) -> Result<Option<OutboundGrant>, String> {
        self.outbound_grant("id", id)
    }

    fn outbound_grant(&self, column: &str, value: &str) -> Result<Option<OutboundGrant>, String> {
        self.with(|connection| {
            connection
                .prepare_cached(
                    &format!("SELECT id, token_hash, password_hash, tenant, link_id, upload_id, package_root,
                            name, suite, root, file_index, bytes_hi, bytes_lo, label, created_at,
                            expires_at, revoked_at, downloads, max_downloads, notifications_json, first_download_at,
                            last_download_at,
                            files_json
                     FROM outbound_grants WHERE {column} = ?1"),
                )?
                .query_row([value], map_outbound_grant)
                .optional()
                .and_then(|grant| {
                    grant
                        .map(|mut grant| {
                            overlay_outbound_file_counters(connection, &mut grant)?;
                            Ok(grant)
                        })
                        .transpose()
                })
        })
    }

    /// Records a minted fetch capability against its grant, only if the
    /// deliveries recorded plus the tickets still live and undelivered leave
    /// room under `max_downloads`. An unadmitted ticket from this same
    /// holder is replaced by the new capability in the same transaction;
    /// admitted tickets and other holders still consume the reservation.
    /// The insert and replacement are atomic, so two mints racing for the
    /// last delivery cannot both reserve it.
    pub fn put_fetch_ticket(&self, ticket: &FetchTicket, now: u64) -> Result<bool, String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let tx = connection.transaction().map_err(|e| e.to_string())?;
        let job = workflows::release_in(&tx, &ticket.grant_id)?;
        if job.as_ref().map_or(0, |job| job.project.revision) != ticket.policy_revision
            || job.as_ref().is_some_and(|job| {
                !job.request.recipients.is_empty()
                    && !job.request.recipients.contains(&ticket.holder)
            })
        {
            return Ok(false);
        }
        let changed = tx.execute(
            "INSERT INTO outbound_fetch_tickets(token_id,grant_id,manifest_root,expires_at,delivered_at,holder,grant_token_hash,policy_revision)
             SELECT ?1,?2,?3,?4,NULL,?5,?6,?7 FROM outbound_grants g WHERE g.id=?2 AND g.token_hash=?6 AND g.revoked_at IS NULL AND g.expires_at>?8
             AND (g.max_downloads IS NULL OR g.downloads+(SELECT COUNT(*) FROM outbound_fetch_tickets WHERE grant_id=?2 AND (admitted_at IS NOT NULL OR (grant_token_hash=?6 AND policy_revision=?7 AND holder<>?5)) AND expires_at>?8 AND delivered_at IS NULL)<g.max_downloads)",
            rusqlite::params![ticket.token_id,ticket.grant_id,ticket.manifest_root,ticket.expires_at as i64,ticket.holder,ticket.grant_token_hash,ticket.policy_revision as i64,now as i64]).map_err(|e| e.to_string())?;
        if changed == 1 {
            tx.execute(
                "DELETE FROM outbound_fetch_tickets
                 WHERE grant_id = ?1 AND holder = ?2 AND token_id <> ?3
                   AND expires_at > ?4 AND delivered_at IS NULL AND admitted_at IS NULL",
                rusqlite::params![ticket.grant_id, ticket.holder, ticket.token_id, now as i64],
            )
            .map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(changed == 1)
    }

    pub fn admit_fetch_ticket(&self, ticket: &FetchTicket, now: u64) -> Result<bool, String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let job = workflows::release_in(&tx, &ticket.grant_id)?;
        if job.as_ref().map_or(0, |job| job.project.revision) != ticket.policy_revision
            || job.as_ref().is_some_and(|job| {
                !job.request.recipients.is_empty()
                    && !job.request.recipients.contains(&ticket.holder)
            })
        {
            return Ok(false);
        }
        // Other holders' live, undelivered reservations count as at mint, so
        // a ticket that already delivered cannot fetch again into a slot
        // another recipient reserved.
        let changed = tx.execute("UPDATE outbound_fetch_tickets SET admitted_at=COALESCE(admitted_at,?4) WHERE token_id=?1 AND grant_id=?2 AND grant_token_hash=?3 AND expires_at>?4 AND EXISTS(SELECT 1 FROM outbound_grants g WHERE g.id=?2 AND g.token_hash=?3 AND g.revoked_at IS NULL AND g.expires_at>?4 AND (g.max_downloads IS NULL OR g.downloads+(SELECT COUNT(*) FROM outbound_fetch_tickets o WHERE o.grant_id=?2 AND o.token_id<>?1 AND o.expires_at>?4 AND o.delivered_at IS NULL AND (o.admitted_at IS NOT NULL OR (o.grant_token_hash=?3 AND o.policy_revision=?5 AND o.holder<>?6)))<g.max_downloads))", rusqlite::params![ticket.token_id,ticket.grant_id,ticket.grant_token_hash,now as i64,ticket.policy_revision as i64,ticket.holder]).map_err(|error|error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(changed == 1)
    }

    pub fn fetch_ticket(&self, token_id: &str) -> Result<Option<FetchTicket>, String> {
        self.with(|connection| {
            connection
                .query_row(
                    "SELECT token_id, grant_id, manifest_root, expires_at, delivered_at, holder, grant_token_hash, policy_revision
                     FROM outbound_fetch_tickets WHERE token_id = ?1",
                    [token_id],
                    map_fetch_ticket,
                )
                .optional()
        })
    }

    /// Tickets not yet expired, delivered or not: a capability is good for
    /// its whole window, so a restart warms servers for these and the
    /// registry keeps their state.
    pub fn unexpired_fetch_tickets(&self, now: u64) -> Result<Vec<FetchTicket>, String> {
        self.with(|connection| {
            connection
                .prepare_cached(
                    "SELECT token_id, grant_id, manifest_root, expires_at, delivered_at, holder, grant_token_hash, policy_revision
                     FROM outbound_fetch_tickets WHERE expires_at > ?1",
                )?
                .query_map([now as i64], map_fetch_ticket)?
                .collect()
        })
    }

    /// Grants with a built manifest that may still be fetched: what the serve
    /// registry keeps a server for.
    pub fn servable_grant_ids(&self, now: u64) -> Result<Vec<String>, String> {
        self.with(|connection| {
            connection
                .prepare_cached(
                    "SELECT m.grant_id FROM outbound_grant_manifests m
                     JOIN outbound_grants g ON g.id = m.grant_id
                     WHERE g.revoked_at IS NULL AND g.expires_at > ?1
                       AND (g.max_downloads IS NULL OR g.downloads < g.max_downloads)",
                )?
                .query_map([now as i64], |row| row.get(0))?
                .collect()
        })
    }

    /// Drops tickets expired for more than a day; the audit log keeps the
    /// mint and the delivery.
    pub fn prune_fetch_tickets(&self, before: u64) -> Result<usize, String> {
        self.with(|connection| {
            connection.execute(
                "DELETE FROM outbound_fetch_tickets WHERE expires_at < ?1",
                [before as i64],
            )
        })
    }

    /// Looks up one outbound file without parsing the full manifest.
    pub fn outbound_grant_file_by_token_hash(
        &self,
        token_hash: &str,
        index: usize,
    ) -> Result<Option<(OutboundGrant, Option<OutboundGrantFile>)>, String> {
        self.with(|connection| {
            let parent = outbound_grant_parent(connection, token_hash)?;
            let Some((grant, file_count)) = parent else {
                return Ok(None);
            };
            if index >= file_count {
                return Ok(None);
            }
            let row = connection
                .prepare_cached(
                    "SELECT source, name, suite, root, bytes_hi, bytes_lo, receipt_b64,
                            downloads, first_download_at, last_download_at
                     FROM outbound_grant_files WHERE grant_id = ?1 AND file_index = ?2",
                )?
                .query_row(
                    rusqlite::params![grant.id, i64::try_from(index).unwrap_or(i64::MAX)],
                    map_outbound_grant_file,
                )
                .optional()?;
            if row.is_none() {
                let has_children: bool = connection.query_row(
                    "SELECT EXISTS (SELECT 1 FROM outbound_grant_files WHERE grant_id = ?1)",
                    [&grant.id],
                    |row| row.get(0),
                )?;
                if has_children || file_count != 1 {
                    return Ok(None);
                }
                let files_json: String = connection.query_row(
                    "SELECT files_json FROM outbound_grants WHERE id = ?1",
                    [&grant.id],
                    |row| row.get(0),
                )?;
                if !serde_json::from_str::<Vec<OutboundGrantFile>>(&files_json)
                    .map(|files| files.is_empty())
                    .unwrap_or(false)
                {
                    return Ok(None);
                }
            }
            Ok(Some((grant, row)))
        })
    }

    /// Looks up one page of outbound files without parsing the full manifest.
    pub fn outbound_grant_files_page_by_token_hash(
        &self,
        token_hash: &str,
        offset: usize,
        limit: usize,
    ) -> Result<Option<OutboundGrantFilesPage>, String> {
        let offset =
            i64::try_from(offset).map_err(|_| "outbound file offset overflow".to_owned())?;
        let limit = i64::try_from(limit).map_err(|_| "outbound file limit overflow".to_owned())?;
        self.with(|connection| {
            let parent = outbound_grant_parent(connection, token_hash)?;
            let Some((grant, file_count)) = parent else {
                return Ok(None);
            };
            let mut statement = connection.prepare(
                "SELECT file_index, source, name, suite, root, bytes_hi, bytes_lo, receipt_b64,
                        downloads, first_download_at, last_download_at
                 FROM outbound_grant_files
                 WHERE grant_id = ?1 AND file_index >= ?2
                 ORDER BY file_index
                 LIMIT ?3",
            )?;
            let rows = statement.query_map(rusqlite::params![grant.id, offset, limit], |row| {
                Ok((
                    usize::try_from(row.get::<_, i64>("file_index")?).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Integer,
                            Box::new(error),
                        )
                    })?,
                    map_outbound_grant_file(row)?,
                ))
            })?;
            let mut files = rows.collect::<Result<Vec<_>, _>>()?;
            if files.is_empty() && offset == 0 && file_count == 1 {
                let has_children: bool = connection.query_row(
                    "SELECT EXISTS (SELECT 1 FROM outbound_grant_files WHERE grant_id = ?1)",
                    [&grant.id],
                    |row| row.get(0),
                )?;
                if !has_children {
                    let files_json: String = connection.query_row(
                        "SELECT files_json FROM outbound_grants WHERE id = ?1",
                        [&grant.id],
                        |row| row.get(0),
                    )?;
                    if serde_json::from_str::<Vec<OutboundGrantFile>>(&files_json)
                        .map(|files| files.is_empty())
                        .unwrap_or(false)
                    {
                        files.push((
                            0,
                            OutboundGrantFile {
                                source: String::new(),
                                name: grant.name.clone(),
                                suite: grant.suite.clone(),
                                root: grant.root.clone(),
                                bytes: grant.bytes,
                                receipt_b64: String::new(),
                                downloads: grant.downloads,
                                first_download_at: grant.first_download_at,
                                last_download_at: grant.last_download_at,
                            },
                        ));
                    }
                }
            }
            let (bytes_hi, bytes_lo): (i64, i64) = connection.query_row(
                "SELECT COALESCE(SUM(bytes_hi), 0), COALESCE(SUM(bytes_lo), 0)
                 FROM outbound_grant_files WHERE grant_id = ?1",
                [&grant.id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            let total_bytes = match combine_byte_sums(bytes_hi, bytes_lo) {
                Ok(0) => grant.bytes,
                Ok(total) => total,
                // A corrupt sum is skipped, not clamped: the grant's own
                // recorded size stays the page total.
                Err(error) => {
                    tracing::warn!(
                        %error,
                        grant_id = %grant.id,
                        "grant file byte sum is corrupt; using the recorded grant size"
                    );
                    grant.bytes
                }
            };
            Ok(Some(OutboundGrantFilesPage {
                grant,
                file_count,
                total_bytes,
                files,
            }))
        })
    }

    /// Private bearer storage follows the workflow token model. Never include
    /// it in grant listings, audits, or public metadata.
    pub(crate) fn outbound_share_token(
        &self,
        tenant: &str,
        id: &str,
    ) -> Result<Option<String>, String> {
        self.with(|connection| {
            connection.query_row(
                "SELECT CASE WHEN j.id IS NULL THEN g.share_token ELSE j.token END, g.token_hash
                 FROM outbound_grants AS g
                 LEFT JOIN delivery_jobs AS j ON j.id=g.id AND j.tenant=g.tenant
                 WHERE g.tenant=?1 AND g.id=?2 AND g.revoked_at IS NULL",
                rusqlite::params![tenant, id],
                |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, String>(1)?)),
            ).optional().map(|row| row.and_then(|(token, hash)|
                token.filter(|token| crate::auth::hash_token(token) == hash)))
        })
    }

    pub fn rotate_outbound_grant_token(
        &self,
        tenant: &str,
        id: &str,
        token: &str,
    ) -> Result<bool, String> {
        self.with(|connection| {
            connection
                .execute(
                    "UPDATE outbound_grants SET token_hash=?3, share_token=?4
                     WHERE tenant=?1 AND id=?2 AND revoked_at IS NULL
                     AND NOT EXISTS(SELECT 1 FROM delivery_jobs WHERE id=?2)",
                    rusqlite::params![tenant, id, crate::auth::hash_token(token), token],
                )
                .map(|changed| changed > 0)
        })
    }

    pub fn extend_outbound_grant(
        &self,
        tenant: &str,
        id: &str,
        seconds: u64,
        now: u64,
    ) -> Result<Option<u64>, String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let result = (|| {
            let retired: bool = transaction.query_row("SELECT EXISTS(SELECT 1 FROM delivery_jobs WHERE id=?1 AND tenant=?2 AND state IN ('retiring','retired','suspended'))",rusqlite::params![id,tenant],|row| row.get(0)).map_err(|error| error.to_string())?;
            if retired {
                return Err("delivery is no longer active; create a new job".into());
            }
            let existing: Option<i64> = transaction
                .query_row(
                    "SELECT expires_at FROM outbound_grants
                     WHERE tenant = ?1 AND id = ?2 AND revoked_at IS NULL AND expires_at > ?3",
                    rusqlite::params![tenant, id, i64::try_from(now).unwrap_or(i64::MAX)],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|error| error.to_string())?;
            let Some(existing) = existing else {
                return Ok(None);
            };
            // The predicate above already requires existing > now, so the
            // extension only ever pushes the expiry further out.
            let base = existing.max(0) as u64;
            let new_expiry = base.saturating_add(seconds).min(i64::MAX as u64);
            let changed = transaction
                .execute(
                    "UPDATE outbound_grants SET expires_at = ?3
                     WHERE tenant = ?1 AND id = ?2 AND revoked_at IS NULL",
                    rusqlite::params![tenant, id, new_expiry as i64],
                )
                .map_err(|error| error.to_string())?;
            if changed == 0 {
                return Ok(None);
            }
            Ok(Some(new_expiry))
        })();
        match result {
            Ok(result) => {
                transaction.commit().map_err(|error| error.to_string())?;
                Ok(result)
            }
            Err(error) => Err(error),
        }
    }

    pub fn revoke_outbound_grant(&self, tenant: &str, id: &str, at: u64) -> Result<bool, String> {
        self.with(|connection| {
            connection.execute(
                "UPDATE outbound_grants SET revoked_at = ?3
                 WHERE tenant = ?1 AND id = ?2 AND revoked_at IS NULL",
                rusqlite::params![tenant, id, i64::try_from(at).unwrap_or(i64::MAX)],
            )
        })
        .map(|changed| changed > 0)
    }

    /// Whether the tenant owns the grant row at all, revoked or not; lets the
    /// DELETE handler answer an already-revoked repeat with 200 and only an
    /// unknown id with 404.
    pub fn outbound_grant_exists(&self, tenant: &str, id: &str) -> Result<bool, String> {
        self.with(|connection| {
            connection
                .query_row(
                    "SELECT 1 FROM outbound_grants WHERE tenant = ?1 AND id = ?2",
                    rusqlite::params![tenant, id],
                    |_| Ok(()),
                )
                .optional()
                .map(|found| found.is_some())
        })
    }

    /// Finding 379: deleting a delivery is only a revoke, so revoked grants
    /// keep their names, roots and receipts alive in the grant row and its
    /// dependents. Once a grant is both revoked and expired, the retention
    /// sweep deletes that row and everything keyed by it, plus any orphaned
    /// dependent rows from earlier partial deletions; the signed
    /// delivery_events survive. A grant whose delivery job has not retired
    /// still holds its row, because job retirement and reprocessing read it.
    /// Returns how many grant rows were removed.
    pub fn purge_expired_revoked_grants(&self, now: u64) -> Result<u64, String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let purged = transaction
            .execute(
                "DELETE FROM outbound_grants
                 WHERE revoked_at IS NOT NULL AND expires_at <= ?1
                   AND NOT EXISTS (SELECT 1 FROM delivery_jobs
                                   WHERE id = outbound_grants.id AND state <> 'retired')",
                [i64::try_from(now).unwrap_or(i64::MAX)],
            )
            .map_err(|error| error.to_string())?;
        if purged == 0 {
            return Ok(0);
        }
        for table in [
            "outbound_grant_files",
            "delivery_manifests",
            "delivery_evidence",
            "delivery_policy_cache",
            "outbound_grant_manifests",
            "outbound_fetch_tickets",
        ] {
            transaction
                .execute(
                    &format!(
                        "DELETE FROM {table} WHERE grant_id NOT IN (SELECT id FROM outbound_grants)"
                    ),
                    [],
                )
                .map_err(|error| error.to_string())?;
        }
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(purged as u64)
    }

    pub fn record_outbound_download(
        &self,
        id: &str,
        indexes: &[usize],
        at: u64,
    ) -> Result<OutboundDownloadResult, String> {
        self.record_download(id, indexes, at, None)
    }

    pub fn record_fetch_download(
        &self,
        id: &str,
        indexes: &[usize],
        at: u64,
        token: &str,
    ) -> Result<OutboundDownloadResult, String> {
        self.record_download(id, indexes, at, Some(token))
    }

    fn record_download(
        &self,
        id: &str,
        indexes: &[usize],
        at: u64,
        ticket: Option<&str>,
    ) -> Result<OutboundDownloadResult, String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let event_at = at;
        let result = (|| {
            let (downloads, max_downloads, first_download_at, normalized, file_count): (
                i64,
                Option<i64>,
                Option<i64>,
                bool,
                i64,
            ) = transaction
                .query_row(
                    "SELECT g.downloads, g.max_downloads, g.first_download_at,
                                EXISTS (SELECT 1 FROM outbound_grant_files
                                        WHERE grant_id = g.id),
                                g.file_count
                         FROM outbound_grants AS g WHERE g.id = ?1",
                    [id],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    },
                )
                .optional()
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "outbound grant not found".to_owned())?;
            let file_count = usize::try_from(file_count)
                .map_err(|_| "outbound grant file count out of range".to_owned())?;
            let downloads = downloads.max(0) as u64;
            let max_downloads = max_downloads.and_then(|max| u64::try_from(max).ok());
            if max_downloads.is_some_and(|max| downloads >= max) {
                return Err(OUTBOUND_DOWNLOAD_LIMIT_REACHED.to_owned());
            }
            if normalized {
                let mut unique_indexes = indexes.to_vec();
                unique_indexes.sort_unstable();
                unique_indexes.dedup();
                let was_all_files_downloaded = downloads > 0;
                let first_download = first_download_at.is_none();
                let at = i64::try_from(at).unwrap_or(i64::MAX);
                let first_download_at = if first_download {
                    Some(at)
                } else {
                    first_download_at
                };
                let max_downloads =
                    max_downloads.map(|value| i64::try_from(value).unwrap_or(i64::MAX));
                let full_range = file_count > 0
                    && indexes.len() == file_count
                    && indexes.iter().copied().eq(0..file_count);
                if full_range {
                    let file_count_i64 = i64::try_from(file_count).unwrap_or(i64::MAX);
                    let changed = transaction
                        .execute(
                            "UPDATE outbound_grant_files
                             SET downloads = CASE WHEN downloads = 9223372036854775807
                                                  THEN downloads ELSE downloads + 1 END,
                                 first_download_at = COALESCE(first_download_at, ?3),
                                 last_download_at = ?3
                             WHERE grant_id = ?1
                               AND (?2 IS NULL OR downloads < ?2)",
                            rusqlite::params![id, max_downloads, at],
                        )
                        .map_err(|error| error.to_string())?;
                    if changed != file_count {
                        let (child_count, in_range_count, exhausted): (i64, i64, bool) =
                            transaction
                                .query_row(
                                    "SELECT
                                         (SELECT COUNT(*) FROM outbound_grant_files
                                          WHERE grant_id = ?1),
                                         (SELECT COUNT(*) FROM outbound_grant_files
                                          WHERE grant_id = ?1 AND file_index >= 0
                                            AND file_index < ?2),
                                         EXISTS (SELECT 1 FROM outbound_grant_files
                                          WHERE grant_id = ?1
                                            AND ?3 IS NOT NULL AND downloads >= ?3)",
                                    rusqlite::params![id, file_count_i64, max_downloads],
                                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                                )
                                .map_err(|error| error.to_string())?;
                        if child_count == file_count_i64
                            && in_range_count == file_count_i64
                            && exhausted
                        {
                            return Err(OUTBOUND_DOWNLOAD_LIMIT_REACHED.to_owned());
                        }
                        return Err("outbound file index out of range".to_owned());
                    }
                } else {
                    let mut update = transaction
                        .prepare_cached(
                            "UPDATE outbound_grant_files
                             SET downloads = CASE WHEN downloads = 9223372036854775807
                                                  THEN downloads ELSE downloads + 1 END,
                                 first_download_at = COALESCE(first_download_at, ?3),
                                 last_download_at = ?3
                             WHERE grant_id = ?1 AND file_index = ?2
                               AND (?4 IS NULL OR downloads < ?4)",
                        )
                        .map_err(|error| error.to_string())?;
                    for index in &unique_indexes {
                        let index = i64::try_from(*index).unwrap_or(i64::MAX);
                        let changed = update
                            .execute(rusqlite::params![id, index, at, max_downloads,])
                            .map_err(|error| error.to_string())?;
                        if changed == 0 {
                            let exists: bool = transaction
                                .query_row(
                                    "SELECT EXISTS (SELECT 1 FROM outbound_grant_files
                                                     WHERE grant_id = ?1 AND file_index = ?2)",
                                    rusqlite::params![id, index],
                                    |row| row.get(0),
                                )
                                .map_err(|error| error.to_string())?;
                            if exists {
                                return Err(OUTBOUND_DOWNLOAD_LIMIT_REACHED.to_owned());
                            }
                            return Err("outbound file index out of range".to_owned());
                        }
                    }
                }
                let downloads = if unique_indexes.is_empty() {
                    downloads
                } else {
                    transaction
                        .query_row(
                            "SELECT downloads FROM outbound_grant_files
                             WHERE grant_id = ?1 ORDER BY downloads LIMIT 1",
                            [id],
                            |row| row.get::<_, i64>(0),
                        )
                        .map(|value| value.max(0) as u64)
                        .map_err(|error| error.to_string())?
                };
                let completed_delivery = !was_all_files_downloaded && downloads > 0;
                transaction
                    .execute(
                        "UPDATE outbound_grants
                         SET downloads = ?2, first_download_at = ?3, last_download_at = ?4
                         WHERE id = ?1",
                        rusqlite::params![
                            id,
                            i64::try_from(downloads).unwrap_or(i64::MAX),
                            first_download_at,
                            at,
                        ],
                    )
                    .map_err(|error| error.to_string())?;
                return Ok(OutboundDownloadResult {
                    first_download,
                    completed_delivery,
                    event_at,
                });
            }
            let files_json: String = transaction
                .query_row(
                    "SELECT files_json FROM outbound_grants WHERE id = ?1",
                    [id],
                    |row| row.get(0),
                )
                .map_err(|error| error.to_string())?;
            let files: Vec<OutboundGrantFile> = serde_json::from_str(&files_json)
                .map_err(|error| format!("parse outbound grant files: {error}"))?;
            if !files.is_empty() {
                return Err("outbound grant files are not normalized".to_owned());
            }
            let mut unique_indexes = indexes.to_vec();
            unique_indexes.sort_unstable();
            unique_indexes.dedup();
            if unique_indexes.iter().any(|&index| index != 0) {
                return Err("outbound file index out of range".to_owned());
            }
            let first_download = first_download_at.is_none();
            let at = i64::try_from(at).unwrap_or(i64::MAX);
            let first_download_at = if first_download {
                Some(at)
            } else {
                first_download_at
            };
            let downloads = downloads.saturating_add(1);
            transaction
                .execute(
                    "UPDATE outbound_grants
                     SET downloads = ?2, first_download_at = ?3, last_download_at = ?4
                     WHERE id = ?1",
                    rusqlite::params![
                        id,
                        i64::try_from(downloads).unwrap_or(i64::MAX),
                        first_download_at,
                        at,
                    ],
                )
                .map_err(|error| error.to_string())?;
            Ok(OutboundDownloadResult {
                first_download,
                completed_delivery: first_download,
                event_at,
            })
        })();
        match result {
            Ok(result) => {
                if let Some(ticket) = ticket {
                    let changed = transaction.execute("UPDATE outbound_fetch_tickets SET delivered_at=COALESCE(delivered_at,?3) WHERE token_id=?1 AND grant_id=?2", rusqlite::params![ticket, id, i64::try_from(at).unwrap_or(i64::MAX)]).map_err(|error| error.to_string())?;
                    if changed != 1 {
                        return Err("fetch completion ticket does not match its grant".to_owned());
                    }
                }
                transaction.commit().map_err(|error| error.to_string())?;
                Ok(result)
            }
            Err(error) => Err(error),
        }
    }

    pub fn has_active_outbound_grant(
        &self,
        tenant: &str,
        link_id: &str,
        upload_id: &str,
        file_index: usize,
        now: u64,
    ) -> Result<bool, String> {
        self.with(|connection| {
            connection.query_row(
                "SELECT EXISTS (
                     SELECT 1 FROM outbound_grants
                     WHERE tenant = ?1 AND link_id = ?2 AND upload_id = ?3 AND file_index = ?4
                       AND revoked_at IS NULL AND expires_at > ?5
                       AND (max_downloads IS NULL OR downloads < max_downloads)
                 )",
                rusqlite::params![
                    tenant,
                    link_id,
                    upload_id,
                    i64::try_from(file_index).unwrap_or(i64::MAX),
                    i64::try_from(now).unwrap_or(i64::MAX),
                ],
                |row| row.get::<_, i64>(0),
            )
        })
        .map(|exists| exists != 0)
    }

    /// Whether the tenant owns any live (not revoked) grant whose files
    /// include the library source. Finding 380: expiry alone no longer
    /// frees a source, because extend refuses to revive an expired grant,
    /// so deletion and overwrite stay blocked until the grant is revoked.
    /// Every upload chunk asks, so it reads the source index rather than
    /// parsing every live grant's file list under the store lock.
    pub fn has_active_library_grant(&self, tenant: &str, source: &str) -> Result<bool, String> {
        self.with(|connection| {
            connection
                .prepare_cached(ACTIVE_LIBRARY_GRANT)?
                .query_row(rusqlite::params![tenant, source], |row| row.get(0))
        })
        .map_err(|error| error.to_string())
    }

    /// [`Self::has_active_library_grant`] plus, for a non-ASCII path, the
    /// Unicode case fold and normalization library volumes apply, which
    /// NOCASE lacks. Delete asks this once; it scans the tenant's live grant
    /// files, so the per-chunk upload check does not.
    // ponytail: a non-ASCII source that folds to ASCII (U+212A) is still
    // missed by an ASCII request.
    pub fn serves_library_file(&self, tenant: &str, source: &str) -> Result<bool, String> {
        if self.has_active_library_grant(tenant, source)? {
            return Ok(true);
        }
        if source.is_ascii() {
            return Ok(false);
        }
        let wanted = crate::paths::fold_name(source);
        self.with(|connection| {
            let mut statement = connection.prepare_cached(
                "SELECT f.source FROM outbound_grant_files f JOIN outbound_grants g ON g.id = f.grant_id
                 WHERE g.tenant = ?1 AND g.revoked_at IS NULL",
            )?;
            let mut rows = statement.query([tenant])?;
            while let Some(row) = rows.next()? {
                if crate::paths::fold_name(&row.get::<_, String>(0)?) == wanted {
                    return Ok(true);
                }
            }
            Ok(false)
        })
        .map_err(|error| error.to_string())
    }

    pub fn active_outbound_file_keys(
        &self,
        tenant: &str,
        link_id: &str,
        now: u64,
    ) -> Result<Vec<(String, usize)>, String> {
        self.with(|connection| {
            let mut statement = connection.prepare(
                "SELECT upload_id, file_index
                 FROM outbound_grants
                 WHERE tenant = ?1 AND link_id = ?2
                   AND revoked_at IS NULL AND expires_at > ?3
                   AND (max_downloads IS NULL OR downloads < max_downloads)",
            )?;
            let rows = statement.query_map(
                rusqlite::params![tenant, link_id, i64::try_from(now).unwrap_or(i64::MAX)],
                |row| {
                    let upload_id = row.get::<_, String>(0)?;
                    let file_index = usize::try_from(row.get::<_, i64>(1)?).map_err(|_| {
                        rusqlite::Error::FromSqlConversionFailure(
                            1,
                            rusqlite::types::Type::Integer,
                            Box::new(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "outbound grant file index is outside usize range",
                            )),
                        )
                    })?;
                    Ok((upload_id, file_index))
                },
            )?;
            rows.collect::<Result<Vec<_>, _>>()
        })
    }

    /// Returns globally referenced object keys for non-expired, non-revoked
    /// outbound grants, each with its owning grant id. Catalogs are
    /// content-addressed, so tenant is omitted.
    pub fn active_outbound_object_keys(
        &self,
        now: u64,
    ) -> Result<Vec<(String, String, String, u64)>, String> {
        self.with(|connection| {
            let mut statement = connection.prepare(
                "SELECT grants.id, grants.suite, grants.root, grants.bytes_hi, grants.bytes_lo
                 FROM outbound_grants AS grants
                 WHERE grants.revoked_at IS NULL AND grants.expires_at > ?1
                 UNION
                 SELECT files.grant_id, files.suite, files.root, files.bytes_hi, files.bytes_lo
                 FROM outbound_grant_files AS files
                 JOIN outbound_grants AS grants ON grants.id = files.grant_id
                 WHERE grants.revoked_at IS NULL AND grants.expires_at > ?1
                 ORDER BY suite, root, bytes_hi, bytes_lo",
            )?;
            let rows = statement.query_map([i64::try_from(now).unwrap_or(i64::MAX)], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    combine_byte_sums(row.get(3)?, row.get(4)?).map_err(corrupt_byte_limbs)?,
                ))
            })?;
            rows.collect::<Result<Vec<_>, _>>()
        })
    }

    pub fn link_has_active_outbound_grants(
        &self,
        tenant: &str,
        link_id: &str,
        now: u64,
    ) -> Result<bool, String> {
        self.with(|connection| {
            connection.query_row(
                "SELECT EXISTS (
                     SELECT 1 FROM outbound_grants
                     WHERE tenant = ?1 AND link_id = ?2
                       AND revoked_at IS NULL AND expires_at > ?3
                       AND (max_downloads IS NULL OR downloads < max_downloads)
                 )",
                rusqlite::params![tenant, link_id, i64::try_from(now).unwrap_or(i64::MAX),],
                |row| row.get::<_, i64>(0),
            )
        })
        .map(|exists| exists != 0)
    }
}
