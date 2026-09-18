use super::*;

#[test]
fn usable_now_requires_an_active_link_that_has_not_expired() {
    let now = now_unix();
    let mut link = test_link("usable-now");
    assert!(link.usable_now());

    link.expires_at = Some(now + 3600);
    assert!(link.usable_now());

    // Past the expiry the link is dead even though active never changed.
    link.expires_at = Some(now - 3600);
    assert!(!link.usable_now());

    link.expires_at = Some(now + 3600);
    link.active = false;
    assert!(!link.usable_now());
}

#[test]
fn legacy_upload_records_default_to_http_transport() {
    let record: UploadRecord = serde_json::from_str(
        r#"{"id":"legacy","completed_at":1,"package_root":"root","total_bytes":0,"files":[]}"#,
    )
    .unwrap();
    assert_eq!(record.transport, None);
}

#[test]
fn a_broken_table_is_an_error_not_a_panic() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    store
        .with(|connection| connection.execute_batch("DROP TABLE links"))
        .unwrap();
    // The point of the Result: a handler answers 500 and logs, instead of
    // a panicked task dropping the connection with nothing recorded.
    assert!(store.links("").is_err());
    assert!(store.link("", "any").is_err());
    assert!(store.all_links().is_err());
    // A principal that cannot be read denies the session rather than
    // admitting it.
    store
        .with(|connection| connection.execute_batch("DROP TABLE principals"))
        .unwrap();
    assert!(!store.principal_allows("user@example.com", 1));
}

#[cfg(unix)]
#[tokio::test]
async fn external_sqlite_readers_preserve_open_database_locks() {
    use std::os::unix::fs::MetadataExt as _;

    const CHILD_DATABASE: &str = "VOTPORT_TEST_EXTERNAL_DATABASE";
    const CHILD_BACKUP: &str = "VOTPORT_TEST_EXTERNAL_BACKUP";
    if let Some(path) = std::env::var_os(CHILD_DATABASE) {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let retained = matches!(
            rustix::fs::fcntl_lock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive,),
            Err(rustix::io::Errno::AGAIN | rustix::io::Errno::ACCESS)
        );
        drop(file);
        println!("database lock retained={retained}");
        let connection = Connection::open(&path).unwrap();
        let count: i64 = connection
            .query_row("SELECT count(*) FROM links", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
        if let Some(destination) = std::env::var_os(CHILD_BACKUP) {
            connection
                .execute("VACUUM INTO ?1", [destination.to_str().unwrap()])
                .unwrap();
        }
        return;
    }

    for (reopen, backup) in [(false, false), (false, true), (true, false), (true, true)] {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.insert_link(test_link("before-reader")).unwrap();
        let store = if reopen {
            drop(store);
            Store::open(directory.path()).unwrap()
        } else {
            store
        };
        let files = ["votport.db", "votport.db-wal", "votport.db-shm"]
            .map(|name| directory.path().join(name));
        let identities = files.each_ref().map(|path| {
            let metadata = std::fs::metadata(path).unwrap();
            assert_eq!(metadata.mode() & 0o777, 0o600);
            (metadata.dev(), metadata.ino())
        });
        let mut command = tokio::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "store::tests::external_sqlite_readers_preserve_open_database_locks",
                "--nocapture",
            ])
            .env(CHILD_DATABASE, &files[0])
            .env_remove(CHILD_BACKUP)
            .kill_on_drop(true);
        if backup {
            command.env(CHILD_BACKUP, directory.path().join("external.db"));
        }
        let output = tokio::time::timeout(std::time::Duration::from_secs(20), command.output())
            .await
            .expect("external SQLite reader timed out")
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
        let shared_lock =
            String::from_utf8_lossy(&output.stdout).contains("database lock retained=true");
        let locks_retained = files.iter().zip(identities).all(|(path, identity)| {
            std::fs::metadata(path)
                .is_ok_and(|metadata| (metadata.dev(), metadata.ino()) == identity)
        });
        store.insert_link(test_link("after-reader")).unwrap();
        assert!(store.link("", "after-reader").unwrap().is_some());
        let snapshot = store.backup_into(&directory.path().join("snapshot.db"));
        drop(store);
        let reopened = Store::open(directory.path()).unwrap();
        let durable = reopened.link("", "after-reader").unwrap().is_some();
        assert!(shared_lock && locks_retained && snapshot.is_ok() && durable,
                "reopen={reopen}, external backup={backup}: shared lock={shared_lock}, database/WAL identities retained={locks_retained}, snapshot={snapshot:?}, acknowledged write survived={durable}");
    }
}

#[test]
fn delivered_candidates_match_full_identity_and_seek_past_aliases() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    for suite in [1, 2] {
        for length in [0, u64::from(u32::MAX), 1_u64 << 32, u64::MAX] {
            let object = ObjectId {
                suite,
                root: [7; 32],
                length,
            };
            store.with(|c| {
                    c.execute("DELETE FROM files", [])?;
                    let mut insert = c.prepare("INSERT INTO files (tenant, link_id, upload_id, file_index, bytes_hi, bytes_lo, deleted, stored_as, path, suite, root, receipt) VALUES (?1, ?2, ?3, 0, ?4, ?5, ?6, ?7, 'original', ?8, ?9, 1)")?;
                    for variant in 0..8 {
                        let (hi, lo) = split_bytes(if variant == 5 { length ^ (1_u64 << 32) } else if variant == 6 { length ^ 1 } else { length });
                        insert.execute(rusqlite::params![
                            if variant == 1 { "other" } else { "tenant" },
                            if variant == 2 { "other" } else { "link" },
                            variant.to_string(), hi, lo, variant == 7, format!("candidate-{variant}"),
                            crate::session::suite_name(if variant == 3 { 3 - suite } else { suite }),
                            hex::encode(if variant == 4 { [8; 32] } else { object.root }),
                        ])?;
                    }
                    Ok(())
                }).unwrap();
            assert_eq!(
                store
                    .delivered_candidates("tenant", "link", &object, "")
                    .unwrap(),
                [("candidate-0".into(), true)]
            );
            assert!(store
                .delivered_candidates("tenant", "link", &object, "candidate-0")
                .unwrap()
                .is_empty());
            store.with(|c| {
                    let (hi, lo) = split_bytes(length);
                    let mut insert = c.prepare("INSERT INTO files (tenant, link_id, upload_id, file_index, bytes_hi, bytes_lo, deleted, stored_as, path, suite, root, receipt) VALUES ('tenant', 'link', ?1, 0, ?2, ?3, 0, 'a-alias', 'original', ?4, ?5, 0)")?;
                    for i in 0..DELIVERED_CANDIDATE_PAGE * 2 + 1 {
                        insert.execute(rusqlite::params![format!("alias-{i}"), hi, lo, crate::session::suite_name(suite), hex::encode(object.root)])?;
                    }
                    Ok(())
                }).unwrap();
            let page = store
                .delivered_candidates("tenant", "link", &object, "")
                .unwrap();
            assert_eq!(page.len(), DELIVERED_CANDIDATE_PAGE);
            assert!(page.iter().all(|row| row == &("a-alias".into(), false)));
            assert_eq!(
                store
                    .delivered_candidates("tenant", "link", &object, &page.last().unwrap().0)
                    .unwrap(),
                [("candidate-0".into(), true)]
            );
        }
    }
}

pub(crate) fn test_link(id: &str) -> Link {
    Link {
        retention_days: None,
        id: id.to_owned(),
        tenant: String::new(),
        label: "test".to_owned(),
        dest: String::new(),
        password_hash: None,
        created_at: 0,
        expires_at: None,
        max_bytes: None,
        active: true,
        legal_hold: false,

        notifications: None,
        uploads: Vec::new(),
        events: Vec::new(),
    }
}

pub(crate) fn link_in(tenant: &str, id: &str) -> Link {
    Link {
        tenant: tenant.to_owned(),
        ..test_link(id)
    }
}

pub(crate) fn test_tenant(key: &str) -> Tenant {
    Tenant {
        retention_days: None,
        incarnation: String::new(),
        key: key.to_owned(),
        label: key.to_owned(),
        admin_group: None,
        max_total_bytes: None,
        max_links: None,
        max_sessions: None,
        created_at: 0,
    }
}

pub(crate) fn test_outbound_grant(id: &str, tenant: &str, file_index: usize) -> OutboundGrant {
    OutboundGrant {
        id: id.to_owned(),
        token_hash: format!("hash-{id}"),
        password_hash: None,
        tenant: tenant.to_owned(),
        link_id: "link".to_owned(),
        upload_id: "upload".to_owned(),
        package_root: "package".to_owned(),
        name: "file.bin".to_owned(),
        suite: "blake3".to_owned(),
        root: format!("root-{id}"),
        file_index,
        bytes: u64::MAX,
        label: "download".to_owned(),
        created_at: 10,
        expires_at: 20,
        revoked_at: None,
        downloads: 0,
        max_downloads: None,

        notifications: None,
        first_download_at: None,
        last_download_at: None,
        files: Vec::new(),
    }
}

#[test]
fn tenant_incarnation_survives_updates_and_reopen_but_not_recreation() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    store.insert_tenant(test_tenant("acme")).unwrap();
    let mut tenant = store.tenant("acme").unwrap().unwrap();
    let incarnation = tenant.incarnation.clone();
    assert_eq!(hex::decode(&incarnation).unwrap().len(), 16);
    tenant.label = "updated".into();
    tenant.incarnation = "must-not-replace".into();
    assert!(store.update_tenant(&tenant).unwrap());
    assert_eq!(
        store.tenant("acme").unwrap().unwrap().incarnation,
        incarnation
    );
    drop(store);
    let store = Store::open(directory.path()).unwrap();
    assert_eq!(
        store.tenant("acme").unwrap().unwrap().incarnation,
        incarnation
    );
    assert_eq!(store.remove_tenant("acme").unwrap(), TenantRemoval::Deleted);
    store.insert_tenant(test_tenant("acme")).unwrap();
    let replacement = store.tenant("acme").unwrap().unwrap();
    assert_eq!(replacement.created_at, tenant.created_at);
    assert_ne!(replacement.incarnation, incarnation);
}

#[test]
fn tenant_removal_clears_retained_uploads_atomically_and_only_in_that_tenant() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let residue = |tenant: &str| {
        store.with(|connection| {
                connection.execute("INSERT INTO link_uploads(link_id,tenant,upload_id,document,file_count) VALUES (?1,?1,'retained','{}',1)", [tenant])?;
                connection.execute("INSERT INTO files(link_id,tenant,upload_id,file_index,bytes_hi,bytes_lo,stored_as,path,suite,root,receipt) VALUES (?1,?1,'retained',0,0,8,'frame','frame','blake3','aa',0)", [tenant])
            }).unwrap();
    };
    let retained = |tenant: &str| {
        store.with(|connection| connection.query_row(
                "SELECT (SELECT count(*) FROM link_uploads WHERE tenant=?1),(SELECT count(*) FROM files WHERE tenant=?1)", [tenant],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )).unwrap()
    };
    for key in ["acme", "other"] {
        store.insert_tenant(test_tenant(key)).unwrap();
        residue(key);
    }
    assert_eq!(store.tenant_received_bytes("acme").unwrap(), 8);
    let object = vot_sdk::object::ObjectId {
        suite: 1,
        root: [7; 32],
        length: 8,
    };
    for (id, tenant, committed) in [
        ("pending", "acme", false),
        ("committed", "acme", true),
        ("other", "other", false),
    ] {
        store
            .insert_upload_session(&PersistedUploadSession {
                id: id.into(),
                tenant: tenant.into(),
                link_id: "removed-link".into(),
                push_key: None,
                committed_upload_id: None,
                dest_dir: directory.path().join(tenant),
                dest_rel: String::new(),
                package: object.clone(),
                max_total_bytes: None,
                started_at: 0,
                files: vec![PersistedUploadFile {
                    entry: 0,
                    display_path: "frame".into(),
                    stored_components: vec!["frame".into()],
                    object: object.clone(),
                    staging_path: Default::default(),
                    journal_path: Default::default(),
                    incarnation: [0; 16],
                    profile: vot_sdk_file::CommitProfile::Balanced,
                    nas_contract: vot_sdk_file::NasContract::Unqualified,
                    prefix_bytes: 0,
                    published: false,
                    receipt: false,
                }],
            })
            .unwrap();
        if committed {
            store
                .with(|connection| {
                    connection.execute(
                        "UPDATE upload_sessions SET committed_upload_id='finished' WHERE id=?1",
                        [id],
                    )
                })
                .unwrap();
        }
    }
    store.with(|connection| connection.execute_batch("CREATE TRIGGER fail_upload_removal BEFORE DELETE ON upload_session_files WHEN OLD.session_id='pending' BEGIN SELECT RAISE(ABORT, 'fixture'); END;")).unwrap();
    assert!(store.remove_tenant("acme").is_err());
    assert!(store.tenant("acme").unwrap().is_some());
    assert_eq!(store.tenant_received_bytes("acme").unwrap(), 8);
    assert_eq!(retained("acme"), (1, 1));
    assert_eq!(retained("other"), (1, 1));
    assert_eq!(store.load_upload_sessions().unwrap().len(), 3);
    assert_eq!(
        store
            .with(|connection| connection.query_row(
                "SELECT COUNT(*) FROM upload_session_files",
                [],
                |row| row.get::<_, i64>(0)
            ))
            .unwrap(),
        3
    );
    store
        .with(|connection| connection.execute_batch("DROP TRIGGER fail_upload_removal;"))
        .unwrap();
    assert_eq!(store.remove_tenant("acme").unwrap(), TenantRemoval::Deleted);
    assert_eq!(retained("acme"), (0, 0));
    assert_eq!(retained("other"), (1, 1));
    residue("acme");
    assert_eq!(store.remove_tenant("acme").unwrap(), TenantRemoval::Absent);
    assert_eq!(retained("acme"), (0, 0));
    assert_eq!(retained("other"), (1, 1));
    let remaining = store.load_upload_sessions().unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].tenant, "other");
    assert_eq!(
        store
            .with(|connection| connection.query_row(
                "SELECT COUNT(*) FROM upload_session_files",
                [],
                |row| row.get::<_, i64>(0)
            ))
            .unwrap(),
        1
    );
    store.insert_tenant(test_tenant("acme")).unwrap();
    assert!(store.tenant_admission_usage("acme").unwrap().1.is_empty());
    assert_eq!(store.tenant_admission_usage("other").unwrap().1.len(), 1);
}

#[test]
fn grant_insertion_refuses_ambiguous_and_nonportable_names() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let mut grant = test_outbound_grant("ambiguous", "", 0);
    for name in ["XML:EDL/file.mov", "CON.txt", "clip.mov."] {
        grant.name = name.into();
        assert!(store
            .insert_outbound_grant(grant.clone())
            .unwrap_err()
            .contains("not portable"));
    }
    grant.files = ["Café.mov", "Cafe\u{301}.mov"]
        .into_iter()
        .map(|name| OutboundGrantFile {
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
    assert!(store
        .insert_outbound_grant(grant.clone())
        .unwrap_err()
        .contains("collide"));
    assert!(store.outbound_grants("").unwrap().is_empty());
    grant.files[1].name = "second.mov".into();
    store.insert_outbound_grant(grant.clone()).unwrap();
    assert_eq!(store.outbound_grants("").unwrap(), vec![grant]);
}

#[test]
fn automation_tokens_preserve_permissions_across_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    store
        .insert_automation_token(test_automation_token("agent", "tenant"))
        .unwrap();
    drop(store);
    let reopened = Store::open(directory.path()).unwrap();
    let token = reopened
        .authenticate_automation_token("hash-agent", 15)
        .unwrap()
        .unwrap();
    assert_eq!(token.tenant, "tenant");
    assert_eq!(token.permissions, ["deliveries:create"]);
    assert!(reopened
        .automation_operation("agent", "missing")
        .unwrap()
        .is_none());
}

fn test_automation_token(id: &str, tenant: &str) -> AutomationToken {
    AutomationToken {
        id: id.to_owned(),
        token_hash: format!("hash-{id}"),
        tenant: tenant.to_owned(),
        label: format!("Token {id}"),
        directory: None,
        permissions: vec!["deliveries:create".to_owned()],
        created_by: String::new(),
        created_at: 10,
        expires_at: 20,
        revoked_at: None,
        last_used_at: None,
    }
}

#[test]
fn outbound_grants_round_trip_full_byte_range() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let schema = store
        .with(|connection| {
            connection.query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |row| row.get::<_, String>(0),
            )
        })
        .unwrap();
    assert_eq!(schema, SCHEMA_VERSION.to_string());
    assert!(store
            .with(|connection| {
                connection.query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'outbound_grants'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
            })
            .unwrap() > 0);

    let grant = test_outbound_grant("g1", "acme", 3);
    store.insert_outbound_grant(grant.clone()).unwrap();
    assert_eq!(store.outbound_grants("acme").unwrap(), vec![grant]);
}

#[test]
fn outbound_summary_counts_open_links_deliveries_and_active_downloads() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let open = test_outbound_grant("open", "acme", 1);
    let mut used = test_outbound_grant("used", "acme", 1);
    used.downloads = 2;
    used.max_downloads = Some(2);
    let mut revoked = test_outbound_grant("gone", "acme", 1);
    revoked.revoked_at = Some(5);
    let other = test_outbound_grant("other", "beta", 1);
    for grant in [open.clone(), used, revoked, other] {
        store.insert_outbound_grant(grant).unwrap();
    }
    // The status handler keeps the part of each in-flight key before the
    // first colon: the grant's token hash.
    let active = vec![open.token_hash.clone(), "hash-other".to_owned()];
    let summary = store.outbound_summary("acme", 10, &active).unwrap();
    assert_eq!(summary.open_grants, 1, "used and revoked are not open");
    assert_eq!(summary.deliveries, 2);
    assert_eq!(summary.active, 1, "the other tenant's download is not ours");
    assert_eq!(store.outbound_active_count("acme", &active).unwrap(), 1);
    let expired = store.outbound_summary("acme", 25, &[]).unwrap();
    assert_eq!(expired.open_grants, 0);
    assert_eq!(expired.active, 0);
}

#[test]
fn uploads_since_preserves_u64_max_and_saturates_sum_overflow() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let upload = |id: &str, total_bytes| UploadRecord {
        id: id.to_owned(),
        started_at: 1,
        completed_at: 10,
        replayed_chunks: 0,
        rejected_chunks: 0,
        transport: None,
        package_root: String::new(),
        total_bytes,
        files: Vec::new(),
        partial: false,
        log: Vec::new(),
    };
    let mut first = test_link("first");
    first.uploads = vec![upload("max", u64::MAX)];
    store.insert_link(first).unwrap();
    assert_eq!(store.uploads_since("", 0).unwrap(), (1, u64::MAX));

    let mut second = test_link("second");
    second.uploads = vec![upload("one", 1)];
    store.insert_link(second).unwrap();
    assert_eq!(store.uploads_since("", 0).unwrap(), (2, u64::MAX));
}

#[test]
fn outbound_grants_round_trip_multiple_library_files() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let mut grant = test_outbound_grant("library", "acme", 0);
    grant.files = vec![
        OutboundGrantFile {
            source: "objects/a".to_owned(),
            name: "a.txt".to_owned(),
            suite: "blake3".to_owned(),
            root: "aa".to_owned(),
            bytes: 3,
            receipt_b64: "receipt-a".to_owned(),
            downloads: 0,
            first_download_at: None,
            last_download_at: None,
        },
        OutboundGrantFile {
            source: "objects/b".to_owned(),
            name: "b.txt".to_owned(),
            suite: "sha256".to_owned(),
            root: "bb".to_owned(),
            bytes: u64::MAX,
            receipt_b64: "receipt-b".to_owned(),
            downloads: 0,
            first_download_at: None,
            last_download_at: None,
        },
    ];
    store.insert_outbound_grant(grant.clone()).unwrap();
    assert_eq!(
        store.outbound_grant_by_token_hash("hash-library").unwrap(),
        Some(grant)
    );
    store.record_outbound_download("library", &[0], 30).unwrap();
    assert_eq!(
        store
            .with(|connection| connection.query_row(
                "SELECT file_count FROM outbound_grants WHERE id = 'library'",
                [],
                |row| row.get::<_, i64>(0),
            ))
            .unwrap(),
        2
    );
    let page = store.outbound_grants_page("acme", 10, 0, 2).unwrap().0;
    assert_eq!(page[0].0.files[0].downloads, 1);
}

#[test]
fn normalized_file_lookup_and_download_do_not_parse_or_rewrite_manifest() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let mut grant = test_outbound_grant("normalized", "acme", 0);
    grant.files = (0..3)
        .map(|index| OutboundGrantFile {
            source: format!("objects/{index}"),
            name: format!("file-{index}"),
            suite: "blake3".to_owned(),
            root: format!("root-{index}"),
            bytes: if index == 2 { u64::MAX } else { index + 1 },
            receipt_b64: format!("receipt-{index}"),
            downloads: 0,
            first_download_at: None,
            last_download_at: None,
        })
        .collect();
    store.insert_outbound_grant(grant.clone()).unwrap();
    let original_json: String = store
        .with(|connection| {
            connection.query_row(
                "SELECT files_json FROM outbound_grants WHERE id = 'normalized'",
                [],
                |row| row.get(0),
            )
        })
        .unwrap();
    store
            .with(|connection| {
                connection.execute(
                    "UPDATE outbound_grants SET files_json = 'deliberately invalid' WHERE id = 'normalized'",
                    [],
                )
            })
            .unwrap();
    let (_, file) = store
        .outbound_grant_file_by_token_hash("hash-normalized", 2)
        .unwrap()
        .unwrap();
    assert_eq!(file.unwrap().bytes, u64::MAX);
    store
        .record_outbound_download("normalized", &[2], 30)
        .unwrap();
    let current_json: String = store
        .with(|connection| {
            connection.query_row(
                "SELECT files_json FROM outbound_grants WHERE id = 'normalized'",
                [],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert_eq!(current_json, "deliberately invalid");
    store
        .with(|connection| {
            connection.execute(
                "UPDATE outbound_grants SET files_json = ?1 WHERE id = 'normalized'",
                [&original_json],
            )
        })
        .unwrap();
    let full = store
        .outbound_grant_by_token_hash("hash-normalized")
        .unwrap()
        .unwrap();
    assert_eq!(full.files[2].downloads, 1);
    store
        .with(|connection| {
            connection.execute(
                "UPDATE outbound_grant_files SET downloads = 9223372036854775807
                     WHERE grant_id = 'normalized' AND file_index = 2",
                [],
            )
        })
        .unwrap();
    store
        .record_outbound_download("normalized", &[2], 31)
        .unwrap();
    let saturated: i64 = store
        .with(|connection| {
            connection.query_row(
                "SELECT downloads FROM outbound_grant_files
                     WHERE grant_id = 'normalized' AND file_index = 2",
                [],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert_eq!(saturated, i64::MAX);
}

#[test]
fn legacy_file_lookup_allows_only_scalar_index_zero() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    store
        .insert_outbound_grant(test_outbound_grant("legacy-lookup", "acme", 0))
        .unwrap();
    let (grant, file) = store
        .outbound_grant_file_by_token_hash("hash-legacy-lookup", 0)
        .unwrap()
        .unwrap();
    assert_eq!(grant.id, "legacy-lookup");
    assert!(file.is_none());
    assert!(store
        .outbound_grant_file_by_token_hash("hash-legacy-lookup", 1)
        .unwrap()
        .is_none());

    let mut normalized = test_outbound_grant("missing-child", "acme", 0);
    normalized.files = vec![OutboundGrantFile {
        source: "objects/only".to_owned(),
        name: "only".to_owned(),
        suite: "blake3".to_owned(),
        root: "root".to_owned(),
        bytes: 1,
        receipt_b64: String::new(),
        downloads: 0,
        first_download_at: None,
        last_download_at: None,
    }];
    store.insert_outbound_grant(normalized).unwrap();
    store
        .with(|connection| {
            connection.execute(
                "DELETE FROM outbound_grant_files WHERE grant_id = 'missing-child'",
                [],
            )
        })
        .unwrap();
    assert!(store
        .outbound_grant_file_by_token_hash("hash-missing-child", 0)
        .unwrap()
        .is_none());
    let page = store
        .outbound_grant_files_page_by_token_hash("hash-missing-child", 0, 100)
        .unwrap()
        .unwrap();
    assert!(page.files.is_empty());
}

#[test]
fn protected_outbound_grant_password_round_trips() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let mut grant = test_outbound_grant("protected", "acme", 0);
    grant.password_hash = Some("argon2id-hash".to_owned());

    store.insert_outbound_grant(grant.clone()).unwrap();

    assert_eq!(
        store
            .outbound_grant_by_token_hash("hash-protected")
            .unwrap(),
        Some(grant)
    );
}

#[test]
fn outbound_grants_are_tenant_scoped_and_hash_lookup_is_global() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    store
        .insert_outbound_grant(test_outbound_grant("g1", "acme", 0))
        .unwrap();
    store
        .insert_outbound_grant(test_outbound_grant("g2", "other", 1))
        .unwrap();

    assert_eq!(store.outbound_grants("acme").unwrap().len(), 1);
    assert_eq!(
        store
            .outbound_grant_by_token_hash("hash-g1")
            .unwrap()
            .unwrap()
            .id,
        "g1"
    );
}

#[test]
fn active_library_grants_match_source_with_tenant_and_revocation_scope() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let mut active = test_outbound_grant("active", "acme", 0);
    active.files = vec![OutboundGrantFile {
        source: "project/file.bin".to_owned(),
        name: "file.bin".to_owned(),
        suite: "blake3".to_owned(),
        root: "root".to_owned(),
        bytes: 1,
        receipt_b64: "receipt".to_owned(),
        downloads: 0,
        first_download_at: None,
        last_download_at: None,
    }];
    store.insert_outbound_grant(active).unwrap();

    let mut other = test_outbound_grant("other", "other", 0);
    other.files = vec![OutboundGrantFile {
        source: "other/file.bin".to_owned(),
        name: "file.bin".to_owned(),
        suite: "blake3".to_owned(),
        root: "root".to_owned(),
        bytes: 1,
        receipt_b64: "receipt".to_owned(),
        downloads: 0,
        first_download_at: None,
        last_download_at: None,
    }];
    store.insert_outbound_grant(other).unwrap();

    // Finding 380: expiry and exhausted downloads no longer free a source
    // for deletion or overwrite (extend refuses to revive an expired grant);
    // only revocation does.
    for (id, revoked_at, expires_at, downloads, max_downloads) in [
        ("expired", None, Some(14), 0, None),
        ("revoked", Some(12), Some(20), 0, None),
        ("spent", None, Some(20), 1, Some(1)),
    ] {
        let mut grant = test_outbound_grant(id, "acme", 0);
        grant.files = vec![OutboundGrantFile {
            source: "ignored/file.bin".to_owned(),
            name: "file.bin".to_owned(),
            suite: "blake3".to_owned(),
            root: "root".to_owned(),
            bytes: 1,
            receipt_b64: "receipt".to_owned(),
            downloads: 0,
            first_download_at: None,
            last_download_at: None,
        }];
        grant.revoked_at = revoked_at;
        grant.expires_at = expires_at.unwrap();
        grant.downloads = downloads;
        grant.max_downloads = max_downloads;
        store.insert_outbound_grant(grant).unwrap();
    }

    assert!(store
        .has_active_library_grant("acme", "project/file.bin")
        .unwrap());
    assert!(!store
        .has_active_library_grant("other", "project/file.bin")
        .unwrap());
    // Expired and download-spent grants still pin their sources; revoking
    // every non-revoked grant is what frees the files again.
    assert!(store
        .has_active_library_grant("acme", "ignored/file.bin")
        .unwrap());
    assert!(store.revoke_outbound_grant("acme", "expired", 15).unwrap());
    // "spent" is still non-revoked, so the source stays pinned...
    assert!(store
        .has_active_library_grant("acme", "ignored/file.bin")
        .unwrap());
    // ...until the last pinning grant is revoked.
    assert!(store.revoke_outbound_grant("acme", "spent", 15).unwrap());
    assert!(!store
        .has_active_library_grant("acme", "ignored/file.bin")
        .unwrap());
}

#[test]
fn purge_expired_revoked_grants_drops_traces_keeps_live_and_signed() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let mut dead = test_outbound_grant("dead", "acme", 0);
    dead.expires_at = 50;
    dead.revoked_at = Some(40);
    store.insert_outbound_grant(dead).unwrap();
    // Revoked but not yet expired: traces stay until the window closes.
    let mut fresh = test_outbound_grant("fresh", "acme", 0);
    fresh.expires_at = 500;
    fresh.revoked_at = Some(40);
    store.insert_outbound_grant(fresh).unwrap();
    // Expired but never revoked: still deliverable history (finding 380).
    let mut live = test_outbound_grant("live", "acme", 0);
    live.expires_at = 50;
    store.insert_outbound_grant(live).unwrap();
    // Revoked and expired, but its delivery job has not retired yet: the
    // retirement sweep and reprocessing still read the grant row. A twin
    // ("gone") has a retired job and loses its row like "dead".
    let mut jobbed = test_outbound_grant("jobbed", "acme", 0);
    jobbed.expires_at = 50;
    jobbed.revoked_at = Some(40);
    store.insert_outbound_grant(jobbed).unwrap();
    let mut gone = test_outbound_grant("gone", "acme", 0);
    gone.expires_at = 50;
    gone.revoked_at = Some(40);
    store.insert_outbound_grant(gone).unwrap();
    store
        .with(|connection| {
            connection.execute_batch(
                "INSERT INTO delivery_jobs(id,tenant,actor,operation_id,project_id,state,not_before,token,document,created_at)
                 VALUES ('jobbed','acme','alice','op1','project','queued',0,'t','{}',10),
                        ('gone','acme','alice','op2','project','retired',0,'t2','{}',10);
                 INSERT INTO outbound_grant_files(grant_id,file_index,source,name,suite,root,bytes_hi,bytes_lo,receipt_b64) VALUES
                     ('dead',0,'project/file.bin','file.bin','blake3','root',0,1,'r'),
                     ('fresh',0,'project/file.bin','file.bin','blake3','root',0,1,'r'),
                     ('live',0,'project/file.bin','file.bin','blake3','root',0,1,'r'),
                     ('gone',0,'project/file.bin','file.bin','blake3','root',0,1,'r');
                 INSERT INTO delivery_manifests(grant_id,digest) VALUES ('orphan','digest');
                 INSERT INTO delivery_evidence(id,grant_id,holder,kind,received_at,document) VALUES
                     ('e1','dead','holder','accepted',10,'{}'),
                     ('e2','gone','holder','accepted',10,'{}');
                 INSERT INTO delivery_policy_cache(grant_id,protected) VALUES
                     ('dead',0),('orphan',1);
                 INSERT INTO outbound_grant_manifests(grant_id,manifest_root,created_at) VALUES
                     ('dead','mroot',10),('gone','mroot',10);
                 INSERT INTO outbound_fetch_tickets(token_id,grant_id,manifest_root,expires_at) VALUES
                     ('t1','dead','mroot',500),('t2','orphan','mroot',500);
                 INSERT INTO delivery_events(tenant,grant_id,kind,created_at,payload,previous_hash,hash,issuer,signature) VALUES
                     ('acme','dead','delivery_revoked',40,'{}','p','h','i','s');",
            )
        })
        .unwrap();

    let purged = store.purge_expired_revoked_grants(100).unwrap();
    assert_eq!(purged, 2);
    let survivors: Vec<String> = store
        .with(|connection| {
            let mut statement = connection.prepare("SELECT id FROM outbound_grants ORDER BY id")?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
            rows.collect::<rusqlite::Result<_>>()
        })
        .unwrap();
    assert_eq!(survivors, ["fresh", "jobbed", "live"]);
    store
        .with(|connection| {
            for table in [
                "outbound_grant_files",
                "delivery_manifests",
                "delivery_evidence",
                "delivery_policy_cache",
                "outbound_grant_manifests",
                "outbound_fetch_tickets",
            ] {
                let grants: Vec<String> = connection
                    .prepare(&format!("SELECT DISTINCT grant_id FROM {table}"))
                    .unwrap()
                    .query_map([], |row| row.get::<_, String>(0))
                    .unwrap()
                    .collect::<rusqlite::Result<_>>()
                    .unwrap();
                assert!(
                    grants
                        .iter()
                        .all(|grant| { grant == "fresh" || grant == "live" || grant == "jobbed" }),
                    "{table} still holds {grants:?}"
                );
            }
            // The signed delivery event survives the purge of its grant row.
            let events: i64 = connection
                .query_row("SELECT COUNT(*) FROM delivery_events", [], |row| row.get(0))
                .unwrap();
            assert_eq!(events, 1);
            Ok(())
        })
        .unwrap();
}

#[test]
fn delivery_storage_deletion_refuses_jobs_and_trade_routes() {
    // Finding 381: delivery storage connections were undeletable. Removal
    // works once no non-retired job references the connection, and stored
    // credentials go with it.
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let folder: crate::api::outbound::workflows::storage::Storage = serde_json::from_str(
        r#"{"id":"archive","revision":0,"label":"Archive","kind":"s3",
            "endpoint":"https://s3.example.com","bucket":"bucket","region":"us-east-1",
            "kms_key_id":null,"tenants":[],"enabled":true}"#,
    )
    .unwrap();
    let saved = store
        .save_delivery_storage(
            "alice",
            folder,
            Some(
                crate::api::outbound::workflows::storage::Credentials::AccessKey {
                    access_key_id: "key".into(),
                    secret_access_key: "secret".into(),
                    session_token: None,
                },
            ),
        )
        .unwrap();
    assert!(store.delivery_storage_has_credentials("archive").unwrap());
    assert_eq!(saved.revision, 1);

    // A queued job still importing from, or delivering to, the connection
    // pins it; a retired job does not.
    store
        .with(|connection| {
            connection.execute_batch(
                "INSERT INTO delivery_jobs(id,tenant,actor,operation_id,project_id,state,not_before,token,document,created_at) VALUES
                     ('job-queued','acme','alice','op1','project','queued',0,'t',
                      '{\"project\":{\"destinations\":[\"archive\"]}}',10),
                     ('job-retired','acme','alice','op2','project','retired',0,'t2',
                      '{\"request\":{\"import\":{\"storage_id\":\"archive\"}}}',10);
                 INSERT INTO trade_routes(id,tenant,direction,peer_key,endpoint,document,credential)
                 VALUES ('routed','acme','outbound','peer','https://peer.example','{}','{}');",
            )
        })
        .unwrap();

    assert_eq!(
        store.delete_delivery_storage("archive").unwrap(),
        crate::store::DeliveryStorageRemoval::JobsAttached
    );
    assert_eq!(store.delivery_storages().unwrap().len(), 1);

    // A trade route owns its id; the store refuses and the page says so.
    assert_eq!(
        store.delete_delivery_storage("routed").unwrap(),
        crate::store::DeliveryStorageRemoval::PairedTradeRoute
    );

    // Unknown ids answer Absent so the handler can 404.
    assert_eq!(
        store.delete_delivery_storage("nope").unwrap(),
        crate::store::DeliveryStorageRemoval::Absent
    );

    // Once every referencing job has retired, the connection and its stored
    // credentials go together.
    store
        .with(|connection| {
            connection.execute(
                "UPDATE delivery_jobs SET state='retired' WHERE id='job-queued'",
                [],
            )
        })
        .unwrap();
    assert_eq!(
        store.delete_delivery_storage("archive").unwrap(),
        crate::store::DeliveryStorageRemoval::Deleted
    );
    assert!(store.delivery_storages().unwrap().is_empty());
    assert!(!store.delivery_storage_has_credentials("archive").unwrap());
}

#[test]
fn outbound_grants_page_is_newest_first_bounded_and_tenant_scoped() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    for id in ["g1", "g2", "g3"] {
        store
            .insert_outbound_grant(test_outbound_grant(id, "acme", 0))
            .unwrap();
    }
    store
        .insert_outbound_grant(test_outbound_grant("other", "other", 0))
        .unwrap();

    let page = store.outbound_grants_page("acme", 2, 0, 64).unwrap();
    assert_eq!(page.1, 3);
    assert_eq!(
        page.0
            .into_iter()
            .map(|(grant, _)| grant.id)
            .collect::<Vec<_>>(),
        ["g3", "g2"]
    );
    assert_eq!(
        store
            .outbound_grants_page("acme", 2, 2, 64)
            .unwrap()
            .0
            .into_iter()
            .map(|(grant, _)| grant.id)
            .collect::<Vec<_>>(),
        ["g1"]
    );
    assert!(store
        .outbound_grants_page("acme", 2, 3, 64)
        .unwrap()
        .0
        .is_empty());
    assert_eq!(store.outbound_grants_page("other", 2, 0, 64).unwrap().1, 1);
}

#[test]
fn outbound_grants_page_reports_counts_and_bounds_file_previews() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let legacy = test_outbound_grant("legacy", "acme", 0);
    store.insert_outbound_grant(legacy).unwrap();
    let mut small = test_outbound_grant("small", "acme", 0);
    small.files = (0..2)
        .map(|index| OutboundGrantFile {
            source: format!("small-{index}"),
            name: format!("small-{index}.txt"),
            suite: "blake3".to_owned(),
            root: format!("small-root-{index}"),
            bytes: index + 1,
            receipt_b64: "receipt".to_owned(),
            downloads: 0,
            first_download_at: None,
            last_download_at: None,
        })
        .collect();
    store.insert_outbound_grant(small).unwrap();
    let mut large = test_outbound_grant("large", "acme", 0);
    large.files = (0..3)
        .map(|index| OutboundGrantFile {
            source: format!("large-{index}"),
            name: format!("large-{index}.txt"),
            suite: "blake3".to_owned(),
            root: format!("large-root-{index}"),
            bytes: index + 1,
            receipt_b64: "receipt".to_owned(),
            downloads: 0,
            first_download_at: None,
            last_download_at: None,
        })
        .collect();
    store.insert_outbound_grant(large).unwrap();

    let counts = store
        .with(|connection| {
            let mut statement = connection.prepare(
                "SELECT id, file_count FROM outbound_grants WHERE tenant = 'acme' ORDER BY id",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?;
            rows.collect::<Result<Vec<_>, _>>()
        })
        .unwrap();
    assert_eq!(
        counts,
        [
            ("large".to_owned(), 3),
            ("legacy".to_owned(), 1),
            ("small".to_owned(), 2),
        ]
    );

    let page = store.outbound_grants_page("acme", 10, 0, 2).unwrap().0;
    let find = |id: &str| page.iter().find(|(grant, _)| grant.id == id).unwrap();
    let (legacy, legacy_count) = find("legacy");
    assert_eq!(*legacy_count, 1);
    assert!(legacy.files.is_empty());
    let (small, small_count) = find("small");
    assert_eq!(*small_count, 2);
    assert_eq!(small.files.len(), 2);
    let (large, large_count) = find("large");
    assert_eq!(*large_count, 3);
    assert!(large.files.is_empty());
}

#[test]
fn automation_tokens_round_trip_and_list_by_tenant() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let token = test_automation_token("t1", "acme");
    store.insert_automation_token(token.clone()).unwrap();
    store
        .insert_automation_token(test_automation_token("t2", "other"))
        .unwrap();

    assert_eq!(
        store.automation_tokens("acme", "", 100).unwrap(),
        vec![token]
    );
    assert!(store
        .automation_tokens("missing", "", 100)
        .unwrap()
        .is_empty());
}

#[test]
fn remove_tenant_cleans_outbound_credentials_atomically() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    store.insert_tenant(test_tenant("acme")).unwrap();
    let mut grant = test_outbound_grant("grant", "acme", 0);
    grant.files = vec![OutboundGrantFile {
        source: "objects/file".to_owned(),
        name: "file".to_owned(),
        suite: "blake3".to_owned(),
        root: "root".to_owned(),
        bytes: 1,
        receipt_b64: String::new(),
        downloads: 0,
        first_download_at: None,
        last_download_at: None,
    }];
    store.insert_outbound_grant(grant).unwrap();
    store
        .insert_automation_token(test_automation_token("token", "acme"))
        .unwrap();
    store
            .with(|connection| {
                connection.execute(
                    "INSERT INTO outbound_grant_manifests(grant_id,manifest_root,created_at) VALUES ('grant','root',1)",
                    [],
                )?;
                connection.execute(
                    "INSERT INTO outbound_fetch_tickets(token_id,grant_id,manifest_root,expires_at) VALUES ('ticket','grant','root',2)",
                    [],
                )?;
                Ok(())
            })
            .unwrap();

    assert_eq!(store.remove_tenant("acme").unwrap(), TenantRemoval::Deleted);
    assert!(store.outbound_grants("acme").unwrap().is_empty());
    assert!(store
        .outbound_grant_by_token_hash("hash-grant")
        .unwrap()
        .is_none());
    assert_eq!(
        store
            .with(|connection| connection.query_row(
                "SELECT COUNT(*) FROM outbound_grant_files",
                [],
                |row| row.get::<_, i64>(0),
            ))
            .unwrap(),
        0
    );
    assert_eq!(
        store
            .with(|connection| connection.query_row(
                "SELECT COUNT(*) FROM outbound_grant_manifests",
                [],
                |row| row.get::<_, i64>(0),
            ))
            .unwrap(),
        0
    );
    assert_eq!(
        store
            .with(|connection| connection.query_row(
                "SELECT COUNT(*) FROM outbound_fetch_tickets",
                [],
                |row| row.get::<_, i64>(0),
            ))
            .unwrap(),
        0
    );
    assert!(store.automation_tokens("acme", "", 100).unwrap().is_empty());
    assert!(store
        .authenticate_automation_token("hash-token", 15)
        .unwrap()
        .is_none());
}

#[test]
fn automation_token_authentication_updates_last_used_atomically() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    store
        .insert_automation_token(test_automation_token("t1", "acme"))
        .unwrap();

    let authenticated = store
        .authenticate_automation_token("hash-t1", 15)
        .unwrap()
        .unwrap();
    assert_eq!(authenticated.last_used_at, Some(15));
    assert_eq!(
        store.automation_tokens("acme", "", 100).unwrap()[0],
        authenticated
    );
    assert!(store
        .authenticate_automation_token("hash-t1", 20)
        .unwrap()
        .is_none());
}

#[test]
fn automation_token_revocation_is_tenant_scoped_and_idempotent() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    store
        .insert_automation_token(test_automation_token("t1", "acme"))
        .unwrap();

    assert!(!store.revoke_automation_token("other", "t1", 12).unwrap());
    assert!(store
        .authenticate_automation_token("hash-t1", 15)
        .unwrap()
        .is_some());
    assert!(store.revoke_automation_token("acme", "t1", 16).unwrap());
    assert!(!store.revoke_automation_token("acme", "t1", 17).unwrap());
    assert_eq!(
        store.automation_tokens("acme", "", 100).unwrap()[0].revoked_at,
        Some(16)
    );
    assert!(store
        .authenticate_automation_token("hash-t1", 18)
        .unwrap()
        .is_none());
}

#[test]
fn automation_token_records_creator_and_revoking_the_creator_revokes_it() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let mut minted = test_automation_token("minted", "acme");
    minted.created_by = "Minter@Example.com".to_owned();
    store.insert_automation_token(minted.clone()).unwrap();
    let mut other = test_automation_token("other", "acme");
    other.created_by = "someone.else@example.com".to_owned();
    store.insert_automation_token(other.clone()).unwrap();
    // The minter is a real principal: revoking it must take its tokens with it.
    store
        .upsert_sso_principal("Minter@Example.com", &[], &serde_json::json!([]))
        .unwrap();

    // The list payload carries the creator the mint recorded.
    let listed = store.automation_tokens("acme", "", 100).unwrap();
    assert_eq!(listed, vec![minted.clone(), other.clone()]);

    // Revoking the principal deactivates exactly the tokens it minted,
    // matched case-insensitively like the principals row itself.
    assert!(store.revoke_principal("minter@example.com").unwrap());
    let listed = store.automation_tokens("acme", "", 100).unwrap();
    assert!(listed[0].revoked_at.is_some());
    assert_eq!(listed[1].revoked_at, None);
    assert!(store
        .authenticate_automation_token("hash-minted", 15)
        .unwrap()
        .is_none());
    assert!(store
        .authenticate_automation_token("hash-other", 15)
        .unwrap()
        .is_some());

    // Revoking again leaves already-revoked tokens untouched.
    assert!(store.revoke_principal("MINTER@example.com").unwrap());
    assert_eq!(
        store.automation_tokens("acme", "", 100).unwrap()[0].revoked_at,
        listed[0].revoked_at
    );
}

#[test]
fn outbound_grant_expiry_and_revoke_control_active_state() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    store
        .insert_outbound_grant(test_outbound_grant("g1", "acme", 0))
        .unwrap();

    assert!(store
        .has_active_outbound_grant("acme", "link", "upload", 0, 19)
        .unwrap());
    assert!(!store
        .has_active_outbound_grant("acme", "link", "upload", 0, 20)
        .unwrap());
    assert!(store.revoke_outbound_grant("acme", "g1", 12).unwrap());
    assert!(!store.revoke_outbound_grant("acme", "g1", 13).unwrap());
    assert!(!store
        .has_active_outbound_grant("acme", "link", "upload", 0, 11)
        .unwrap());
}

#[test]
fn serve_prune_queries_preserve_expiry_revoke_and_ticket_retention() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let mut open = test_outbound_grant("open", "acme", 0);
    open.expires_at = 200;
    let mut expired = test_outbound_grant("expired", "acme", 0);
    expired.expires_at = 10;
    let mut revoked = test_outbound_grant("revoked", "acme", 0);
    revoked.expires_at = 200;
    revoked.revoked_at = Some(3);
    let mut exhausted = test_outbound_grant("exhausted", "acme", 0);
    exhausted.expires_at = 200;
    exhausted.max_downloads = Some(1);
    exhausted.downloads = 1;
    for grant in [open, expired, revoked, exhausted] {
        store.insert_outbound_grant(grant).unwrap();
    }
    store
            .with(|connection| {
                for (grant_id, root) in [
                    ("open", "root-open"),
                    ("expired", "root-expired"),
                    ("revoked", "root-revoked"),
                    ("exhausted", "root-exhausted"),
                ] {
                    connection.execute(
                        "INSERT INTO outbound_grant_manifests(grant_id,manifest_root,created_at) VALUES (?1,?2,0)",
                        rusqlite::params![grant_id, root],
                    )?;
                }
                for (token_id, expires_at) in [("old", 10), ("boundary", 20), ("live", 30)] {
                    connection.execute(
                        "INSERT INTO outbound_fetch_tickets(token_id,grant_id,manifest_root,expires_at) VALUES (?1,'open','root-open',?2)",
                        rusqlite::params![token_id, expires_at],
                    )?;
                }
                Ok(())
            })
            .unwrap();

    assert_eq!(
        store.servable_manifest_roots(20).unwrap(),
        vec!["root-open".to_owned()]
    );
    assert_eq!(store.prune_fetch_tickets(20).unwrap(), 1);
    let remaining: Vec<String> = store
        .with(|connection| {
            connection
                .prepare("SELECT token_id FROM outbound_fetch_tickets ORDER BY token_id")?
                .query_map([], |row| row.get(0))?
                .collect()
        })
        .unwrap();
    assert_eq!(remaining, ["boundary".to_owned(), "live".to_owned()]);
}

#[test]
fn fetch_delivery_and_ticket_commit_atomically() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let mut grant = test_outbound_grant("g1", "acme", 0);
    grant.max_downloads = Some(1);
    store.insert_outbound_grant(grant).unwrap();
    store
        .insert_outbound_grant(test_outbound_grant("g2", "acme", 0))
        .unwrap();
    let ticket = FetchTicket {
        holder: "holder".into(),
        grant_token_hash: "hash-g1".into(),
        policy_revision: 0,
        token_id: "ticket".into(),
        grant_id: "g1".into(),
        manifest_root: "00".repeat(32),
        expires_at: 19,
        delivered_at: None,
    };
    assert!(store.put_fetch_ticket(&ticket, 1).unwrap());
    let connection = rusqlite::Connection::open(directory.path().join("votport.db")).unwrap();
    connection.execute_batch("CREATE TRIGGER fail_ticket BEFORE UPDATE OF delivered_at ON outbound_fetch_tickets BEGIN SELECT RAISE(FAIL, 'fixture'); END;").unwrap();
    assert!(store
        .record_fetch_download("g1", &[0], 10, "ticket")
        .is_err());
    assert_eq!(
        store.outbound_grant_by_id("g1").unwrap().unwrap().downloads,
        0
    );
    assert_eq!(
        store.fetch_ticket("ticket").unwrap().unwrap().delivered_at,
        None
    );
    connection
        .execute_batch("DROP TRIGGER fail_ticket;")
        .unwrap();
    for (grant, token) in [("g2", "ticket"), ("g1", "missing")] {
        assert!(store.record_fetch_download(grant, &[0], 10, token).is_err());
        assert_eq!(
            store
                .outbound_grant_by_id(grant)
                .unwrap()
                .unwrap()
                .downloads,
            0
        );
    }
    store
        .record_fetch_download("g1", &[0], 10, "ticket")
        .unwrap();
    assert_eq!(
        store.outbound_grant_by_id("g1").unwrap().unwrap().downloads,
        1
    );
    assert_eq!(
        store.fetch_ticket("ticket").unwrap().unwrap().delivered_at,
        Some(10)
    );
    assert!(!store.admit_fetch_ticket(&ticket, 11).unwrap());
}

#[test]
fn outbound_download_count_and_active_link_query_round_trip() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    store
        .insert_outbound_grant(test_outbound_grant("g1", "acme", 0))
        .unwrap();
    let mut other = test_outbound_grant("g2", "acme", 1);
    other.link_id = "other-link".to_owned();
    other.expires_at = 100;
    store.insert_outbound_grant(other).unwrap();

    assert_eq!(
        store.record_outbound_download("g1", &[0], 100).unwrap(),
        OutboundDownloadResult {
            first_download: true,
            completed_delivery: true,
            event_at: 100,
        }
    );
    assert_eq!(
        store.record_outbound_download("g1", &[0], 110).unwrap(),
        OutboundDownloadResult {
            first_download: false,
            completed_delivery: false,
            event_at: 110,
        }
    );
    let grant = store
        .outbound_grant_by_token_hash("hash-g1")
        .unwrap()
        .unwrap();
    assert_eq!(grant.downloads, 2);
    assert_eq!(grant.first_download_at, Some(100));
    assert_eq!(grant.last_download_at, Some(110));
    assert!(store
        .record_outbound_download("missing", &[0], 100)
        .is_err());
    assert!(store
        .link_has_active_outbound_grants("acme", "link", 19)
        .unwrap());
    assert!(!store
        .link_has_active_outbound_grants("other", "link", 19)
        .unwrap());
    assert!(store
        .link_has_active_outbound_grants("acme", "other-link", 99)
        .unwrap());
    assert!(!store
        .link_has_active_outbound_grants("acme", "other-link", 100)
        .unwrap());
}

#[test]
fn outbound_download_limit_refuses_after_one_download() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let mut grant = test_outbound_grant("limited", "acme", 0);
    grant.max_downloads = Some(1);
    store.insert_outbound_grant(grant).unwrap();

    assert!(store
        .has_active_outbound_grant("acme", "link", "upload", 0, 19)
        .unwrap());
    store.record_outbound_download("limited", &[0], 15).unwrap();
    let downloaded = store
        .outbound_grant_by_token_hash("hash-limited")
        .unwrap()
        .unwrap();
    let error = store
        .record_outbound_download("limited", &[0], 16)
        .unwrap_err();
    assert_eq!(error, OUTBOUND_DOWNLOAD_LIMIT_REACHED);
    assert_eq!(
        store
            .outbound_grant_by_token_hash("hash-limited")
            .unwrap()
            .unwrap(),
        downloaded
    );
    assert!(!store
        .has_active_outbound_grant("acme", "link", "upload", 0, 19)
        .unwrap());
    assert!(!store
        .link_has_active_outbound_grants("acme", "link", 19)
        .unwrap());
}

#[test]
fn saved_download_address_survives_restart_and_rotates_atomically() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let token = crate::auth::random_token();
    let mut grant = test_outbound_grant("saved", "acme", 0);
    grant.token_hash = crate::auth::hash_token(&token);
    assert!(store
        .insert_workflow_grant(grant.clone(), None, None, Some("wrong"))
        .is_err());
    assert!(store.outbound_grant_by_id("saved").unwrap().is_none());
    store
        .insert_workflow_grant(grant.clone(), None, None, Some(&token))
        .unwrap();
    assert_eq!(store.outbound_share_token("other", "saved").unwrap(), None);
    assert_eq!(store.outbound_share_token("acme", "missing").unwrap(), None);
    store
        .with(|connection| {
            connection
                .execute(
                    "UPDATE outbound_grants SET share_token='mismatched' WHERE id='saved'",
                    [],
                )
                .map(|_| ())
        })
        .unwrap();
    assert_eq!(store.outbound_share_token("acme", "saved").unwrap(), None);
    store
        .with(|connection| {
            connection
                .execute(
                    "UPDATE outbound_grants SET share_token=?1 WHERE id='saved'",
                    [&token],
                )
                .map(|_| ())
        })
        .unwrap();
    drop(store);
    let store = Store::open(directory.path()).unwrap();
    assert_eq!(
        store
            .outbound_share_token("acme", "saved")
            .unwrap()
            .as_deref(),
        Some(token.as_str())
    );
    let next = crate::auth::random_token();
    store
        .with(|connection| {
            connection.execute_batch(
                "CREATE TRIGGER refuse_token BEFORE UPDATE OF share_token ON outbound_grants
             BEGIN SELECT RAISE(ABORT, 'fixture refusal'); END;",
            )
        })
        .unwrap();
    assert!(store
        .rotate_outbound_grant_token("acme", "saved", &next)
        .is_err());
    assert_eq!(
        store
            .outbound_share_token("acme", "saved")
            .unwrap()
            .as_deref(),
        Some(token.as_str())
    );
    assert_eq!(store.outbound_grant_by_id("saved").unwrap().unwrap(), grant);
    store
        .with(|connection| connection.execute_batch("DROP TRIGGER refuse_token"))
        .unwrap();
    assert!(store
        .rotate_outbound_grant_token("acme", "saved", &next)
        .unwrap());
    assert_eq!(
        store.outbound_share_token("acme", "saved").unwrap(),
        Some(next)
    );
    assert!(store
        .outbound_grant_by_token_hash(&crate::auth::hash_token(&token))
        .unwrap()
        .is_none());
    store.revoke_outbound_grant("acme", "saved", 12).unwrap();
    assert_eq!(store.outbound_share_token("acme", "saved").unwrap(), None);
}

#[test]
fn current_schema_installs_maintenance_indexes_on_reopen_and_promotion() {
    for promotion in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .with(|connection| {
                connection.execute_batch(
                    "DROP INDEX delivery_jobs_deadline_pending;
                         DROP INDEX delivery_jobs_retirement_due;
                         DROP INDEX outbound_fetch_tickets_expires;
                         DROP INDEX outbound_grants_open_expires;
                         DROP INDEX audit_log_tenant;
                         DROP INDEX audit_log_event;
                         DROP INDEX audit_log_tenant_at;
                         DROP INDEX audit_log_event_at;
                         ",
                )
            })
            .unwrap();
        drop(store);
        if promotion {
            std::fs::write(directory.path().join(crate::standby::STATUS_FILE), b"{}").unwrap();
        }
        let store = Store::open(directory.path()).unwrap();
        assert!(store.claim_snapshot_retirement(1).unwrap().is_none());
        store.escalate_delivery_jobs(1).unwrap();
        let indexes = store
            .with(|connection| {
                connection
                    .prepare(
                        "SELECT name FROM sqlite_schema WHERE type='index' AND name IN (
                                'delivery_jobs_deadline_pending',
                                'delivery_jobs_retirement_due',
                                'outbound_fetch_tickets_expires',
                                'outbound_grants_open_expires',
                                'audit_log_tenant',
                                'audit_log_event',
                                'audit_log_tenant_at',
                                'audit_log_event_at'
                            ) ORDER BY name",
                    )?
                    .query_map([], |row| row.get(0))?
                    .collect::<rusqlite::Result<Vec<String>>>()
            })
            .unwrap();
        assert_eq!(
            indexes,
            [
                "audit_log_event".to_owned(),
                "audit_log_event_at".to_owned(),
                "audit_log_tenant".to_owned(),
                "audit_log_tenant_at".to_owned(),
                "delivery_jobs_deadline_pending".to_owned(),
                "delivery_jobs_retirement_due".to_owned(),
                "outbound_fetch_tickets_expires".to_owned(),
                "outbound_grants_open_expires".to_owned()
            ],
            "promotion {promotion}"
        );
    }
}

#[test]
fn schema41_upgrade_preserves_existing_grants_and_can_store_new_addresses() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let grant = test_outbound_grant("preserved", "acme", 0);
    store.insert_outbound_grant(grant.clone()).unwrap();
    store
        .with(|connection| {
            connection
                .execute(
                    "INSERT INTO files
                     (link_id,tenant,upload_id,file_index,bytes_hi,bytes_lo,deleted,
                      stored_as,path,suite,root,receipt)
                     VALUES ('anonymous-link','', 'anonymous-upload',0,0,13,0,
                             'anonymous-object','anonymous-object','blake3','root',0)",
                    [],
                )
                .and_then(|_| {
                    connection.execute(
                        "INSERT INTO files
                         (link_id,tenant,upload_id,file_index,bytes_hi,bytes_lo,deleted,
                          stored_as,path,suite,root,receipt)
                         VALUES ('duplicate-low','', 'duplicate-upload',0,0,5,0,
                                 'shared-object','shared-object','blake3','root',0)",
                        [],
                    )
                })
                .and_then(|_| {
                    connection.execute(
                        "INSERT INTO files
                         (link_id,tenant,upload_id,file_index,bytes_hi,bytes_lo,deleted,
                          stored_as,path,suite,root,receipt)
                         VALUES ('duplicate-high','', 'duplicate-upload',1,0,17,0,
                                 'shared-object','shared-object','blake3','root',0)",
                        [],
                    )
                })
        })
        .unwrap();
    store
        .with(|connection| {
            connection.execute_batch(
                "DROP INDEX delivery_jobs_retirement_due;
             DROP INDEX delivery_jobs_deadline_pending;
             DROP INDEX outbound_fetch_tickets_expires;
             DROP INDEX outbound_grants_open_expires;
             DROP INDEX delivery_jobs_tenant_created;
             DROP INDEX delivery_jobs_tenant_snapshot;
             ALTER TABLE outbound_grants DROP COLUMN share_token;
             ALTER TABLE delivery_jobs DROP COLUMN created_at;
                 ALTER TABLE tenants DROP COLUMN retention_days;
                 ALTER TABLE links DROP COLUMN retention_days;
             ALTER TABLE delivery_jobs DROP COLUMN snapshot_bytes;
             ALTER TABLE automation_tokens DROP COLUMN created_by;
             UPDATE meta SET value='41' WHERE key='schema_version';",
            )
        })
        .unwrap();
    drop(store);
    let store = Store::open(directory.path()).unwrap();
    assert_eq!(
        store.outbound_grant_by_id("preserved").unwrap().unwrap(),
        grant
    );
    assert_eq!(
        store.outbound_share_token("acme", "preserved").unwrap(),
        None
    );
    assert_eq!(store.tenant_received_bytes("").unwrap(), 30);
    let token = crate::auth::random_token();
    assert!(store
        .rotate_outbound_grant_token("acme", "preserved", &token)
        .unwrap());
    assert_eq!(
        store.outbound_share_token("acme", "preserved").unwrap(),
        Some(token)
    );
    drop(store);
    let store = Store::open(directory.path()).unwrap();
    store
        .with(|connection| {
            let version: String = connection.query_row(
                "SELECT value FROM meta WHERE key='schema_version'",
                [],
                |row| row.get(0),
            )?;
            assert_eq!(version, SCHEMA_VERSION.to_string());
            let indexes: Vec<String> = connection
                .prepare(
                    "SELECT name FROM sqlite_schema WHERE type='index' AND name IN (
                            'delivery_jobs_deadline_pending',
                            'delivery_jobs_retirement_due',
                            'outbound_fetch_tickets_expires',
                            'outbound_grants_open_expires',
                            'audit_log_tenant',
                            'audit_log_event',
                            'audit_log_tenant_at',
                            'audit_log_event_at'
                        ) ORDER BY name",
                )?
                .query_map([], |row| row.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            assert_eq!(
                indexes,
                [
                    "audit_log_event".to_owned(),
                    "audit_log_event_at".to_owned(),
                    "audit_log_tenant".to_owned(),
                    "audit_log_tenant_at".to_owned(),
                    "delivery_jobs_deadline_pending".to_owned(),
                    "delivery_jobs_retirement_due".to_owned(),
                    "outbound_fetch_tickets_expires".to_owned(),
                    "outbound_grants_open_expires".to_owned()
                ]
            );
            Ok(())
        })
        .unwrap();
}

#[test]
fn schema45_upgrade_backfills_delivery_job_snapshot_and_created_columns() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    assert_eq!(
        store
            .with(|connection| {
                connection.query_row(
                    "SELECT value FROM meta WHERE key='schema_version'",
                    [],
                    |row| row.get::<_, String>(0),
                )
            })
            .unwrap(),
        SCHEMA_VERSION.to_string()
    );
    // Seed rows the way schema 44 stored them, then strip the 45 columns
    // and stamp the old version to present a pre-upgrade database.
    store
        .with(|connection| {
            connection.execute_batch(
                "INSERT INTO delivery_jobs(id,tenant,actor,operation_id,project_id,state,not_before,document,token)
                 VALUES ('stamped','','sender','operation','project','ready',0,
                         '{\"created_at\":33,\"checks\":{\"snapshot_bytes\":17}}','unused'),
                        ('bare','','sender','bare','project','queued',0,'{}','unused');
                 DROP INDEX delivery_jobs_tenant_created;
                 DROP INDEX delivery_jobs_tenant_snapshot;
                 ALTER TABLE delivery_jobs DROP COLUMN created_at;
                 ALTER TABLE delivery_jobs DROP COLUMN snapshot_bytes;
                 ALTER TABLE automation_tokens DROP COLUMN created_by;
                 ALTER TABLE tenants DROP COLUMN retention_days;
                 ALTER TABLE links DROP COLUMN retention_days;
                 UPDATE meta SET value='44' WHERE key='schema_version';",
            )
        })
        .unwrap();
    drop(store);
    // The upgrade runs inside one transaction, so a restart mid-migration
    // presents exactly as this 44 database does and the next open reruns
    // the whole step.
    let store = Store::open(directory.path()).unwrap();
    assert_eq!(
        store
            .with(|connection| {
                connection.query_row(
                    "SELECT value FROM meta WHERE key='schema_version'",
                    [],
                    |row| row.get::<_, String>(0),
                )
            })
            .unwrap(),
        SCHEMA_VERSION.to_string()
    );
    let backfilled: Vec<(i64, i64)> = store
        .with(|connection| {
            let mut statement = connection
                .prepare("SELECT created_at,snapshot_bytes FROM delivery_jobs ORDER BY id")?;
            let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
            rows.collect::<rusqlite::Result<_>>()
        })
        .unwrap();
    assert_eq!(backfilled, [(0, 0), (33, 17)]);
    let indexes: Vec<String> = store
        .with(|connection| {
            connection
                .prepare(
                    "SELECT name FROM sqlite_schema WHERE type='index' AND name IN (
                            'delivery_jobs_tenant_created',
                            'delivery_jobs_tenant_snapshot'
                        ) ORDER BY name",
                )?
                .query_map([], |row| row.get(0))?
                .collect::<rusqlite::Result<_>>()
        })
        .unwrap();
    assert_eq!(
        indexes,
        [
            "delivery_jobs_tenant_created".to_owned(),
            "delivery_jobs_tenant_snapshot".to_owned()
        ]
    );
    drop(store);
    // Restarting an already upgraded database changes nothing.
    let store = Store::open(directory.path()).unwrap();
    assert_eq!(
        store
            .with(|connection| {
                connection.query_row(
                    "SELECT value FROM meta WHERE key='schema_version'",
                    [],
                    |row| row.get::<_, String>(0),
                )
            })
            .unwrap(),
        SCHEMA_VERSION.to_string()
    );
    let preserved: i64 = store
        .with(|connection| {
            connection.query_row(
                "SELECT snapshot_bytes FROM delivery_jobs WHERE id='stamped'",
                [],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert_eq!(preserved, 17);
}

#[test]
fn schema46_upgrade_backfills_automation_token_creator() {
    let directory = tempfile::tempdir().unwrap();
    // Fresh databases stamp 46 and carry the creator column from the start.
    let store = Store::open(directory.path()).unwrap();
    assert_eq!(
        store
            .with(|connection| {
                connection.query_row(
                    "SELECT value FROM meta WHERE key='schema_version'",
                    [],
                    |row| row.get::<_, String>(0),
                )
            })
            .unwrap(),
        SCHEMA_VERSION.to_string()
    );
    // Seed rows the way schema 45 stored them (the creation audit row names
    // the minter of one token; the other's audit row is already pruned),
    // then strip the 46 column and stamp the old version.
    store
        .with(|connection| {
            connection.execute_batch(
                "INSERT INTO automation_tokens(id,token_hash,tenant,label,created_at,expires_at,revoked_at,last_used_at,directory,permissions)
                 VALUES ('audited','hash-audited','acme','Audited',1,2,NULL,NULL,NULL,'[\"deliveries:create\"]'),
                        ('pruned','hash-pruned','acme','Pruned',1,2,NULL,NULL,NULL,'[\"deliveries:create\"]');
                 INSERT INTO audit_log(at,tenant,actor,event,subject,detail)
                 VALUES (1,'acme','Minter@Example.com','automation_token_created','audited','{}');
                 ALTER TABLE automation_tokens DROP COLUMN created_by;
                 ALTER TABLE tenants DROP COLUMN retention_days;
                 ALTER TABLE links DROP COLUMN retention_days;
                 UPDATE meta SET value='45' WHERE key='schema_version';",
            )
        })
        .unwrap();
    drop(store);
    // The upgrade runs inside one transaction, so a restart mid-migration
    // presents exactly as this 45 database does and the next open reruns
    // the whole step.
    let store = Store::open(directory.path()).unwrap();
    assert_eq!(
        store
            .with(|connection| {
                connection.query_row(
                    "SELECT value FROM meta WHERE key='schema_version'",
                    [],
                    |row| row.get::<_, String>(0),
                )
            })
            .unwrap(),
        SCHEMA_VERSION.to_string()
    );
    let creators: Vec<(String, String)> = store
        .with(|connection| {
            let mut statement =
                connection.prepare("SELECT id, created_by FROM automation_tokens ORDER BY id")?;
            let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
            rows.collect::<rusqlite::Result<_>>()
        })
        .unwrap();
    assert_eq!(
        creators,
        [
            ("audited".to_owned(), "Minter@Example.com".to_owned()),
            ("pruned".to_owned(), String::new())
        ]
    );
    drop(store);
    // Restarting an already upgraded database changes nothing.
    let store = Store::open(directory.path()).unwrap();
    let preserved: String = store
        .with(|connection| {
            connection.query_row(
                "SELECT created_by FROM automation_tokens WHERE id='audited'",
                [],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert_eq!(preserved, "Minter@Example.com");
}

#[test]
fn schema47_upgrade_adds_scoped_upload_retention_columns() {
    let directory = tempfile::tempdir().unwrap();
    // Fresh databases stamp 47 and carry the retention columns from the
    // start; unset scopes read as NULL.
    let store = Store::open(directory.path()).unwrap();
    assert_eq!(
        store
            .with(|connection| {
                connection.query_row(
                    "SELECT value FROM meta WHERE key='schema_version'",
                    [],
                    |row| row.get::<_, String>(0),
                )
            })
            .unwrap(),
        SCHEMA_VERSION.to_string()
    );
    // Seed rows the way schema 46 stored them (a tenant with quotas and a
    // link under it), then strip the 47 columns and stamp the old version.
    store
        .with(|connection| {
            connection.execute_batch(
                "INSERT INTO tenants(key,incarnation,label,admin_group,max_total_bytes,max_links,max_sessions,created_at)
                 VALUES ('acme','inc','Acme',NULL,1000,5,2,7);
                 INSERT INTO links(id,tenant,label,dest,created_at,expires_at,active,events_json,legal_hold)
                 VALUES ('link','acme','Link','work',10,NULL,1,'[]',0);
                 ALTER TABLE tenants DROP COLUMN retention_days;
                 ALTER TABLE links DROP COLUMN retention_days;
                 UPDATE meta SET value='46' WHERE key='schema_version';",
            )
        })
        .unwrap();
    drop(store);
    // The upgrade runs inside one transaction, so a restart mid-migration
    // presents exactly as this 46 database does and the next open reruns
    // the whole step.
    let store = Store::open(directory.path()).unwrap();
    assert_eq!(
        store
            .with(|connection| {
                connection.query_row(
                    "SELECT value FROM meta WHERE key='schema_version'",
                    [],
                    |row| row.get::<_, String>(0),
                )
            })
            .unwrap(),
        SCHEMA_VERSION.to_string()
    );
    let tenant = store.tenant("acme").unwrap().unwrap();
    assert_eq!(tenant.retention_days, None);
    let link = store.link("acme", "link").unwrap().unwrap();
    assert_eq!(link.retention_days, None);
    // Values written at 47 survive a reopen.
    assert!(store
        .update_link("acme", "link", |link| link.retention_days = Some(30))
        .unwrap());
    drop(store);
    let store = Store::open(directory.path()).unwrap();
    assert_eq!(
        store.link("acme", "link").unwrap().unwrap().retention_days,
        Some(30)
    );
}

#[test]
fn current_schema_rejects_quota_literal_mutations() {
    for (left, right) in [
        ("SELECT 'a b'", "SELECT 'ab'"),
        ("SELECT ';'", "SELECT ''"),
        ("SELECT 'A'", "SELECT 'a'"),
        ("SELECT 'a'' b'", "SELECT 'a''b'"),
        ("SELECT a b", "SELECT ab"),
        ("SELECT 1; SELECT 2", "SELECT 1 SELECT 2"),
    ] {
        assert_ne!(normalize_schema_sql(left), normalize_schema_sql(right));
    }
    assert_eq!(
        normalize_schema_sql("  SELECT \n'A'' B' ;  "),
        "select 'A'' B'"
    );
    for (kind, name) in [
        ("trigger", "tenant_quota_usage_insert"),
        ("index", "files_quota_identity"),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .with(|connection| {
                connection.execute_batch("PRAGMA writable_schema=ON")?;
                let changed = connection.execute(
                    "UPDATE sqlite_schema
                         SET sql=replace(sql, ?1, ?2)
                         WHERE type=?3 AND name=?4",
                    rusqlite::params!["stored_as = ''", "stored_as = ' '", kind, name],
                )?;
                connection.execute_batch("PRAGMA writable_schema=OFF")?;
                assert_eq!(changed, 1, "{kind} {name} was not changed");
                Ok(())
            })
            .unwrap();
        drop(store);

        let error = match Store::open(directory.path()) {
            Ok(_) => panic!("malformed {kind} {name} was accepted"),
            Err(error) => error,
        };
        assert!(
            error.contains("definition is invalid"),
            "{kind} {name}: {error}"
        );
    }
}

#[test]
fn outbound_grant_token_rotation_is_tenant_scoped() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    store
        .insert_outbound_grant(test_outbound_grant("rotate", "acme", 0))
        .unwrap();

    assert!(!store
        .rotate_outbound_grant_token("other", "rotate", "new-hash")
        .unwrap());
    assert!(store
        .rotate_outbound_grant_token("acme", "rotate", "new-hash")
        .unwrap());
    assert!(store
        .outbound_grant_by_token_hash("hash-rotate")
        .unwrap()
        .is_none());
    assert_eq!(
        store
            .outbound_grant_by_token_hash(&crate::auth::hash_token("new-hash"))
            .unwrap()
            .unwrap()
            .id,
        "rotate"
    );
    store.revoke_outbound_grant("acme", "rotate", 12).unwrap();
    assert!(!store
        .rotate_outbound_grant_token("acme", "rotate", "other-hash")
        .unwrap());
}

#[test]
fn outbound_grant_extension_handles_live_expired_and_scoped_rows() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let mut expired = test_outbound_grant("expired", "acme", 0);
    expired.expires_at = 10;
    store.insert_outbound_grant(expired).unwrap();
    store
        .insert_outbound_grant(test_outbound_grant("live", "acme", 1))
        .unwrap();
    store
        .insert_outbound_grant(test_outbound_grant("revoked", "acme", 2))
        .unwrap();
    store.revoke_outbound_grant("acme", "revoked", 12).unwrap();

    assert_eq!(
        store.extend_outbound_grant("acme", "live", 5, 15).unwrap(),
        Some(25)
    );
    // Finding 380: an expired grant refuses extension and keeps its expiry.
    assert_eq!(
        store
            .extend_outbound_grant("acme", "expired", 5, 20)
            .unwrap(),
        None
    );
    assert_eq!(
        store.extend_outbound_grant("other", "live", 5, 20).unwrap(),
        None
    );
    assert_eq!(
        store
            .extend_outbound_grant("acme", "revoked", 5, 20)
            .unwrap(),
        None
    );
    assert_eq!(
        store
            .outbound_grant_by_token_hash("hash-expired")
            .unwrap()
            .unwrap()
            .expires_at,
        10
    );
}

#[test]
fn outbound_grant_extension_never_revives_an_expired_grant() {
    // Finding 380: extending an expired grant used to resurrect it as a
    // live delivery, so expiry must refuse the extension outright.
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let mut expired = test_outbound_grant("expired", "acme", 0);
    expired.expires_at = 10;
    store.insert_outbound_grant(expired).unwrap();
    assert_eq!(
        store
            .extend_outbound_grant("acme", "expired", 5, 20)
            .unwrap(),
        None
    );
    assert_eq!(
        store
            .outbound_grant_by_token_hash("hash-expired")
            .unwrap()
            .unwrap()
            .expires_at,
        10
    );
    // A live grant still extends from its own expiry.
    let mut live = test_outbound_grant("live", "acme", 1);
    live.expires_at = 30;
    store.insert_outbound_grant(live).unwrap();
    assert_eq!(
        store.extend_outbound_grant("acme", "live", 5, 20).unwrap(),
        Some(35)
    );
}

#[test]
fn outbound_download_tracking_reports_first_and_completed_transitions() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let mut grant = test_outbound_grant("multi", "acme", 0);
    grant.files = vec![
        OutboundGrantFile {
            source: "objects/a".to_owned(),
            name: "a.txt".to_owned(),
            suite: "blake3".to_owned(),
            root: "aa".to_owned(),
            bytes: 3,
            receipt_b64: "receipt-a".to_owned(),
            downloads: 0,
            first_download_at: None,
            last_download_at: None,
        },
        OutboundGrantFile {
            source: "objects/b".to_owned(),
            name: "b.txt".to_owned(),
            suite: "blake3".to_owned(),
            root: "bb".to_owned(),
            bytes: 4,
            receipt_b64: "receipt-b".to_owned(),
            downloads: 0,
            first_download_at: None,
            last_download_at: None,
        },
    ];
    store.insert_outbound_grant(grant).unwrap();

    assert_eq!(
        store.record_outbound_download("multi", &[1], 100).unwrap(),
        OutboundDownloadResult {
            first_download: true,
            completed_delivery: false,
            event_at: 100,
        }
    );
    assert_eq!(
        store.record_outbound_download("multi", &[0], 200).unwrap(),
        OutboundDownloadResult {
            first_download: false,
            completed_delivery: true,
            event_at: 200,
        }
    );
    assert_eq!(
        store
            .record_outbound_download("multi", &[0, 1, 1], 300)
            .unwrap(),
        OutboundDownloadResult {
            first_download: false,
            completed_delivery: false,
            event_at: 300,
        }
    );
    let grant = store
        .outbound_grant_by_token_hash("hash-multi")
        .unwrap()
        .unwrap();
    assert_eq!(grant.downloads, 2);
    assert_eq!(grant.first_download_at, Some(100));
    assert_eq!(grant.last_download_at, Some(300));
    assert_eq!(grant.files[0].downloads, 2);
    assert_eq!(grant.files[0].first_download_at, Some(200));
    assert_eq!(grant.files[0].last_download_at, Some(300));
    assert_eq!(grant.files[1].downloads, 2);
    assert_eq!(grant.files[1].first_download_at, Some(100));
    assert_eq!(grant.files[1].last_download_at, Some(300));

    assert_eq!(
        store
            .record_outbound_download("multi", &[0, 1], 400)
            .unwrap(),
        OutboundDownloadResult {
            first_download: false,
            completed_delivery: false,
            event_at: 400,
        }
    );
    assert_eq!(
        store
            .record_outbound_download("multi", &[0, 1], 500)
            .unwrap(),
        OutboundDownloadResult {
            first_download: false,
            completed_delivery: false,
            event_at: 500,
        }
    );
    let grant = store
        .outbound_grant_by_token_hash("hash-multi")
        .unwrap()
        .unwrap();
    assert_eq!(grant.downloads, 4);
    assert_eq!(grant.files[0].downloads, 4);
    assert_eq!(grant.files[1].downloads, 4);
}

#[test]
fn outbound_multi_file_limit_applies_per_file_and_counts_rounds() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let mut grant = test_outbound_grant("multi-limit", "acme", 0);
    grant.max_downloads = Some(1);
    grant.files = (0..2)
        .map(|index| OutboundGrantFile {
            source: format!("objects/{index}"),
            name: format!("{index}.txt"),
            suite: "blake3".to_owned(),
            root: format!("root-{index}"),
            bytes: 1,
            receipt_b64: "receipt".to_owned(),
            downloads: 0,
            first_download_at: None,
            last_download_at: None,
        })
        .collect();
    store.insert_outbound_grant(grant).unwrap();

    store
        .record_outbound_download("multi-limit", &[0], 100)
        .unwrap();
    let grant = store
        .outbound_grant_by_token_hash("hash-multi-limit")
        .unwrap()
        .unwrap();
    assert_eq!(grant.downloads, 0);
    assert_eq!(grant.files[0].downloads, 1);
    assert_eq!(grant.files[1].downloads, 0);

    assert_eq!(
        store
            .record_outbound_download("multi-limit", &[0, 1], 150)
            .unwrap_err(),
        OUTBOUND_DOWNLOAD_LIMIT_REACHED
    );
    let grant = store
        .outbound_grant_by_token_hash("hash-multi-limit")
        .unwrap()
        .unwrap();
    assert_eq!(grant.files[0].downloads, 1);
    assert_eq!(grant.files[1].downloads, 0);

    let completed = store
        .record_outbound_download("multi-limit", &[1], 200)
        .unwrap();
    assert!(completed.completed_delivery);
    let grant = store
        .outbound_grant_by_token_hash("hash-multi-limit")
        .unwrap()
        .unwrap();
    assert_eq!(grant.downloads, 1);
    assert_eq!(grant.files[0].downloads, 1);
    assert_eq!(grant.files[1].downloads, 1);

    assert_eq!(
        store
            .record_outbound_download("multi-limit", &[0], 300)
            .unwrap_err(),
        OUTBOUND_DOWNLOAD_LIMIT_REACHED
    );
    let grant = store
        .outbound_grant_by_token_hash("hash-multi-limit")
        .unwrap()
        .unwrap();
    assert_eq!(grant.files[1].downloads, 1);
}

#[test]
fn outbound_download_tracking_rejects_invalid_indexes_atomically() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let mut grant = test_outbound_grant("atomic", "acme", 0);
    grant.files = vec![OutboundGrantFile {
        source: "objects/a".to_owned(),
        name: "a.txt".to_owned(),
        suite: "blake3".to_owned(),
        root: "aa".to_owned(),
        bytes: 3,
        receipt_b64: "receipt-a".to_owned(),
        downloads: 0,
        first_download_at: None,
        last_download_at: None,
    }];
    store.insert_outbound_grant(grant.clone()).unwrap();

    assert!(store
        .record_outbound_download("atomic", &[0, 1], 100)
        .is_err());
    assert_eq!(
        store
            .outbound_grant_by_token_hash("hash-atomic")
            .unwrap()
            .unwrap(),
        grant
    );
}

#[test]
fn outbound_full_range_rejects_missing_child_atomically() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let mut grant = test_outbound_grant("missing-child", "acme", 0);
    grant.files = (0..2)
        .map(|index| OutboundGrantFile {
            source: format!("objects/{index}"),
            name: format!("{index}.txt"),
            suite: "blake3".to_owned(),
            root: format!("root-{index}"),
            bytes: 1,
            receipt_b64: "receipt".to_owned(),
            downloads: 0,
            first_download_at: None,
            last_download_at: None,
        })
        .collect();
    store.insert_outbound_grant(grant).unwrap();
    store
        .with(|connection| {
            connection.execute(
                "DELETE FROM outbound_grant_files
                     WHERE grant_id = 'missing-child' AND file_index = 1",
                [],
            )
        })
        .unwrap();

    assert_eq!(
        store
            .record_outbound_download("missing-child", &[0, 1], 100)
            .unwrap_err(),
        "outbound file index out of range"
    );
    let downloads: Vec<i64> = store
        .with(|connection| {
            let mut statement = connection.prepare(
                "SELECT downloads FROM outbound_grant_files
                     WHERE grant_id = 'missing-child' ORDER BY file_index",
            )?;
            let downloads = statement
                .query_map([], |row| row.get(0))?
                .collect::<Result<Vec<_>, _>>();
            downloads
        })
        .unwrap();
    assert_eq!(downloads, vec![0]);
}

#[test]
fn legal_hold_rolls_back_when_audit_fails() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    store.insert_link(test_link("held")).unwrap();
    store
        .with(|connection| connection.execute_batch("DROP TABLE audit_log"))
        .unwrap();

    assert!(store
        .set_link_legal_hold("", "held", true, "admin")
        .is_err());
    assert!(!store.link("", "held").unwrap().unwrap().legal_hold);
}

#[test]
fn link_upload_extracts_one_record_without_the_full_history() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let mut link = test_link("link-1");
    for index in 0..3 {
        link.uploads.push(UploadRecord {
            partial: false,
            log: Vec::new(),
            id: format!("up-{index}"),
            started_at: 1,
            completed_at: 2,
            replayed_chunks: 0,
            rejected_chunks: 0,
            transport: None,
            package_root: format!("root-{index}"),
            total_bytes: 5,
            files: Vec::new(),
        });
    }
    store.insert_link(link).unwrap();
    let found = store.link_upload("", "link-1", "up-1").unwrap().unwrap();
    assert_eq!(found.id, "up-1");
    assert_eq!(found.package_root, "root-1");
    assert!(store.link_upload("", "link-1", "up-9").unwrap().is_none());
    // Tenant scoping holds: the wrong namespace sees nothing.
    assert!(store
        .link_upload("other", "link-1", "up-1")
        .unwrap()
        .is_none());
}

#[test]
fn schema41_quota_backfill_failure_rolls_back_without_partial_schema() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    store
        .with(|connection| {
            connection.execute_batch(
                "DROP TRIGGER tenant_quota_usage_insert;
                     DROP TRIGGER tenant_quota_usage_delete;
                     DROP TRIGGER tenant_quota_usage_update;
                     DROP INDEX files_quota_identity;
                     DROP INDEX upload_sessions_quota_live;
                     DROP TABLE tenant_quota_usage;
                     ALTER TABLE outbound_grants DROP COLUMN share_token;
                     INSERT INTO files
                         (link_id,tenant,upload_id,file_index,bytes_hi,bytes_lo,deleted,
                          stored_as,path,suite,root,receipt)
                     VALUES ('anonymous-link','', 'anonymous-upload',0,-1,13,0,
                             'anonymous-object','anonymous-object','blake3','root',0);
                     UPDATE meta SET value='41' WHERE key='schema_version';",
            )
        })
        .unwrap();
    drop(store);

    let error = match Store::open(directory.path()) {
        Ok(_) => panic!("invalid file limbs must abort schema upgrade"),
        Err(error) => error,
    };
    assert!(
        error.contains("file byte limbs are outside the u32 range"),
        "{error}"
    );
    let connection = Connection::open(directory.path().join("votport.db")).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT value FROM meta WHERE key='schema_version'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "41"
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                     WHERE type IN ('table','trigger','index')
                       AND (name='tenant_quota_usage' OR name LIKE 'tenant_quota_usage_%'
                            OR name IN ('files_quota_identity','upload_sessions_quota_live'))",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT bytes_hi,bytes_lo FROM files WHERE link_id='anonymous-link'",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .unwrap(),
        (-1, 13)
    );
}

#[test]
fn links_round_trip_with_uploads_and_events() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let mut link = test_link("link-1");
    link.uploads.push(UploadRecord {
        partial: false,
        log: Vec::new(),
        id: "up-1".to_owned(),
        started_at: 1,
        completed_at: 2,
        replayed_chunks: 3,
        rejected_chunks: 4,
        transport: None,
        package_root: "aa".to_owned(),
        total_bytes: 5,
        files: vec![FileRecord {
            path: "a.txt".to_owned(),
            stored_as: "a.txt".to_owned(),
            bytes: 5,
            suite: "blake3".to_owned(),
            root: "bb".to_owned(),
            receipt: true,
            deleted: false,
        }],
    });
    link.events.push(SessionEvent {
        at: 3,
        started_at: 1,
        outcome: "cancelled".to_owned(),
        detail: "by sender".to_owned(),
        received_bytes: 6,
        expected_bytes: 7,
        replayed_chunks: 8,
        rejected_chunks: 9,
    });
    store.insert_link(link).unwrap();

    let loaded = store.link("", "link-1").unwrap().unwrap();
    assert_eq!(loaded.uploads.len(), 1);
    assert!(loaded.uploads[0].files[0].receipt);
    assert_eq!(loaded.events[0].outcome, "cancelled");
    assert_eq!(store.links("").unwrap().len(), 1);
    let upload_link = store.upload_link("link-1").unwrap().unwrap();
    assert!(upload_link.uploads.is_empty());
    assert!(upload_link.events.is_empty());
    assert_eq!(store.uploads_by_id("link-1").unwrap().unwrap().len(), 1);
    assert!(store.upload_link("missing").unwrap().is_none());
    assert!(store.uploads_by_id("missing").unwrap().is_none());
    store
        .with(|connection| {
            connection.execute(
                "UPDATE link_uploads SET document = 'broken' WHERE link_id = 'link-1'",
                [],
            )
        })
        .unwrap();
    assert!(store.uploads_by_id("link-1").is_err());
    assert!(store.link("", "link-1").is_err());
    store
            .with(|connection| {
                connection.execute_batch("DELETE FROM link_uploads WHERE link_id='link-1'; UPDATE links SET events_json='broken' WHERE id='link-1';")
            })
            .unwrap();
    assert!(store.uploads_by_id("link-1").is_err());
    assert!(store.link("", "link-1").is_err());
}

#[test]
fn update_and_remove_report_presence() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    store.insert_link(test_link("link-1")).unwrap();
    let found = store
        .update_link("", "link-1", |link| link.active = false)
        .unwrap();
    assert!(found);
    assert!(!store.link("", "link-1").unwrap().unwrap().active);
    assert!(!store.update_link("", "missing", |_| {}).unwrap());
    assert!(store.remove_link("", "link-1").unwrap());
    assert!(!store.remove_link("", "link-1").unwrap());
    assert!(store.link("", "link-1").unwrap().is_none());
}

#[test]
fn remove_link_cleans_request_children_atomically_and_scoped() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    for tenant in ["acme", "other"] {
        store.insert_tenant(test_tenant(tenant)).unwrap();
    }
    for (tenant, link, route, session, upload) in [
        (
            "acme",
            "target",
            "route-target",
            "session-target",
            "upload-target",
        ),
        ("acme", "same", "route-same", "session-same", "upload-same"),
        (
            "other",
            "other-link",
            "route-other",
            "session-other",
            "upload-other",
        ),
    ] {
        store.insert_link(link_in(tenant, link)).unwrap();
        store
                .with(|connection| {
                    connection.execute(
                        "INSERT INTO receive_workflows(link_id,document) VALUES (?1,'{}')",
                        [link],
                    )?;
                    connection.execute(
                        "INSERT INTO receive_workflow_uploads(link_id,upload_id) VALUES (?1,?2)",
                        rusqlite::params![link, upload],
                    )?;
                    connection.execute(
                        "INSERT INTO inbound_routes(id,tenant,link_id,issuer,operation_id,source,ancestry,created_at)
                         VALUES (?1,?2,?3,'issuer','operation','{}','[]',1)",
                        rusqlite::params![route, tenant, link],
                    )?;
                    connection.execute(
                        "INSERT INTO route_uploads(route_id,upload_id,partial) VALUES (?1,?2,0)",
                        rusqlite::params![route, upload],
                    )?;
                    connection.execute(
                        "INSERT INTO trade_delivery_policies(route_id,document) VALUES (?1,'{}')",
                        [route],
                    )?;
                    connection.execute(
                        "INSERT INTO upload_sessions
                         (id,link_id,tenant,dest_dir,dest_rel,package_suite,package_root,package_length,
                          max_total_bytes,started_at,created_at,push_key,committed_upload_id)
                         VALUES (?1,?2,?3,'dest','',1,'root',1,NULL,1,1,NULL,?4)",
                        rusqlite::params![session, link, tenant, (upload.to_owned())],
                    )?;
                    connection.execute(
                        "INSERT INTO upload_session_files
                         (session_id,entry,display_path,stored_components,object_suite,object_root,
                          object_length,staging_path,journal_path,incarnation)
                         VALUES (?1,0,'file','[]',1,'root',1,'stage','journal','incarnation')",
                        [session],
                    )?;
                    Ok(())
                })
                .unwrap();
    }
    store
            .with(|connection| {
                connection.execute_batch(
                    "INSERT INTO trade_routes(id,tenant,direction,peer_key,endpoint,document,credential,enrollment)
                     VALUES ('trade-incoming','acme','incoming','peer','target','{\"state\":\"revoked\"}','credential',NULL);
                     INSERT INTO trade_rotations(route_id,credential) VALUES ('trade-incoming','rotation-incoming');
                     INSERT INTO trade_routes(id,tenant,direction,peer_key,endpoint,document,credential,enrollment)
                     VALUES ('trade-outgoing','acme','outgoing','peer','target','{\"state\":\"active\"}','credential',NULL);
                     INSERT INTO trade_rotations(route_id,credential) VALUES ('trade-outgoing','rotation-outgoing');",
                )
            })
            .unwrap();

    let child_counts = |link: &str, route: &str, session: &str| {
        store
            .with(|connection| {
                connection.query_row(
                    "SELECT
                           (SELECT COUNT(*) FROM receive_workflows WHERE link_id=?1),
                           (SELECT COUNT(*) FROM receive_workflow_uploads WHERE link_id=?1),
                           (SELECT COUNT(*) FROM inbound_routes WHERE id=?2),
                           (SELECT COUNT(*) FROM route_uploads WHERE route_id=?2),
                           (SELECT COUNT(*) FROM trade_delivery_policies WHERE route_id=?2),
                           (SELECT COUNT(*) FROM upload_sessions WHERE id=?3),
                           (SELECT COUNT(*) FROM upload_session_files WHERE session_id=?3)",
                    rusqlite::params![link, route, session],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, i64>(4)?,
                            row.get::<_, i64>(5)?,
                            row.get::<_, i64>(6)?,
                        ))
                    },
                )
            })
            .unwrap()
    };
    let expected = (1, 1, 1, 1, 1, 1, 1);
    assert_eq!(
        child_counts("target", "route-target", "session-target"),
        expected
    );

    assert!(!store.remove_link("other", "target").unwrap());
    assert_eq!(
        child_counts("target", "route-target", "session-target"),
        expected
    );

    store
        .with(|connection| {
            connection.execute_batch(
                "CREATE TRIGGER fail_request_child_delete
                     BEFORE DELETE ON links
                     WHEN OLD.id='target'
                     BEGIN SELECT RAISE(ABORT,'fixture remove failure'); END;",
            )
        })
        .unwrap();
    assert!(store.remove_link("acme", "target").is_err());
    assert!(store.link("acme", "target").unwrap().is_some());
    assert_eq!(
        child_counts("target", "route-target", "session-target"),
        expected
    );
    store
        .with(|connection| connection.execute_batch("DROP TRIGGER fail_request_child_delete"))
        .unwrap();

    assert!(store.remove_link("acme", "target").unwrap());
    assert!(store.link("acme", "target").unwrap().is_none());
    assert_eq!(
        child_counts("target", "route-target", "session-target"),
        (0, 0, 0, 0, 0, 0, 0)
    );
    assert_eq!(child_counts("same", "route-same", "session-same"), expected);
    assert_eq!(
        child_counts("other-link", "route-other", "session-other"),
        expected
    );
    assert_eq!(
        store
            .with(|connection| connection.query_row(
                "SELECT COUNT(*) FROM trade_rotations WHERE route_id='trade-incoming'",
                [],
                |row| row.get::<_, i64>(0),
            ))
            .unwrap(),
        0
    );
    assert_eq!(
        store
            .with(|connection| connection.query_row(
                "SELECT COUNT(*) FROM trade_rotations WHERE route_id='trade-outgoing'",
                [],
                |row| row.get::<_, i64>(0),
            ))
            .unwrap(),
        1
    );
    assert!(!store.remove_link("acme", "target").unwrap());
    assert!(!store.remove_link("acme", "missing").unwrap());
}

#[test]
fn remove_missing_link_ignores_stale_matching_records() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    store.insert_tenant(test_tenant("acme")).unwrap();
    store
        .with(|connection| {
            connection.execute(
                "INSERT INTO delivery_jobs
                     (id,tenant,actor,operation_id,project_id,state,owner,not_before,
                      deadline,escalated,token,document)
                     VALUES ('stale-job','acme','actor','operation','project','queued','',0,
                             NULL,0,'token','{\"received\":{\"link_id\":\"stale\"}}')",
                [],
            )?;
            connection.execute(
                "INSERT INTO trade_routes
                     (id,tenant,direction,peer_key,endpoint,document,credential,enrollment)
                     VALUES ('stale-route','acme','incoming','peer','stale',
                             '{\"state\":\"active\"}','credential',NULL)",
                [],
            )?;
            connection.execute(
                "INSERT INTO trade_rotations(route_id,credential)
                     VALUES ('stale-route','rotation')",
                [],
            )?;
            Ok(())
        })
        .unwrap();

    assert!(!store.remove_link("acme", "stale").unwrap());
    assert!(store.link("acme", "stale").unwrap().is_none());
    assert_eq!(
        store
            .with(|connection| connection.query_row(
                "SELECT
                       (SELECT COUNT(*) FROM delivery_jobs WHERE id='stale-job'),
                       (SELECT COUNT(*) FROM trade_routes WHERE id='stale-route'),
                       (SELECT COUNT(*) FROM trade_rotations WHERE route_id='stale-route')",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            ))
            .unwrap(),
        (1, 1, 1)
    );
}

#[test]
fn tombstones_do_not_decode_upload_headers() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let mut link = test_link("link");
    link.uploads.push(UploadRecord {
        id: "upload".into(),
        started_at: 1,
        completed_at: 2,
        replayed_chunks: 0,
        rejected_chunks: 0,
        transport: None,
        package_root: "package".into(),
        total_bytes: 1,
        partial: false,
        log: Vec::new(),
        files: vec![FileRecord {
            path: "display".into(),
            stored_as: "stored".into(),
            bytes: 1,
            suite: "blake3".into(),
            root: "aa".into(),
            receipt: true,
            deleted: false,
        }],
    });
    let mut alias = link.uploads[0].clone();
    alias.id = "alias".into();
    link.uploads.push(alias);
    let mut unrelated = link.uploads[0].clone();
    unrelated.id = "unrelated".into();
    unrelated.files[0].stored_as = "other".into();
    link.uploads.push(unrelated);
    store.insert_link(link).unwrap();
    store
        .with(|connection| {
            connection.execute_batch(
                "UPDATE link_uploads SET document='{}' WHERE link_id='link';
             CREATE TRIGGER fail_alias_tombstone BEFORE UPDATE ON files
             WHEN old.upload_id='alias' BEGIN SELECT RAISE(FAIL,'fixture alias failure'); END;",
            )
        })
        .unwrap();
    let paths = std::collections::HashSet::from(["stored"]);
    assert!(store
        .tombstone_files("", "link", &paths)
        .unwrap_err()
        .contains("fixture alias failure"));
    assert_eq!(store.tenant_received_bytes("").unwrap(), 2);
    assert_eq!(
        store
            .with(|c| {
                c.query_row("SELECT count(*) FROM files WHERE deleted=0", [], |row| {
                    row.get::<_, i64>(0)
                })
            })
            .unwrap(),
        3
    );
    store
        .with(|c| c.execute_batch("DROP TRIGGER fail_alias_tombstone"))
        .unwrap();
    assert!(!store
        .tombstone_files("other-tenant", "link", &paths)
        .unwrap());
    assert_eq!(store.tenant_received_bytes("").unwrap(), 2);
    assert_eq!(
        store
            .with(|c| {
                c.query_row("SELECT count(*) FROM files WHERE deleted=0", [], |row| {
                    row.get::<_, i64>(0)
                })
            })
            .unwrap(),
        3
    );
    assert!(store.link_upload("", "link", "upload").is_err());
    assert!(store
        .tombstone_files("", "link", &std::collections::HashSet::from(["stored"]))
        .unwrap());
    let mut spool = Vec::new();
    store.write_tenant_live_files("", &mut spool).unwrap();
    let live: Vec<(String, u64)> = spool
        .split(|byte| *byte == b'\n')
        .filter(|row| !row.is_empty())
        .map(|row| serde_json::from_slice(row).unwrap())
        .collect();
    assert_eq!(live, vec![("other".to_owned(), 1)]);
    assert!(store.link_upload("", "link", "upload").is_err());
    assert!(store.link_upload("", "link", "unrelated").is_err());
}

#[test]
fn upload_headers_stay_small_and_typed_files_round_trip() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let mut link = test_link("link");
    let upload = UploadRecord {
        id: "upload".into(),
        started_at: 11,
        completed_at: 22,
        replayed_chunks: 3,
        rejected_chunks: 4,
        transport: Some("native".into()),
        package_root: "aa".repeat(32),
        total_bytes: u64::MAX,
        partial: true,
        log: vec![LogEvent {
            at: 22,
            kind: "interrupted".into(),
            path: None,
            bytes: Some(u64::MAX),
            secs: Some(5),
            count: Some(2048),
        }],
        files: (0..2048)
            .map(|index| FileRecord {
                path: format!("folder/納品-{index}.mov"),
                stored_as: format!("stored/{index}.mov"),
                bytes: if index == 0 { u64::MAX } else { index },
                suite: if index % 2 == 0 { "sha256" } else { "blake3" }.into(),
                root: format!("{index:064x}"),
                receipt: index % 2 == 0,
                deleted: index % 2 != 0,
            })
            .collect(),
    };
    link.uploads.push(upload.clone());
    let mut empty = upload.clone();
    empty.id = "empty".into();
    empty.files.clear();
    empty.total_bytes = 0;
    link.uploads.push(empty.clone());
    store.insert_link(link).unwrap();
    let (header, count): (String, i64) = store
        .with(|c| {
            c.query_row(
                "SELECT document,file_count FROM link_uploads WHERE upload_id='upload'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
        })
        .unwrap();
    assert!(
        header.len() < 1024,
        "header includes file-sized metadata: {}",
        header.len()
    );
    assert_eq!(count, 2048);
    let header: serde_json::Value = serde_json::from_str(&header).unwrap();
    assert_eq!(header["files"], serde_json::json!([]));
    drop(store);
    let store = Store::open(directory.path()).unwrap();
    assert_eq!(
        store.link_upload("", "link", "upload").unwrap().unwrap(),
        upload
    );
    assert_eq!(
        store.link_upload("", "link", "empty").unwrap().unwrap(),
        empty
    );
    assert_eq!(
        store.uploads_by_id("link").unwrap().unwrap(),
        vec![upload, empty]
    );
    let result = store.search("", "納品-0.mov", 10).unwrap();
    assert_eq!(result.files.len(), 1);
    assert_eq!(result.files[0].bytes, u64::MAX);
    assert_eq!(result.files[0].upload_id, "upload");
    assert!(store.search("", "納品-1.mov", 10).unwrap().files.is_empty());
}

#[test]
fn full_upload_reads_refuse_missing_or_misindexed_file_records() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let mut link = test_link("link");
    link.uploads.push(UploadRecord {
        id: "upload".into(),
        started_at: 1,
        completed_at: 2,
        replayed_chunks: 0,
        rejected_chunks: 0,
        transport: None,
        package_root: "package".into(),
        total_bytes: 2,
        partial: false,
        log: Vec::new(),
        files: (0..2)
            .map(|index| FileRecord {
                path: format!("file-{index}"),
                stored_as: format!("stored-{index}"),
                bytes: 1,
                suite: "blake3".into(),
                root: "aa".into(),
                receipt: true,
                deleted: false,
            })
            .collect(),
    });
    store.insert_link(link).unwrap();
    store
        .with(|c| c.execute("UPDATE files SET file_index=2 WHERE file_index=0", []))
        .unwrap();
    assert!(store
        .link_upload("", "link", "upload")
        .unwrap_err()
        .contains("do not match"));
    store
        .with(|c| c.execute("UPDATE files SET file_index=0 WHERE file_index=2", []))
        .unwrap();
    for count in [-1, 1, 3] {
        store
            .with(|c| c.execute("UPDATE link_uploads SET file_count=?1", [count]))
            .unwrap();
        assert!(store
            .link_upload("", "link", "upload")
            .unwrap_err()
            .contains("do not match"));
    }
    store
        .with(|c| {
            c.execute_batch(
                "UPDATE link_uploads SET file_count=2; DELETE FROM files WHERE file_index=0",
            )
        })
        .unwrap();
    assert!(store
        .link_upload("", "link", "upload")
        .unwrap_err()
        .contains("do not match"));
    assert!(store.uploads_by_id("link").is_err());
}

#[test]
fn link_policy_updates_do_not_decode_upload_history() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    store.insert_link(test_link("link")).unwrap();
    store.with(|connection| connection.execute(
            "INSERT INTO link_uploads(link_id,tenant,upload_id,document,file_count) VALUES ('link','','bad','{}',0)", [],
        )).unwrap();
    assert!(store
        .update_link("", "link", |link| link.active = false)
        .unwrap());
    assert!(!store.upload_link("link").unwrap().unwrap().active);
    assert!(store.uploads_by_id("link").is_err());
}

#[test]
fn upload_mutations_preserve_other_records_and_rollback_together() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let record = |id: &str, path: &str, partial| UploadRecord {
        id: id.into(),
        started_at: 1,
        completed_at: 2,
        replayed_chunks: 0,
        rejected_chunks: 0,
        transport: None,
        package_root: "package".into(),
        total_bytes: 1,
        partial,
        log: Vec::new(),
        files: vec![FileRecord {
            path: path.into(),
            stored_as: path.into(),
            bytes: 1,
            suite: "blake3".into(),
            root: "aa".into(),
            receipt: false,
            deleted: false,
        }],
    };
    let mut link = test_link("history");
    link.uploads = vec![
        record("first", "shared", true),
        record("second", "shared", true),
        record("third", "other", false),
    ];
    store.insert_link(link).unwrap();
    let third = store
        .with(|c| {
            c.query_row(
                "SELECT position,document FROM link_uploads WHERE upload_id='third'",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
        })
        .unwrap();
    store.with(|c| c.execute_batch("CREATE TABLE history_writes(upload_id TEXT, kind TEXT);
            CREATE TRIGGER history_update AFTER UPDATE ON link_uploads BEGIN INSERT INTO history_writes VALUES(new.upload_id,'update'); END;
            CREATE TABLE file_updates(upload_id TEXT);
            CREATE TRIGGER file_update AFTER UPDATE ON files BEGIN INSERT INTO file_updates VALUES(new.upload_id); END;
            CREATE TRIGGER history_delete AFTER DELETE ON link_uploads BEGIN INSERT INTO history_writes VALUES(old.upload_id,'delete'); END;
            CREATE TRIGGER history_insert AFTER INSERT ON link_uploads BEGIN INSERT INTO history_writes VALUES(new.upload_id,'insert'); END;
            CREATE TRIGGER fail_file_delete BEFORE DELETE ON files BEGIN SELECT RAISE(ABORT,'fixture delete failure'); END;")).unwrap();
    assert!(!store.remove_upload("other", "history", "first").unwrap());
    assert!(!store.remove_upload("", "history", "missing").unwrap());
    assert!(store
        .remove_upload("", "history", "first")
        .unwrap_err()
        .contains("fixture delete failure"));
    assert!(store.link_upload("", "history", "first").unwrap().is_some());
    store
        .with(|c| c.execute_batch("DROP TRIGGER fail_file_delete"))
        .unwrap();
    assert!(store.remove_upload("", "history", "first").unwrap());
    store
        .update_link("", "history", |link| link.active = false)
        .unwrap();
    store.with(|c| c.execute_batch("CREATE TRIGGER fail_history_update BEFORE UPDATE ON files BEGIN SELECT RAISE(ABORT,'fixture update failure'); END;")).unwrap();
    let paths = std::collections::HashSet::from(["shared"]);
    assert!(store
        .tombstone_files("", "history", &paths)
        .unwrap_err()
        .contains("fixture update failure"));
    assert!(
        !store
            .link_upload("", "history", "second")
            .unwrap()
            .unwrap()
            .files[0]
            .deleted
    );
    assert_eq!(store.tenant_received_bytes("").unwrap(), 2);
    store
        .with(|c| c.execute_batch("DROP TRIGGER fail_history_update"))
        .unwrap();
    store.tombstone_files("", "history", &paths).unwrap();
    assert_eq!(
        store
            .with(|c| c.query_row(
                "SELECT count(*) FROM history_writes WHERE kind='update'",
                [],
                |row| row.get::<_, i64>(0),
            ))
            .unwrap(),
        0
    );
    let mut recovered = record("second", "shared", true);
    recovered.files[0].receipt = true;
    recovered
        .files
        .push(record("extra", "extra", true).files.remove(0));
    store
        .append_upload("", "history", recovered.clone())
        .unwrap();
    let file_updates = || {
        store
            .with(|c| {
                c.query_row("SELECT count(*) FROM file_updates", [], |row| {
                    row.get::<_, i64>(0)
                })
            })
            .unwrap()
    };
    assert_eq!(file_updates(), 2);
    store
        .append_upload("", "history", recovered.clone())
        .unwrap();
    assert_eq!(
        file_updates(),
        2,
        "unchanged recovery must not rewrite file rows"
    );
    let second = store.link_upload("", "history", "second").unwrap().unwrap();
    assert!(second.files[0].deleted && second.files[0].receipt);
    assert_eq!(second.files[1].stored_as, "extra");
    assert!(!second.files[1].deleted);
    assert_eq!(second.total_bytes, 2);
    assert_eq!(store.tenant_received_bytes("").unwrap(), 2);
    let before = serde_json::to_string(&second).unwrap();
    recovered.files[0].root = "changed".into();
    assert!(store
        .append_upload("", "history", recovered.clone())
        .unwrap_err()
        .contains("file identity"));
    recovered.package_root = "changed".into();
    assert!(store
        .append_upload("", "history", recovered)
        .unwrap_err()
        .contains("upload identity"));
    assert_eq!(
        serde_json::to_string(&store.link_upload("", "history", "second").unwrap().unwrap())
            .unwrap(),
        before
    );
    let full = record("third", "other", false);
    store.append_upload("", "history", full.clone()).unwrap();
    let mut conflicting = full;
    conflicting.files[0].root = "different".into();
    assert!(store
        .append_upload("", "history", conflicting)
        .unwrap_err()
        .contains("upload identity"));
    store.with(|c| c.execute_batch("CREATE TRIGGER fail_file_insert BEFORE INSERT ON files BEGIN SELECT RAISE(ABORT,'fixture insert failure'); END;")).unwrap();
    assert!(store
        .append_upload("", "history", record("last", "last", false))
        .is_err());
    assert!(store.link_upload("", "history", "last").unwrap().is_none());
    store
        .with(|c| c.execute_batch("DROP TRIGGER fail_file_insert"))
        .unwrap();
    store
        .append_upload("", "history", record("aaa", "last", false))
        .unwrap();
    assert_eq!(
        store
            .with(|c| c.query_row(
                "SELECT position,document FROM link_uploads WHERE upload_id='third'",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            ))
            .unwrap(),
        third
    );
    assert_eq!(
        store
            .with(|c| c.query_row(
                "SELECT count(*) FROM history_writes WHERE upload_id='third'",
                [],
                |row| row.get::<_, i64>(0)
            ))
            .unwrap(),
        0
    );
    let files = store
        .with(|c| {
            c.prepare(
                "SELECT upload_id,file_index,deleted FROM files ORDER BY upload_id,file_index",
            )?
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, bool>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
        })
        .unwrap();
    assert_eq!(
        files,
        [
            ("aaa".into(), 0, false),
            ("second".into(), 0, true),
            ("second".into(), 1, false),
            ("third".into(), 0, false)
        ]
    );
    let ids = || {
        store
            .uploads_by_id("history")
            .unwrap()
            .unwrap()
            .into_iter()
            .map(|upload| upload.id)
            .collect::<Vec<_>>()
    };
    assert_eq!(ids(), ["second", "third", "aaa"]);
    let snapshot = directory.path().join("snapshot");
    std::fs::create_dir(&snapshot).unwrap();
    store.backup_into(&snapshot.join("votport.db")).unwrap();
    let restored = Store::open(&snapshot).unwrap();
    assert_eq!(
        restored
            .uploads_by_id("history")
            .unwrap()
            .unwrap()
            .into_iter()
            .map(|upload| upload.id)
            .collect::<Vec<_>>(),
        ids()
    );
    assert_eq!(restored.tenant_received_bytes("").unwrap(), 3);
    assert!(store.remove_link("", "history").unwrap());
    assert_eq!(
        store
            .with(
                |c| c.query_row("SELECT count(*) FROM link_uploads", [], |row| row
                    .get::<_, i64>(0))
            )
            .unwrap(),
        0
    );
}

#[test]
fn links_preserve_insertion_order() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    store.insert_link(test_link("b")).unwrap();
    store.insert_link(test_link("a")).unwrap();
    let ids: Vec<String> = store
        .links("")
        .unwrap()
        .into_iter()
        .map(|link| link.id)
        .collect();
    assert_eq!(ids, ["b", "a"]);
}

#[test]
fn admin_hash_persists_across_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    assert!(store.admin_password_hash().unwrap().is_none());
    store
        .set_admin_password_hash("argon2-hash".to_owned())
        .unwrap();
    drop(store);
    let reopened = Store::open(directory.path()).unwrap();
    assert_eq!(
        reopened.admin_password_hash().unwrap().as_deref(),
        Some("argon2-hash")
    );
}

#[test]
fn optional_columns_round_trip() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let mut link = test_link("link-1");
    link.password_hash = Some("argon2".to_owned());
    link.expires_at = Some(12345);
    link.max_bytes = Some(999);
    store.insert_link(link).unwrap();
    drop(store);
    let reopened = Store::open(directory.path()).unwrap();
    let loaded = reopened.link("", "link-1").unwrap().unwrap();
    assert_eq!(loaded.password_hash.as_deref(), Some("argon2"));
    assert_eq!(loaded.expires_at, Some(12345));
    assert_eq!(loaded.max_bytes, Some(999));
    // And the None side survives too.
    let mut bare = test_link("link-2");
    bare.expires_at = None;
    reopened.insert_link(bare).unwrap();
    assert_eq!(
        reopened.link("", "link-2").unwrap().unwrap().expires_at,
        None
    );
}

#[test]
fn audit_rows_round_trip_export_and_prune() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    store.audit(
        "",
        "",
        "link_created",
        "link-1",
        &serde_json::json!({ "label": "x" }),
    );
    store.audit("", "", "admin_login", "10.0.0.1", &serde_json::json!({}));

    let rows = store.audit_export(None, 0, 0, 100).unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].event, "link_created");
    assert_eq!(rows[0].tenant, "");
    assert_eq!(rows[0].detail["label"], "x");
    // `since` is strictly greater-than (rows share second granularity).
    let after_all = store
        .audit_export(None, rows.last().unwrap().at + 1, 0, 100)
        .unwrap();
    assert!(after_all.is_empty());
    assert_eq!(store.audit_export(None, 0, 0, 1).unwrap().len(), 1);

    // Pruning removes only rows strictly older than the cutoff.
    let now = now_unix();
    let pruned = store.audit_prune(now + 1, &[]).unwrap();
    assert_eq!(pruned, 2);
    assert!(store.audit_export(None, 0, 0, 100).unwrap().is_empty());

    store.audit("", "", "test", "corrupt", &serde_json::json!({}));
    store
        .with(|connection| connection.execute("UPDATE audit_log SET detail = 'broken'", []))
        .unwrap();
    assert!(store.audit_export(None, 0, 0, 100).is_err());
}

#[test]
fn audit_count_tracks_mutations_rollbacks_pruning_and_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    assert_eq!(store.audit_count().unwrap(), 0);
    store.audit("", "", "committed", "one", &serde_json::json!({}));
    assert_eq!(store.audit_count().unwrap(), 1);

    store
        .with(|connection| {
            connection.execute(
                "INSERT INTO audit_log(at,tenant,actor,event,subject,detail)
                     VALUES (?1,'','',?2,'two','{}')",
                rusqlite::params![now_unix() as i64, "direct"],
            )
        })
        .unwrap();
    assert_eq!(store.audit_count().unwrap(), 2);

    store
        .with(|connection| {
            connection.execute_batch("BEGIN")?;
            connection.execute(
                "INSERT INTO audit_log(at,tenant,actor,event,subject,detail)
                     VALUES (?1,'','',?2,'rolled-back','{}')",
                rusqlite::params![now_unix() as i64, "rollback"],
            )?;
            connection.execute_batch("ROLLBACK")
        })
        .unwrap();
    assert_eq!(store.audit_count().unwrap(), 2);

    store
        .with(|connection| connection.execute("DELETE FROM audit_log WHERE event='direct'", []))
        .unwrap();
    assert_eq!(store.audit_count().unwrap(), 1);
    assert_eq!(store.audit_prune(now_unix() + 1, &[]).unwrap(), 1);
    assert_eq!(store.audit_count().unwrap(), 0);

    drop(store);
    let reopened = Store::open(directory.path()).unwrap();
    assert_eq!(reopened.audit_count().unwrap(), 0);
}

#[test]
fn audit_count_reads_retained_counter_after_audit_history_removed() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    store.audit("", "", "first", "one", &serde_json::json!({}));
    store.audit("", "", "second", "two", &serde_json::json!({}));
    store.audit("", "", "third", "three", &serde_json::json!({}));
    assert_eq!(store.audit_count().unwrap(), 3);

    store
        .with(|connection| connection.execute_batch("DROP TABLE audit_log"))
        .unwrap();
    assert_eq!(store.audit_count().unwrap(), 3);
}

#[cfg(test)]
mod tenant_tests {
    use super::*;
    use super::{link_in, test_tenant};

    #[test]
    fn links_are_invisible_across_tenants() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .insert_tenant(Tenant {
                retention_days: None,
                incarnation: String::new(),
                key: "acme".to_owned(),
                label: "Acme".to_owned(),
                admin_group: None,
                max_total_bytes: None,
                max_links: None,
                max_sessions: None,
                created_at: 0,
            })
            .unwrap();
        store.insert_link(link_in("acme", "secret-link")).unwrap();
        store.insert_link(link_in("", "default-link")).unwrap();

        assert!(store.link("acme", "secret-link").unwrap().is_some());
        // Another tenant (and the default) cannot see or touch it.
        assert!(store.link("", "secret-link").unwrap().is_none());
        assert!(!store.update_link("", "secret-link", |_| {}).unwrap());
        assert!(!store.remove_link("", "secret-link").unwrap());
        assert_eq!(store.links("acme").unwrap().len(), 1);
        assert_eq!(store.links("").unwrap().len(), 1);
    }

    #[test]
    fn tenant_crud_refuses_while_links_remain() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .insert_tenant(Tenant {
                retention_days: None,
                incarnation: String::new(),
                key: "acme".to_owned(),
                label: String::new(),
                admin_group: Some("acme-admins".to_owned()),
                max_total_bytes: Some(1024),
                max_links: Some(2),
                max_sessions: Some(1),
                created_at: 0,
            })
            .unwrap();
        assert_eq!(store.tenants().unwrap().len(), 1);
        assert_eq!(store.tenant("acme").unwrap().unwrap().max_links, Some(2));
        assert!(store.tenant("missing").unwrap().is_none());

        store.insert_link(link_in("acme", "blocked")).unwrap();
        // The handler refuses deletion while links remain; the store exposes
        // the count and the raw delete.
        assert_eq!(store.tenant_link_count("acme").unwrap(), 1);

        store.remove_link("acme", "blocked").unwrap();
        assert_eq!(store.tenant_link_count("acme").unwrap(), 0);
        assert_eq!(store.remove_tenant("acme").unwrap(), TenantRemoval::Deleted);
        assert!(store.tenant("acme").unwrap().is_none());
        let err = store.insert_link(link_in("acme", "orphan")).unwrap_err();
        assert_eq!(err, InsertLinkError::NamedTenantGone);
        assert!(store.link("acme", "orphan").unwrap().is_none());
    }

    #[test]
    fn received_bytes_count_live_files_only() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut link = link_in("acme", "link-1");
        let mut file = FileRecord {
            path: "a.bin".to_owned(),
            stored_as: "a.bin".to_owned(),
            bytes: 500,
            suite: "blake3".to_owned(),
            root: "aa".to_owned(),
            receipt: false,
            deleted: false,
        };
        link.uploads.push(UploadRecord {
            partial: false,
            log: Vec::new(),
            id: "up".to_owned(),
            started_at: 0,
            completed_at: 0,
            replayed_chunks: 0,
            rejected_chunks: 0,
            transport: None,
            package_root: "cc".to_owned(),
            total_bytes: 500,
            files: vec![file.clone()],
        });
        store.insert_tenant(test_tenant("acme")).unwrap();
        store.insert_link(link.clone()).unwrap();
        assert_eq!(store.tenant_received_bytes("acme").unwrap(), 500);
        assert_eq!(store.tenant_received_bytes("").unwrap(), 0);
        let usage = store.tenant_usage().unwrap();
        assert_eq!(usage.len(), 2);
        assert_eq!(usage[0].tenant, "");
        assert_eq!(usage[0].links, 0);
        assert_eq!(usage[1].tenant, "acme");
        assert_eq!(usage[1].links, 1);
        assert_eq!(usage[1].received_bytes, 500);

        store
            .with(|connection| {
                connection.execute_batch(
                    "CREATE TRIGGER fail_file_update BEFORE UPDATE ON files
                     BEGIN SELECT RAISE(FAIL, 'test file failure'); END;",
                )
            })
            .unwrap();
        assert!(store
            .tombstone_files(
                "acme",
                "link-1",
                &std::collections::HashSet::from(["a.bin"])
            )
            .is_err());
        assert!(!store.link("acme", "link-1").unwrap().unwrap().uploads[0].files[0].deleted);
        assert_eq!(store.tenant_received_bytes("acme").unwrap(), 500);
        store
            .with(|connection| connection.execute_batch("DROP TRIGGER fail_file_update"))
            .unwrap();

        file.deleted = true;
        link.uploads[0].files[0] = file;
        store
            .tombstone_files(
                "acme",
                "link-1",
                &std::collections::HashSet::from(["a.bin"]),
            )
            .unwrap();
        assert_eq!(store.tenant_received_bytes("acme").unwrap(), 0);
        assert_eq!(store.tenant_usage().unwrap()[1].received_bytes, 0);
        assert!(store.remove_link("acme", "link-1").unwrap());
        let files = store
            .with(|connection| {
                connection.query_row("SELECT COUNT(*) FROM files", [], |row| row.get::<_, i64>(0))
            })
            .unwrap();
        assert_eq!(files, 0);
    }

    #[test]
    fn quota_aggregate_tracks_identity_limb_and_saturation_changes() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let insert = |tenant: &str, link: &str, upload: &str, stored_as: &str, bytes: u64| {
            store
                .with(|connection| {
                    let (hi, lo) = split_bytes(bytes);
                    connection.execute(
                        "INSERT INTO files(link_id,tenant,upload_id,file_index,bytes_hi,bytes_lo,deleted,stored_as,path,suite,root,receipt)
                         VALUES (?1,?2,?3,0,?4,?5,0,?6,'path','blake3','root',0)",
                        rusqlite::params![link, tenant, upload, hi, lo, stored_as],
                    )?;
                    Ok(())
                })
                .unwrap();
        };
        insert("acme", "a", "one", "same", u64::from(u32::MAX));
        insert("acme", "b", "two", "same", (1_u64 << 32) + 1);
        insert("acme", "c", "three", "", 5);
        insert("acme", "d", "four", "c/three/0", 7);
        insert("other", "e", "five", "same", 10);
        assert_eq!(
            store.tenant_received_bytes("acme").unwrap(),
            (1_u64 << 32) + 13
        );

        store
            .with(|connection| {
                connection.execute(
                    "UPDATE files SET bytes_hi=1,bytes_lo=10 WHERE tenant='acme' AND link_id='b'",
                    [],
                )
            })
            .unwrap();
        assert_eq!(
            store.tenant_received_bytes("acme").unwrap(),
            (1_u64 << 32) + 22
        );
        store
            .with(|connection| {
                connection.execute("DELETE FROM files WHERE tenant='acme' AND link_id='b'", [])
            })
            .unwrap();
        assert_eq!(
            store.tenant_received_bytes("acme").unwrap(),
            (1_u64 << 32) + 11
        );
        store
            .with(|connection| {
                connection.execute(
                    "UPDATE files SET deleted=1 WHERE tenant='acme' AND link_id='a'",
                    [],
                )
            })
            .unwrap();
        assert_eq!(store.tenant_received_bytes("acme").unwrap(), 12);
        store
            .with(|connection| {
                connection.execute(
                    "UPDATE files SET tenant='other' WHERE tenant='acme' AND link_id='c'",
                    [],
                )
            })
            .unwrap();
        assert_eq!(store.tenant_received_bytes("acme").unwrap(), 7);
        assert_eq!(store.tenant_received_bytes("other").unwrap(), 15);

        insert("acme", "max", "six", "max", u64::MAX);
        insert("acme", "small", "seven", "small", 1);
        assert_eq!(store.tenant_received_bytes("acme").unwrap(), u64::MAX);
        store
            .with(|connection| {
                connection.execute(
                    "DELETE FROM files WHERE tenant='acme' AND link_id='small'",
                    [],
                )
            })
            .unwrap();
        assert_eq!(store.tenant_received_bytes("acme").unwrap(), u64::MAX);
        store
            .with(|connection| {
                connection.execute(
                    "DELETE FROM files WHERE tenant='acme' AND link_id='max'",
                    [],
                )
            })
            .unwrap();
        assert_eq!(store.tenant_received_bytes("acme").unwrap(), 7);
        let state = store
            .with(|connection| {
                connection.query_row(
                    "SELECT state FROM tenant_quota_usage WHERE tenant='acme'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
            })
            .unwrap();
        assert_eq!(state, 0);

        insert("acme", "tie-a", "eight", "tie", (7_u64 << 32) + 1);
        insert("acme", "tie-b", "nine", "tie", (7_u64 << 32) + 9);
        assert_eq!(
            store.tenant_received_bytes("acme").unwrap(),
            (7_u64 << 32) + 16
        );
        store
            .with(|connection| {
                connection.execute(
                    "DELETE FROM files WHERE tenant='acme' AND link_id='tie-b'",
                    [],
                )
            })
            .unwrap();
        assert_eq!(
            store.tenant_received_bytes("acme").unwrap(),
            (7_u64 << 32) + 8
        );
        store
            .with(|connection| {
                connection.execute(
                    "DELETE FROM files WHERE tenant='acme' AND link_id='tie-a'",
                    [],
                )
            })
            .unwrap();
        assert_eq!(store.tenant_received_bytes("acme").unwrap(), 7);
        store
            .with(|connection| {
                connection.execute("DELETE FROM files WHERE tenant='acme' AND link_id='d'", [])
            })
            .unwrap();
        assert_eq!(store.tenant_received_bytes("acme").unwrap(), 0);
    }

    #[test]
    fn tenant_received_bytes_admission_vm_work_is_bounded() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let insert = |start: usize, count: usize| {
            store
                .with(|connection| {
                    connection.execute_batch("BEGIN")?;
                    for index in start..start + count {
                        let (hi, lo) = split_bytes((index + 1) as u64);
                        connection.execute(
                            "INSERT INTO files(link_id,tenant,upload_id,file_index,bytes_hi,bytes_lo,deleted,stored_as,path,suite,root,receipt)
                             VALUES (?1,'acme','upload',?2,?3,?4,0,?5,?5,'blake3','root',0)",
                            rusqlite::params![format!("link-{index}"), index as i64, hi, lo, format!("path-{index}")],
                        )?;
                    }
                    connection.execute_batch("COMMIT")
                })
                .unwrap();
        };
        insert(0, 100);

        let read_work = || {
            LAST_TENANT_RECEIVED_VM_STEPS.with(|steps| steps.set(TENANT_RECEIVED_VM_UNOBSERVED));
            let value = store.tenant_received_bytes("acme").unwrap();
            let vm_steps = LAST_TENANT_RECEIVED_VM_STEPS.with(Cell::get);
            assert_ne!(
                vm_steps, TENANT_RECEIVED_VM_UNOBSERVED,
                "production reader did not report VM work"
            );
            (value, vm_steps)
        };
        assert_eq!(read_work().0, 5_050);
        let hundred_rows = read_work().1;

        insert(100, 900);
        assert_eq!(read_work().0, 500_500);
        let thousand_rows = read_work().1;

        assert!(
            (1..=500).contains(&hundred_rows),
            "aggregate read used {hundred_rows} VM callbacks"
        );
        assert!(
            (1..=500).contains(&thousand_rows),
            "aggregate read used {thousand_rows} VM callbacks"
        );
    }

    /// A deduped re-send or a partial record references a file an earlier
    /// record already counts; the physical file counts once until every
    /// record over it is tombstoned.
    #[test]
    fn shared_stored_paths_count_once() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.insert_tenant(test_tenant("acme")).unwrap();
        let record = |id: &str, files: Vec<FileRecord>| UploadRecord {
            partial: false,
            log: Vec::new(),
            id: id.to_owned(),
            started_at: 0,
            completed_at: 0,
            replayed_chunks: 0,
            rejected_chunks: 0,
            transport: None,
            package_root: "cc".to_owned(),
            total_bytes: files.iter().map(|file| file.bytes).sum(),
            files,
        };
        let file = |path: &str, bytes: u64| FileRecord {
            path: path.to_owned(),
            stored_as: path.to_owned(),
            bytes,
            suite: "blake3".to_owned(),
            root: "00".to_owned(),
            receipt: true,
            deleted: false,
        };
        let mut link = link_in("acme", "link-1");
        link.uploads
            .push(record("partial", vec![file("a.bin", 300)]));
        store.insert_link(link).unwrap();
        assert_eq!(store.tenant_received_bytes("acme").unwrap(), 300);
        // The full re-send records a.bin again beside a new file.
        store
            .append_upload(
                "acme",
                "link-1",
                record("full", vec![file("a.bin", 300), file("b.bin", 200)]),
            )
            .unwrap();
        assert_eq!(store.tenant_received_bytes("acme").unwrap(), 500);
        assert_eq!(store.tenant_usage().unwrap()[1].received_bytes, 500);
        assert_eq!(store.tenant_stored("acme").unwrap(), (2, 500));
        let mut spool = Vec::new();
        store.write_tenant_live_files("acme", &mut spool).unwrap();
        let live: Vec<(String, u64)> = spool
            .split(|byte| *byte == b'\n')
            .filter(|row| !row.is_empty())
            .map(|row| serde_json::from_slice(row).unwrap())
            .collect();
        assert_eq!(live, [("a.bin".to_owned(), 300), ("b.bin".to_owned(), 200)]);
        // Delete file tombstones every record over the path, so the bytes go.
        store
            .tombstone_files(
                "acme",
                "link-1",
                &std::collections::HashSet::from(["a.bin"]),
            )
            .unwrap();
        assert_eq!(store.tenant_received_bytes("acme").unwrap(), 200);
        let files = store
            .with(|connection| {
                connection.query_row(
                    "SELECT COUNT(*) FROM files WHERE deleted = 0 AND stored_as = 'a.bin'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
            })
            .unwrap();
        assert_eq!(
            files, 0,
            "the matcher tombstones every record over the path"
        );
    }

    #[test]
    fn scim_groups_round_trip_and_map_to_subjects() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let admins = store
            .create_scim_group(
                "votport-admins",
                Some("g1"),
                &["a@example.com".to_owned(), "b@example.com".to_owned()],
            )
            .unwrap()
            .unwrap();
        assert_eq!(admins.members, ["a@example.com", "b@example.com"]);
        assert_eq!(admins.external_id.as_deref(), Some("g1"));
        assert!(admins.created_at > 0);
        assert!(
            store
                .create_scim_group("votport-admins", None, &[])
                .unwrap()
                .is_none(),
            "names are unique"
        );
        let viewers = store
            .create_scim_group("viewers", None, &["a@example.com".to_owned()])
            .unwrap()
            .unwrap();
        assert_eq!(
            store.scim_groups_of("a@example.com").unwrap(),
            ["viewers", "votport-admins"]
        );
        assert_eq!(
            store.scim_groups_of("b@example.com").unwrap(),
            ["votport-admins"]
        );
        assert!(store.scim_groups_of("nobody").unwrap().is_empty());

        let (page, total) = store.scim_groups_page(10, 0).unwrap();
        assert_eq!(total, 2);
        assert_eq!(page[0].display_name, "viewers");
        assert_eq!(page[1].members.len(), 2);
        assert_eq!(
            store.scim_group_by_name("viewers").unwrap().unwrap().id,
            viewers.id
        );
        assert_eq!(
            store.scim_group_by_external_id("g1").unwrap().unwrap().id,
            admins.id
        );
        assert!(store.scim_group_by_external_id("g9").unwrap().is_none());

        assert!(store
            .change_scim_group_members(
                &admins.id,
                &["c@example.com".to_owned(), "a@example.com".to_owned()],
                &["b@example.com".to_owned()],
            )
            .unwrap());
        assert_eq!(
            store.scim_group(&admins.id).unwrap().unwrap().members,
            ["a@example.com", "c@example.com"]
        );
        assert!(!store
            .change_scim_group_members("missing", &[], &[])
            .unwrap());

        assert_eq!(
            store
                .replace_scim_group(&admins.id, Some("viewers"), None)
                .unwrap_err(),
            SCIM_GROUP_NAME_TAKEN
        );
        assert!(store
            .replace_scim_group(
                &admins.id,
                Some("admins"),
                Some(&["z@example.com".to_owned()]),
            )
            .unwrap());
        let renamed = store.scim_group(&admins.id).unwrap().unwrap();
        assert_eq!(renamed.display_name, "admins");
        assert_eq!(renamed.members, ["z@example.com"]);
        assert!(!store.replace_scim_group("missing", None, None).unwrap());

        assert!(store.delete_scim_group(&admins.id).unwrap());
        assert!(!store.delete_scim_group(&admins.id).unwrap());
        assert!(store.scim_groups_of("z@example.com").unwrap().is_empty());
        assert_eq!(store.scim_groups_page(10, 0).unwrap().1, 1);
    }

    #[test]
    fn received_bytes_preserve_u64_and_saturate_aggregate() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.insert_tenant(test_tenant("acme")).unwrap();
        let mut link = link_in("acme", "large");
        link.uploads.push(UploadRecord {
            partial: false,
            log: Vec::new(),
            id: "up".to_owned(),
            started_at: 0,
            completed_at: 0,
            replayed_chunks: 0,
            rejected_chunks: 0,
            transport: None,
            package_root: "root".to_owned(),
            total_bytes: u64::MAX,
            files: vec![
                FileRecord {
                    path: "large".to_owned(),
                    stored_as: "large".to_owned(),
                    bytes: u64::MAX,
                    suite: "blake3".to_owned(),
                    root: "aa".to_owned(),
                    receipt: false,
                    deleted: false,
                },
                FileRecord {
                    path: "one".to_owned(),
                    stored_as: "one".to_owned(),
                    bytes: 1,
                    suite: "blake3".to_owned(),
                    root: "bb".to_owned(),
                    receipt: false,
                    deleted: false,
                },
            ],
        });
        store.insert_link(link).unwrap();

        assert_eq!(store.tenant_received_bytes("acme").unwrap(), u64::MAX);
        assert_eq!(store.tenant_usage().unwrap()[1].received_bytes, u64::MAX);
        store
            .append_upload(
                "acme",
                "large",
                UploadRecord {
                    partial: false,
                    log: Vec::new(),
                    id: "second".to_owned(),
                    started_at: u64::MAX,
                    completed_at: u64::MAX,
                    replayed_chunks: u64::MAX,
                    rejected_chunks: u64::MAX,
                    transport: None,
                    package_root: "exact".to_owned(),
                    total_bytes: u64::MAX,
                    files: Vec::new(),
                },
            )
            .unwrap();
        let uploads = store.link("acme", "large").unwrap().unwrap().uploads;
        assert_eq!(uploads.len(), 2);
        assert_eq!(uploads[0].total_bytes, u64::MAX);
        assert_eq!(uploads[1].started_at, u64::MAX);
        assert_eq!(uploads[1].total_bytes, u64::MAX);
        let limbs = store
            .with(|connection| {
                connection.query_row(
                    "SELECT bytes_hi, bytes_lo FROM files WHERE file_index = 0",
                    [],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                )
            })
            .unwrap();
        assert_eq!(limbs, (u32::MAX as i64, u32::MAX as i64));
        store
            .with(|connection| {
                connection.execute(
                    "UPDATE link_uploads SET document='{}' WHERE link_id='large' AND upload_id='up'",
                    [],
                )
            })
            .unwrap();
        let mut next = uploads[1].clone();
        next.id = "third".into();
        assert!(store.append_upload("acme", "large", next.clone()).unwrap());
        store
            .with(|connection| {
                connection.execute(
                    "UPDATE links SET events_json = 'broken'
                     WHERE id = 'large'",
                    [],
                )
            })
            .unwrap();
        assert!(store
            .append_upload("acme", "large", {
                next.id = "fourth".into();
                next
            })
            .is_err());
    }

    #[test]
    fn tenant_quotas_preserve_u64_across_create_and_update() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut tenant = test_tenant("acme");
        tenant.max_total_bytes = Some(u64::MAX);
        tenant.max_links = Some(u64::MAX);
        tenant.max_sessions = Some(u64::MAX);
        store.insert_tenant(tenant).unwrap();
        assert_eq!(
            store.tenant("acme").unwrap().unwrap().max_total_bytes,
            Some(u64::MAX)
        );

        let mut tenant = store.tenant("acme").unwrap().unwrap();
        tenant.max_total_bytes = Some(u64::MAX - 1);
        tenant.max_links = Some(u64::MAX - 1);
        tenant.max_sessions = Some(u64::MAX - 1);
        assert!(store.update_tenant(&tenant).unwrap());
        drop(store);

        let reopened = Store::open(directory.path()).unwrap();
        let tenant = reopened.tenant("acme").unwrap().unwrap();
        assert_eq!(tenant.max_total_bytes, Some(u64::MAX - 1));
        assert_eq!(tenant.max_links, Some(u64::MAX - 1));
        assert_eq!(tenant.max_sessions, Some(u64::MAX - 1));
    }

    #[test]
    fn projection_writes_only_changed_files() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.insert_tenant(test_tenant("acme")).unwrap();
        let mut link = link_in("acme", "link");
        let file = FileRecord {
            path: "a".to_owned(),
            stored_as: "a".to_owned(),
            bytes: 1,
            suite: "blake3".to_owned(),
            root: "aa".to_owned(),
            receipt: false,
            deleted: false,
        };
        link.uploads.push(UploadRecord {
            partial: false,
            log: Vec::new(),
            id: "up".to_owned(),
            started_at: 0,
            completed_at: 0,
            replayed_chunks: 0,
            rejected_chunks: 0,
            transport: None,
            package_root: "root".to_owned(),
            total_bytes: 50,
            files: vec![file.clone(); 50],
        });
        store.insert_link(link).unwrap();
        store
            .with(|connection| {
                connection.execute_batch(
                    "CREATE TABLE projection_writes (count INTEGER NOT NULL);
                     INSERT INTO projection_writes VALUES (0);
                     CREATE TRIGGER count_file_insert AFTER INSERT ON files BEGIN
                       UPDATE projection_writes SET count = count + 1; END;
                     CREATE TRIGGER count_file_update AFTER UPDATE ON files BEGIN
                       UPDATE projection_writes SET count = count + 1; END;
                     CREATE TRIGGER count_file_delete AFTER DELETE ON files BEGIN
                       UPDATE projection_writes SET count = count + 1; END;",
                )
            })
            .unwrap();

        store
            .update_link("acme", "link", |link| link.active = false)
            .unwrap();
        store
            .append_upload(
                "acme",
                "link",
                UploadRecord {
                    partial: false,
                    log: Vec::new(),
                    id: "new".to_owned(),
                    started_at: 0,
                    completed_at: 0,
                    replayed_chunks: 0,
                    rejected_chunks: 0,
                    transport: None,
                    package_root: "new-root".to_owned(),
                    total_bytes: 1,
                    files: vec![FileRecord {
                        path: "b".to_owned(),
                        stored_as: "b".to_owned(),
                        ..file
                    }],
                },
            )
            .unwrap();
        let writes = || {
            store
                .with(|connection| {
                    connection.query_row("SELECT count FROM projection_writes", [], |row| {
                        row.get::<_, i64>(0)
                    })
                })
                .unwrap()
        };
        assert_eq!(writes(), 1);
        store
            .tombstone_files("acme", "link", &std::collections::HashSet::from(["b"]))
            .unwrap();
        assert_eq!(writes(), 2);
    }
}

#[cfg(test)]
mod ops_tests {
    use super::*;
    use super::{link_in, test_link, test_tenant};

    #[test]
    fn backup_creates_a_queryable_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.insert_link(test_link("link-1")).unwrap();

        let snapshot = directory.path().join("snapshot.db");
        store.backup_into(&snapshot).unwrap();
        assert!(snapshot.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&snapshot).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        // The snapshot is a real database with the same rows: drop it into
        // a fresh data dir and open it as one.
        let restore = tempfile::tempdir().unwrap();
        std::fs::copy(&snapshot, restore.path().join("votport.db")).unwrap();
        let reopened = Store::open(restore.path()).unwrap();
        assert!(reopened.link("", "link-1").unwrap().is_some());

        // A fresh VACUUM INTO needs the destination gone; that is the
        // caller's contract.
        std::fs::remove_file(&snapshot).unwrap();
        store.backup_into(&snapshot).unwrap();
        assert!(snapshot.exists());
    }

    #[test]
    fn backup_runs_without_the_shared_store_lock() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.insert_link(test_link("link-1")).unwrap();

        // Hold the serving connection for the whole snapshot: requests keep
        // flowing while VACUUM INTO runs on its own connection.
        let guard = store.connection.lock().unwrap();
        let snapshot = directory.path().join("snapshot.db");
        store.backup_into(&snapshot).unwrap();
        drop(guard);
        assert!(snapshot.exists());
    }

    #[test]
    fn backup_bounds_wal_after_a_pinned_reader_grows_it() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let database = directory.path().join("votport.db");
        let wal = directory.path().join("votport.db-wal");

        // A backup's VACUUM INTO reader pins the WAL read mark for its whole
        // run; commits in that window cannot be checkpointed away and pile
        // up in the WAL. Reproduce the shape with a plain read transaction.
        let reader = Connection::open(&database).unwrap();
        reader
            .execute_batch("BEGIN; SELECT count(*) FROM meta;")
            .unwrap();
        let payload = "x".repeat(512 * 1024);
        for index in 0..40 {
            store
                .put_settings(
                    "test",
                    &[(
                        format!("growth-{index}"),
                        SettingWrite::Set(format!("{payload}-{index}")),
                    )],
                )
                .unwrap();
        }
        let high_water = std::fs::metadata(&wal).unwrap().len();
        assert!(
            high_water > WAL_SIZE_LIMIT_BYTES as u64,
            "pinned-reader backlog should exceed the WAL bound, got {high_water}"
        );

        // The backup's explicit checkpoint drains and truncates the pileup,
        // so no writer after the backup pays for it inside its own
        // transaction and the file is back under the bound (a probe finds no
        // frames left to copy; the unbounded shape would show the whole
        // backlog here).
        drop(reader);
        let snapshot = directory.path().join("snapshot.db");
        store.backup_into(&snapshot).unwrap();
        let pending = store
            .with(|connection| {
                connection.query_row::<(i64, i64, i64), _, _>(
                    "PRAGMA wal_checkpoint(PASSIVE)",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
            })
            .unwrap();
        assert_eq!(
            pending,
            (0, 0, 0),
            "backup left WAL frames for the next writer to drain"
        );

        // The next write resets the drained WAL and the journal size limit
        // truncates the file back under the bound; later writes stay there.
        store
            .put_settings(
                "test",
                &[("after".to_owned(), SettingWrite::Set(payload.clone()))],
            )
            .unwrap();
        let after_write = std::fs::metadata(&wal).unwrap().len();
        assert!(
            after_write <= WAL_SIZE_LIMIT_BYTES as u64,
            "WAL stayed at the backup-time high water after the next write: {after_write}"
        );
        store
            .put_settings(
                "test",
                &[("after-2".to_owned(), SettingWrite::Set(payload))],
            )
            .unwrap();
        let after_more_writes = std::fs::metadata(&wal).unwrap().len();
        assert!(after_more_writes <= WAL_SIZE_LIMIT_BYTES as u64);
    }

    #[cfg(unix)]
    #[test]
    fn open_protects_existing_and_new_database_state() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("votport.db");
        std::fs::write(&database, b"").unwrap();
        std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o644)).unwrap();
        let backups = directory.path().join("backups");
        std::fs::create_dir(&backups).unwrap();
        let snapshot = backups.join("snapshot.db");
        std::fs::write(&snapshot, b"snapshot").unwrap();
        std::fs::set_permissions(&backups, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&snapshot, std::fs::Permissions::from_mode(0o644)).unwrap();

        let store = Store::open(directory.path()).unwrap();
        assert_eq!(
            std::fs::metadata(directory.path().join("votport.db"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(directory.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&backups).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(snapshot).unwrap().permissions().mode() & 0o777,
            0o600
        );
        for suffix in ["-wal", "-shm"] {
            let path = directory.path().join(format!("votport.db{suffix}"));
            if path.exists() {
                assert_eq!(
                    std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
        drop(store);
    }

    #[test]
    fn all_links_spans_tenants() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.insert_link(test_link("default-link")).unwrap();
        store.insert_tenant(test_tenant("acme")).unwrap();
        let mut scoped = test_link("scoped-link");
        scoped.tenant = "acme".to_owned();
        store.insert_link(scoped).unwrap();
        assert_eq!(store.all_links().unwrap().len(), 2);
    }

    #[test]
    fn retention_link_ids_page_is_bounded_and_spans_tenants() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.insert_link(test_link("a-link")).unwrap();
        store.insert_link(test_link("b-link")).unwrap();
        store.insert_tenant(test_tenant("acme")).unwrap();
        store.insert_link(link_in("acme", "c-link")).unwrap();
        store
            .with(|connection| {
                connection.execute("UPDATE links SET events_json = '{' WHERE id = 'a-link'", [])
            })
            .unwrap();

        // The page reads identities only, so an unrelated malformed history
        // does not make the bounded scan allocate or parse that history.
        let first = store.retention_link_ids(None, 2).unwrap();
        assert_eq!(
            first,
            vec![
                (String::new(), "a-link".into(), None),
                (String::new(), "b-link".into(), None)
            ]
        );
        let second = store
            .retention_link_ids(Some(&first.last().unwrap().1), 2)
            .unwrap();
        assert_eq!(second, vec![("acme".into(), "c-link".into(), None)]);
        assert!(store
            .retention_link_ids(Some(&second.last().unwrap().1), 2)
            .unwrap()
            .is_empty());
        assert!(store.retention_link_ids(None, 0).unwrap().is_empty());
    }
}

#[cfg(test)]
mod phase4_review_tests {
    use super::*;
    use super::{link_in, test_outbound_grant, test_tenant};

    #[test]
    fn link_by_id_spans_tenants_for_the_public_protocol() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.insert_tenant(super::test_tenant("acme")).unwrap();
        store.insert_link(link_in("acme", "scoped")).unwrap();
        // Senders never know a tenant key; the id is the capability.
        assert!(store.link_by_id("scoped").unwrap().is_some());
        assert!(store.link_by_id("missing").unwrap().is_none());
    }

    #[test]
    fn audit_export_cursor_survives_same_second_rows() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        for index in 0..3 {
            store.audit(
                "",
                "",
                "event",
                &format!("row-{index}"),
                &serde_json::json!({}),
            );
        }
        // Page size 2: the third row shares the second with the first two
        // and must still be reachable through the rowid cursor.
        let page_one = store.audit_export(None, 0, 0, 2).unwrap();
        assert_eq!(page_one.len(), 2);
        let last = page_one.last().unwrap();
        let page_two = store
            .audit_export(None, last.at, last.rowid as u64, 2)
            .unwrap();
        assert_eq!(page_two.len(), 1);
        assert_eq!(page_two[0].subject, "row-2");
    }

    #[test]
    fn audit_export_filters_by_tenant() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.audit("acme", "", "link_created", "l-1", &serde_json::json!({}));
        store.audit("", "", "admin_login", "ip", &serde_json::json!({}));
        let scoped = store.audit_export(Some("acme"), 0, 0, 100).unwrap();
        assert_eq!(scoped.len(), 1);
        assert_eq!(scoped[0].tenant, "acme");
        let default = store.audit_export(Some(""), 0, 0, 100).unwrap();
        assert_eq!(default.len(), 1);
        assert_eq!(default[0].tenant, "");
        assert_eq!(store.audit_export(None, 0, 0, 100).unwrap().len(), 2);
    }

    #[test]
    fn links_page_is_stable_literal_filtered_and_tenant_scoped() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut newest = link_in("", "z-link");
        newest.created_at = 100;
        newest.label = "Hundred% match".to_owned();
        newest.dest = "incoming".to_owned();
        let mut middle = link_in("", "m-link");
        middle.created_at = 100;
        middle.label = "100X match".to_owned();
        let mut oldest = link_in("", "a-link");
        oldest.created_at = 100;
        oldest.active = false;
        store.insert_link(newest).unwrap();
        store.insert_link(middle).unwrap();
        store.insert_link(oldest).unwrap();
        store.insert_tenant(test_tenant("acme")).unwrap();
        store.insert_link(link_in("acme", "foreign")).unwrap();

        let first = store
            .links_page("", 2, None, "HUNDRED%", "all", 1000, false)
            .unwrap();
        assert_eq!(
            first
                .links
                .iter()
                .map(|link| link.id.as_str())
                .collect::<Vec<_>>(),
            vec!["z-link"]
        );

        let first = store
            .links_page("", 2, None, "", "all", 1000, false)
            .unwrap();
        assert_eq!(
            first
                .links
                .iter()
                .map(|link| link.id.as_str())
                .collect::<Vec<_>>(),
            vec!["z-link", "m-link"]
        );
        let cursor = first.next_cursor.unwrap();
        let second = store
            .links_page("", 2, Some(&cursor), "", "all", 1000, false)
            .unwrap();
        assert_eq!(second.links[0].id, "a-link");
        assert!(second.next_cursor.is_none());
        assert!(store
            .links_page("", 2, None, "", "all", 1000, false)
            .unwrap()
            .links
            .iter()
            .all(|link| link.tenant.is_empty()));
        assert_eq!(
            store
                .links_page("", 10, None, "", "open", 1000, false)
                .unwrap()
                .links
                .len(),
            2
        );
        assert_eq!(
            store
                .links_page("", 10, None, "", "closed", 1000, false)
                .unwrap()
                .links
                .len(),
            1
        );
    }

    #[test]
    fn links_page_unfiltered_query_uses_created_index() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let plan = store
            .with(|connection| {
                let mut statement = connection.prepare(
                    "EXPLAIN QUERY PLAN
                     SELECT id FROM links
                     WHERE tenant = ?1
                       AND (?2 = '' OR lower(label) LIKE '%' || ?2 || '%' ESCAPE '\\'
                            OR lower(dest) LIKE '%' || ?2 || '%' ESCAPE '\\'
                            OR id = ?2)
                       AND (?3 = 'all'
                            OR (?3 = 'open' AND active != 0
                                AND (expires_at IS NULL OR expires_at > ?4))
                            OR (?3 = 'closed' AND (active = 0
                                OR (expires_at IS NOT NULL AND expires_at <= ?4))))
                       AND (?5 = 0 OR created_at < ?6
                            OR (created_at = ?6 AND id < ?7))
                     ORDER BY created_at DESC, id DESC
                     LIMIT ?8",
                )?;
                let rows = statement.query_map(
                    rusqlite::params!["", "", "all", 1000_i64, 0_i64, 0_i64, "", 11_i64],
                    |row| row.get::<_, String>(3),
                )?;
                rows.collect::<Result<Vec<_>, _>>()
            })
            .unwrap();
        assert!(plan
            .iter()
            .any(|detail| detail.contains("USING INDEX links_tenant_created")));
    }

    #[test]
    fn active_outbound_file_keys_filter_scope_state_and_bad_indexes() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();

        store
            .insert_outbound_grant(test_outbound_grant("active", "acme", 2))
            .unwrap();
        let mut expired = test_outbound_grant("expired", "acme", 3);
        expired.expires_at = 19;
        store.insert_outbound_grant(expired).unwrap();
        let mut revoked = test_outbound_grant("revoked", "acme", 4);
        revoked.revoked_at = Some(1);
        store.insert_outbound_grant(revoked).unwrap();
        let mut spent = test_outbound_grant("spent", "acme", 5);
        spent.max_downloads = Some(1);
        spent.downloads = 1;
        store.insert_outbound_grant(spent).unwrap();
        let other_tenant = test_outbound_grant("other-tenant", "other", 6);
        store.insert_outbound_grant(other_tenant).unwrap();
        let mut other_link = test_outbound_grant("other-link", "acme", 7);
        other_link.link_id = "other-link".to_owned();
        store.insert_outbound_grant(other_link).unwrap();

        assert_eq!(
            store.active_outbound_file_keys("acme", "link", 19).unwrap(),
            vec![("upload".to_owned(), 2)]
        );
        assert!(store
            .active_outbound_file_keys("acme", "link", 20)
            .unwrap()
            .is_empty());

        store
            .with(|connection| {
                connection.execute(
                    "UPDATE outbound_grants SET file_index = ?1 WHERE id = ?2",
                    rusqlite::params![-1_i64, "active"],
                )
            })
            .unwrap();
        assert!(store.active_outbound_file_keys("acme", "link", 19).is_err());
    }

    #[test]
    fn active_outbound_object_keys_are_global_and_deduplicated() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let object = |suite: &str, root: &str, bytes: u64| OutboundGrantFile {
            source: format!("objects/{root}"),
            name: root.to_owned(),
            suite: suite.to_owned(),
            root: root.to_owned(),
            bytes,
            receipt_b64: String::new(),
            downloads: 0,
            first_download_at: None,
            last_download_at: None,
        };

        let mut legacy = test_outbound_grant("legacy", "acme", 0);
        legacy.root = "parent".to_owned();
        legacy.bytes = 3;
        store.insert_outbound_grant(legacy).unwrap();

        let mut active = test_outbound_grant("active", "other", 0);
        active.root = "parent".to_owned();
        active.bytes = 3;
        active.files = vec![object("blake3", "parent", 3), object("sha256", "child", 4)];
        store.insert_outbound_grant(active).unwrap();

        let mut expired = test_outbound_grant("expired", "acme", 0);
        expired.root = "expired-parent".to_owned();
        expired.expires_at = 19;
        expired.files = vec![object("blake3", "expired-child", 5)];
        store.insert_outbound_grant(expired).unwrap();

        let mut revoked = test_outbound_grant("revoked", "other", 0);
        revoked.root = "revoked-parent".to_owned();
        revoked.revoked_at = Some(1);
        revoked.files = vec![object("blake3", "revoked-child", 6)];
        store.insert_outbound_grant(revoked).unwrap();

        // The grant id rides along so callers can name unparseable grants.
        // Identical tuples still deduplicate (the active grant's own row
        // appears in both UNION halves); rows that differ only by owner now
        // each appear, which only widens the keep set the prune reads.
        assert_eq!(
            store.active_outbound_object_keys(19).unwrap(),
            vec![
                (
                    "active".to_owned(),
                    "blake3".to_owned(),
                    "parent".to_owned(),
                    3
                ),
                (
                    "legacy".to_owned(),
                    "blake3".to_owned(),
                    "parent".to_owned(),
                    3
                ),
                (
                    "active".to_owned(),
                    "sha256".to_owned(),
                    "child".to_owned(),
                    4
                ),
            ]
        );
    }

    #[test]
    fn recent_audit_is_descending_and_tenant_scoped() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.audit("acme", "", "first", "a", &serde_json::json!({}));
        store.audit("acme", "", "second", "b", &serde_json::json!({}));
        store.audit("other", "", "foreign", "c", &serde_json::json!({}));

        let page = store.audit_recent(Some("acme"), 0, 1).unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].event, "second");
        let older = store
            .audit_recent(Some("acme"), page[0].rowid as u64, 10)
            .unwrap();
        assert_eq!(older.len(), 1);
        assert_eq!(older[0].event, "first");
    }

    #[test]
    fn audit_filters_match_fields_without_searching_detail() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.audit(
            "acme",
            "Alice",
            "link_created",
            "request-1",
            &serde_json::json!({"secret_marker": "needle"}),
        );
        store.audit(
            "acme",
            "Bob",
            "link_deleted",
            "request-2",
            &serde_json::json!({}),
        );
        store.audit(
            "other",
            "Alice",
            "link_created",
            "request-3",
            &serde_json::json!({}),
        );
        store.audit("", "", "default_event", "request-4", &serde_json::json!({}));

        let filters = AuditFilters {
            event: Some("link_created"),
            query: Some("ALICE"),
        };
        let recent = store
            .audit_recent_filtered(Some("acme"), 0, 100, filters)
            .unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].subject, "request-1");

        let detail_only = store
            .audit_recent_filtered(
                Some("acme"),
                0,
                100,
                AuditFilters {
                    event: None,
                    query: Some("needle"),
                },
            )
            .unwrap();
        assert!(detail_only.is_empty());

        let display_tenant = store
            .audit_recent_filtered(
                None,
                0,
                100,
                AuditFilters {
                    event: None,
                    query: Some("DEFAULT"),
                },
            )
            .unwrap();
        assert_eq!(display_tenant.len(), 1);
        assert_eq!(display_tenant[0].event, "default_event");

        let legacy = store
            .audit_export_filtered(Some("acme"), 0, 0, 100, filters)
            .unwrap();
        assert_eq!(legacy.len(), 1);
        assert_eq!(legacy[0].subject, "request-1");
    }

    #[test]
    fn filtered_audit_cursor_paginates_recent_rows() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        for subject in ["first", "second", "third"] {
            store.audit("acme", "", "match", subject, &serde_json::json!({}));
        }
        let filters = AuditFilters {
            event: Some("match"),
            query: None,
        };
        let first = store
            .audit_recent_filtered(Some("acme"), 0, 2, filters)
            .unwrap();
        assert_eq!(first.len(), 2);
        let second = store
            .audit_recent_filtered(Some("acme"), first[1].rowid as u64, 2, filters)
            .unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].subject, "first");
    }

    #[test]
    fn filtered_audit_reads_use_scope_indexes() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .with(|connection| {
                connection.execute_batch("BEGIN")?;
                for index in 0..100 {
                    connection.execute(
                        "INSERT INTO audit_log(at,tenant,actor,event,subject)
                         VALUES (?1,?2,'actor',?3,?4)",
                        rusqlite::params![
                            (index / 4) as i64,
                            if index % 10 < 2 { "acme" } else { "other" },
                            if index % 7 == 0 { "rare" } else { "common" },
                            if index == 70 { "needle" } else { "other" },
                        ],
                    )?;
                }
                connection.execute_batch("COMMIT")
            })
            .unwrap();
        fn measure_audit<F>(read: F) -> Vec<AuditRow>
        where
            F: FnOnce() -> Result<Vec<AuditRow>, String>,
        {
            LAST_AUDIT_VM_STEPS.with(|steps| steps.set(AUDIT_VM_STEPS_UNOBSERVED));
            let rows = read().unwrap();
            let vm_steps = LAST_AUDIT_VM_STEPS.with(Cell::get);
            assert!(vm_steps > 0, "audit reader did not report VM steps");
            assert!(vm_steps < 500, "audit reader used {vm_steps} VM steps");
            rows
        }

        let tenant_recent = measure_audit(|| {
            store.audit_recent_filtered(Some("acme"), 0, 5, AuditFilters::default())
        });
        assert_eq!(
            tenant_recent
                .iter()
                .map(|row| row.subject.as_str())
                .collect::<Vec<_>>(),
            ["other", "other", "other", "other", "other"]
        );
        assert!(tenant_recent.iter().all(|row| row.tenant == "acme"));
        let tenant_recent_page_two = measure_audit(|| {
            store.audit_recent_filtered(
                Some("acme"),
                tenant_recent.last().unwrap().rowid as u64,
                5,
                AuditFilters::default(),
            )
        });
        assert_eq!(tenant_recent_page_two.len(), 5);
        assert!(tenant_recent_page_two
            .iter()
            .all(|row| row.tenant == "acme"));

        let event_recent = measure_audit(|| {
            store.audit_recent_filtered(
                None,
                0,
                5,
                AuditFilters {
                    event: Some("rare"),
                    query: None,
                },
            )
        });
        assert_eq!(event_recent.len(), 5);
        assert!(event_recent.iter().all(|row| row.event == "rare"));

        let common_recent = measure_audit(|| {
            store.audit_recent_filtered(
                None,
                0,
                5,
                AuditFilters {
                    event: Some("common"),
                    query: None,
                },
            )
        });
        assert_eq!(common_recent.len(), 5);
        assert!(common_recent.iter().all(|row| row.event == "common"));

        let combined_recent = measure_audit(|| {
            store.audit_recent_filtered(
                Some("acme"),
                0,
                5,
                AuditFilters {
                    event: Some("rare"),
                    query: Some("NEEDLE"),
                },
            )
        });
        assert_eq!(combined_recent.len(), 1);
        assert_eq!(combined_recent[0].subject, "needle");

        let tenant_export = measure_audit(|| {
            store.audit_export_filtered(Some("acme"), 0, 0, 5, AuditFilters::default())
        });
        assert_eq!(
            tenant_export
                .iter()
                .map(|row| row.rowid)
                .collect::<Vec<_>>(),
            [1, 2, 11, 12, 21]
        );
        let tenant_export_page_two = measure_audit(|| {
            store.audit_export_filtered(
                Some("acme"),
                tenant_export.last().unwrap().at,
                tenant_export.last().unwrap().rowid as u64,
                5,
                AuditFilters::default(),
            )
        });
        assert_eq!(
            tenant_export_page_two
                .iter()
                .map(|row| row.rowid)
                .collect::<Vec<_>>(),
            [22, 31, 32, 41, 42]
        );

        let event_export = measure_audit(|| {
            store.audit_export_filtered(
                None,
                0,
                0,
                5,
                AuditFilters {
                    event: Some("rare"),
                    query: None,
                },
            )
        });
        assert_eq!(
            event_export.iter().map(|row| row.rowid).collect::<Vec<_>>(),
            [1, 8, 15, 22, 29]
        );

        let common_export = measure_audit(|| {
            store.audit_export_filtered(
                None,
                0,
                0,
                5,
                AuditFilters {
                    event: Some("common"),
                    query: None,
                },
            )
        });
        assert_eq!(
            common_export
                .iter()
                .map(|row| row.rowid)
                .collect::<Vec<_>>(),
            [2, 3, 4, 5, 6]
        );

        let combined_export = measure_audit(|| {
            store.audit_export_filtered(
                Some("acme"),
                0,
                0,
                5,
                AuditFilters {
                    event: Some("rare"),
                    query: None,
                },
            )
        });
        assert_eq!(
            combined_export
                .iter()
                .map(|row| row.rowid)
                .collect::<Vec<_>>(),
            [1, 22, 71, 92]
        );

        let deep_directory = tempfile::tempdir().unwrap();
        let deep_store = Store::open(deep_directory.path()).unwrap();
        deep_store
            .with(|connection| {
                connection.execute_batch("BEGIN")?;
                for index in 0..1000 {
                    connection.execute(
                        "INSERT INTO audit_log(at,tenant,actor,event,subject)
                         VALUES (?1,?2,'actor',?3,'subject')",
                        rusqlite::params![
                            (index / 4) as i64,
                            if index % 10 < 2 { "acme" } else { "other" },
                            if index % 7 == 0 { "rare" } else { "common" },
                        ],
                    )?;
                }
                connection.execute_batch("COMMIT")
            })
            .unwrap();
        let deep_export = measure_audit(|| {
            deep_store.audit_export_filtered(None, 200, 803, 5, AuditFilters::default())
        });
        assert_eq!(
            deep_export.iter().map(|row| row.rowid).collect::<Vec<_>>(),
            [804, 805, 806, 807, 808]
        );
        assert!(deep_export.iter().all(|row| row.at >= 200));
    }
}

#[cfg(test)]
mod settings_tests {
    use super::*;
    use super::{test_link, test_tenant};

    fn test_config() -> Config {
        Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            push_bind: None,
            push_certificate: None,
            push_private_key: None,
            push_advertise: None,
            serve_bind: None,
            serve_advertise: None,
            data_dir: std::path::PathBuf::from("/nonexistent"),
            receive_dir: std::path::PathBuf::from("/nonexistent"),
            outbound_dir: std::path::PathBuf::from("/nonexistent"),
            web_root: std::path::PathBuf::from("../web"),
            admin_password_hash: "x".to_owned(),
            admin_token_tag: "tag".to_owned(),
            smtp_host: Some("https://env.example/hook".to_owned()),

            smtp_port: 587,
            smtp_starttls: true,
            smtp_username: None,
            smtp_password: None,
            scim_token: None,
            replica_token: None,
            smtp_from: None,

            public_url: None,
            max_upload_bytes: 1024,
            workflow_snapshot_bytes: 4 * 1024 * 1024,
            allow_hidden: false,
            session_idle_secs: 60,
            audit_retention_days: 400,
            upload_retention_days: 0,
            metrics_token: None,
            max_total_sessions: 32,
            max_link_sessions: 8,
            sso_session_secs: 7 * 24 * 3600,
            trusted_proxies: Vec::new(),
            oidc: None,
            default_max_total_bytes: None,
            default_max_links: None,
            default_max_sessions: None,
            public_password_login: true,
            require_provisioning: false,
        }
    }

    fn schema_version(data_dir: &Path) -> String {
        let connection = Connection::open(data_dir.join("votport.db")).unwrap();
        connection
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn overridden(overlay: &SettingsOverlay, key: &str) -> bool {
        overlay.overridden_keys.iter().any(|value| value == key)
    }

    #[test]
    fn empty_settings_table_follows_env() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let overlay = store.overlay(&test_config()).unwrap();
        assert_eq!(
            overlay.smtp_host.as_deref(),
            Some("https://env.example/hook")
        );
        assert!(!overridden(&overlay, "smtp_host"));
        assert_eq!(overlay.resolved.audit_retention_days, 400);
        assert!(!overridden(&overlay, "audit_retention_days"));
        assert_eq!(overlay.resolved.upload_retention_days, 0);
        assert!(overlay.resolved.default_max_total_bytes.is_none());
        assert!(overlay.resolved.public_password_login);
    }

    #[test]
    fn written_key_wins_unwritten_keys_keep_env() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .put_settings(
                "local",
                &[(
                    "smtp_host".to_owned(),
                    SettingWrite::Set("https://db.example/hook".to_owned()),
                )],
            )
            .unwrap();
        let overlay = store.overlay(&test_config()).unwrap();
        assert_eq!(
            overlay.smtp_host.as_deref(),
            Some("https://db.example/hook")
        );
        assert!(overridden(&overlay, "smtp_host"));
        assert_eq!(overlay.resolved.audit_retention_days, 400);
        assert!(!overridden(&overlay, "audit_retention_days"));
    }

    #[test]
    fn empty_string_disables_url_despite_env() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .put_settings(
                "local",
                &[("smtp_host".to_owned(), SettingWrite::Set(String::new()))],
            )
            .unwrap();
        let overlay = store.overlay(&test_config()).unwrap();
        assert_eq!(overlay.smtp_host, None);
        assert!(overridden(&overlay, "smtp_host"));
    }

    #[test]
    fn reset_deletes_the_row_and_env_applies() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .put_settings(
                "local",
                &[(
                    "smtp_host".to_owned(),
                    SettingWrite::Set("https://db.example/hook".to_owned()),
                )],
            )
            .unwrap();
        store
            .put_settings("local", &[("smtp_host".to_owned(), SettingWrite::Reset)])
            .unwrap();
        let overlay = store.overlay(&test_config()).unwrap();
        assert_eq!(
            overlay.smtp_host.as_deref(),
            Some("https://env.example/hook")
        );
        assert!(!overridden(&overlay, "smtp_host"));
        assert!(store.setting("smtp_host").unwrap().is_none());
    }

    #[test]
    fn invalid_stored_days_skip_to_env() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .put_settings(
                "local",
                &[(
                    "audit_retention_days".to_owned(),
                    SettingWrite::Set("nope".to_owned()),
                )],
            )
            .unwrap();
        let overlay = store.overlay(&test_config()).unwrap();
        assert_eq!(overlay.resolved.audit_retention_days, 400);
        assert!(!overridden(&overlay, "audit_retention_days"));
    }

    #[test]
    fn sso_session_override_has_a_bounded_cached_fallback() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        for (value, accepted) in [
            (crate::config::MAX_SSO_SESSION_SECS.to_string(), true),
            ((crate::config::MAX_SSO_SESSION_SECS + 1).to_string(), false),
            ("0".to_owned(), false),
            (u64::MAX.to_string(), false),
        ] {
            store
                .put_settings(
                    "local",
                    &[("sso_session_secs".to_owned(), SettingWrite::Set(value))],
                )
                .unwrap();
            let overlay = store.overlay(&test_config()).unwrap();
            assert_eq!(
                overlay.resolved.sso_session_secs,
                if accepted {
                    crate::config::MAX_SSO_SESSION_SECS
                } else {
                    7 * 24 * 3600
                }
            );
            assert_eq!(overridden(&overlay, "sso_session_secs"), accepted);
        }
        store
            .put_settings(
                "local",
                &[("sso_session_secs".to_owned(), SettingWrite::Reset)],
            )
            .unwrap();
        let overlay = store.overlay(&test_config()).unwrap();
        assert_eq!(overlay.resolved.sso_session_secs, 7 * 24 * 3600);
        assert!(!overridden(&overlay, "sso_session_secs"));
    }

    #[test]
    fn cached_overrides_are_reapplied_to_each_config() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut first = test_config();
        first.smtp_host = Some("https://first.example/hook".to_owned());
        first.audit_retention_days = 11;
        let mut second = test_config();
        second.smtp_host = Some("https://second.example/hook".to_owned());
        second.audit_retention_days = 22;

        let first_overlay = store.overlay(&first).unwrap();
        let second_overlay = store.overlay(&second).unwrap();
        assert_eq!(
            first_overlay.smtp_host.as_deref(),
            Some("https://first.example/hook")
        );
        assert_eq!(
            second_overlay.smtp_host.as_deref(),
            Some("https://second.example/hook")
        );
        assert_eq!(first_overlay.resolved.audit_retention_days, 11);
        assert_eq!(second_overlay.resolved.audit_retention_days, 22);
        assert!(first_overlay.overridden_keys.is_empty());
        assert!(second_overlay.overridden_keys.is_empty());
    }

    #[test]
    fn invalid_setting_warns_once_without_logging_its_value() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let sentinel = "settings-secret-sentinel-7c4f";
        store
            .put_settings(
                "local",
                &[(
                    "audit_retention_days".to_owned(),
                    SettingWrite::Set(sentinel.to_owned()),
                )],
            )
            .unwrap();
        let log = tempfile::NamedTempFile::new().unwrap();
        let writer = log.reopen().unwrap();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_ansi(false)
            .with_writer(move || writer.try_clone().unwrap())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            for _ in 0..3 {
                let overlay = store.overlay(&test_config()).unwrap();
                assert_eq!(overlay.resolved.audit_retention_days, 400);
                assert!(!overridden(&overlay, "audit_retention_days"));
            }
        });
        let text = std::fs::read_to_string(log.path()).unwrap();
        let records = text.lines().collect::<Vec<_>>();
        assert_eq!(records.len(), 1, "{text}");
        assert!(text.contains("audit_retention_days"));
        assert!(!text.contains(sentinel));
    }

    #[test]
    fn failed_write_keeps_the_cached_override() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .put_settings(
                "local",
                &[(
                    "smtp_host".to_owned(),
                    SettingWrite::Set("https://before.example/hook".to_owned()),
                )],
            )
            .unwrap();
        assert_eq!(
            store.overlay(&test_config()).unwrap().smtp_host.as_deref(),
            Some("https://before.example/hook")
        );
        store
            .with(|connection| {
                connection.execute_batch(
                    "CREATE TRIGGER refuse_settings_update BEFORE UPDATE ON settings
                     BEGIN SELECT RAISE(FAIL, 'fixture refusal'); END;",
                )
            })
            .unwrap();
        assert!(store
            .put_settings(
                "local",
                &[(
                    "smtp_host".to_owned(),
                    SettingWrite::Set("https://after.example/hook".to_owned()),
                )],
            )
            .is_err());
        assert_eq!(
            store.overlay(&test_config()).unwrap().smtp_host.as_deref(),
            Some("https://before.example/hook")
        );
    }

    #[test]
    fn db_retention_is_what_the_sweeper_would_read() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .put_settings(
                "local",
                &[(
                    "audit_retention_days".to_owned(),
                    SettingWrite::Set("7".to_owned()),
                )],
            )
            .unwrap();
        assert_eq!(
            store
                .resolved_settings(&test_config())
                .unwrap()
                .audit_retention_days,
            7
        );
    }

    #[test]
    fn unsupported_schema_is_refused_without_rewriting_data() {
        let previous = "40".to_owned();
        let future = (SCHEMA_VERSION + 1).to_string();
        for version in [
            None,
            Some("3"),
            Some("31"),
            Some("34"),
            Some(previous.as_str()),
            Some(future.as_str()),
            Some("99"),
            Some("invalid"),
            Some("-1"),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let store = Store::open(directory.path()).unwrap();
            store.insert_link(test_link("preserved")).unwrap();
            drop(store);
            let path = directory.path().join("votport.db");
            let connection = Connection::open(&path).unwrap();
            connection.execute_batch("PRAGMA journal_mode=DELETE; DROP INDEX links_tenant; DROP INDEX links_tenant_created; DROP INDEX delivery_jobs_deadline_pending; DROP INDEX delivery_jobs_retirement_due; DROP INDEX outbound_fetch_tickets_expires; DROP INDEX outbound_grants_open_expires; DROP INDEX audit_log_tenant; DROP INDEX audit_log_event; DROP INDEX audit_log_tenant_at; DROP INDEX audit_log_event_at; DELETE FROM meta WHERE key='schema_version';").unwrap();
            if let Some(version) = version {
                connection
                    .execute(
                        "INSERT INTO meta(key,value) VALUES ('schema_version',?1)",
                        [version],
                    )
                    .unwrap();
            }
            drop(connection);
            let before = std::fs::read(&path).unwrap();
            assert!(
                Store::open(directory.path()).is_err(),
                "version {version:?}"
            );
            assert_eq!(std::fs::read(&path).unwrap(), before, "version {version:?}");
            let connection = Connection::open(&path).unwrap();
            let indexes: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema WHERE type='index' AND name IN (
                        'delivery_jobs_deadline_pending',
                        'delivery_jobs_retirement_due',
                        'outbound_fetch_tickets_expires',
                        'outbound_grants_open_expires',
                        'audit_log_tenant',
                        'audit_log_event',
                        'audit_log_tenant_at',
                        'audit_log_event_at'
                    )",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(indexes, 0, "version {version:?}");
            assert!(!directory.path().join("votport.db-wal").exists());
        }
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("votport.db");
        Connection::open(&path).unwrap().execute_batch("CREATE TABLE sqliteX_private(value TEXT); INSERT INTO sqliteX_private VALUES ('preserve');").unwrap();
        let before = std::fs::read(&path).unwrap();
        assert!(Store::open(directory.path()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(!directory.path().join("receipt.key").exists());
    }

    #[test]
    fn unsupported_storage_layout_is_refused_without_relayout() {
        for layout in [None, Some("old"), Some("")] {
            let directory = tempfile::tempdir().unwrap();
            let data = directory.path().join("data");
            let receive = directory.path().join("receive/acme");
            std::fs::create_dir_all(&receive).unwrap();
            std::fs::write(receive.join("frame.mov"), b"preserved payload").unwrap();
            let store = Store::open(&data).unwrap();
            store.insert_tenant(test_tenant("acme")).unwrap();
            store
                .with(|connection| {
                    connection.execute("DELETE FROM meta WHERE key='tenant_storage_layout'", [])?;
                    if let Some(layout) = layout {
                        connection.execute(
                            "INSERT INTO meta(key,value) VALUES ('tenant_storage_layout',?1)",
                            [layout],
                        )?;
                    }
                    Ok(())
                })
                .unwrap();
            drop(store);
            let path = data.join("votport.db");
            let before = std::fs::read(&path).unwrap();
            let error = Store::open(&data).err().expect("unsupported layout");
            assert!(error.contains("unsupported tenant storage layout"));
            assert_eq!(std::fs::read(&path).unwrap(), before);
            assert_eq!(
                std::fs::read(receive.join("frame.mov")).unwrap(),
                b"preserved payload"
            );
            assert!(!directory.path().join("receive/.vot-tenants.stage").exists());
        }
    }

    #[test]
    fn unsupported_schema_does_not_checkpoint_a_surviving_wal() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .with(|connection| {
                connection.set_db_config(
                    rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
                    true,
                )?;
                connection.execute("UPDATE meta SET value='34' WHERE key='schema_version'", [])?;
                Ok(())
            })
            .unwrap();
        drop(store);
        let database = directory.path().join("votport.db");
        let wal = directory.path().join("votport.db-wal");
        let database_before = std::fs::read(&database).unwrap();
        let wal_before = std::fs::read(&wal).unwrap();
        assert!(!wal_before.is_empty());
        assert!(Store::open(directory.path()).is_err());
        assert_eq!(std::fs::read(&database).unwrap(), database_before);
        assert_eq!(std::fs::read(&wal).unwrap(), wal_before);
    }

    #[test]
    fn state_json_is_preserved_and_refused_before_creating_a_database() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state.json");
        std::fs::write(&state, br#"{"links":[{"id":"preserved"}]}"#).unwrap();
        let before = std::fs::read(&state).unwrap();
        assert!(Store::open(directory.path())
            .err()
            .unwrap()
            .contains("state.json is unsupported"));
        assert_eq!(std::fs::read(&state).unwrap(), before);
        assert!(!directory.path().join("votport.db").exists());
        assert!(!directory.path().join("receipt.key").exists());
    }

    #[test]
    fn open_refuses_a_newer_schema_version() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        drop(store);
        {
            let connection = Connection::open(directory.path().join("votport.db")).unwrap();
            connection
                .execute(
                    "UPDATE meta SET value = '99' WHERE key = 'schema_version'",
                    [],
                )
                .unwrap();
        }
        let error = match Store::open(directory.path()) {
            Err(error) => error,
            Ok(_) => panic!("expected open to refuse a newer schema"),
        };
        assert!(error.contains("99"), "{error}");
        assert!(error.contains("unsupported"), "{error}");
        assert_eq!(schema_version(directory.path()), "99");
    }

    #[test]
    fn open_does_not_stamp_schema_version_down() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        drop(store);
        assert_eq!(schema_version(directory.path()), SCHEMA_VERSION.to_string());
        Store::open(directory.path()).unwrap();
        assert_eq!(schema_version(directory.path()), SCHEMA_VERSION.to_string());
    }

    #[test]
    fn schema43_refusal_preserves_invalid_quota_schema() {
        for damaged in [
            "DROP INDEX files_quota_identity;",
            "DROP TRIGGER tenant_quota_usage_insert;",
        ] {
            let directory = tempfile::tempdir().unwrap();
            drop(Store::open(directory.path()).unwrap());
            let path = directory.path().join("votport.db");
            let connection = Connection::open(&path).unwrap();
            connection
                .execute_batch(
                    "PRAGMA journal_mode=DELETE;
                     DROP TRIGGER audit_log_count_insert;
                     DROP TRIGGER audit_log_count_delete;
                     DROP TABLE audit_log_count;
                     UPDATE meta SET value='43' WHERE key='schema_version';",
                )
                .unwrap();
            connection.execute_batch(damaged).unwrap();
            drop(connection);
            let before = std::fs::read(&path).unwrap();

            assert!(Store::open(directory.path()).is_err(), "{damaged}");
            assert_eq!(schema_version(directory.path()), "43", "{damaged}");
            assert!(
                std::fs::read(&path).unwrap() == before,
                "rejected schema43 database changed: {damaged}"
            );
        }
    }

    #[test]
    fn schema43_upgrade_backfills_and_maintains_audit_count() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.audit("", "", "first", "one", &serde_json::json!({}));
        store.audit("", "", "second", "two", &serde_json::json!({}));
        drop(store);

        let connection = Connection::open(directory.path().join("votport.db")).unwrap();
        connection
            .execute_batch(
                "DROP TRIGGER audit_log_count_insert;
                 DROP TRIGGER audit_log_count_delete;
                 DROP TABLE audit_log_count;
                 DROP INDEX delivery_jobs_tenant_created;
                 DROP INDEX delivery_jobs_tenant_snapshot;
                 ALTER TABLE delivery_jobs DROP COLUMN created_at;
                 ALTER TABLE delivery_jobs DROP COLUMN snapshot_bytes;
                 ALTER TABLE automation_tokens DROP COLUMN created_by;
                 ALTER TABLE tenants DROP COLUMN retention_days;
                 ALTER TABLE links DROP COLUMN retention_days;
                 UPDATE meta SET value='43' WHERE key='schema_version';",
            )
            .unwrap();
        drop(connection);

        let store = Store::open(directory.path()).unwrap();
        assert_eq!(schema_version(directory.path()), SCHEMA_VERSION.to_string());
        assert_eq!(store.audit_count().unwrap(), 2);
        store.audit("", "", "third", "three", &serde_json::json!({}));
        assert_eq!(store.audit_count().unwrap(), 3);
    }

    #[test]
    fn branding_rows_round_trip_and_delete() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        assert!(store.branding("acme").unwrap().is_none());

        let branding = Branding {
            tenant: "acme".to_owned(),
            name: "Acme Corp".to_owned(),
            color: "#0a84ff".to_owned(),
            logo_ext: String::new(),
            updated_at: 42,
            ..Default::default()
        };
        store.set_branding(&branding).unwrap();
        let read = store.branding("acme").unwrap().unwrap();
        assert_eq!(read.name, "Acme Corp");
        assert_eq!(read.color, "#0a84ff");
        assert_eq!(read.logo_ext, "");
        assert_eq!(read.updated_at, 42);

        // Upsert replaces the row; the default tenant ("") is a row like any.
        store
            .set_branding(&Branding {
                logo_ext: "png".to_owned(),
                ..branding.clone()
            })
            .unwrap();
        assert_eq!(store.branding("acme").unwrap().unwrap().logo_ext, "png");
        store
            .set_branding(&Branding {
                tenant: String::new(),
                ..branding
            })
            .unwrap();
        assert_eq!(store.branding("").unwrap().unwrap().name, "Acme Corp");

        assert!(store.delete_branding("acme").unwrap());
        assert!(!store.delete_branding("acme").unwrap());
        assert!(store.branding("acme").unwrap().is_none());
        assert!(store.branding("").unwrap().is_some());
    }

    #[test]
    fn tenant_delete_removes_its_branding_row() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .insert_tenant(Tenant {
                retention_days: None,
                incarnation: String::new(),
                key: "acme".to_owned(),
                label: String::new(),
                admin_group: None,
                max_total_bytes: None,
                max_links: None,
                max_sessions: None,
                created_at: 0,
            })
            .unwrap();
        store
            .set_branding(&Branding {
                tenant: "acme".to_owned(),
                name: "Acme".to_owned(),
                color: String::new(),
                logo_ext: String::new(),
                updated_at: 0,
                ..Default::default()
            })
            .unwrap();
        assert!(matches!(
            store.remove_tenant("acme").unwrap(),
            TenantRemoval::Deleted
        ));
        assert!(store.branding("acme").unwrap().is_none());
    }

    #[test]
    fn upload_sessions_round_trip() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut session = PersistedUploadSession {
            committed_upload_id: None,
            push_key: None,
            id: "abcd1234".to_owned(),
            link_id: "link-1".to_owned(),
            tenant: String::new(),
            dest_dir: PathBuf::from("/received/link-1"),
            dest_rel: String::new(),
            package: ObjectId {
                suite: 1,
                root: [7u8; 32],
                length: 100,
            },
            max_total_bytes: Some(1000),
            started_at: 42,
            files: vec![PersistedUploadFile {
                entry: 0,
                display_path: "a.bin".to_owned(),
                stored_components: vec!["a.bin".to_owned()],
                object: ObjectId {
                    suite: 1,
                    root: [9u8; 32],
                    length: 100,
                },
                staging_path: PathBuf::from("/received/link-1/.vot-1-0-2.stage"),
                journal_path: PathBuf::from("/received/link-1/.vot-1-0-2.journal"),
                incarnation: [3u8; 16],
                profile: vot_sdk_file::CommitProfile::Balanced,
                nas_contract: vot_sdk_file::NasContract::Unqualified,
                prefix_bytes: 0,
                published: false,
                receipt: false,
            }],
        };
        let mut second = session.files[0].clone();
        second.entry = 1;
        second.profile = vot_sdk_file::CommitProfile::Fast;
        second.display_path = "b.bin".to_owned();
        second.stored_components = vec!["b.bin".to_owned()];
        session.files.push(second);
        store.insert_upload_session(&session).unwrap();
        let (received, reserved) = store.tenant_admission_usage("").unwrap();
        assert_eq!(received, 0);
        assert_eq!(reserved.len(), 1);
        assert_eq!(
            (reserved[0].id.as_str(), reserved[0].bytes),
            (session.id.as_str(), 100)
        );
        assert!(store.tenant_admission_usage("other").unwrap().1.is_empty());
        store
            .update_upload_file_progress(
                &session.id,
                [(0, 64 * 1024, true, true), (1, 32, false, false)],
            )
            .unwrap();

        let loaded = store.load_upload_sessions().unwrap();
        assert_eq!(loaded.len(), 1);
        let mut expected = session.clone();
        expected.files[0].prefix_bytes = 64 * 1024;
        expected.files[0].published = true;
        expected.files[0].receipt = true;
        expected.files[1].prefix_bytes = 32;
        assert_eq!(loaded[0], expected);

        // Re-inserting the same id replaces its file rows, no duplication.
        store.insert_upload_session(&session).unwrap();
        assert_eq!(store.load_upload_sessions().unwrap()[0].files.len(), 2);
        store
            .with(|connection| {
                connection.execute(
                    "UPDATE upload_session_files SET stored_components=?1 WHERE session_id=?2 AND entry=0",
                    rusqlite::params!["not json", session.id],
                )
            })
            .unwrap();
        let error = store.load_upload_sessions().unwrap_err();
        assert!(error.contains("stored_components"), "{error}");
        store
            .with(|connection| {
                connection.execute(
                    "UPDATE upload_session_files SET stored_components=?1 WHERE session_id=?2 AND entry=0",
                    rusqlite::params![r#""private-path-sentinel""#, session.id],
                )
            })
            .unwrap();
        let error = store.load_upload_sessions().unwrap_err();
        assert!(error.contains("stored_components"), "{error}");
        assert!(!error.contains("private-path-sentinel"), "{error}");
        store
            .with(|connection| {
                connection.execute(
                    "UPDATE upload_session_files SET stored_components=?1 WHERE session_id=?2 AND entry=0",
                    rusqlite::params!["[]", session.id],
                )
            })
            .unwrap();
        let error = store.load_upload_sessions().unwrap_err();
        assert!(error.contains("stored_components"), "{error}");
        store
            .with(|connection| {
                connection.execute(
                    "UPDATE upload_session_files SET stored_components=?1 WHERE session_id=?2 AND entry=0",
                    rusqlite::params![r#"["a.bin"]"#, session.id],
                )
            })
            .unwrap();
        assert!(store.load_upload_sessions().is_ok());
        store
            .with(|connection| {
                connection.execute_batch(
                    "CREATE TRIGGER fail_second_checkpoint BEFORE UPDATE ON upload_session_files
             WHEN NEW.entry = 1 BEGIN SELECT RAISE(FAIL, 'checkpoint failure'); END;",
                )
            })
            .unwrap();
        assert!(store
            .update_upload_file_progress(&session.id, [(0, 64, true, true), (1, 32, false, false)])
            .is_err());
        assert_eq!(store.load_upload_sessions().unwrap(), vec![session.clone()]);
        store
            .with(|connection| connection.execute_batch("DROP TRIGGER fail_second_checkpoint"))
            .unwrap();

        drop(store);
        let store = Store::open(directory.path()).unwrap();
        assert_eq!(store.load_upload_sessions().unwrap(), vec![session.clone()]);

        store.delete_upload_session(&session.id).unwrap();
        assert!(store.load_upload_sessions().unwrap().is_empty());

        session.push_key = Some("resume-key".to_owned());
        store.insert_upload_session(&session).unwrap();
        let mut unrelated = session.clone();
        unrelated.id = "unrelated".to_owned();
        unrelated.push_key = None;
        store.insert_upload_session(&unrelated).unwrap();
        let mut replacement = session.clone();
        replacement.id = "replacement".to_owned();
        replacement.files.truncate(1);
        let owners = || {
            store
                .with(|connection| {
                    let mut statement = connection.prepare(
                        "SELECT session_id FROM upload_session_files ORDER BY session_id, entry",
                    )?;
                    let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
                    rows.collect::<rusqlite::Result<Vec<_>>>()
                })
                .unwrap()
        };
        let before = owners();
        store.with(|connection| connection.execute_batch(
            "CREATE TRIGGER fail_replacement BEFORE INSERT ON upload_session_files
             WHEN NEW.session_id = 'replacement' BEGIN SELECT RAISE(FAIL, 'replacement failure'); END;",
        )).unwrap();
        assert!(store.insert_upload_session(&replacement).is_err());
        assert_eq!(owners(), before);
        assert_eq!(
            store.load_push_session("resume-key").unwrap(),
            Some(session.clone())
        );
        store
            .with(|connection| connection.execute_batch("DROP TRIGGER fail_replacement"))
            .unwrap();

        store.insert_upload_session(&replacement).unwrap();
        assert_eq!(
            store.load_push_session("resume-key").unwrap(),
            Some(replacement.clone())
        );
        assert_eq!(owners(), vec!["replacement", "unrelated", "unrelated"]);
        store.delete_upload_session(&replacement.id).unwrap();
        assert_eq!(store.load_upload_sessions().unwrap(), vec![unrelated]);
        assert_eq!(owners(), vec!["unrelated", "unrelated"]);
    }

    #[test]
    fn smtp_is_none_without_host() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut config = test_config();
        config.smtp_host = None;
        config.smtp_from = Some("votport@example.com".to_owned());

        assert!(store.resolved_settings(&config).unwrap().smtp.is_none());
    }

    #[test]
    fn smtp_is_none_without_from() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut config = test_config();
        config.smtp_host = Some("smtp.example.com".to_owned());
        config.smtp_from = None;
        assert!(store.resolved_settings(&config).unwrap().smtp.is_none());
    }

    #[test]
    fn smtp_assembles_when_host_and_from_resolve() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .put_settings(
                "local",
                &[(
                    "smtp_host".to_owned(),
                    SettingWrite::Set("db.example.com".to_owned()),
                )],
            )
            .unwrap();
        let mut config = test_config();
        config.smtp_from = Some("votport@example.com".to_owned());

        let smtp = store
            .resolved_settings(&config)
            .unwrap()
            .smtp
            .expect("host from DB plus sender from env");
        assert_eq!(smtp.host, "db.example.com");
        assert_eq!(smtp.from, "votport@example.com");

        assert_eq!(smtp.port, 587);
        assert!(smtp.starttls);
        assert!(smtp.password.is_none());
    }

    #[test]
    fn invalid_smtp_port_skips_to_env() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .put_settings(
                "local",
                &[("smtp_port".to_owned(), SettingWrite::Set("nope".to_owned()))],
            )
            .unwrap();
        let overlay = store.overlay(&test_config()).unwrap();
        assert_eq!(overlay.smtp_port, 587);
        assert!(!overridden(&overlay, "smtp_port"));
    }
}

#[cfg(test)]
mod principals_store_tests {
    use super::*;

    #[test]
    fn upsert_revoke_unblock_preserve_version() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let grants = serde_json::json!([{"tenant":"","role":"admin"}]);
        let row = store
            .upsert_sso_principal("user@example.com", &["employees".to_owned()], &grants)
            .unwrap();
        assert_eq!(row.credential_version, 1);
        assert!(!row.blocked);
        assert_eq!(row.last_groups, vec!["employees".to_owned()]);
        assert_eq!(row.source, "sso");
        assert!(store.principal_allows("user@example.com", 1));
        assert!(!store.principal_allows("user@example.com", 2));
        assert!(store.principal_allows("missing", 1));
        assert!(!store.principal_allows("missing", 2));

        store
            .with(|connection| {
                connection.execute(
                    "UPDATE principals SET last_login_at = 123 WHERE subject = ?1",
                    ["user@example.com"],
                )
            })
            .unwrap();

        assert!(store.revoke_principal("user@example.com").unwrap());
        let revoked = store.principal("user@example.com").unwrap().unwrap();
        assert_eq!(revoked.credential_version, 2);
        assert!(revoked.blocked);
        assert_eq!(revoked.last_login_at, 123);
        assert_eq!(revoked.last_groups, vec!["employees".to_owned()]);
        assert_eq!(revoked.last_grants, grants);
        assert!(!store.principal_allows("user@example.com", 1));
        assert!(!store.principal_allows("user@example.com", 2));

        let blocked_upsert = store
            .upsert_sso_principal(
                "user@example.com",
                &["after".to_owned()],
                &serde_json::json!([{"tenant":"after","role":"viewer"}]),
            )
            .unwrap();
        assert_eq!(blocked_upsert.credential_version, 2);
        assert!(blocked_upsert.blocked);
        assert_eq!(blocked_upsert.last_login_at, 123);
        assert_eq!(blocked_upsert.last_groups, vec!["employees".to_owned()]);
        assert_eq!(blocked_upsert.last_grants, grants);

        assert!(store.unblock_principal("user@example.com").unwrap());
        let unblocked = store.principal("user@example.com").unwrap().unwrap();
        assert_eq!(unblocked.credential_version, 2);
        assert!(!unblocked.blocked);
        assert!(store.principal_allows("user@example.com", 2));
        assert!(!store.principal_allows("user@example.com", 1));
        assert!(!store.revoke_principal("missing").unwrap());
        assert!(!store.unblock_principal("missing").unwrap());

        let refreshed = store
            .upsert_sso_principal(
                "user@example.com",
                &["after-unblock".to_owned()],
                &serde_json::json!([{"tenant":"after-unblock","role":"editor"}]),
            )
            .unwrap();
        assert_eq!(refreshed.credential_version, unblocked.credential_version);
        assert!(!refreshed.blocked);
        assert!(refreshed.last_login_at > 123);
        assert_eq!(refreshed.last_groups, vec!["after-unblock".to_owned()]);
        assert_eq!(
            refreshed.last_grants,
            serde_json::json!([{"tenant":"after-unblock","role":"editor"}])
        );
        assert_eq!(refreshed.source, unblocked.source);
        assert_eq!(refreshed.external_id, unblocked.external_id);
        assert_eq!(refreshed.created_at, unblocked.created_at);

        store
            .with(|connection| {
                connection.execute(
                    "UPDATE principals SET last_groups = 'broken' WHERE subject = ?1",
                    ["user@example.com"],
                )
            })
            .unwrap();
        assert!(store.principal("user@example.com").is_err());
        assert!(!store.principal_allows("user@example.com", 2));
        store
            .with(|connection| {
                connection.execute(
                    "UPDATE principals SET last_groups = '[]', last_grants = 'broken'
                     WHERE subject = ?1",
                    ["user@example.com"],
                )
            })
            .unwrap();
        assert!(store.principal("user@example.com").is_err());
        assert!(!store.principal_allows("user@example.com", 2));
    }

    #[test]
    fn principals_page_searches_literally_and_orders_stably() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        for subject in ["Alice%literal", "alice_literal", "aliceXliteral"] {
            store
                .upsert_sso_principal(subject, &[], &serde_json::json!([]))
                .unwrap();
        }
        store
            .with(|connection| connection.execute("UPDATE principals SET last_login_at = 0", []))
            .unwrap();

        let (page, total) = store.principals_page(2, 0, Some("%literal")).unwrap();
        assert_eq!(total, 1);
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].subject, "Alice%literal");

        let (page, total) = store.principals_page(2, 0, Some("_literal")).unwrap();
        assert_eq!(total, 1);
        assert_eq!(page[0].subject, "alice_literal");

        let (page, total) = store.principals_page(2, 0, Some("ALICEXLITERAL")).unwrap();
        assert_eq!(total, 1);
        assert_eq!(page[0].subject, "aliceXliteral");

        let (page, total) = store.principals_page(2, 0, None).unwrap();
        assert_eq!(total, 3);
        assert_eq!(
            page.iter()
                .map(|item| item.subject.as_str())
                .collect::<Vec<_>>(),
            ["Alice%literal", "aliceXliteral"]
        );
        let (page, total) = store.principals_page(2, 2, None).unwrap();
        assert_eq!(total, 3);
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].subject, "alice_literal");
    }
}

#[test]
fn quota_layout_migration_records_the_tenants_it_moved() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();

    // Nothing stored: re-running the layout install moves nothing and
    // writes no row.
    store.with(install_quota_schema).unwrap();
    let rows = store.audit_export(None, 0, 0, 100).unwrap();
    assert!(rows
        .iter()
        .all(|row| row.event != "tenant_storage_migrated"));

    // A stored file makes the next install migrate its bytes into the
    // layout and name the tenant and total it moved.
    let mut link = test_link("link-1");
    link.uploads.push(UploadRecord {
        partial: false,
        log: Vec::new(),
        id: "up-1".to_owned(),
        started_at: 1,
        completed_at: 2,
        replayed_chunks: 0,
        rejected_chunks: 0,
        transport: None,
        package_root: "aa".to_owned(),
        total_bytes: 5000,
        files: vec![FileRecord {
            path: "a.txt".to_owned(),
            stored_as: "a.txt".to_owned(),
            bytes: 5000,
            suite: "blake3".to_owned(),
            root: "bb".to_owned(),
            receipt: false,
            deleted: false,
        }],
    });
    store.insert_link(link).unwrap();
    store.with(install_quota_schema).unwrap();
    let rows = store.audit_export(None, 0, 0, 100).unwrap();
    let row = rows
        .iter()
        .find(|row| row.event == "tenant_storage_migrated")
        .expect("the layout migration names what it moved");
    assert_eq!(row.detail["tenants"][0]["tenant"], "");
    assert_eq!(row.detail["tenants"][0]["bytes"], 5000);
}

#[test]
fn store_outage_logs_use_the_reduced_subject_form() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    store
        .with(|connection| connection.execute_batch("DROP TABLE principals"))
        .unwrap();
    let (log, _guard) = crate::logging::captured(crate::logging::stdout_filter(None, false));
    assert!(!store.principal_allows("jane@example.com", 1));
    let text = std::fs::read_to_string(log.path()).unwrap();
    assert!(text.contains("ja..om (16)"), "{text}");
    assert!(!text.contains("jane@example.com"), "{text}");
}

/// Audit finding 224: corrupt byte limbs are refused, never saturated to a
/// fabricated total. The pure limb decision rejects negatives and overflow,
/// and a damaged file row makes the page read fail instead of reporting a
/// bogus size.
#[test]
fn corrupt_grant_byte_limbs_are_refused_not_saturated() {
    // The old saturation inputs now refuse: negative limbs and a hi limb
    // whose shift overflows 64 bits.
    assert!(combine_byte_sums(-1, 0).is_err());
    assert!(combine_byte_sums(0, -5).is_err());
    assert!(combine_byte_sums(1 << 32, 0).is_err());
    assert_eq!(combine_byte_sums(1, 0).unwrap(), 1 << 32);

    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    store
        .with(|connection| {
            connection.execute(
                "INSERT INTO outbound_grants(id, token_hash, tenant, link_id, upload_id,
                    package_root, name, suite, root, file_index, bytes_hi, bytes_lo,
                    label, created_at, expires_at, downloads)
                 VALUES ('grant-corrupt', 'hash-corrupt', 'team', 'link', 'upload',
                    'root', 'file.txt', 'blake3', 'root', 0, 0, 8,
                    'Delivery', 0, 0, 0)",
                [],
            )?;
            connection.execute(
                "INSERT INTO outbound_grant_files(grant_id, file_index, source, name, suite,
                    root, bytes_hi, bytes_lo, receipt_b64)
                 VALUES ('grant-corrupt', 0, 'src', 'file.txt', 'blake3', 'root', -1, 0, '')",
                [],
            )
        })
        .unwrap();
    let page = store.outbound_grant_files_page_by_token_hash("hash-corrupt", 0, 50);
    assert!(
        page.is_err(),
        "corrupt limbs refuse the row instead of fabricating a total"
    );
}

// Audit finding 377: retention deletes the bytes but the tombstoned row
// kept the in-package path, which can carry a person or project name. The
// tombstone must blank the path while keeping the identity fields.
#[test]
fn tombstoning_blanks_the_in_package_path_but_keeps_the_identity() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let record = |id: &str, path: &str| UploadRecord {
        id: id.to_owned(),
        started_at: 0,
        completed_at: 0,
        transport: None,
        package_root: "root".to_owned(),
        total_bytes: 1,
        partial: false,
        replayed_chunks: 0,
        rejected_chunks: 0,
        log: Vec::new(),
        files: vec![FileRecord {
            path: path.into(),
            stored_as: path.into(),
            bytes: 1,
            suite: "blake3".into(),
            root: "aa".into(),
            receipt: false,
            deleted: false,
        }],
    };
    let mut link = test_link("link");
    link.uploads = vec![record("upload", "Report Final v2.xlsx")];
    store.insert_link(link).unwrap();
    assert!(store
        .tombstone_files(
            "",
            "link",
            &std::collections::HashSet::from(["Report Final v2.xlsx"])
        )
        .unwrap());
    let file = store
        .link_upload("", "link", "upload")
        .unwrap()
        .unwrap()
        .files[0]
        .clone();
    assert!(file.deleted);
    assert_eq!(file.stored_as, "Report Final v2.xlsx");
    assert_eq!(file.path, "");
    assert_eq!(store.tenant_received_bytes("").unwrap(), 0);
}
