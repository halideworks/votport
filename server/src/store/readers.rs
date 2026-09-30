use super::*;
use std::ops::Deref;
use std::sync::Condvar;

const READ_CONNECTIONS: usize = 4;

pub(super) struct Readers {
    available: Mutex<Vec<Connection>>,
    changed: Condvar,
}

impl Readers {
    pub(super) fn open(path: &Path) -> Result<Self, String> {
        let mut available = Vec::with_capacity(READ_CONNECTIONS);
        for _ in 0..READ_CONNECTIONS {
            let connection = Connection::open_with_flags(
                path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                    | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .map_err(|error| error.to_string())?;
            register_functions(&connection)?;
            connection
                .busy_timeout(std::time::Duration::from_secs(5))
                .and_then(|()| connection.pragma_update(None, "cache_size", -8000))
                .and_then(|()| connection.pragma_update(None, "mmap_size", 268435456))
                .and_then(|()| connection.pragma_update(None, "temp_store", "MEMORY"))
                .map_err(|error| error.to_string())?;
            connection.set_prepared_statement_cache_capacity(64);
            available.push(connection);
        }
        Ok(Self {
            available: Mutex::new(available),
            changed: Condvar::new(),
        })
    }

    fn acquire(&self) -> ReadConnection<'_> {
        let mut available = self
            .changed
            .wait_while(
                self.available.lock().expect("readers poisoned"),
                |available| available.is_empty(),
            )
            .expect("readers poisoned");
        ReadConnection {
            connection: available.pop(),
            readers: self,
        }
    }
}

struct ReadConnection<'a> {
    connection: Option<Connection>,
    readers: &'a Readers,
}

impl Deref for ReadConnection<'_> {
    type Target = Connection;

    fn deref(&self) -> &Self::Target {
        self.connection.as_ref().expect("read connection returned")
    }
}

impl Drop for ReadConnection<'_> {
    fn drop(&mut self) {
        self.readers
            .available
            .lock()
            .expect("readers poisoned")
            .push(self.connection.take().expect("read connection returned"));
        self.readers.changed.notify_one();
    }
}

impl Store {
    #[cfg(test)]
    pub(crate) fn with_all_readers<T>(
        &self,
        f: impl FnOnce(&Connection) -> rusqlite::Result<T>,
    ) -> Result<T, String> {
        let held: Vec<_> = (0..READ_CONNECTIONS)
            .map(|_| self.readers.acquire())
            .collect();
        f(&held[0]).map_err(|error| error.to_string())
    }

    /// Each call owns one WAL snapshot; reads never take the writer mutex.
    pub(crate) fn read<T>(
        &self,
        f: impl FnOnce(&Connection) -> rusqlite::Result<T>,
    ) -> Result<T, String> {
        let connection = self.readers.acquire();
        let transaction = connection
            .unchecked_transaction()
            .map_err(|error| error.to_string())?;
        let result = f(&transaction).map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn readers_progress_during_an_uncommitted_write_and_keep_one_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.set_admin_password_hash("before".into()).unwrap();
        std::thread::scope(|scope| {
            let mut writer = store.connection.lock().unwrap();
            let transaction = writer.transaction().unwrap();
            transaction
                .execute(
                    "UPDATE meta SET value='uncommitted' WHERE key='admin_password_hash'",
                    [],
                )
                .unwrap();
            let (done, result) = mpsc::channel();
            let store = &store;
            scope.spawn(move || done.send(store.admin_password_hash()).unwrap());
            let result = result.recv_timeout(Duration::from_secs(5));
            drop(transaction);
            drop(writer);
            assert_eq!(result.unwrap().unwrap().as_deref(), Some("before"));
        });
        std::thread::scope(|scope| {
            let (started, ready) = mpsc::channel();
            let (release, proceed) = mpsc::channel();
            let store = &store;
            let reader = scope.spawn(move || {
                store.read(|connection| {
                    let value = || {
                        connection.query_row(
                            "SELECT value FROM meta WHERE key='admin_password_hash'",
                            [],
                            |row| row.get::<_, String>(0),
                        )
                    };
                    let before = value()?;
                    started.send(()).unwrap();
                    proceed.recv_timeout(Duration::from_secs(5)).unwrap();
                    assert_eq!(value()?, before);
                    Ok(())
                })
            });
            ready.recv_timeout(Duration::from_secs(5)).unwrap();
            store.set_admin_password_hash("after".into()).unwrap();
            assert_eq!(
                store.admin_password_hash().unwrap().as_deref(),
                Some("after")
            );
            release.send(()).unwrap();
            reader.join().unwrap().unwrap();
        });
    }

    #[test]
    fn readers_are_bounded_read_only_and_return_after_errors_and_panics() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let held: Vec<_> = (0..READ_CONNECTIONS)
            .map(|_| store.readers.acquire())
            .collect();
        assert!(store.readers.available.lock().unwrap().is_empty());
        drop(held);
        assert!(store
            .read(|connection| connection.execute("DELETE FROM meta", []))
            .is_err());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: Result<(), String> = store.read(|_| panic!("controlled reader failure"));
        }))
        .is_err());
        assert_eq!(
            store.readers.available.lock().unwrap().len(),
            READ_CONNECTIONS
        );
        store.health_check().unwrap();
    }

    #[test]
    fn stored_claim_query_uses_the_live_covering_index() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let plan = store.read(|connection| {
            connection.prepare("EXPLAIN QUERY PLAN SELECT stored_as, suite, root FROM files WHERE tenant=?1 AND deleted=0 AND stored_as IN (SELECT value FROM json_each(?2))")?
                .query_map(["tenant", "[\"selected\"]"], |row| row.get::<_, String>(3))?
                .collect::<rusqlite::Result<Vec<_>>>()
        }).unwrap();
        assert!(
            plan.iter().any(
                |line| line.contains("files_live_stored_claim") && line.contains("stored_as=?")
            ),
            "{plan:?}"
        );
    }

    #[test]
    #[ignore = "isolated scale measurement; no production data"]
    fn stored_claim_lookup_benchmark() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.with(|connection| {
            let transaction = connection.unchecked_transaction()?;
            transaction.execute_batch("WITH RECURSIVE n(i) AS (VALUES(0) UNION ALL SELECT i+1 FROM n WHERE i<99999) INSERT INTO files(link_id,tenant,upload_id,file_index,bytes_hi,bytes_lo,deleted,stored_as,path,suite,root,receipt) SELECT 'link','tenant','upload',i,0,1,0,'file-'||i,'file-'||i,'blake3','root',0 FROM n")?;
            transaction.commit()
        }).unwrap();
        let candidates = vec![("file-99999".into(), "blake3".into(), "root".into())];
        let measure = || {
            let mut elapsed = Vec::new();
            for _ in 0..7 {
                let start = std::time::Instant::now();
                assert!(store
                    .conflicting_stored_claims("tenant", &candidates)
                    .unwrap()
                    .is_empty());
                elapsed.push(start.elapsed().as_secs_f64() * 1000.0);
            }
            elapsed.sort_by(f64::total_cmp);
            elapsed[elapsed.len() / 2]
        };
        store
            .with(|connection| connection.execute_batch("DROP INDEX files_live_stored_claim"))
            .unwrap();
        let unindexed_ms = measure();
        store.with(|connection| connection.execute_batch("CREATE INDEX files_live_stored_claim ON files(tenant,stored_as,suite,root) WHERE deleted=0")).unwrap();
        let indexed_ms = measure();
        println!(
            "{}",
            serde_json::json!({"live_files":100000,"candidates":1,"samples":7,"unindexed_median_ms":unindexed_ms,"indexed_median_ms":indexed_ms})
        );
        for concurrent in [false, true, false, true, false, true] {
            let start = std::time::Instant::now();
            let barrier = std::sync::Barrier::new(9);
            let (mut reads, mut writes) = std::thread::scope(|scope| {
                let barrier = &barrier;
                let store = &store;
                let readers: Vec<_> = (0..8).map(|_| scope.spawn(move || {
                    barrier.wait();
                    (0..16).map(|_| {
                        let start = std::time::Instant::now();
                        let query = |connection: &Connection| connection.query_row("SELECT COUNT(*) FROM files WHERE tenant='tenant' AND deleted=0", [], |row| row.get::<_, i64>(0));
                        let count = if concurrent { store.read(query) } else { store.with(query) }.unwrap();
                        assert_eq!(count, 100000);
                        start.elapsed().as_secs_f64() * 1000.0
                    }).collect::<Vec<_>>()
                })).collect();
                let writer = scope.spawn(move || {
                    barrier.wait();
                    (0..20)
                        .map(|index| {
                            let start = std::time::Instant::now();
                            store
                                .set_admin_password_hash(format!("benchmark-{index}"))
                                .unwrap();
                            start.elapsed().as_secs_f64() * 1000.0
                        })
                        .collect::<Vec<_>>()
                });
                (
                    readers
                        .into_iter()
                        .flat_map(|reader| reader.join().unwrap())
                        .collect::<Vec<_>>(),
                    writer.join().unwrap(),
                )
            });
            reads.sort_by(f64::total_cmp);
            writes.sort_by(f64::total_cmp);
            println!(
                "{}",
                serde_json::json!({"concurrent_readers":concurrent,"reader_threads":8,"reads":reads.len(),"writes":writes.len(),"wall_ms":start.elapsed().as_secs_f64()*1000.0,"read_p95_ms":reads[reads.len()*95/100],"write_p95_ms":writes[writes.len()*95/100]})
            );
        }
    }
}
