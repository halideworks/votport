use super::*;
use serde::ser::{SerializeSeq, Serializer};
use std::io::Write;

#[derive(Clone)]
pub struct UploadHeader {
    pub upload: UploadRecord,
    pub file_count: usize,
    pub position: i64,
    pub route: Option<serde_json::Value>,
}

pub struct UploadPage {
    pub uploads: Vec<UploadHeader>,
    pub next_position: Option<i64>,
}

pub struct UploadFilesPage {
    pub header: UploadHeader,
    pub files: Vec<(usize, FileRecord)>,
}

const HEADER_COLUMNS: &str = "document,file_count,upload_id,position,
    (SELECT json_object('issuer',issuer,'revoked_at',revoked_at)
     FROM inbound_routes WHERE tenant=link_uploads.tenant
       AND link_id=link_uploads.link_id AND upload_id=link_uploads.upload_id
       AND receipt IS NOT NULL)";

fn header(row: &rusqlite::Row<'_>) -> rusqlite::Result<UploadHeader> {
    let upload: UploadRecord = parse_json(&row.get::<_, String>(0)?, 0)?;
    let file_count = usize::try_from(row.get::<_, i64>(1)?).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            1,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })?;
    if upload.id != row.get::<_, String>(2)? || !upload.files.is_empty() {
        return Err(invalid_upload());
    }
    Ok(UploadHeader {
        upload,
        file_count,
        position: row.get(3)?,
        route: row
            .get::<_, Option<String>>(4)?
            .map(|text| parse_json(&text, 4))
            .transpose()?,
    })
}

fn invalid_upload() -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Text,
        "upload file records do not match their header".into(),
    )
}

fn read_header(
    connection: &Connection,
    tenant: &str,
    link: &str,
    upload: &str,
) -> rusqlite::Result<Option<UploadHeader>> {
    connection
        .prepare_cached(&format!(
            "SELECT {HEADER_COLUMNS} FROM link_uploads
        WHERE tenant=?1 AND link_id=?2 AND upload_id=?3
        AND EXISTS(SELECT 1 FROM links WHERE tenant=?1 AND id=?2)"
        ))?
        .query_row([tenant, link, upload], header)
        .optional()
}

impl Store {
    /// Totals for one displayed request page, without hydrating upload or file records.
    pub fn link_upload_totals(
        &self,
        tenant: &str,
        links: &[String],
    ) -> Result<HashMap<String, (u64, u64)>, String> {
        let ids = serde_json::to_string(links).map_err(|error| error.to_string())?;
        self.with(|connection| {
            let mut statement = connection.prepare_cached(
                "SELECT link_id, document -> '$.total_bytes' FROM link_uploads
                 WHERE tenant=?1 AND link_id IN (SELECT value FROM json_each(?2))",
            )?;
            let mut rows = statement.query(rusqlite::params![tenant, ids])?;
            let mut totals = HashMap::<String, (u64, u64)>::new();
            while let Some(row) = rows.next()? {
                let bytes = row.get::<_, String>(1)?.parse::<u64>().map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        1,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?;
                let total = totals.entry(row.get(0)?).or_default();
                total.0 = total.0.saturating_add(1);
                total.1 = total.1.saturating_add(bytes);
            }
            Ok(totals)
        })
    }

    pub fn upload_headers_page(
        &self,
        tenant: &str,
        link: &str,
        before: Option<i64>,
        limit: usize,
    ) -> Result<Option<UploadPage>, String> {
        self.with(|connection| {
            let exists: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM links WHERE tenant=?1 AND id=?2)",
                [tenant, link],
                |row| row.get(0),
            )?;
            if !exists {
                return Ok(None);
            }
            let mut statement = connection.prepare_cached(&format!(
                "SELECT {HEADER_COLUMNS} FROM link_uploads
                 WHERE tenant=?1 AND link_id=?2 AND position<?3
                 ORDER BY position DESC LIMIT ?4"
            ))?;
            let mut uploads = statement
                .query_map(
                    rusqlite::params![
                        tenant,
                        link,
                        before.unwrap_or(i64::MAX),
                        i64::try_from(limit.saturating_add(1)).unwrap_or(i64::MAX)
                    ],
                    header,
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let next_position = if uploads.len() > limit {
                uploads.truncate(limit);
                uploads.last().map(|row| row.position)
            } else {
                None
            };
            Ok(Some(UploadPage {
                uploads,
                next_position,
            }))
        })
    }

    pub fn upload_header(
        &self,
        tenant: &str,
        link: &str,
        upload: &str,
    ) -> Result<Option<UploadHeader>, String> {
        self.with(|connection| read_header(connection, tenant, link, upload))
    }

    pub fn upload_files_page(
        &self,
        tenant: &str,
        link: &str,
        upload: &str,
        offset: usize,
        limit: usize,
    ) -> Result<Option<UploadFilesPage>, String> {
        self.with(|connection| {
            let Some(header) = read_header(connection, tenant, link, upload)? else {
                return Ok(None);
            };
            let end = offset.saturating_add(limit).min(header.file_count);
            let mut statement = connection.prepare_cached(
                "SELECT file_index,path,stored_as,bytes_hi,bytes_lo,suite,root,receipt,deleted
                 FROM files WHERE tenant=?1 AND link_id=?2 AND upload_id=?3
                   AND file_index>=?4 ORDER BY file_index LIMIT ?5",
            )?;
            let mut rows = statement.query(rusqlite::params![
                tenant,
                link,
                upload,
                i64::try_from(offset).unwrap_or(i64::MAX),
                i64::try_from(limit).unwrap_or(i64::MAX)
            ])?;
            let mut files = Vec::new();
            while let Some(row) = rows.next()? {
                let index = usize::try_from(row.get::<_, i64>(0)?).map_err(|_| invalid_upload())?;
                if index != offset.saturating_add(files.len()) || index >= header.file_count {
                    return Err(invalid_upload());
                }
                files.push((index, row_to_upload_file(row)?));
            }
            if files.len() != end.saturating_sub(offset) {
                return Err(invalid_upload());
            }
            Ok(Some(UploadFilesPage { header, files }))
        })
    }

    pub fn write_upload_timeline(
        &self,
        tenant: &str,
        link: &str,
        upload: &str,
        output: impl Write,
    ) -> Result<bool, String> {
        let connection = self.connection.lock().expect("store poisoned");
        let Some(link_record) = read_link_metadata(&connection, tenant, link)? else {
            return Ok(false);
        };
        let Some(header) =
            read_header(&connection, tenant, link, upload).map_err(|e| e.to_string())?
        else {
            return Ok(false);
        };
        let record = &header.upload;
        let duration = (record.started_at > 0 && record.completed_at > record.started_at)
            .then(|| record.completed_at - record.started_at);
        let average = duration.map(|seconds| (record.total_bytes as f64 / seconds as f64).round());
        let mut peak: Option<f64> = None;
        let (mut pauses, mut restarts) = (0_u64, 0_u64);
        for event in &record.log {
            if event.kind == "published" {
                if let (Some(bytes), Some(seconds)) = (
                    event.bytes.filter(|bytes| *bytes > 0),
                    event.secs.filter(|seconds| *seconds > 0),
                ) {
                    let rate = bytes as f64 / seconds as f64;
                    peak = Some(peak.map_or(rate, |previous| previous.max(rate)));
                }
            }
            if event.kind == "quiet" {
                pauses = pauses.saturating_add(event.secs.unwrap_or(0));
            }
            if event.kind == "reattached" {
                restarts = restarts.saturating_add(1);
            }
        }
        let outcome = record
            .log
            .iter()
            .map(|event| event.kind.as_str())
            .find(|kind| matches!(*kind, "finished" | "cancelled" | "interrupted" | "dropped"))
            .unwrap_or(if record.partial {
                "partial"
            } else {
                "finished"
            });
        let transport = record.transport.as_deref().unwrap_or("http");
        let summary = serde_json::json!({
            "files": header.file_count, "bytes": record.total_bytes, "duration": duration,
            "average": average, "peak": peak.map(f64::round), "pauses": pauses,
            "restarts": restarts, "resent": record.replayed_chunks, "rejected": record.rejected_chunks,
            "outcome": outcome, "transport": transport,
        });
        let document = Timeline {
            request: serde_json::json!({"id":link_record.id,"label":link_record.label,"dest":link_record.dest}),
            upload: TimelineUpload {
                id: &record.id,
                started_at: record.started_at,
                completed_at: record.completed_at,
                transport,
                package_root: &record.package_root,
                total_bytes: record.total_bytes,
                partial: record.partial,
                replayed_chunks: record.replayed_chunks,
                rejected_chunks: record.rejected_chunks,
                files: TimelineFiles {
                    connection: &connection,
                    tenant,
                    link,
                    upload,
                    count: header.file_count,
                },
            },
            summary,
            events: &record.log,
        };
        // ponytail: one export holds the Store lock while spooling metadata; a dedicated read snapshot is the upgrade for very large histories.
        serde_json::to_writer(output, &document).map_err(|error| error.to_string())?;
        Ok(true)
    }
}

#[derive(Serialize)]
struct Timeline<'a> {
    request: serde_json::Value,
    upload: TimelineUpload<'a>,
    summary: serde_json::Value,
    events: &'a [LogEvent],
}

#[derive(Serialize)]
struct TimelineUpload<'a> {
    id: &'a str,
    started_at: u64,
    completed_at: u64,
    transport: &'a str,
    package_root: &'a str,
    total_bytes: u64,
    partial: bool,
    replayed_chunks: u64,
    rejected_chunks: u64,
    files: TimelineFiles<'a>,
}

struct TimelineFiles<'a> {
    connection: &'a Connection,
    tenant: &'a str,
    link: &'a str,
    upload: &'a str,
    count: usize,
}

impl Serialize for TimelineFiles<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as _;
        let mut statement = self
            .connection
            .prepare_cached(
                "SELECT file_index,path,stored_as,bytes_hi,bytes_lo,suite,root,receipt,deleted
             FROM files WHERE tenant=?1 AND link_id=?2 AND upload_id=?3 ORDER BY file_index",
            )
            .map_err(S::Error::custom)?;
        let mut rows = statement
            .query([self.tenant, self.link, self.upload])
            .map_err(S::Error::custom)?;
        let mut sequence = serializer.serialize_seq(Some(self.count))?;
        let mut count = 0;
        while let Some(row) = rows.next().map_err(S::Error::custom)? {
            let index: i64 = row.get(0).map_err(S::Error::custom)?;
            if index != i64::try_from(count).map_err(S::Error::custom)? || count >= self.count {
                return Err(S::Error::custom(invalid_upload()));
            }
            let file = row_to_upload_file(row).map_err(S::Error::custom)?;
            sequence.serialize_element(&serde_json::json!({
                "path":file.path,"bytes":file.bytes,"suite":file.suite,"root":file.root,"receipt":file.receipt,
            }))?;
            count += 1;
        }
        if count != self.count {
            return Err(S::Error::custom(invalid_upload()));
        }
        sequence.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::tests::{test_link, test_tenant};

    fn upload(id: &str, count: usize) -> UploadRecord {
        serde_json::from_value(serde_json::json!({
            "id":id, "started_at":10, "completed_at":20, "total_bytes":count,
            "package_root":"package", "files":(0..count).map(|index| serde_json::json!({
                "path":format!("file-{index}"), "stored_as":format!("file-{index}"),
                "bytes":1,"suite":"blake3","root":"aa","receipt":true,"deleted":index == 1,
            })).collect::<Vec<_>>(),
        }))
        .unwrap()
    }

    #[test]
    fn received_pages_seek_interleaved_history_and_keep_file_indices() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.insert_tenant(test_tenant("other")).unwrap();
        store.insert_link(test_link("request")).unwrap();
        store.insert_link(test_link("interleaved")).unwrap();
        for index in 0..5 {
            store
                .append_upload("", "request", upload(&format!("upload-{index}"), 3))
                .unwrap();
            store
                .append_upload("", "interleaved", upload(&format!("other-{index}"), 0))
                .unwrap();
        }
        let first = store
            .upload_headers_page("", "request", None, 2)
            .unwrap()
            .unwrap();
        assert_eq!(
            first
                .uploads
                .iter()
                .map(|row| row.upload.id.as_str())
                .collect::<Vec<_>>(),
            ["upload-4", "upload-3"]
        );
        assert!(first
            .uploads
            .iter()
            .all(|row| row.upload.files.is_empty() && row.file_count == 3));
        store
            .append_upload("", "request", upload("new", 0))
            .unwrap();
        let second = store
            .upload_headers_page("", "request", first.next_position, 2)
            .unwrap()
            .unwrap();
        assert_eq!(
            second
                .uploads
                .iter()
                .map(|row| row.upload.id.as_str())
                .collect::<Vec<_>>(),
            ["upload-2", "upload-1"]
        );
        let last = store
            .upload_headers_page("", "request", second.next_position, 2)
            .unwrap()
            .unwrap();
        assert_eq!(last.uploads[0].upload.id, "upload-0");
        assert!(last.next_position.is_none());
        assert!(store
            .upload_headers_page("other", "request", None, 2)
            .unwrap()
            .is_none());
        assert!(store
            .upload_header("", "interleaved", "upload-0")
            .unwrap()
            .is_none());
        assert!(store
            .upload_files_page("other", "request", "upload-0", 0, 2)
            .unwrap()
            .is_none());
        let UploadFilesPage { files, .. } = store
            .upload_files_page("", "request", "upload-0", 1, 2)
            .unwrap()
            .unwrap();
        assert_eq!(
            files.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
            [1, 2]
        );
        assert!(files[0].1.deleted);
        assert_eq!(
            store.link_upload_totals("", &["request".into()]).unwrap()["request"],
            (6, 15)
        );
        let page = store
            .links_page("", 1, None, "request", "all", 100, false)
            .unwrap();
        assert!(page.links[0].uploads.is_empty());
        drop(store);
        let reopened = Store::open(directory.path()).unwrap();
        assert_eq!(
            reopened
                .upload_headers_page("", "request", first.next_position, 2)
                .unwrap()
                .unwrap()
                .uploads[0]
                .upload
                .id,
            "upload-2"
        );
    }

    #[test]
    fn received_export_validates_complete_files_without_affecting_bounded_reads() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut link = test_link("request");
        link.uploads.push(upload("upload", 3));
        store.insert_link(link).unwrap();
        for sql in [
            "DELETE FROM files WHERE file_index=2",
            "UPDATE link_uploads SET file_count=4",
            "UPDATE files SET root=x'01' WHERE file_index=2",
            "UPDATE link_uploads SET document=json_set(document,'$.files',json('[{}]'))",
        ] {
            let connection = store.connection.lock().unwrap();
            connection.execute_batch("SAVEPOINT corruption").unwrap();
            connection.execute_batch(sql).unwrap();
            drop(connection);
            if !sql.contains("$.files") {
                assert_eq!(
                    store
                        .upload_files_page("", "request", "upload", 0, 2)
                        .unwrap()
                        .unwrap()
                        .files
                        .len(),
                    2
                );
            }
            let mut incomplete = Vec::new();
            assert!(
                store
                    .write_upload_timeline("", "request", "upload", &mut incomplete)
                    .is_err(),
                "{sql}"
            );
            assert!(serde_json::from_slice::<serde_json::Value>(&incomplete).is_err());
            store
                .connection
                .lock()
                .unwrap()
                .execute_batch("ROLLBACK TO corruption; RELEASE corruption")
                .unwrap();
        }
        let mut complete = Vec::new();
        assert!(store
            .write_upload_timeline("", "request", "upload", &mut complete)
            .unwrap());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&complete).unwrap()["upload"]["files"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
        assert!(!store
            .write_upload_timeline("other", "request", "upload", std::io::sink())
            .unwrap());
        assert!(!store
            .write_upload_timeline("", "request", "missing", std::io::sink())
            .unwrap());
        struct Fails;
        impl Write for Fails {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("fixture disk failure"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        assert!(store
            .write_upload_timeline("", "request", "upload", Fails)
            .unwrap_err()
            .contains("fixture disk failure"));
        assert!(store.connection.try_lock().is_ok());
    }

    #[test]
    fn received_totals_preserve_unsigned_bytes_and_route_filter_precedes_limit() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        for index in 0..5 {
            let mut link = test_link(&format!("link-{index}"));
            link.created_at = index;
            if index > 0 {
                link.password_hash = Some("password".into());
            }
            store.insert_link(link).unwrap();
        }
        let page = store.links_page("", 1, None, "", "all", 100, true).unwrap();
        assert_eq!(page.links[0].id, "link-0");
        assert!(page.next_cursor.is_none());
        let mut record = upload("unsigned", 0);
        record.total_bytes = u64::MAX;
        store.append_upload("", "link-0", record).unwrap();
        assert_eq!(
            store.link_upload_totals("", &["link-0".into()]).unwrap()["link-0"],
            (1, u64::MAX)
        );
        assert!(store
            .links_page("", 1, None, "", "all", 100, true)
            .unwrap()
            .links
            .is_empty());
    }
}
