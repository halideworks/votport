//! Explicit conversion of a stopped, disposable schema35 data copy.

use super::*;
use crate::{auth, receipt::ReceiptSigner, workflow::Job};
use ed25519_dalek::Signer as _;
use rusqlite::{params, types::ValueRef};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{BufRead as _, BufReader, Read as _, Seek as _, Write as _};

const SOURCE_SCHEMA: &str = include_str!("schema35.sql");
const ARTIFACT: &str = "schema35-conversion.jsonl";
const META_KEY: &str = "schema35_conversion";
// ponytail: one source JSON document is decoded at a time; larger histories need a streaming source decoder.
const MAX_SOURCE_JSON: usize = 64 * 1024 * 1024;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Conversion {
    id: String,
    source: u64,
    target: u64,
    public_url: String,
    issuer: String,
    created_at: u64,
    bytes: u64,
    sha256: String,
    replacements: u64,
}

pub fn command(arguments: Vec<String>) -> std::result::Result<(), String> {
    const HELP: &str = "Usage: votport convert-schema35 --data-copy /absolute/private/disposable-copy --public-url https://drop.example.com\n\nConverts only a stopped schema35 copy. Requires existing secret and receipt.key, no retained admissions, and matching upload projections. Never use the production directory. On any error, discard this copy and recreate it from the retained cold backup. Already-converted copies are refused. Does not copy payloads or start services. Review the private schema35-conversion.jsonl before distributing replacement workflow links.";
    if arguments == ["--help"] {
        println!("{HELP}");
        return Ok(());
    }
    let mut data = None;
    let mut origin = None;
    let mut args = arguments.iter();
    while let Some(argument) = args.next() {
        let slot = match argument.as_str() {
            "--data-copy" => &mut data,
            "--public-url" => &mut origin,
            _ => return Err(HELP.into()),
        };
        if slot.is_some() {
            return Err(HELP.into());
        }
        *slot = Some(args.next().ok_or(HELP)?);
    }
    let result = convert(Path::new(data.ok_or(HELP)?), origin.ok_or(HELP)?)
        .map_err(|error| format!("conversion refused: {error}"))?;
    println!(
        "Converted schema35 copy to schema{}; {} workflow links rotated. Review {}.",
        result.target,
        result.replacements,
        Path::new(data.unwrap()).join(ARTIFACT).display()
    );
    Ok(())
}

fn existing_private(path: &Path, required: bool) -> Result<bool> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if !required && error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(false)
        }
        Err(error) => return Err(error.into()),
    };
    use std::os::unix::fs::MetadataExt as _;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(format!("{} must be a regular file with one link", path.display()).into());
    }
    crate::paths::tighten_private_file(path)?;
    Ok(true)
}

fn existing_seed(path: &Path) -> Result<[u8; 32]> {
    existing_private(path, true)?;
    let mut file = File::open(path)?;
    if file.metadata()?.len() != 32 {
        return Err(format!("{} must contain exactly 32 bytes", path.display()).into());
    }
    let mut seed = [0; 32];
    file.read_exact(&mut seed)?;
    Ok(seed)
}

fn convert(data: &Path, public_url: &str) -> Result<Conversion> {
    crate::config::validate_public_url(public_url)?;
    let origin = reqwest::Url::parse(public_url)?
        .origin()
        .ascii_serialization();
    if !data.is_absolute() || std::fs::canonicalize(data)? != data {
        return Err(
            "--data-copy must name an absolute, canonical directory without symlinks".into(),
        );
    }
    crate::paths::tighten_private_dir(data)?;
    existing_private(&data.join("lock"), false)?;
    let _lock = crate::app::lock_data_dir(data)?;
    for marker in [
        crate::backup::PENDING_FILE,
        crate::standby::STATUS_FILE,
        "state.json",
    ] {
        match std::fs::symlink_metadata(data.join(marker)) {
            Ok(_) => {
                return Err(format!("resolve {marker} before making a new conversion copy").into())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    let seed = existing_seed(&data.join("receipt.key"))?;
    let _secret = existing_seed(&data.join("secret"))?;
    let signer = ReceiptSigner::from_seed(seed);
    existing_private(&data.join("votport.db"), true)?;
    for name in [
        "votport.db-wal",
        "votport.db-shm",
        "votport.db-journal",
        ARTIFACT,
    ] {
        existing_private(&data.join(name), false)?;
    }
    // No descriptor-based permission helpers may run after SQLite opens its database or journals.
    let mut connection = Connection::open_with_flags(
        data.join("votport.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
    )?;
    connection.set_db_config(
        rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
        true,
    )?;
    connection.execute_batch("PRAGMA synchronous=FULL; PRAGMA foreign_keys=OFF;")?;
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Exclusive)?;
    validate_schema(&transaction, 35)?;
    if data.join(ARTIFACT).try_exists()? {
        return Err("a prepared artifact exists without a committed conversion; preserve it and use a fresh disposable copy".into());
    }
    let source = Connection::open_in_memory()?;
    source.execute_batch(SOURCE_SCHEMA)?;
    check_schema(&transaction, &source)?;
    integrity(&transaction)?;
    let pending: bool = transaction.query_row("SELECT EXISTS(SELECT 1 FROM upload_sessions) OR EXISTS(SELECT 1 FROM upload_session_files)", [], |row| row.get(0))?;
    if pending {
        return Err("schema35 retained admissions have no reliable completion identity; finish or remove them using the source release before making a new copy".into());
    }
    verify_events(&transaction, &signer)?;
    let mut target = Connection::open_in_memory()?;
    initialize_schema(&mut target)?;
    validate_schema(&target, SCHEMA_VERSION)?;
    let mut result = Conversion {
        id: auth::random_token(),
        source: 35,
        target: SCHEMA_VERSION,
        public_url: origin,
        issuer: signer.public_hex.clone(),
        created_at: now_unix(),
        bytes: 0,
        sha256: String::new(),
        replacements: 0,
    };
    transaction.execute_batch(
        "ALTER TABLE upload_sessions ADD COLUMN committed_upload_id TEXT;
             ALTER TABLE outbound_grants ADD COLUMN share_token TEXT;",
    )?;
    transaction.execute_batch(OUTBOUND_INDEXES)?;
    transaction.execute_batch(AUDIT_INDEXES)?;
    transaction.execute_batch(AUDIT_COUNT_SCHEMA)?;
    rebuild(
        &transaction,
        &target,
        "tenants",
        &[("incarnation", "''"), ("retention_days", "''")],
        |connection| {
            let mut rows = connection.prepare("SELECT key FROM tenants ORDER BY key")?;
            for key in rows.query_map([], |row| row.get::<_, String>(0))? {
                connection.execute(
                    "UPDATE conversion_tenants SET incarnation=?2 WHERE key=?1",
                    params![key?, auth::random_token()],
                )?;
            }
            // Finding 378: the source predates scoped retention; every
            // converted tenant defers to the platform setting.
            connection.execute("UPDATE conversion_tenants SET retention_days=NULL", [])?;
            Ok(())
        },
    )?;
    normalize_uploads(&transaction, &target)?;
    install_quota_schema(&transaction)?;
    result.replacements = convert_jobs(&transaction, &target, &signer, seed, result.created_at)?;
    transaction.execute(
        "UPDATE meta SET value=?1 WHERE key='schema_version'",
        [SCHEMA_VERSION.to_string()],
    )?;
    check_schema(&transaction, &target)?;
    integrity(&transaction)?;
    verify_events(&transaction, &signer)?;
    let artifact = data.join(ARTIFACT);
    let mut file = private_new(&artifact)?;
    serde_json::to_writer(
        &mut file,
        &serde_json::json!({"state":"prepared","id":result.id,"source":35,"target":SCHEMA_VERSION,"public_url":result.public_url,"issuer":result.issuer,"created_at":result.created_at,"replacements":result.replacements}),
    )?;
    file.write_all(b"\n")?;
    write_replacements(&transaction, &result, &mut file)?;
    file.sync_all()?;
    File::open(data)?.sync_all()?;
    result.bytes = file.stream_position()?;
    result.sha256 = hash_prefix(&mut file, result.bytes)?;
    transaction.execute(
        "INSERT INTO meta(key,value) VALUES (?1,?2)",
        params![META_KEY, serde_json::to_string(&result)?],
    )?;
    transaction.commit()?;
    finish_artifact(data, &connection, &result)?;
    Ok(result)
}

fn private_new(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

fn integrity(connection: &Connection) -> Result<()> {
    let check: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if check != "ok" {
        return Err(format!("SQLite integrity check failed: {check}").into());
    }
    if connection
        .prepare("PRAGMA foreign_key_check")?
        .query([])?
        .next()?
        .is_some()
    {
        return Err("SQLite foreign key check failed".into());
    }
    Ok(())
}

// Clause comparison permits historical column order, but refuses unknown constraints and schema objects.
fn schema(connection: &Connection) -> Result<BTreeMap<(String, String), Vec<String>>> {
    let mut statement = connection.prepare("SELECT type,name,sql,tbl_name FROM sqlite_schema WHERE sql IS NOT NULL AND name NOT GLOB 'sqlite_*' ORDER BY type,name")?;
    let mut result = BTreeMap::new();
    for row in statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })? {
        let (kind, name, sql, table) = row?;
        if kind == "trigger" {
            result.insert((kind, name), vec![super::normalize_schema_sql(&sql)]);
            continue;
        }
        if kind != "table" && kind != "index" {
            return Err(format!("unsupported schema object {name}").into());
        }
        let body = &sql[sql.find('(').ok_or("invalid schema definition")?..];
        let mut clauses = Vec::new();
        let (mut depth, mut quote) = (0, None);
        let mut clause = String::new();
        for character in body.chars() {
            if let Some(delimiter) = quote {
                clause.push(character);
                if character == delimiter {
                    quote = None;
                }
                continue;
            }
            match character {
                '\'' | '"' | '`' => {
                    quote = Some(character);
                    clause.push(character);
                }
                '(' => {
                    depth += 1;
                    if depth > 1 {
                        clause.push(character);
                    }
                }
                ')' => {
                    depth -= 1;
                    if depth > 0 {
                        clause.push(character);
                    }
                }
                ',' if depth == 1 && kind == "table" => {
                    clauses.push(std::mem::take(&mut clause));
                }
                c if !c.is_ascii_whitespace() => clause.push(c.to_ascii_lowercase()),
                _ => {}
            }
        }
        clauses.push(clause);
        if kind == "table" {
            clauses.sort();
            // Declared types can contain whitespace that changes SQLite affinity.
            let mut columns = connection.prepare(r#"SELECT name,type,"notnull",dflt_value,pk,hidden FROM pragma_table_xinfo(?1) ORDER BY name"#)?;
            let columns = columns
                .query_map([&name], |row| {
                    Ok(format!(
                        "{:?}",
                        (
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, bool>(2)?,
                            row.get::<_, Option<String>>(3)?,
                            row.get::<_, i64>(4)?,
                            row.get::<_, i64>(5)?,
                        )
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            result.insert(("columns".to_owned(), name.clone()), columns);
        }
        if kind == "index" {
            clauses.push(format!(
                "table={table};unique={}",
                sql.split_whitespace()
                    .any(|word| word.eq_ignore_ascii_case("unique"))
            ));
        }
        result.insert((kind, name), clauses);
    }
    Ok(result)
}

fn check_schema(connection: &Connection, reference: &Connection) -> Result<()> {
    let actual = schema(connection)?;
    let expected = schema(reference)?;
    if actual != expected {
        let mismatch = actual
            .keys()
            .chain(expected.keys())
            .find(|key| actual.get(*key) != expected.get(*key))
            .ok_or("schema mismatch")?;
        if mismatch.0 == "trigger" {
            return Err(format!("unsupported schema object {}", mismatch.1).into());
        }
        return Err(format!(
            "unsupported schema35/target definition for {} {}",
            mismatch.0, mismatch.1
        )
        .into());
    }
    Ok(())
}

fn target_table(
    connection: &Connection,
    target: &Connection,
    table: &str,
    temporary: bool,
) -> Result<()> {
    let sql: String = target.query_row(
        "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1",
        [table],
        |row| row.get(0),
    )?;
    let body = &sql[sql.find('(').ok_or("invalid target schema")?..];
    let name = if temporary {
        format!("conversion_{table}")
    } else {
        table.into()
    };
    connection.execute_batch(&format!("CREATE TABLE {name} {body}"))?;
    Ok(())
}

fn target_indexes(connection: &Connection, target: &Connection, table: &str) -> Result<()> {
    let mut statement = target.prepare(
        "SELECT sql FROM sqlite_schema WHERE type='index' AND tbl_name=?1 AND sql IS NOT NULL",
    )?;
    for sql in statement.query_map([table], |row| row.get::<_, String>(0))? {
        connection.execute_batch(&sql?)?;
    }
    Ok(())
}

fn rebuild(
    connection: &Connection,
    target: &Connection,
    table: &str,
    // Columns the source may predate, with the select expression that
    // satisfies the target column while `fill` runs its backfill.
    backfill: &[(&str, &str)],
    fill: impl FnOnce(&Connection) -> Result<()>,
) -> Result<()> {
    target_table(connection, target, table, true)?;
    let mut statement = target.prepare("SELECT name FROM pragma_table_info(?1) ORDER BY cid")?;
    let columns = statement
        .query_map([table], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let select = columns
        .iter()
        .map(|name| {
            backfill
                .iter()
                .find(|(column, _)| column == &name.as_str())
                .map_or_else(|| name.clone(), |(_, expression)| (*expression).to_owned())
        })
        .collect::<Vec<_>>()
        .join(",");
    connection.execute_batch(&format!(
        "INSERT INTO conversion_{table}(rowid,{}) SELECT rowid,{select} FROM {table}",
        columns.join(",")
    ))?;
    fill(connection)?;
    connection.execute_batch(&format!(
        "DROP TABLE {table}; ALTER TABLE conversion_{table} RENAME TO {table};"
    ))?;
    target_indexes(connection, target, table)
}

fn bounded_json<'a>(row: &'a rusqlite::Row<'_>, column: usize) -> rusqlite::Result<&'a str> {
    match row.get_ref(column)? {
        ValueRef::Text(bytes) if bytes.len() <= MAX_SOURCE_JSON => std::str::from_utf8(bytes).map_err(|error| rusqlite::Error::FromSqlConversionFailure(column, rusqlite::types::Type::Text, Box::new(error))),
        _ => Err(rusqlite::Error::FromSqlConversionFailure(column, rusqlite::types::Type::Text, "source JSON must be text and at most 64 MiB; use a separately reviewed streaming conversion for larger histories".into())),
    }
}

fn check_upload_fields(value: &serde_json::Value) -> Result<()> {
    fn fields(value: &serde_json::Value, allowed: &[&str]) -> Result<()> {
        let object = value
            .as_object()
            .ok_or("source upload record must be an object")?;
        if object.keys().any(|key| !allowed.contains(&key.as_str())) {
            return Err("source upload contains fields outside the schema35 contract".into());
        }
        Ok(())
    }
    for upload in value.as_array().ok_or("source uploads must be an array")? {
        fields(
            upload,
            &[
                "id",
                "started_at",
                "completed_at",
                "replayed_chunks",
                "rejected_chunks",
                "transport",
                "package_root",
                "total_bytes",
                "files",
                "partial",
                "log",
            ],
        )?;
        for file in upload["files"]
            .as_array()
            .ok_or("source files must be an array")?
        {
            fields(
                file,
                &[
                    "path",
                    "stored_as",
                    "bytes",
                    "suite",
                    "root",
                    "receipt",
                    "deleted",
                ],
            )?;
        }
        if let Some(log) = upload.get("log") {
            for event in log
                .as_array()
                .ok_or("source transfer log must be an array")?
            {
                fields(event, &["at", "kind", "path", "bytes", "secs", "count"])?;
            }
        }
    }
    Ok(())
}

fn normalize_uploads(connection: &Connection, target: &Connection) -> Result<()> {
    target_table(connection, target, "files", true)?;
    target_table(connection, target, "link_uploads", false)?;
    let mut statement =
        connection.prepare("SELECT id,tenant,uploads_json FROM links ORDER BY rowid")?;
    let mut rows = statement.query([])?;
    let mut total = 0_u64;
    while let Some(row) = rows.next()? {
        let link: String = row.get(0)?;
        let tenant: String = row.get(1)?;
        let source: serde_json::Value = serde_json::from_str(bounded_json(row, 2)?)?;
        check_upload_fields(&source)?;
        let uploads: Vec<UploadRecord> = serde_json::from_value(source)?;
        let mut ids = BTreeSet::new();
        for (upload_index, upload) in uploads.iter().enumerate() {
            if upload.id.is_empty() || !ids.insert(&upload.id) {
                return Err("missing or duplicate source upload ID".into());
            }
            let expected: i64 = connection.query_row(
                "SELECT count(*) FROM files WHERE link_id=?1 AND upload_index=?2",
                params![link, upload_index as i64],
                |row| row.get(0),
            )?;
            if expected != upload.files.len() as i64 {
                return Err("source positional file count disagrees with uploads_json".into());
            }
            for (index, file) in upload.files.iter().enumerate() {
                let (hi, lo) = split_bytes(file.bytes);
                let matches: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM files WHERE link_id=?1 AND upload_index=?2 AND file_index=?3 AND tenant=?4 AND bytes_hi=?5 AND bytes_lo=?6 AND deleted=?7 AND stored_as=?8)", params![link,upload_index as i64,index as i64,tenant,hi,lo,file.deleted,file.stored_as], |row| row.get(0))?;
                if !matches {
                    return Err(
                        "source positional file identity disagrees with uploads_json".into(),
                    );
                }
                connection.execute("INSERT INTO conversion_files(link_id,tenant,upload_id,file_index,bytes_hi,bytes_lo,deleted,stored_as,path,suite,root,receipt) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)", params![link,tenant,upload.id,index as i64,hi,lo,file.deleted,file.stored_as,file.path,file.suite,file.root,file.receipt])?;
                total += 1;
            }
            connection.execute("INSERT INTO link_uploads(link_id,tenant,upload_id,document,file_count) VALUES (?1,?2,?3,?4,?5)", params![link,tenant,upload.id,upload_header_json(upload)?,upload.files.len() as i64])?;
        }
    }
    let expected: i64 = connection.query_row("SELECT count(*) FROM files", [], |row| row.get(0))?;
    if expected != i64::try_from(total)? {
        return Err("source file projection contains orphan rows".into());
    }
    drop(rows);
    drop(statement);
    connection.execute_batch("DROP TABLE files; ALTER TABLE conversion_files RENAME TO files;")?;
    target_indexes(connection, target, "files")?;
    target_indexes(connection, target, "link_uploads")?;
    // Finding 378: the source predates scoped link retention; converted
    // links defer to tenant and platform windows.
    // Finding 24: the source may predate link verification levels; converted
    // links keep the mount-based choice, which the CHECK accepts.
    rebuild(
        connection,
        target,
        "links",
        &[("retention_days", "''"), ("verification", "'default'")],
        |connection| {
            connection.execute("UPDATE conversion_links SET retention_days=NULL", [])?;
            Ok(())
        },
    )?;
    // Schema 35 tokens predate creator tracking; the column stays ''.
    rebuild(
        connection,
        target,
        "automation_tokens",
        &[("created_by", "''")],
        |_| Ok(()),
    )
}

fn convert_jobs(
    connection: &Connection,
    target: &Connection,
    signer: &ReceiptSigner,
    seed: [u8; 32],
    now: u64,
) -> Result<u64> {
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let mut count = 0;
    rebuild(
        connection,
        target,
        "delivery_jobs",
        &[
            ("token", "''"),
            ("created_at", "''"),
            ("snapshot_bytes", "''"),
        ],
        |connection| {
            let mut statement = connection.prepare("SELECT id,tenant,actor,operation_id,project_id,state,document FROM delivery_jobs ORDER BY rowid")?;
            let mut rows = statement.query([])?;
            while let Some(row) = rows.next()? {
                let mut document: serde_json::Value = serde_json::from_str(bounded_json(row, 6)?)?;
                let mut job: Job = serde_json::from_value(document.clone())?;
                if job.id != row.get::<_, String>(0)?
                    || job.tenant != row.get::<_, String>(1)?
                    || job.actor != row.get::<_, String>(2)?
                    || job.request.operation_id != row.get::<_, String>(3)?
                    || job.project.id != row.get::<_, String>(4)?
                    || job.state != row.get::<_, String>(5)?
                {
                    return Err("workflow document disagrees with indexed authority".into());
                }
                let raw = auth::random_token();
                let grant: Option<(String, String)> = connection
                    .query_row(
                        "SELECT tenant,token_hash FROM outbound_grants WHERE id=?1",
                        [&job.id],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?;
                if let Some((tenant, old_hash)) = grant {
                    let message =
                        format!("votport-job-token-v1\0{}:{}", job.id, job.token_generation);
                    let old = hex::encode(Sha256::digest(key.sign(message.as_bytes()).to_bytes()))
                        [..32]
                        .to_owned();
                    if tenant != job.tenant || old_hash != auth::hash_token(&old) {
                        return Err(
                            "workflow grant does not match the source signing key and generation"
                                .into(),
                        );
                    }
                    job.token_generation = job
                        .token_generation
                        .checked_add(1)
                        .ok_or("workflow token generation overflow")?;
                    document["token_generation"] = job.token_generation.into();
                    document["updated_at"] = now.into();
                    connection.execute(
                        "UPDATE outbound_grants SET token_hash=?2 WHERE id=?1",
                        params![job.id, auth::hash_token(&raw)],
                    )?;
                    connection.execute(
                        "DELETE FROM outbound_fetch_tickets WHERE grant_id=?1 AND delivered_at IS NULL",
                        [&job.id],
                    )?;
                    evidence::delivery_event(
                        connection,
                        signer,
                        &job.tenant,
                        &job.id,
                        "delivery_link_rotated",
                        &serde_json::json!({"generation":job.token_generation,"reason":"offline_schema35_conversion"}),
                        now,
                    )?;
                    count += 1;
                }
                connection.execute(
                    "UPDATE conversion_delivery_jobs SET token=?2,document=?3 WHERE id=?1",
                    params![job.id, raw, serde_json::to_string(&document)?],
                )?;
            }
            connection.execute_batch(
                "UPDATE conversion_delivery_jobs
                 SET created_at=COALESCE(CAST(json_extract(document,'$.created_at') AS INTEGER),0),
                     snapshot_bytes=COALESCE(CAST(json_extract(document,'$.checks.snapshot_bytes') AS INTEGER),0);",
            )?;
            Ok(())
        },
    )?;
    Ok(count)
}

fn verify_events(connection: &Connection, signer: &ReceiptSigner) -> Result<()> {
    let mut statement = connection.prepare(&format!(
        "SELECT {} FROM delivery_events ORDER BY tenant,id",
        evidence::EVENT_COLUMNS
    ))?;
    let mut previous = (String::new(), String::new());
    for event in statement.query_map([], evidence::event_row)? {
        let event = event?;
        let predecessor = if event.tenant == previous.0 {
            previous.1.as_str()
        } else {
            ""
        };
        if event.id == 0
            || event.issuer != signer.public_hex
            || event.previous_hash != predecessor
            || !event.verify()
        {
            return Err("delivery event chain or signing identity is invalid".into());
        }
        previous = (event.tenant, event.hash);
    }
    Ok(())
}

fn write_replacements(
    connection: &Connection,
    result: &Conversion,
    output: &mut File,
) -> Result<()> {
    let mut statement = connection.prepare("SELECT j.id,j.tenant,j.token,j.document,g.token_hash,g.revoked_at,g.expires_at FROM delivery_jobs j JOIN outbound_grants g ON g.id=j.id ORDER BY j.id")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let job: Job = serde_json::from_str(bounded_json(row, 3)?)?;
        let token: String = row.get(2)?;
        let hash: String = row.get(4)?;
        if auth::hash_token(&token) != hash {
            return Err("converted workflow token does not match its grant".into());
        }
        let released = job.released() && workflows::release_in(connection, &job.id).is_ok();
        let active = released
            && row.get::<_, Option<i64>>(5)?.is_none()
            && row.get::<_, i64>(6)? > result.created_at as i64;
        let url = active.then(|| format!("{}/s/{token}", result.public_url));
        serde_json::to_writer(
            &mut *output,
            &serde_json::json!({"job_id":job.id,"tenant":job.tenant,"label":job.request.label,"state":job.state,"generation":job.token_generation,"token_hash":hash,"url":url}),
        )?;
        output.write_all(b"\n")?;
    }
    Ok(())
}

fn hash_prefix(file: &mut File, length: u64) -> Result<String> {
    file.rewind()?;
    let mut remaining = length;
    let mut buffer = [0; 64 * 1024];
    let mut hash = Sha256::new();
    while remaining > 0 {
        let limit = usize::try_from(remaining.min(buffer.len() as u64))?;
        let read = file.read(&mut buffer[..limit])?;
        if read == 0 {
            return Err("conversion artifact is truncated".into());
        }
        hash.update(&buffer[..read]);
        remaining -= read as u64;
    }
    Ok(hex::encode(hash.finalize()))
}

fn finish_artifact(data: &Path, connection: &Connection, result: &Conversion) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(data.join(ARTIFACT))?;
    if hash_prefix(&mut file, result.bytes)? != result.sha256 {
        return Err("conversion artifact does not match the committed database".into());
    }
    file.rewind()?;
    let mut reader = BufReader::new((&mut file).take(result.bytes));
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let mut count = 0;
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let record: serde_json::Value = serde_json::from_str(&line)?;
        let id = record["job_id"].as_str().ok_or("invalid replacement job")?;
        let (tenant,token,document,hash): (String,String,String,String) = connection.query_row("SELECT j.tenant,j.token,j.document,g.token_hash FROM delivery_jobs j JOIN outbound_grants g ON g.id=j.id WHERE j.id=?1",[id],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)))?;
        let job: Job = serde_json::from_str(&document)?;
        if record["tenant"] != tenant
            || record["generation"] != job.token_generation
            || record["token_hash"] != hash
            || hash != auth::hash_token(&token)
            || record["url"]
                .as_str()
                .is_some_and(|url| url != format!("{}/s/{token}", result.public_url))
        {
            return Err("replacement artifact disagrees with current workflow authority".into());
        }
        count += 1;
    }
    if count != result.replacements {
        return Err("conversion artifact replacement count is wrong".into());
    }
    file.set_len(result.bytes)?;
    file.seek(std::io::SeekFrom::Start(result.bytes))?;
    serde_json::to_writer(
        &mut file,
        &serde_json::json!({"state":"committed","id":result.id,"sha256":result.sha256,"bytes":result.bytes}),
    )?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    File::open(data)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workflow::tests::{project, request};

    fn fixture() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        auth::write_private(&directory.path().join("receipt.key"), &[19; 32]).unwrap();
        auth::write_private(&directory.path().join("secret"), &[23; 32]).unwrap();
        crate::paths::create_private_file(&directory.path().join("votport.db")).unwrap();
        let connection = Connection::open(directory.path().join("votport.db")).unwrap();
        connection.execute_batch(SOURCE_SCHEMA).unwrap();
        directory
    }

    #[test]
    fn conversion_requires_existing_private_keys_and_an_unlocked_copy() {
        for name in ["receipt.key", "secret"] {
            for invalid in ["missing", "short", "symlink", "hardlink"] {
                let directory = fixture();
                let path = directory.path().join(name);
                let retained = directory.path().join("retained-key");
                std::fs::rename(&path, &retained).unwrap();
                match invalid {
                    "missing" => {}
                    "short" => std::fs::write(&path, [0; 31]).unwrap(),
                    "symlink" => std::os::unix::fs::symlink(&retained, &path).unwrap(),
                    "hardlink" => std::fs::hard_link(&retained, &path).unwrap(),
                    _ => unreachable!(),
                }
                let database = directory.path().join("votport.db");
                let before = std::fs::read(&database).unwrap();
                assert!(
                    convert(directory.path(), "https://drop.example.com").is_err(),
                    "{name}/{invalid}"
                );
                assert_eq!(std::fs::read(database).unwrap(), before);
                assert!(!directory.path().join(ARTIFACT).exists());
                assert_eq!(
                    std::fs::read(retained).unwrap(),
                    if name == "receipt.key" {
                        [19; 32]
                    } else {
                        [23; 32]
                    }
                );
            }
        }
        for marker in [
            crate::backup::PENDING_FILE,
            crate::standby::STATUS_FILE,
            "state.json",
        ] {
            let directory = fixture();
            std::os::unix::fs::symlink("missing", directory.path().join(marker)).unwrap();
            assert!(convert(directory.path(), "https://drop.example.com")
                .unwrap_err()
                .to_string()
                .contains("resolve"));
            let connection = Connection::open(directory.path().join("votport.db")).unwrap();
            validate_schema(&connection, 35).unwrap();
        }
        let directory = fixture();
        let lock = crate::app::lock_data_dir(directory.path()).unwrap();
        assert!(convert(directory.path(), "https://drop.example.com")
            .unwrap_err()
            .to_string()
            .contains("lock"));
        drop(lock);
        assert!(convert(directory.path(), "https://drop.example.com").is_ok());
    }

    #[test]
    fn conversion_refusals_roll_back_schema_records_and_authority() {
        fn snapshot(connection: &Connection) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
            [
                "sqlite_schema",
                "sqlite_sequence",
                "meta",
                "tenants",
                "links",
                "files",
                "delivery_jobs",
                "outbound_grants",
                "delivery_events",
            ]
            .into_iter()
            .map(|table| {
                let mut statement = connection
                    .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
                    .unwrap();
                let columns = statement.column_count();
                statement
                    .query_map([], |row| {
                        (0..columns).map(|column| row.get(column)).collect()
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap()
            })
            .collect()
        }
        for (change, expected) in [
            ("UPDATE files SET stored_as='wrong' WHERE file_index=0", "positional file identity"),
            ("DELETE FROM files WHERE file_index=0", "positional file count"),
            ("UPDATE links SET uploads_json='[}'", "expected"),
            ("UPDATE links SET uploads_json=json_set(uploads_json,'$[0].unexpected',1)", "outside the schema35 contract"),
            ("UPDATE links SET uploads_json=json_set(uploads_json,'$[0].id','')", "missing or duplicate"),
            ("UPDATE delivery_jobs SET actor='wrong'", "indexed authority"),
            ("UPDATE outbound_grants SET token_hash='wrong'", "source signing key"),
            ("UPDATE outbound_grants SET tenant='wrong'", "source signing key"),
            ("CREATE TRIGGER unexpected AFTER UPDATE ON meta BEGIN SELECT 1; END", "unsupported schema object"),
            ("INSERT INTO upload_sessions VALUES ('pending','link','team','','',1,'root',1,NULL,1,1,NULL)", "retained admissions"),
            ("INSERT INTO upload_session_files(session_id,entry,display_path,stored_components,object_suite,object_root,object_length,staging_path,journal_path,incarnation) VALUES ('orphan',0,'file','[]',1,'root',1,'','','')", "retained admissions"),
        ] {
            let directory = fixture();
            let path = directory.path().join("votport.db");
            let connection = Connection::open(&path).unwrap();
            seed_job(&connection, "job", true, false);
            seed_upload(&connection);
            connection.execute_batch(change).unwrap();
            let before = snapshot(&connection);
            drop(connection);
            let error = convert(directory.path(), "https://drop.example.com").unwrap_err().to_string();
            assert!(error.contains(expected), "{change}: {error}");
            let connection = Connection::open(&path).unwrap();
            assert_eq!(snapshot(&connection), before, "{change}");
            assert!(!directory.path().join(ARTIFACT).exists(), "{change}");
            assert_eq!(std::fs::read(directory.path().join("receipt.key")).unwrap(), [19; 32]);
            assert_eq!(std::fs::read(directory.path().join("secret")).unwrap(), [23; 32]);
        }
    }

    fn seed_job(connection: &Connection, id: &str, grant: bool, revoked: bool) -> Job {
        let mut request = request();
        request.operation_id = id.into();
        let job = Job {
            id: id.into(),
            tenant: "team".into(),
            token_generation: 7,
            actor: "sso:sender".into(),
            credential_version: 3,
            automation_token_id: None,
            actor_human: None,
            request,
            project: project(),
            state: if grant { "ready" } else { "queued" }.into(),
            manifest: None,
            approved_by: Some("sso:approver".into()),
            attempts: 2,
            created_at: 10,
            updated_at: 20,
            error: None,
            checks: serde_json::json!({"destinations":{"disk":{"state":"complete"}}}),
            received: None,
            reprocessed_from: None,
            reprocessed_as: None,
        };
        connection
            .execute(
                "INSERT OR IGNORE INTO tenants(key,label) VALUES ('team','Team')",
                [],
            )
            .unwrap();
        connection.execute("INSERT OR IGNORE INTO delivery_projects(tenant,id,revision,document) VALUES ('team',?1,?2,?3)",params![job.project.id,job.project.revision as i64,serde_json::to_string(&job.project).unwrap()]).unwrap();
        connection.execute("INSERT INTO delivery_jobs(id,tenant,actor,operation_id,project_id,state,not_before,document) VALUES (?1,?2,?3,?4,?5,?6,0,?7)",params![job.id,job.tenant,job.actor,job.request.operation_id,job.project.id,job.state,serde_json::to_string(&job).unwrap()]).unwrap();
        if grant {
            let message = format!("votport-job-token-v1\0{}:{}", job.id, job.token_generation);
            let token = hex::encode(Sha256::digest(
                ed25519_dalek::SigningKey::from_bytes(&[19; 32])
                    .sign(message.as_bytes())
                    .to_bytes(),
            ))[..32]
                .to_owned();
            connection.execute("INSERT INTO outbound_grants(id,token_hash,tenant,link_id,upload_id,package_root,name,suite,root,file_index,bytes_hi,bytes_lo,label,created_at,expires_at,revoked_at,downloads) VALUES (?1,?2,'team','','','package','movie','blake3','root',0,0,8,'Delivery',10,?3,?4,2)",params![id,auth::hash_token(&token),now_unix() as i64+100000,revoked.then_some(7)]).unwrap();
        }
        job
    }

    fn seed_upload(connection: &Connection) -> UploadRecord {
        let upload: UploadRecord = serde_json::from_value(serde_json::json!({
            "id":"upload","started_at":1,"completed_at":2,"package_root":"package","total_bytes":u64::MAX,
            "partial":true,"log":[{"at":2,"kind":"interrupted"}],
            "files":[{"path":"Résumé.mov","stored_as":"movie.mov","bytes":u64::MAX,"suite":"sha256","root":"cd".repeat(32),"receipt":true,"deleted":true},
                {"path":"empty","stored_as":"empty","bytes":0,"suite":"blake3","root":"ab".repeat(32),"receipt":false}]
        })).unwrap();
        connection.execute("INSERT INTO links(id,tenant,label,created_at,uploads_json) VALUES ('link','team','Link',1,?1)",[serde_json::to_string(&vec![&upload]).unwrap()]).unwrap();
        for (index, file) in upload.files.iter().enumerate() {
            let (hi, lo) = split_bytes(file.bytes);
            connection.execute("INSERT INTO files(link_id,tenant,upload_index,file_index,bytes_hi,bytes_lo,deleted,stored_as) VALUES ('link','team',0,?1,?2,?3,?4,?5)",params![index as i64,hi,lo,file.deleted,file.stored_as]).unwrap();
        }
        upload
    }

    fn seed_anonymous_upload(connection: &Connection) -> UploadRecord {
        let upload: UploadRecord = serde_json::from_value(serde_json::json!({
            "id":"anonymous-upload","started_at":1,"completed_at":2,"package_root":"anonymous-package","total_bytes":20,
            "files":[{"path":"anonymous.mov","stored_as":"shared-anonymous-object","bytes":13,"suite":"blake3","root":"ef".repeat(32),"receipt":false},
                {"path":"anonymous-copy.mov","stored_as":"shared-anonymous-object","bytes":7,"suite":"blake3","root":"01".repeat(32),"receipt":false}]
        })).unwrap();
        connection.execute("INSERT INTO links(id,tenant,label,created_at,uploads_json) VALUES ('anonymous-link','','Anonymous',1,?1)",[serde_json::to_string(&vec![&upload]).unwrap()]).unwrap();
        for (index, file) in upload.files.iter().enumerate() {
            let (hi, lo) = split_bytes(file.bytes);
            connection.execute("INSERT INTO files(link_id,tenant,upload_index,file_index,bytes_hi,bytes_lo,deleted,stored_as) VALUES ('anonymous-link','',0,?1,?2,?3,0,?4)",params![index as i64,hi,lo,file.stored_as]).unwrap();
        }
        upload
    }

    #[test]
    fn conversion_backfills_anonymous_live_quota_usage() {
        let directory = fixture();
        let path = directory.path().join("votport.db");
        let connection = Connection::open(&path).unwrap();
        seed_anonymous_upload(&connection);
        drop(connection);

        convert(directory.path(), "https://drop.example.com").unwrap();

        let store = Store::open(directory.path()).unwrap();
        assert_eq!(store.tenant_received_bytes(""), Ok(13));
        assert_eq!(
            store
                .with(|connection| {
                    connection.query_row(
                        "SELECT bytes_hi,bytes_lo,state FROM tenant_quota_usage WHERE tenant=''",
                        [],
                        |row| {
                            Ok((
                                row.get::<_, i64>(0)?,
                                row.get::<_, i64>(1)?,
                                row.get::<_, i64>(2)?,
                            ))
                        },
                    )
                })
                .unwrap(),
            (0, 13, 0)
        );
    }

    #[test]
    fn conversion_rolls_back_anonymous_quota_backfill_on_late_failure() {
        let directory = fixture();
        let path = directory.path().join("votport.db");
        let connection = Connection::open(&path).unwrap();
        seed_anonymous_upload(&connection);
        seed_job(&connection, "job", false, false);
        connection
            .execute("UPDATE delivery_jobs SET document='{}' WHERE id='job'", [])
            .unwrap();
        drop(connection);

        let error = convert(directory.path(), "https://drop.example.com")
            .unwrap_err()
            .to_string();
        assert!(!error.is_empty());

        let connection = Connection::open(&path).unwrap();
        validate_schema(&connection, 35).unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE name='tenant_quota_usage' OR name LIKE 'tenant_quota_usage_%'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT bytes_hi,bytes_lo FROM files
                     WHERE link_id='anonymous-link' AND upload_index=0 AND file_index=0",
                    [],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                )
                .unwrap(),
            (0, 13)
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM files WHERE link_id='anonymous-link'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            2
        );
        assert!(!directory.path().join(ARTIFACT).exists());
    }

    #[test]
    fn conversion_invalidates_outstanding_rotated_tickets_but_preserves_delivery_history() {
        let directory = fixture();
        let path = directory.path().join("votport.db");
        let connection = Connection::open(&path).unwrap();
        seed_job(&connection, "job", true, false);
        let old_hash: String = connection
            .query_row(
                "SELECT token_hash FROM outbound_grants WHERE id='job'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let now = now_unix();
        connection
            .execute(
                "UPDATE outbound_grants SET downloads=2,max_downloads=3 WHERE id='job'",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO outbound_fetch_tickets(token_id,grant_id,manifest_root,expires_at,holder,grant_token_hash,policy_revision,admitted_at) VALUES ('old-ticket','job','job-root',?1,'',?2,0,?3)",
                params![now as i64 + 600, old_hash, now as i64],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO outbound_fetch_tickets(token_id,grant_id,manifest_root,expires_at,delivered_at,holder,grant_token_hash,policy_revision,admitted_at) VALUES ('delivered-ticket','job','job-root',?1,?2,'',?3,0,?4)",
                params![now as i64 + 600, now as i64 - 1, old_hash, now as i64 - 2],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO outbound_grants(id,token_hash,tenant,link_id,upload_id,package_root,name,suite,root,file_index,bytes_hi,bytes_lo,label,created_at,expires_at,downloads,max_downloads) VALUES ('unrelated','unrelated-hash','team','','','unrelated','file','blake3','root',0,0,1,'Unrelated',10,?1,0,1)",
                [now as i64 + 600],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO outbound_fetch_tickets(token_id,grant_id,manifest_root,expires_at,holder,grant_token_hash,policy_revision,admitted_at) VALUES ('unrelated-ticket','unrelated','unrelated-root',?1,'','unrelated-hash',0,?2)",
                params![now as i64 + 600, now as i64],
            )
            .unwrap();
        drop(connection);

        convert(directory.path(), "https://drop.example.com").unwrap();

        let store = Store::open(directory.path()).unwrap();
        assert!(store.fetch_ticket("old-ticket").unwrap().is_none());
        assert!(!store
            .admit_fetch_ticket(
                &FetchTicket {
                    holder: String::new(),
                    grant_token_hash: old_hash,
                    policy_revision: 0,
                    token_id: "old-ticket".into(),
                    grant_id: "job".into(),
                    manifest_root: "job-root".into(),
                    expires_at: now + 600,
                    delivered_at: None,
                },
                now,
            )
            .unwrap());
        assert_eq!(
            store
                .fetch_ticket("delivered-ticket")
                .unwrap()
                .unwrap()
                .delivered_at,
            Some(now - 1)
        );
        assert_eq!(
            store
                .fetch_ticket("unrelated-ticket")
                .unwrap()
                .unwrap()
                .grant_id,
            "unrelated"
        );
        let grant = store.outbound_grant_by_id("job").unwrap().unwrap();
        assert_eq!(grant.downloads, 2);
        assert_eq!(grant.max_downloads, Some(3));
        let unrelated = store.outbound_grant_by_id("unrelated").unwrap().unwrap();
        assert_eq!(unrelated.token_hash, "unrelated-hash");

        let token = store.delivery_job_token("team", "job").unwrap();
        let ticket = FetchTicket {
            holder: String::new(),
            grant_token_hash: grant.token_hash,
            policy_revision: 0,
            token_id: "replacement-ticket".into(),
            grant_id: "job".into(),
            manifest_root: "job-root".into(),
            expires_at: now + 600,
            delivered_at: None,
        };
        assert_eq!(ticket.grant_token_hash, auth::hash_token(&token));
        assert!(store.put_fetch_ticket(&ticket, now).unwrap());
        assert!(store.admit_fetch_ticket(&ticket, now).unwrap());
    }

    #[test]
    fn conversion_refuses_generation_overflow_without_rotating_authority() {
        let directory = fixture();
        let path = directory.path().join("votport.db");
        let connection = Connection::open(&path).unwrap();
        let mut job = seed_job(&connection, "job", true, false);
        job.token_generation = u64::MAX;
        let message = format!("votport-job-token-v1\0{}:{}", job.id, job.token_generation);
        let token = hex::encode(Sha256::digest(
            ed25519_dalek::SigningKey::from_bytes(&[19; 32])
                .sign(message.as_bytes())
                .to_bytes(),
        ))[..32]
            .to_owned();
        let hash = auth::hash_token(&token);
        let document = serde_json::to_string(&job).unwrap();
        connection
            .execute("UPDATE delivery_jobs SET document=?1", [&document])
            .unwrap();
        connection
            .execute("UPDATE outbound_grants SET token_hash=?1", [&hash])
            .unwrap();
        drop(connection);
        assert!(convert(directory.path(), "https://drop.example.com")
            .unwrap_err()
            .to_string()
            .contains("generation overflow"));
        let connection = Connection::open(path).unwrap();
        validate_schema(&connection, 35).unwrap();
        assert_eq!(
            connection
                .query_row("SELECT document FROM delivery_jobs", [], |row| row
                    .get::<_, String>(0))
                .unwrap(),
            document
        );
        assert_eq!(
            connection
                .query_row("SELECT token_hash FROM outbound_grants", [], |row| row
                    .get::<_, String>(
                    0
                ))
                .unwrap(),
            hash
        );
        assert!(!directory.path().join(ARTIFACT).exists());
    }

    #[test]
    fn conversion_preserves_and_refuses_damaged_event_chains() {
        for change in [
            "UPDATE delivery_events SET payload='{}' WHERE id=1",
            "UPDATE delivery_events SET signature='invalid' WHERE id=1",
            "DELETE FROM delivery_events WHERE id=1",
        ] {
            let directory = fixture();
            let path = directory.path().join("votport.db");
            let connection = Connection::open(&path).unwrap();
            let signer = ReceiptSigner::from_seed([19; 32]);
            for at in [1, 2] {
                evidence::delivery_event(
                    &connection,
                    &signer,
                    "team",
                    "job",
                    "delivery_created",
                    &serde_json::json!({"at":at}),
                    at,
                )
                .unwrap();
            }
            connection.execute_batch(change).unwrap();
            let before: String = connection
                .query_row(
                    "SELECT group_concat(hash || signature || payload) FROM delivery_events",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            drop(connection);
            assert!(
                convert(directory.path(), "https://drop.example.com")
                    .unwrap_err()
                    .to_string()
                    .contains("event chain"),
                "{change}"
            );
            let connection = Connection::open(path).unwrap();
            validate_schema(&connection, 35).unwrap();
            assert_eq!(
                connection
                    .query_row(
                        "SELECT group_concat(hash || signature || payload) FROM delivery_events",
                        [],
                        |row| row.get::<_, String>(0)
                    )
                    .unwrap(),
                before
            );
            assert!(!directory.path().join(ARTIFACT).exists());
        }
    }

    #[test]
    fn incomplete_conversion_artifacts_never_authorize_a_retry() {
        let directory = fixture();
        let artifact = directory.path().join(ARTIFACT);
        std::fs::write(&artifact, b"preserve prior output").unwrap();
        assert!(convert(directory.path(), "https://drop.example.com")
            .unwrap_err()
            .to_string()
            .contains("prepared artifact"));
        let connection = Connection::open(directory.path().join("votport.db")).unwrap();
        validate_schema(&connection, 35).unwrap();
        assert_eq!(std::fs::read(&artifact).unwrap(), b"preserve prior output");
        drop(connection);
        for failure in ["truncated", "changed", "unwritable"] {
            let directory = fixture();
            let result = convert(directory.path(), "https://drop.example.com").unwrap();
            let artifact = directory.path().join(ARTIFACT);
            let mut bytes = std::fs::read(&artifact).unwrap();
            match failure {
                "truncated" => {
                    bytes.truncate(result.bytes as usize - 1);
                    std::fs::write(&artifact, &bytes).unwrap();
                }
                "changed" => {
                    bytes[0] = b'[';
                    std::fs::write(&artifact, &bytes).unwrap();
                }
                "unwritable" => {
                    use std::os::unix::fs::PermissionsExt as _;
                    std::fs::set_permissions(&artifact, std::fs::Permissions::from_mode(0o400))
                        .unwrap();
                }
                _ => unreachable!(),
            }
            let before = std::fs::read(&artifact).unwrap();
            let connection = Connection::open(directory.path().join("votport.db")).unwrap();
            assert!(
                finish_artifact(directory.path(), &connection, &result).is_err(),
                "{failure}"
            );
            validate_schema(&connection, SCHEMA_VERSION).unwrap();
            assert_eq!(std::fs::read(&artifact).unwrap(), before);
            drop(connection);
            assert!(convert(directory.path(), "https://drop.example.com")
                .unwrap_err()
                .to_string()
                .contains("schema version"));
        }
    }

    #[test]
    fn conversion_refuses_a_different_declared_type_with_the_same_letters() {
        let directory = fixture();
        let path = directory.path().join("votport.db");
        let connection = Connection::open(&path).unwrap();
        connection.execute_batch("DROP TABLE settings; CREATE TABLE settings(key TEXT PRIMARY KEY,value T EXT NOT NULL,updated_at INTEGER NOT NULL,updated_by TEXT NOT NULL DEFAULT '');").unwrap();
        drop(connection);
        assert!(convert(directory.path(), "https://drop.example.com")
            .unwrap_err()
            .to_string()
            .contains("unsupported schema"));
        let connection = Connection::open(path).unwrap();
        validate_schema(&connection, 35).unwrap();
        assert!(!directory.path().join(ARTIFACT).exists());
    }

    #[test]
    fn quota_literal_validation_rejects_malformed_schema_and_rolls_back() {
        for (kind, name) in [
            ("trigger", "tenant_quota_usage_insert"),
            ("index", "files_quota_identity"),
        ] {
            let mut actual = Connection::open_in_memory().unwrap();
            initialize_schema(&mut actual).unwrap();
            let mut reference = Connection::open_in_memory().unwrap();
            initialize_schema(&mut reference).unwrap();
            let transaction = actual.transaction().unwrap();
            transaction
                .execute_batch("PRAGMA writable_schema=ON")
                .unwrap();
            let changed = transaction
                .execute(
                    "UPDATE sqlite_schema
                     SET sql=replace(sql, ?1, ?2)
                     WHERE type=?3 AND name=?4",
                    rusqlite::params!["stored_as = ''", "stored_as = ' '", kind, name],
                )
                .unwrap();
            transaction
                .execute_batch("PRAGMA writable_schema=OFF")
                .unwrap();
            assert_eq!(changed, 1, "{kind} {name} was not changed");
            assert!(check_schema(&transaction, &reference).is_err());
            transaction.rollback().unwrap();
            check_schema(&actual, &reference).unwrap();
        }
    }

    #[test]
    fn conversion_refuses_a_user_table_resembling_a_sqlite_internal_table() {
        let directory = fixture();
        let path = directory.path().join("votport.db");
        let connection = Connection::open(&path).unwrap();
        connection.execute_batch("CREATE TABLE sqliteX_private(value TEXT); INSERT INTO sqliteX_private VALUES ('preserve');").unwrap();
        drop(connection);
        assert!(convert(directory.path(), "https://drop.example.com")
            .unwrap_err()
            .to_string()
            .contains("unsupported schema"));
        let connection = Connection::open(path).unwrap();
        validate_schema(&connection, 35).unwrap();
        assert_eq!(
            connection
                .query_row("SELECT value FROM sqliteX_private", [], |row| row
                    .get::<_, String>(0))
                .unwrap(),
            "preserve"
        );
        assert!(!directory.path().join(ARTIFACT).exists());
    }

    #[test]
    fn converts_only_explicit_schema35_copy_and_preserves_authority() {
        let directory = fixture();
        let path = directory.path().join("votport.db");
        let connection = Connection::open(&path).unwrap();
        let original = seed_job(&connection, "job", true, false);
        seed_job(&connection, "revoked", true, true);
        seed_job(&connection, "queued", false, false);
        let upload = seed_upload(&connection);
        evidence::delivery_event(
            &connection,
            &ReceiptSigner::from_seed([19; 32]),
            "team",
            "job",
            "delivery_created",
            &serde_json::json!({"original":true}),
            12,
        )
        .unwrap();
        let event: (String, String) = connection
            .query_row(
                "SELECT hash,signature FROM delivery_events WHERE id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO audit_log(at,tenant,actor,event,subject,detail)
                 VALUES (12,'team','seed','conversion_audit','subject','{}')",
                [],
            )
            .unwrap();
        connection.execute("INSERT INTO settings(key,value,updated_at,updated_by) VALUES ('fixture','unchanged',1,'operator')",[]).unwrap();
        drop(connection);
        assert!(Store::open(directory.path())
            .err()
            .unwrap()
            .contains("schema version 35"));
        let result = convert(directory.path(), "https://DROP.EXAMPLE.com:443/").unwrap();
        assert_eq!(result.replacements, 2);
        let converted = Connection::open(&path).unwrap();
        let indexes: Vec<String> = converted
            .prepare(
                "SELECT name FROM sqlite_schema WHERE type='index' AND name IN (
                    'outbound_fetch_tickets_expires',
                    'outbound_grants_open_expires',
                    'audit_log_tenant',
                    'audit_log_event',
                    'audit_log_tenant_at',
                    'audit_log_event_at'
                ) ORDER BY name",
            )
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();

        assert_eq!(
            indexes,
            [
                "audit_log_event".to_owned(),
                "audit_log_event_at".to_owned(),
                "audit_log_tenant".to_owned(),
                "audit_log_tenant_at".to_owned(),
                "outbound_fetch_tickets_expires".to_owned(),
                "outbound_grants_open_expires".to_owned()
            ]
        );
        drop(converted);
        let store = Store::open(directory.path()).unwrap();
        assert_eq!(
            store.retention_clock_anchor().unwrap(),
            None,
            "converted existing data starts in the retention hold"
        );
        // Four rows the conversion itself wrote, plus the storage layout
        // migration naming the tenants whose totals it moved.
        assert_eq!(store.audit_count().unwrap(), 5);
        let connection = store.connection.lock().unwrap();
        assert_eq!(read_uploads(&connection, "link").unwrap(), vec![upload]);
        assert_eq!(
            connection
                .query_row(
                    "SELECT value FROM settings WHERE key='fixture'",
                    [],
                    |row| row.get::<_, String>(0)
                )
                .unwrap(),
            "unchanged"
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT hash,signature FROM delivery_events WHERE id=1",
                    [],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                )
                .unwrap(),
            event
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT revoked_at,downloads FROM outbound_grants WHERE id='revoked'",
                    [],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
                )
                .unwrap(),
            (7, 2)
        );
        let (token, document): (String, String) = connection
            .query_row(
                "SELECT token,document FROM delivery_jobs WHERE id='job'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let job: Job = serde_json::from_str(&document).unwrap();
        assert_eq!(job.token_generation, original.token_generation + 1);
        assert_eq!(job.checks, original.checks);
        assert_eq!(job.approved_by, original.approved_by);
        assert_eq!(job.attempts, original.attempts);
        assert_eq!(
            connection
                .query_row(
                    "SELECT token_hash FROM outbound_grants WHERE id='job'",
                    [],
                    |row| row.get::<_, String>(0)
                )
                .unwrap(),
            auth::hash_token(&token)
        );
        assert_eq!(connection.query_row("SELECT json_extract(document,'$.token_generation') FROM delivery_jobs WHERE id='queued'",[],|row|row.get::<_,i64>(0)).unwrap(),7);
        drop(connection);
        drop(store);
        let lines: Vec<serde_json::Value> =
            std::fs::read_to_string(directory.path().join(ARTIFACT))
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
        assert_eq!(lines[0]["state"], "prepared");
        assert_eq!(lines.last().unwrap()["state"], "committed");
        assert_eq!(
            lines[1]["url"],
            format!("https://drop.example.com/s/{token}")
        );
        assert!(lines[2]["url"].is_null());
        assert!(convert(directory.path(), "https://drop.example.com")
            .unwrap_err()
            .to_string()
            .contains("schema version"));
        assert_eq!(
            std::fs::read(directory.path().join("receipt.key")).unwrap(),
            [19; 32]
        );
        assert_eq!(
            std::fs::read(directory.path().join("secret")).unwrap(),
            [23; 32]
        );
    }
}
