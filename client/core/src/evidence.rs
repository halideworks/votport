//! Verification statements have their own outbox; retrying them never downloads files.

use crate::api::{Client, OutboundMetadata};
use crate::delivery_protocol::{manifest_digest, Evidence, EvidenceKind, SignedChallenge};
use crate::error::{Error, Result};
use crate::identity::{self, Device};
use crate::progress::{Event, Observer};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, Once};
use std::time::Duration;

pub struct Prepared {
    authorization: SignedChallenge,
    key: ed25519_dalek::SigningKey,
}

#[derive(Serialize, Deserialize)]
struct Pending {
    base: String,
    evidence: Evidence,
}

#[derive(Default, Debug, Clone, uniffi::Record)]
pub struct OutboxStatus {
    pub pending: u64,
    pub recorded: u64,
    pub failed: u64,
}

#[derive(Clone, Debug, Serialize, uniffi::Record)]
pub struct VerificationRecord {
    pub id: String,
    pub server: String,
    pub grant_id: String,
    pub manifest: String,
    pub expires_at: u64,
    pub verification_status: String,
    pub acceptance_status: String,
}

fn prepare(
    client: &Client,
    metadata: &OutboundMetadata,
    device: &Device,
) -> Result<Option<Prepared>> {
    let Some(manifest) = &metadata.delivery_manifest else {
        return Ok(None);
    };
    let base = client.base();
    let authorization = metadata
        .evidence_authorization
        .clone()
        .ok_or_else(|| Error::Other("delivery acknowledgement authorization is missing".into()))?;
    if !authorization.verify(metadata.receipt_key.as_deref().unwrap_or_default())
        || &authorization.challenge.manifest != manifest
        || Some(&authorization.challenge.grant_id) != metadata.grant_id.as_ref()
        || authorization.challenge.holder != device.holder_key_hex()
        || authorization.challenge.origin.trim_end_matches('/') != base.trim_end_matches('/')
    {
        return Err(Error::Other(
            "delivery acknowledgement authorization does not match".into(),
        ));
    }
    Ok(Some(Prepared {
        authorization,
        key: device.signing_key(),
    }))
}

pub fn prepare_receive(
    client: &Client,
    metadata: &OutboundMetadata,
    device: Option<&Device>,
    observer: &mut dyn Observer,
) -> Result<Option<Prepared>> {
    let Some(manifest) = &metadata.delivery_manifest else {
        return Ok(None);
    };
    if *manifest
        != manifest_digest(
            metadata
                .files
                .iter()
                .map(|f| (&*f.name, &*f.suite, &*f.root, f.bytes)),
        )
    {
        return Err(Error::Other(
            "delivery manifest does not match the announced files".into(),
        ));
    }
    if let Some(device) = device {
        if let Ok(prepared) = prepare(client, metadata, device) {
            return Ok(prepared);
        }
    }
    observer.event(Event::Evidence {
        status: "unavailable".into(),
    });
    Ok(None)
}

pub fn complete(base: &str, prepared: Option<Prepared>, observer: &mut dyn Observer) {
    let Some(prepared) = prepared else {
        return;
    };
    let evidence = Evidence::sign(
        prepared.authorization,
        EvidenceKind::Verified,
        &prepared.key,
    );
    let directory = outbox();
    match enqueue(base, evidence, &directory) {
        Ok(_) => {
            observer.event(Event::Evidence {
                status: "pending".into(),
            });
            start_retry_worker();
        }
        Err(_) => observer.event(Event::Evidence {
            status: "unavailable".into(),
        }),
    }
}

fn outbox() -> PathBuf {
    identity::state_dir().join("evidence")
}

fn create_directory(directory: &Path) -> std::io::Result<()> {
    if directory.is_dir() {
        return Ok(());
    }
    if let Some(parent) = directory.parent().filter(|p| !p.as_os_str().is_empty()) {
        create_directory(parent)?;
    }
    match std::fs::create_dir(directory) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && directory.is_dir() => {}
        Err(error) => return Err(error),
    }
    #[cfg(unix)]
    if let Some(parent) = directory.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn enqueue(base: &str, evidence: Evidence, directory: &Path) -> Result<PathBuf> {
    create_directory(directory)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
    }
    let path = directory.join(format!("{}.json", evidence.id()));
    let pending = Pending {
        base: base.into(),
        evidence,
    };
    let bytes = serde_json::to_vec(&pending).map_err(|e| Error::Other(e.to_string()))?;
    identity::write_private(&path, &bytes)?;
    Ok(path)
}

fn cache(directory: &Path, id: &str, base: &str, evidence: &Evidence) -> Result<()> {
    create_directory(directory)?;
    let bytes = serde_json::to_vec(&Pending {
        base: base.into(),
        evidence: evidence.clone(),
    })
    .map_err(|e| Error::Other(e.to_string()))?;
    identity::write_private(&directory.join(format!("{id}.json")), &bytes)
}

fn read_pending(path: &Path) -> Result<Pending> {
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 16384 {
        return Err(Error::Other("invalid acknowledgement outbox entry".into()));
    }
    serde_json::from_slice(&std::fs::read(path)?).map_err(|e| Error::Other(e.to_string()))
}

fn send_pending(path: &Path) -> Result<()> {
    let pending = read_pending(path)?;
    let client = Client::with_timeout(&pending.base, Some(Duration::from_secs(5)))?;
    client.submit_evidence(&pending.evidence)?;
    let directory = path
        .parent()
        .ok_or_else(|| Error::Other("invalid outbox path".into()))?;
    if pending.evidence.kind == EvidenceKind::Verified {
        cache(
            &directory.join("verified"),
            &pending.evidence.id(),
            &pending.base,
            &pending.evidence,
        )?;
    }
    let recorded = directory.join("recorded");
    create_directory(&recorded)?;
    identity::write_private(&recorded.join(pending.evidence.id()), b"recorded")?;
    std::fs::remove_file(path)?;
    #[cfg(unix)]
    std::fs::File::open(directory)?.sync_all()?;
    Ok(())
}

fn report_status(directory: &Path, id: &str) -> String {
    if directory.join("recorded").join(id).is_file() {
        "recorded"
    } else if directory.join(format!("{id}.json")).is_file() {
        "pending"
    } else if directory
        .join("failed")
        .join(format!("{id}.json"))
        .is_file()
    {
        "expired"
    } else {
        "unavailable"
    }
    .into()
}

#[uniffi::export]
pub fn delivery_verifications() -> Vec<VerificationRecord> {
    let directory = outbox();
    let entries = std::fs::read_dir(&directory)
        .into_iter()
        .flatten()
        .chain(
            std::fs::read_dir(directory.join("verified"))
                .into_iter()
                .flatten(),
        )
        .chain(
            std::fs::read_dir(directory.join("failed"))
                .into_iter()
                .flatten(),
        );
    let mut records = vec![];
    let mut seen = std::collections::HashSet::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(pending) = read_pending(&path)
            .or_else(|_| read_pending(&directory.join("verified").join(entry.file_name())))
            .or_else(|_| read_pending(&directory.join("failed").join(entry.file_name())))
        else {
            continue;
        };
        let id = pending.evidence.id();
        if pending.evidence.kind != EvidenceKind::Verified || !seen.insert(id.clone()) {
            continue;
        }
        let challenge = &pending.evidence.authorization.challenge;
        let accepted = read_pending(&directory.join("accepted").join(format!("{id}.json"))).ok();
        records.push(VerificationRecord {
            verification_status: report_status(&directory, &id),
            acceptance_status: accepted.as_ref().map_or_else(
                || "not_accepted".into(),
                |pending| report_status(&directory, &pending.evidence.id()),
            ),
            id,
            server: pending.base,
            grant_id: challenge.grant_id.clone(),
            manifest: challenge.manifest.clone(),
            expires_at: challenge.expires_at,
        });
    }
    records.sort_by(|a, b| {
        b.expires_at
            .cmp(&a.expires_at)
            .then_with(|| a.id.cmp(&b.id))
    });
    records
}

#[uniffi::export]
pub fn accept_delivery(verification_id: String) -> Result<String> {
    accept_in(&outbox(), &verification_id, &Device::load_or_create()?)
}

fn accept_in(directory: &Path, id: &str, device: &Device) -> Result<String> {
    if id.len() != 64 || !id.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::Other("invalid verification ID".into()));
    }
    let pending = read_pending(&directory.join(format!("{id}.json")))
        .or_else(|_| read_pending(&directory.join("verified").join(format!("{id}.json"))))?;
    if pending.evidence.id() != id
        || pending.evidence.kind != EvidenceKind::Verified
        || pending.evidence.authorization.challenge.holder != device.holder_key_hex()
        || !pending
            .evidence
            .verify(&pending.evidence.authorization.issuer)
    {
        return Err(Error::Other(
            "this device does not hold the original verification record".into(),
        ));
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if pending.evidence.authorization.challenge.expires_at <= now {
        return Err(Error::Other(
            "the acceptance authorization has expired".into(),
        ));
    }
    let evidence = Evidence::sign(
        pending.evidence.authorization,
        EvidenceKind::Accepted,
        &device.signing_key(),
    );
    cache(&directory.join("accepted"), id, &pending.base, &evidence)?;
    let path = enqueue(&pending.base, evidence, directory)?;
    let status = if send_pending(&path).is_ok() {
        "recorded"
    } else {
        "pending"
    };
    start_retry_worker();
    Ok(status.into())
}

#[uniffi::export]
pub fn recipient_device_key() -> Result<String> {
    Ok(Device::load_or_create()?.holder_key_hex())
}

fn retry_in(directory: &Path) -> OutboxStatus {
    for kind in ["verified", "accepted"] {
        for entry in std::fs::read_dir(directory.join(kind))
            .into_iter()
            .flatten()
            .flatten()
        {
            let Ok(pending) = read_pending(&entry.path()) else {
                continue;
            };
            if report_status(directory, &pending.evidence.id()) == "unavailable" {
                let _ = enqueue(&pending.base, pending.evidence, directory);
            }
        }
    }
    let mut result = OutboxStatus::default();
    let Ok(entries) = std::fs::read_dir(directory) else {
        return result;
    };
    // ponytail: list the outbox for fair batches; use an indexed queue if it reaches millions of reports.
    let mut paths: Vec<_> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    paths.sort();
    result.pending = paths.len() as u64;
    let cursor = std::fs::read_to_string(directory.join("cursor")).unwrap_or_default();
    let start = paths.partition_point(|p| {
        p.file_name().unwrap_or_default().to_string_lossy().as_ref() <= cursor.as_str()
    });
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    for path in paths[start..].iter().chain(&paths[..start]).take(16) {
        let expired = std::fs::read(path)
            .ok()
            .filter(|bytes| bytes.len() <= 16384)
            .and_then(|bytes| serde_json::from_slice::<Pending>(&bytes).ok())
            .is_some_and(|pending| pending.evidence.authorization.challenge.expires_at <= now);
        let sent = send_pending(path);
        if sent.is_ok() {
            result.recorded += 1;
            result.pending -= 1;
        } else if expired && matches!(sent, Err(Error::Server { status: 401, .. })) {
            let failed = directory.join("failed");
            if std::fs::create_dir_all(&failed)
                .and_then(|()| {
                    std::fs::rename(path, failed.join(path.file_name().unwrap_or_default()))
                })
                .is_ok()
            {
                result.pending -= 1;
            }
        }
        let _ = identity::write_private(
            &directory.join("cursor"),
            path.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .as_bytes(),
        );
    }
    result.failed = std::fs::read_dir(directory.join("failed"))
        .map(|entries| entries.flatten().count() as u64)
        .unwrap_or(0);
    result
}

#[uniffi::export]
pub fn retry_evidence() -> OutboxStatus {
    static RETRY: Mutex<()> = Mutex::new(());
    let _guard = RETRY.lock().unwrap_or_else(|e| e.into_inner());
    retry_in(&outbox())
}

pub fn start_retry_worker() {
    static START: Once = Once::new();
    START.call_once(|| {
        std::thread::spawn(|| loop {
            retry_evidence();
            std::thread::sleep(Duration::from_secs(60));
        });
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery_protocol::Challenge;

    fn report(base: &str, nonce: &str, expires_at: u64, kind: EvidenceKind) -> Evidence {
        let server = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        let key = ed25519_dalek::SigningKey::from_bytes(&[2; 32]);
        Evidence::sign(
            SignedChallenge::issue(
                Challenge {
                    origin: base.into(),
                    grant_id: "grant".into(),
                    manifest: "manifest".into(),
                    holder: hex::encode(key.verifying_key().to_bytes()),
                    nonce: nonce.into(),
                    issued_at: 1,
                    expires_at,
                },
                &server,
            ),
            kind,
            &key,
        )
    }

    fn respond(
        listener: std::net::TcpListener,
        status: u16,
        body: String,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            use std::io::{BufRead, Read, Write};
            listener.set_nonblocking(true).unwrap();
            for _ in 0..400 {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        stream
                            .set_write_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let mut reader = std::io::BufReader::new(&stream);
                        let mut length = 0;
                        for _ in 0..64 {
                            let mut line = String::new();
                            assert!(reader.read_line(&mut line).unwrap() > 0);
                            if line == "\r\n" {
                                break;
                            }
                            if let Some(value) =
                                line.to_ascii_lowercase().strip_prefix("content-length:")
                            {
                                length = value.trim().parse::<usize>().unwrap();
                            }
                        }
                        assert!(length < 16384);
                        reader.read_exact(&mut vec![0; length]).unwrap();
                        write!(stream,"HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
                        return;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(error) => panic!("{error}"),
                }
            }
            panic!("evidence client did not connect");
        })
    }

    #[test]
    fn only_exact_successful_acknowledgements_remove_reports() {
        for (status, body, recorded) in [
            (302, "valid", false),
            (200, "{}", false),
            (200, "wrong", false),
            (200, "false", false),
            (200, "valid", true),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let evidence = report(&base, "test", u64::MAX, EvidenceKind::Verified);
            let body = match body {
                "valid" => serde_json::json!({"id":evidence.id(),"recorded":true}).to_string(),
                "false" => serde_json::json!({"id":evidence.id(),"recorded":false}).to_string(),
                "wrong" => serde_json::json!({"id":"wrong","recorded":true}).to_string(),
                other => other.into(),
            };
            let path = enqueue(&base, evidence.clone(), dir.path()).unwrap();
            let server = respond(listener, status, body);
            let result = retry_in(dir.path());
            server.join().unwrap();
            assert_eq!(result.recorded, u64::from(recorded));
            assert_eq!(path.exists(), !recorded);
            assert_eq!(
                report_status(dir.path(), &evidence.id()),
                if recorded { "recorded" } else { "pending" }
            );
            if recorded {
                assert_eq!(
                    read_pending(
                        &dir.path()
                            .join("verified")
                            .join(format!("{}.json", evidence.id()))
                    )
                    .unwrap()
                    .evidence,
                    evidence
                );
            }
        }
    }

    #[test]
    fn expired_transport_failures_are_retained_and_fair_batches_reach_later_reports() {
        let dir = tempfile::tempdir().unwrap();
        let base = "http://127.0.0.1:1";
        for index in 0..17 {
            enqueue(
                base,
                report(base, &index.to_string(), 1, EvidenceKind::Verified),
                dir.path(),
            )
            .unwrap();
        }
        let mut paths: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        paths.sort();
        let result = retry_in(dir.path());
        assert_eq!((result.pending, result.failed), (17, 0));
        assert_eq!(
            std::fs::read_to_string(dir.path().join("cursor")).unwrap(),
            paths[15].to_str().unwrap()
        );
        let result = retry_in(dir.path());
        assert_eq!((result.pending, result.failed), (17, 0));
        assert_eq!(
            std::fs::read_to_string(dir.path().join("cursor")).unwrap(),
            paths[14].to_str().unwrap()
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let expired = report(&base, "expired", 1, EvidenceKind::Verified);
        let separate = tempfile::tempdir().unwrap();
        enqueue(&base, expired.clone(), separate.path()).unwrap();
        let server = respond(listener, 401, "{}".into());
        let result = retry_in(separate.path());
        server.join().unwrap();
        assert_eq!((result.pending, result.failed), (0, 1));
        assert_eq!(report_status(separate.path(), &expired.id()), "expired");
    }

    #[test]
    fn cached_acceptance_recovers_a_missing_outbox_without_changing_signed_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let base = "http://127.0.0.1:1";
        let verified = report(base, "test", u64::MAX, EvidenceKind::Verified);
        let accepted = report(base, "test", u64::MAX, EvidenceKind::Accepted);
        cache(
            &dir.path().join("verified"),
            &verified.id(),
            base,
            &verified,
        )
        .unwrap();
        cache(
            &dir.path().join("accepted"),
            &verified.id(),
            base,
            &accepted,
        )
        .unwrap();
        assert_eq!(report_status(dir.path(), &accepted.id()), "unavailable");
        assert_eq!(retry_in(dir.path()).pending, 2);
        assert_eq!(
            read_pending(&dir.path().join(format!("{}.json", accepted.id())))
                .unwrap()
                .evidence,
            accepted
        );
        let other = Device::load_or_create_in(&dir.path().join("other")).unwrap();
        assert!(accept_in(dir.path(), &verified.id(), &other).is_err());
        assert!(accept_in(dir.path(), "../invalid", &other).is_err());
    }

    #[test]
    fn failed_acknowledgements_keep_the_complete_signed_record() {
        let dir = tempfile::tempdir().unwrap();
        let server = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        let device = ed25519_dalek::SigningKey::from_bytes(&[2; 32]);
        let authorization = SignedChallenge::issue(
            Challenge {
                origin: "http://127.0.0.1:1".into(),
                grant_id: "grant".into(),
                manifest: "manifest".into(),
                holder: hex::encode(device.verifying_key().to_bytes()),
                nonce: "nonce".into(),
                issued_at: 1,
                expires_at: u64::MAX,
            },
            &server,
        );
        let evidence = Evidence::sign(authorization, EvidenceKind::Verified, &device);
        let path = enqueue("http://127.0.0.1:1", evidence.clone(), dir.path()).unwrap();
        let result = retry_in(dir.path());
        assert_eq!((result.pending, result.recorded), (1, 0));
        let saved: Pending = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(saved.evidence, evidence);
        assert!(saved
            .evidence
            .verify(&hex::encode(server.verifying_key().to_bytes())));
    }
}
