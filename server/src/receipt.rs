//! Signed VOT assurance receipts written as sidecars next to received files.
//!
//! Each published file gets `<name>.vot-receipt`: a canonical vot-receipt
//! CBOR envelope, ed25519-signed with a key generated in the data directory,
//! attesting that this exact object (suite, root, length) reached Published
//! assurance under the Balanced commit profile. The key id is the 32-byte
//! public key itself, so a receipt is verifiable against the key the admin
//! page displays with nothing else.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use vot_receipt::{
    encode_authenticated, required_predecessor, sign_ed25519, AssuranceLevel, CommitProfile,
    Receipt, SubjectKind,
};
use vot_sdk::object::ObjectId;
use vot_sdk_file::PublishObservation;

/// votport's provider version in issued receipts.
const PROVIDER_VERSION: [u16; 3] = [0, 1, 0];
/// POSIX_LOCAL in spec/registries.yaml.
const PROVIDER: u16 = 1;

pub struct ReceiptSigner {
    key: SigningKey,
    /// Hex of the ed25519 public key; shown in the admin UI for verification.
    pub public_hex: String,
}

impl ReceiptSigner {
    /// Loads or creates the 32-byte signing seed in the data directory.
    pub fn load_or_create(data_dir: &Path) -> Result<Self, String> {
        let path = data_dir.join("receipt.key");
        crate::paths::tighten_private_file(&path)?;
        let seed: [u8; 32] = match std::fs::read(&path) {
            Ok(bytes) => bytes
                .try_into()
                .map_err(|_| format!("{} is not a 32-byte key seed", path.display()))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut seed = [0u8; 32];
                use rand::RngCore as _;
                rand::rngs::OsRng.fill_bytes(&mut seed);
                crate::auth::write_private(&path, &seed).map_err(|error| error.to_string())?;
                seed
            }
            Err(error) => return Err(format!("read {}: {error}", path.display())),
        };
        let key = SigningKey::from_bytes(&seed);
        let public_hex = hex::encode(key.verifying_key().to_bytes());
        Ok(Self { key, public_hex })
    }

    /// Verifying key for checking issued receipts; avoids re-parsing the
    /// hex on every request.
    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.key.verifying_key()
    }

    /// Writes `<destination>.vot-receipt` attesting the published object.
    pub fn write_sidecar(
        &self,
        destination: &Path,
        object: &ObjectId,
        session_id: [u8; 16],
        observation: PublishObservation,
    ) -> Result<PathBuf, String> {
        let bytes = self.encode(object, session_id, observation)?;
        let mut sidecar = destination.as_os_str().to_owned();
        sidecar.push(".vot-receipt");
        let sidecar = PathBuf::from(sidecar);
        write_sidecar_file(&sidecar, &bytes, |file, bytes| file.write_all(bytes))
            .map_err(|error| format!("write or publish {}: {error}", sidecar.display()))?;
        Ok(sidecar)
    }

    /// Encodes a signed receipt for a newly prepared object.
    pub fn encode(
        &self,
        object: &ObjectId,
        session_id: [u8; 16],
        observation: PublishObservation,
    ) -> Result<Vec<u8>, String> {
        let receipt = Receipt {
            subject_kind: SubjectKind::Object,
            suite_id: object.suite,
            subject_digest: object.root,
            subject_length: object.length,
            assurance: AssuranceLevel::Published,
            profile: CommitProfile::Balanced,
            actual_predecessor: required_predecessor(CommitProfile::Balanced),
            provider: PROVIDER,
            provider_version: PROVIDER_VERSION,
            session_id,
            incarnation_id: observation.incarnation,
            sequence: observation.sequence,
            observed_at: rfc3339_now(),
            // 1 = system UTC, matching the canonical vot-receipt vectors.
            clock_source: 1,
            flags: 0,
            // ponytail: no chain; each receipt stands alone. Link `previous`
            // if a subject is ever observed more than once.
            previous: None,
        };
        let key_id = self.key.verifying_key().to_bytes();
        let authenticated = sign_ed25519(receipt, &key_id, &self.key)
            .map_err(|error| format!("sign receipt: {error:?}"))?;
        encode_authenticated(&authenticated).map_err(|error| format!("encode receipt: {error:?}"))
    }
}

fn write_sidecar_file(
    sidecar: &Path,
    bytes: &[u8],
    write: impl FnOnce(&mut File, &[u8]) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let parent = sidecar
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let temporary = parent.join(format!(".vot-{}.stage", crate::auth::random_token()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    let temporary_guard = TemporaryFile(temporary);
    write(&mut file, bytes)?;
    file.sync_all()?;
    std::fs::hard_link(&temporary_guard.0, sidecar)
}

struct TemporaryFile(PathBuf);

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// RFC 3339 UTC seconds from the system clock, e.g. "2026-08-20T04:05:06Z".
fn rfc3339_now() -> String {
    rfc3339(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs()),
    )
}

fn rfc3339(unix: u64) -> String {
    let days = i64::try_from(unix / 86_400).unwrap_or(0);
    let seconds = unix % 86_400;
    // Civil-from-days (Howard Hinnant's algorithm), valid for the era range
    // a running server can observe.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds / 3600,
        (seconds % 3600) / 60,
        seconds % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_matches_known_timestamps() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(1_755_662_400), "2025-08-20T04:00:00Z");
        assert_eq!(rfc3339(4_102_444_799), "2099-12-31T23:59:59Z");
    }

    #[test]
    fn sidecar_receipt_round_trips_and_verifies() {
        let directory = tempfile::tempdir().unwrap();
        let signer = ReceiptSigner::load_or_create(directory.path()).unwrap();
        let reloaded = ReceiptSigner::load_or_create(directory.path()).unwrap();
        assert_eq!(signer.public_hex, reloaded.public_hex, "key is persistent");

        let destination = directory.path().join("payload.bin");
        let object = ObjectId {
            suite: 1,
            root: [9; 32],
            length: 4096,
        };
        let sidecar = signer
            .write_sidecar(
                &destination,
                &object,
                [2; 16],
                PublishObservation {
                    incarnation: [3; 16],
                    sequence: 7,
                },
            )
            .unwrap();
        assert_eq!(sidecar, directory.path().join("payload.bin.vot-receipt"));

        let bytes = std::fs::read(&sidecar).unwrap();
        let decoded = vot_receipt::decode_authenticated(&bytes).unwrap();
        let key = ed25519_dalek::VerifyingKey::from_bytes(
            &hex::decode(&signer.public_hex).unwrap().try_into().unwrap(),
        )
        .unwrap();
        let verified = vot_receipt::verify_ed25519(&decoded, &key).unwrap();
        assert_eq!(verified.receipt().subject_digest, [9; 32]);
        assert_eq!(verified.receipt().sequence, 7);
    }

    #[cfg(unix)]
    #[test]
    fn loading_an_existing_receipt_key_tightens_it() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("receipt.key");
        std::fs::write(&path, [8u8; 32]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        ReceiptSigner::load_or_create(directory.path()).unwrap();
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn partial_write_removes_final_and_temporary_sidecars() {
        let directory = tempfile::tempdir().unwrap();
        let sidecar = directory.path().join("payload.bin.vot-receipt");
        assert!(write_sidecar_file(&sidecar, b"complete", |file, bytes| {
            file.write_all(&bytes[..1])?;
            Err(std::io::Error::other("injected receipt write failure"))
        })
        .is_err());
        assert!(!sidecar.exists());
        assert!(!std::fs::read_dir(directory.path())
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.starts_with(".vot-") && name.ends_with(".stage")
            }));
    }

    #[test]
    fn existing_sidecar_is_preserved() {
        let directory = tempfile::tempdir().unwrap();
        let signer = ReceiptSigner::load_or_create(directory.path()).unwrap();
        let destination = directory.path().join("payload.bin");
        let sidecar = directory.path().join("payload.bin.vot-receipt");
        let original = b"existing receipt";
        std::fs::write(&sidecar, original).unwrap();

        let error = signer
            .write_sidecar(
                &destination,
                &ObjectId {
                    suite: 1,
                    root: [9; 32],
                    length: 4096,
                },
                [2; 16],
                PublishObservation {
                    incarnation: [3; 16],
                    sequence: 7,
                },
            )
            .unwrap_err();

        assert!(error.contains("publish"));
        assert_eq!(std::fs::read(&sidecar).unwrap(), original);
        assert!(!std::fs::read_dir(directory.path())
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.starts_with(".vot-") && name.ends_with(".stage")
            }));
    }

    #[test]
    fn receipt_stage_orphan_is_removed_at_startup() {
        let directory = tempfile::tempdir().unwrap();
        let orphan = directory
            .path()
            .join(format!(".vot-{}.stage", crate::auth::random_token()));
        std::fs::write(&orphan, b"partial receipt").unwrap();

        crate::paths::clean_staging(directory.path(), &Default::default());

        assert!(!orphan.exists());
    }
}
