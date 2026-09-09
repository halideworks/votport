//! Signed statements about an immutable, ordered delivery file set.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub fn manifest_digest<'a>(
    files: impl IntoIterator<Item = (&'a str, &'a str, &'a str, u64)>,
) -> String {
    let mut hash = Sha256::new();
    hash.update(b"votport-delivery-files-v1\0");
    let mut count = 0u64;
    for (name, suite, root, bytes) in files {
        for field in [name, suite, root] {
            hash.update((field.len() as u64).to_be_bytes());
            hash.update(field.as_bytes());
        }
        hash.update(bytes.to_be_bytes());
        count += 1;
    }
    hash.update(count.to_be_bytes());
    hex::encode(hash.finalize())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub origin: String,
    pub grant_id: String,
    pub manifest: String,
    pub holder: String,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedChallenge {
    pub challenge: Challenge,
    pub issuer: String,
    pub signature: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Verified,
    Accepted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub authorization: SignedChallenge,
    pub kind: EvidenceKind,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessProof {
    pub authorization: SignedChallenge,
    pub signature: String,
}

impl AccessProof {
    pub fn sign(authorization: SignedChallenge, key: &SigningKey) -> Self {
        let signature = hex::encode(
            key.sign(&message(b"votport-recipient-access-v1\0", &authorization))
                .to_bytes(),
        );
        Self {
            authorization,
            signature,
        }
    }

    pub fn verify(&self, issuer: &str) -> bool {
        self.authorization.verify(issuer)
            && verify_signature(
                &self.authorization.challenge.holder,
                &message(b"votport-recipient-access-v1\0", &self.authorization),
                &self.signature,
            )
    }
}

fn message(domain: &[u8], value: &impl Serialize) -> Vec<u8> {
    let mut bytes = domain.to_vec();
    bytes.extend(serde_json::to_vec(value).expect("evidence fields serialize"));
    bytes
}

impl SignedChallenge {
    pub fn issue(challenge: Challenge, key: &SigningKey) -> Self {
        let signature = key.sign(&message(b"votport-evidence-challenge-v1\0", &challenge));
        Self {
            challenge,
            issuer: hex::encode(key.verifying_key().to_bytes()),
            signature: hex::encode(signature.to_bytes()),
        }
    }

    pub fn verify(&self, issuer: &str) -> bool {
        self.issuer == issuer
            && verify_signature(
                issuer,
                &message(b"votport-evidence-challenge-v1\0", &self.challenge),
                &self.signature,
            )
    }
}

impl Evidence {
    pub fn sign(authorization: SignedChallenge, kind: EvidenceKind, key: &SigningKey) -> Self {
        let signature = key.sign(&message(
            b"votport-evidence-statement-v1\0",
            &(&authorization, kind),
        ));
        Self {
            authorization,
            kind,
            signature: hex::encode(signature.to_bytes()),
        }
    }

    pub fn verify(&self, issuer: &str) -> bool {
        self.authorization.verify(issuer)
            && verify_signature(
                &self.authorization.challenge.holder,
                &message(
                    b"votport-evidence-statement-v1\0",
                    &(&self.authorization, self.kind),
                ),
                &self.signature,
            )
    }

    pub fn id(&self) -> String {
        hex::encode(Sha256::digest(message(b"votport-evidence-id-v1\0", self)))
    }
}

fn verify_signature(holder: &str, message: &[u8], signature: &str) -> bool {
    let Some(key) = hex::decode(holder)
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .and_then(|v| VerifyingKey::from_bytes(&v).ok())
    else {
        return false;
    };
    let Some(signature) = hex::decode(signature)
        .ok()
        .and_then(|v| Signature::from_slice(&v).ok())
    else {
        return false;
    };
    key.verify_strict(message, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statements_bind_issuer_device_manifest_and_explicit_acceptance() {
        let server = SigningKey::from_bytes(&[1; 32]);
        let device = SigningKey::from_bytes(&[2; 32]);
        let authorization = SignedChallenge::issue(
            Challenge {
                origin: "https://drop.example".into(),
                grant_id: "delivery-1".into(),
                manifest: manifest_digest([("file", "blake3", "abcd", 7)]),
                holder: hex::encode(device.verifying_key().to_bytes()),
                nonce: "nonce-1".into(),
                issued_at: 1,
                expires_at: 2,
            },
            &server,
        );
        let original = Evidence::sign(authorization, EvidenceKind::Verified, &device);
        assert_eq!(
            original.authorization.challenge.manifest,
            "e3177fb9094c6dc5112fe278bf01979847f154d451961e035489847baba8c5f0"
        );
        assert_eq!(original.authorization.signature, "848bbbbd34ecef86faa736d49a731a9e09f77a18ee8cdb418ba3057811e74738d6e395af5cbf79d199b6da8dbdec910b75e72057af8ce1ad5df97128b2c4f10c");
        assert_eq!(original.signature, "5f50ff0e9bf768b9ab3a33645c7397f443d59ecb39e07413385084a86f7a4d8725607fd0256d036fb3ed1352d91bae6c244e61bd02727354c0d299f2049d1c0c");
        assert_eq!(
            original.id(),
            "d293c3e7a19882f40969541c482dd9fe79bfaa908c873e893b57190bfd2d3ba8"
        );
        let issuer = hex::encode(server.verifying_key().to_bytes());
        assert!(original.verify(&issuer));
        assert!(!original.verify(&hex::encode(device.verifying_key().to_bytes())));
        let mut changed = original.clone();
        changed.kind = EvidenceKind::Accepted;
        assert!(!changed.verify(&issuer));
        changed = original.clone();
        changed.authorization.challenge.manifest.push('0');
        assert!(!changed.verify(&issuer));
        changed = original.clone();
        changed.authorization.challenge.expires_at += 1;
        assert!(!changed.verify(&issuer));
        changed = original.clone();
        changed.signature = "bad".into();
        assert!(!changed.verify(&issuer));
        assert_eq!(original.id(), original.clone().id());
        assert_ne!(original.id(), changed.id());
    }

    #[test]
    fn manifest_commits_to_every_field_and_order_without_ambiguous_names() {
        let a = ("a", "blake3", "abc", 7);
        let b = ("b", "blake3", "abc", 7);
        assert_ne!(manifest_digest([a, b]), manifest_digest([b, a]));
        assert_ne!(manifest_digest([a]), manifest_digest([a, a]));
        for changed in [
            ("ab", "lake3", "abc", 7),
            ("a", "sha256", "abc", 7),
            ("a", "blake3", "abcd", 7),
            ("a", "blake3", "abc", 8),
        ] {
            assert_ne!(manifest_digest([a]), manifest_digest([changed]));
        }
        assert_eq!(manifest_digest([a]), manifest_digest([a]));
    }
}
