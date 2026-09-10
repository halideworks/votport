//! Signed custody statements exchanged by independent Votport installations.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub fn manifest_digest<'a>(
    files: impl IntoIterator<Item = (&'a str, &'a str, &'a str, u64)>,
) -> String {
    let mut files: Vec<_> = files.into_iter().collect();
    files.sort_by(|a, b| a.0.cmp(b.0));
    crate::delivery_protocol::manifest_digest(files)
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteDocument {
    pub issuer: String,
    pub operation_id: String,
    pub manifest: String,
    pub label: String,
    pub metadata: BTreeMap<String, String>,
    pub parent_receipt: Option<String>,
    pub visited: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRoute {
    pub document: RouteDocument,
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptDocument {
    pub source: SignedRoute,
    pub receiver: String,
    pub upload_id: String,
    pub received_at: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteReceipt {
    pub document: ReceiptDocument,
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationDocument {
    pub route_digest: String,
    pub source: SignedRoute,
    pub receiver: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRevocation {
    pub document: RevocationDocument,
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokedDocument {
    pub request: RouteRevocation,
    pub revoked_at: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRevoked {
    pub document: RevokedDocument,
    pub signature: String,
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn message(domain: &[u8], document: &impl Serialize) -> Vec<u8> {
    let mut bytes = domain.to_vec();
    bytes.extend(serde_json::to_vec(document).expect("route statement serializes"));
    bytes
}

fn verify(key: &str, signature: &str, message: &[u8]) -> bool {
    let key = hex::decode(key)
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok());
    let signature = hex::decode(signature)
        .ok()
        .and_then(|bytes| ed25519_dalek::Signature::from_slice(&bytes).ok());
    key.zip(signature)
        .is_some_and(|(key, signature)| key.verify_strict(message, &signature).is_ok())
}

impl SignedRoute {
    pub fn sign(mut document: RouteDocument, key: &SigningKey) -> Self {
        document.issuer = hex::encode(key.verifying_key().as_bytes());
        let signature = hex::encode(
            key.sign(&message(b"votport-trade-route-v1\0", &document))
                .to_bytes(),
        );
        Self {
            document,
            signature,
        }
    }

    pub fn verify(&self) -> bool {
        let document = &self.document;
        digest(&document.issuer)
            && digest(&document.manifest)
            && id(&document.operation_id)
            && !document.label.trim().is_empty()
            && document.label.len() <= 200
            && document.metadata.len() <= 50
            && document
                .metadata
                .iter()
                .all(|(key, value)| id(key) && value.len() <= 4096)
            && document
                .parent_receipt
                .as_ref()
                .is_none_or(|value| digest(value))
            && !document.visited.is_empty()
            && document.visited.len() <= 8
            && document.visited.iter().all(|value| digest(value))
            && document
                .visited
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == document.visited.len()
            && document.visited.last() == Some(&document.issuer)
            && verify(
                &document.issuer,
                &self.signature,
                &message(b"votport-trade-route-v1\0", document),
            )
    }

    pub fn admits(&self, receiver: &str) -> bool {
        self.verify()
            && digest(receiver)
            && !self.document.visited.iter().any(|port| port == receiver)
    }
}

pub fn verify_ancestry(source: &SignedRoute, ancestors: &[RouteReceipt]) -> bool {
    source.verify()
        && ancestors.len() + 1 == source.document.visited.len()
        && source.document.parent_receipt == ancestors.last().map(RouteReceipt::digest)
        && ancestors.iter().enumerate().all(|(index, receipt)| {
            receipt.verify(&source.document.visited[index + 1])
                && receipt.document.source.document.visited == source.document.visited[..index + 1]
                && receipt.document.source.document.manifest == source.document.manifest
                && receipt.document.source.document.parent_receipt
                    == index
                        .checked_sub(1)
                        .map(|previous| ancestors[previous].digest())
        })
}

impl RouteReceipt {
    pub fn sign(
        source: SignedRoute,
        upload_id: String,
        received_at: u64,
        key: &SigningKey,
    ) -> Self {
        let document = ReceiptDocument {
            source,
            receiver: hex::encode(key.verifying_key().as_bytes()),
            upload_id,
            received_at,
        };
        let signature = hex::encode(
            key.sign(&message(b"votport-route-receipt-v1\0", &document))
                .to_bytes(),
        );
        Self {
            document,
            signature,
        }
    }

    pub fn verify(&self, receiver: &str) -> bool {
        self.document.receiver == receiver
            && self.document.source.admits(receiver)
            && id(&self.document.upload_id)
            && self.document.received_at > 0
            && verify(
                receiver,
                &self.signature,
                &message(b"votport-route-receipt-v1\0", &self.document),
            )
    }

    pub fn digest(&self) -> String {
        hex::encode(Sha256::digest(
            serde_json::to_vec(self).expect("route receipt serializes"),
        ))
    }
}

impl RouteRevocation {
    pub fn sign(source: SignedRoute, receiver: String, route_id: &str, key: &SigningKey) -> Self {
        let document = RevocationDocument {
            source,
            receiver,
            route_digest: hex::encode(Sha256::digest(route_id.as_bytes())),
        };
        let signature = hex::encode(
            key.sign(&message(b"votport-route-revoke-v1\0", &document))
                .to_bytes(),
        );
        Self {
            document,
            signature,
        }
    }

    pub fn verify(&self) -> bool {
        digest(&self.document.route_digest)
            && self.document.source.admits(&self.document.receiver)
            && verify(
                &self.document.source.document.issuer,
                &self.signature,
                &message(b"votport-route-revoke-v1\0", &self.document),
            )
    }
}

impl RouteRevoked {
    pub fn sign(request: RouteRevocation, revoked_at: u64, key: &SigningKey) -> Self {
        let document = RevokedDocument {
            request,
            revoked_at,
        };
        let signature = hex::encode(
            key.sign(&message(b"votport-route-revoked-v1\0", &document))
                .to_bytes(),
        );
        Self {
            document,
            signature,
        }
    }

    pub fn verify(&self, request: &RouteRevocation) -> bool {
        self.document.request == *request
            && request.verify()
            && self.document.revoked_at > 0
            && verify(
                &request.document.receiver,
                &self.signature,
                &message(b"votport-route-revoked-v1\0", &self.document),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipts_bind_custody_and_refuse_loops_or_changed_statements() {
        let origin = SigningKey::from_bytes(&[31; 32]);
        let receiver = SigningKey::from_bytes(&[32; 32]);
        let source_key = hex::encode(origin.verifying_key().as_bytes());
        let receiver_key = hex::encode(receiver.verifying_key().as_bytes());
        let document = RouteDocument {
            issuer: source_key.clone(),
            operation_id: "job".into(),
            manifest: "ab".repeat(32),
            label: "Delivery".into(),
            metadata: BTreeMap::new(),
            parent_receipt: None,
            visited: vec![source_key.clone()],
        };
        let source = SignedRoute::sign(document.clone(), &origin);
        assert!(source.admits(&receiver_key));
        assert!(!source.admits(&source_key));
        let receipt = RouteReceipt::sign(source.clone(), "upload".into(), 1, &receiver);
        assert!(receipt.verify(&receiver_key));
        assert!(!receipt.verify(&source_key));
        assert!(verify_ancestry(&source, &[]));
        let next = SignedRoute::sign(
            RouteDocument {
                issuer: receiver_key.clone(),
                operation_id: "next".into(),
                manifest: document.manifest.clone(),
                label: "Forward".into(),
                metadata: BTreeMap::new(),
                parent_receipt: Some(receipt.digest()),
                visited: vec![source_key.clone(), receiver_key.clone()],
            },
            &receiver,
        );
        assert!(verify_ancestry(&next, std::slice::from_ref(&receipt)));
        assert!(!verify_ancestry(&next, &[]));
        let mut different = receipt.clone();
        different.document.source.document.manifest = "bb".repeat(32);
        assert!(!verify_ancestry(&next, &[different]));
        let first = ("Z.bin", "blake3", "ab", 1);
        let second = ("a.bin", "blake3", "cd", 2);
        assert_eq!(
            manifest_digest([first, second]),
            manifest_digest([second, first])
        );
        assert_ne!(manifest_digest([first]), manifest_digest([first, first]));
        let revocation =
            RouteRevocation::sign(source.clone(), receiver_key.clone(), "route", &origin);
        assert!(revocation.verify());
        assert!(
            !RouteRevocation::sign(source.clone(), receiver_key.clone(), "route", &receiver)
                .verify()
        );
        let revoked = RouteRevoked::sign(revocation.clone(), 2, &receiver);
        assert!(revoked.verify(&revocation));
        assert!(!RouteRevoked::sign(revocation.clone(), 2, &origin).verify(&revocation));
        let mut changed = revoked.clone();
        changed.document.revoked_at += 1;
        assert!(!changed.verify(&revocation));
        let mut changed = receipt.clone();
        changed.document.upload_id = "elsewhere".into();
        assert!(!changed.verify(&receiver_key));
        assert_ne!(receipt.digest(), changed.digest());
        for update in [0, 1, 2, 3, 4, 5, 6, 7] {
            let mut invalid = document.clone();
            match update {
                0 => invalid.visited.clear(),
                1 => invalid.visited.push(source_key.clone()),
                2 => invalid.visited = vec![receiver_key.clone()],
                3 => invalid.manifest = "no".into(),
                4 => invalid.label.clear(),
                5 => invalid.parent_receipt = Some("no".into()),
                6 => invalid.operation_id = "../job".into(),
                _ => {
                    invalid.metadata.insert("bad key".into(), "value".into());
                }
            }
            assert!(!SignedRoute::sign(invalid, &origin).verify());
        }
        let mut changed = source;
        changed.document.label = "Changed".into();
        assert!(!changed.verify());
    }
}
