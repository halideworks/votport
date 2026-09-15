use std::env;
use std::fs;
use std::path::Path;

use sha2::{Digest, Sha256};
use votport::auth::{self, AdminIdentity, TenantGrant};

#[test]
#[ignore = "requires an isolated browser fixture"]
fn issue_viewer_token() {
    let secret_file = env::var("VOTPORT_VIEWER_SECRET_FILE").expect("private test secret path");
    let token_file = env::var("VOTPORT_VIEWER_TOKEN_FILE").expect("token output path");
    let subject = env::var("VOTPORT_VIEWER_SUBJECT").expect("viewer subject");
    let password = env::var("VOTPORT_ADMIN_PASSWORD").expect("admin password");
    let secret = fs::read(secret_file).expect("read private test secret");
    let secret: [u8; 32] = secret.try_into().expect("private test secret is 32 bytes");
    let version = hex::encode(Sha256::digest(password.as_bytes()));
    let identity = AdminIdentity {
        subject,
        tenant: String::new(),
        role: "viewer".to_owned(),
        grants: vec![TenantGrant {
            incarnation: None,
            tenant: String::new(),
            role: "viewer".to_owned(),
        }],
        credential_version: 1,
    };
    let token = auth::issue_admin_token_with_ttl(&secret, &identity, &version, 300);
    fs::write(Path::new(&token_file), token).expect("write private viewer token");
}
