#![cfg(unix)]

mod common;

use vot_object::Suite;
use votport_client_core::progress::Silent;
use votport_client_core::{
    api::Client, package, receive_over_fetch, receive_over_http, send_http, Delivery, Device,
};

#[test]
fn sha256_partial_proofs_and_both_receive_transports_preserve_identity() {
    let Some(bin) = common::server_binary() else {
        return;
    };
    let port = common::free_port();
    let server = common::start_server(
        &bin,
        &[
            ("VOTPORT_SERVE_BIND", format!("127.0.0.1:{port}")),
            ("VOTPORT_SERVE_ADVERTISE", format!("127.0.0.1:{port}")),
        ],
    );
    let files = tempfile::tempdir().unwrap();
    let source = files.path().join("source.bin");
    let bytes = vec![37; 16 * 1024 * 1024];
    std::fs::write(&source, &bytes).unwrap();
    let manifest = files.path().join("manifest");
    let path = vot_manifest::PackagePath::portable(["source.bin".to_owned()]).unwrap();
    let (summary, served) =
        vot_cli::build_manifest_from(vec![(path, source)], &manifest, Suite::Sha256Bep52).unwrap();
    let prepared = package::load_prepared(summary, served, &manifest).unwrap();
    let request = common::create_link(&server.base);
    let report = send_http::send(
        &Client::new(&server.base).unwrap(),
        &request,
        None,
        &prepared,
        &mut Silent,
    )
    .expect("SHA256 partial-range proofs must be accepted over HTTP");
    let admin = reqwest::blocking::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();
    admin
        .post(format!("{}/api/admin/login", server.base))
        .json(&serde_json::json!({"password": common::ADMIN_PASSWORD}))
        .send()
        .unwrap()
        .error_for_status()
        .unwrap();
    let response: serde_json::Value = admin.post(format!("{}/api/admin/outbound-grants", server.base))
        .header("X-Votport", "1")
        .json(&serde_json::json!({"link_id": request, "upload_id": report.upload_id, "file_index": 0}))
        .send().unwrap().error_for_status().unwrap().json().unwrap();
    let token = response["url"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap();
    let device_dir = tempfile::tempdir().unwrap();
    let device = Device::load_or_create_in(device_dir.path()).unwrap();
    for fetch in [false, true] {
        let destination = tempfile::tempdir().unwrap();
        let delivery = Delivery {
            token: token.to_owned(),
            password: None,
        };
        let received = if fetch {
            receive_over_fetch(
                &server.base,
                delivery,
                &device,
                destination.path(),
                &mut Silent,
            )
        } else {
            let destination_file = destination.path().join("source.bin");
            std::fs::write(
                destination.path().join(".vot-source.bin.journal"),
                &bytes[..12345],
            )
            .unwrap();
            common::write_receive_identity_for_bytes(&destination_file, Suite::Sha256Bep52, &bytes);
            receive_over_http(&server.base, delivery, destination.path(), &mut Silent)
        }
        .expect("both receive transports must verify the advertised SHA256 identity");
        assert_eq!(received.files.len(), 1);
        assert_eq!(std::fs::read(&received.files[0]).unwrap(), bytes);
    }
}
