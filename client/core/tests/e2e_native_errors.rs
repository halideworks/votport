//! Actual HTTP and UniFFI checks for operator not-found context.

#![cfg(target_os = "linux")]

mod common;

use votport_client_core::api::Client;
use votport_client_core::ffi;
use votport_client_core::port::{DeliverySpec, PortError};
use votport_client_core::Error;

fn failed<T: std::fmt::Debug>(result: Result<T, PortError>) -> (String, String, bool) {
    match result {
        Err(PortError::Failed {
            headline,
            detail,
            signed_out,
        }) => (headline, detail, signed_out),
        other => panic!("expected a failure, got {other:?}"),
    }
}

#[test]
fn operator_not_found_errors_keep_their_actual_context() {
    let Some(bin) = common::server_binary() else {
        return;
    };
    let state = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_DATA_HOME", state.path());
    let server = common::start_server(&bin, &[]);
    ffi::sign_in(server.base.clone(), common::ADMIN_PASSWORD.to_owned()).expect("sign in");

    let missing = failed(ffi::issue_delivery(DeliverySpec {
        paths: vec!["missing.mov".to_owned()],
        label: "Missing".to_owned(),
        password: None,
        expires_days: 7,
        max_downloads: None,
    }));
    assert_eq!(
        missing.0,
        "That path is not an available library file. Select files inside folders, or upload local files first with `votport upload <path>`."
    );
    assert!(missing.1.contains("404"), "{}", missing.1);
    assert!(!missing.2);

    // This native call is file-only; folder selection remains a separate server API.
    let _existing = common::deliver(
        &server.base,
        &[("folder/file.txt", b"contents".to_vec())],
        None,
        None,
    );
    let folder = failed(ffi::issue_delivery(DeliverySpec {
        paths: vec!["folder".to_owned()],
        label: "Folder".to_owned(),
        password: None,
        expires_days: 7,
        max_downloads: None,
    }));
    assert_eq!(folder.0, missing.0);
    assert!(folder.1.contains("404"), "{}", folder.1);

    let revoked = failed(ffi::revoke_delivery("missing-delivery".to_owned()));
    assert_eq!(revoked.0, "That delivery is no longer on record.");
    assert!(revoked.1.contains("404"), "{}", revoked.1);

    let closed = failed(ffi::close_request("missing-request".to_owned()));
    assert_eq!(closed.0, "That request is no longer on record.");
    assert!(closed.1.contains("404"), "{}", closed.1);

    // Public link errors keep their closed-link headline and credential
    // status while the admin formatter grows its path context.
    let unknown = ffi::inspect(
        format!("{}/s/missing-delivery", server.base),
        Some(votport_client_core::LinkKind::Delivery),
    );
    assert_eq!(
        unknown.problem.as_deref(),
        Some("This link is closed or has expired.")
    );
    assert!(unknown
        .detail
        .as_deref()
        .is_some_and(|detail| detail.contains("404")));

    let gated = common::deliver(
        &server.base,
        &[("gated.txt", b"contents".to_vec())],
        Some("secret"),
        None,
    );
    let error = Client::new(&server.base)
        .unwrap()
        .verify_outbound(&gated, "wrong")
        .unwrap_err();
    assert_eq!(error.headline(), "The password was not accepted.");
    assert!(
        matches!(error, Error::Server { status: 401, .. }),
        "{error:?}"
    );

    ffi::sign_out();
}
