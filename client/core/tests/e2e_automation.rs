//! Agents and desktop operators share delivery records and verified HTTP downloads.
#![cfg(target_os = "linux")]
mod common;

use serde_json::json;
use votport_client_core::{
    automation::Automation, ffi, port::AutomationTokenSpec, progress::Silent,
};

#[test]
fn desktop_issued_token_runs_an_isolated_verified_delivery_workflow() {
    let Ok(bin) = std::env::var("VOTPORT_BIN") else {
        eprintln!("VOTPORT_BIN unset; skipping automation e2e");
        return;
    };
    let state = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_DATA_HOME", state.path());
    let server = common::start_server(&bin, &[]);
    common::deliver(
        &server.base,
        &[
            ("project/a.txt", b"alpha".to_vec()),
            ("project/b.txt", b"beta".to_vec()),
        ],
        None,
        None,
    );
    ffi::sign_in(server.base.clone(), common::ADMIN_PASSWORD.to_owned()).unwrap();
    let issued = ffi::create_automation_token(AutomationTokenSpec {
        label: "render agent".into(),
        directory: Some("project".into()),
        expires_days: 1,
        permissions: [
            "library:read",
            "deliveries:create",
            "deliveries:read",
            "deliveries:revoke",
            "jobs:read",
            "jobs:create",
            "jobs:cancel",
        ]
        .map(str::to_owned)
        .to_vec(),
    })
    .unwrap();
    assert_eq!(
        ffi::automation_tokens().unwrap()[0],
        issued.automation_token
    );
    let agent = Automation::new(&server.base, &issued.token).unwrap();
    let first = agent.files(None, None, 1).unwrap();
    assert_eq!(first["files"][0]["path"], "project/a.txt");
    let second = agent.files(None, first["next_cursor"].as_str(), 1).unwrap();
    assert_eq!(second["files"][0]["path"], "project/b.txt");
    let spec = json!({"directory": "project", "expires_days": 7, "operation_id": "render-001"});
    let delivery = agent.create_delivery(&spec).unwrap();
    let id = delivery["grant"]["id"].as_str().unwrap();
    assert!(ffi::deliveries().unwrap().iter().any(|d| d.id == id));
    assert_eq!(delivery, agent.create_delivery(&spec).unwrap());
    assert_eq!(delivery, agent.recover("render-001").unwrap());
    ffi::sign_out();
    assert!(ffi::port().is_none());
    assert_eq!(
        agent.session().unwrap()["automation_token"]["id"],
        issued.automation_token.id
    );
    let link = votport_client_core::split_link(delivery["url"].as_str().unwrap()).unwrap();
    let dest = state.path().join("download");
    std::fs::create_dir(&dest).unwrap();
    votport_client_core::receive::receive_over_http(
        &link.base,
        votport_client_core::Delivery {
            token: link.token,
            password: None,
        },
        &dest,
        &mut Silent,
    )
    .unwrap();
    assert_eq!(std::fs::read(dest.join("project/a.txt")).unwrap(), b"alpha");
    assert_eq!(std::fs::read(dest.join("project/b.txt")).unwrap(), b"beta");
    let detail = agent.delivery(id, 0, 1).unwrap();
    assert_eq!(detail["files"][0]["download_starts"], 1);
    assert_eq!(
        detail["files"][0]["root"],
        delivery["grant"]["files"][0]["root"]
    );
    assert!(!detail["files"][0]["receipt_b64"]
        .as_str()
        .unwrap()
        .is_empty());
    agent.revoke(id).unwrap();
    agent.revoke(id).unwrap();
    assert_eq!(agent.delivery(id, 0, 1).unwrap()["state"], "revoked");
    ffi::sign_in(server.base.clone(), common::ADMIN_PASSWORD.to_owned()).unwrap();
    assert!(ffi::deliveries()
        .unwrap()
        .iter()
        .find(|d| d.id == id)
        .unwrap()
        .revoked_at
        .is_some());
    let admin = votport_client_core::api::Client::new(&server.base).unwrap();
    let cookie = admin.admin_login(common::ADMIN_PASSWORD).unwrap();
    let project: serde_json::Value = admin.admin_send(reqwest::Method::PUT, "/api/workflows/projects", &cookie, Some(&json!({
        "id":"project", "directory":"project", "label":"Agent project", "required_metadata":["client"],
        "members":{format!("automation:{}",issued.automation_token.id):"sender"}
    }))).unwrap();
    assert_eq!(agent.projects().unwrap()["projects"][0]["id"], "project");
    let request = json!({"operation_id":"durable-1","project_id":"project","label":"Durable delivery","metadata":{"client":"Example"},"expires_days":1});
    let queued = agent.create_job(&request).unwrap();
    let job_id = queued["job"]["id"].as_str().unwrap();
    assert_eq!(agent.create_job(&request).unwrap()["job"]["id"], job_id);
    let wait = |id: &str, state: &str| {
        for _ in 0..200 {
            let job = agent.job(id).unwrap();
            if job["job"]["state"] == state {
                return job;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        panic!("job {id} did not reach {state}");
    };
    let ready = wait(job_id, "ready");
    assert!(ready["url"].is_string());
    assert_eq!(
        agent.jobs(None, 50).unwrap()["jobs"][0]["job"]["id"],
        job_id
    );
    assert!(agent.job_evidence(job_id, 0, 50).unwrap()["evidence"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(!agent.events(0, 100).unwrap()["events"]
        .as_array()
        .unwrap()
        .is_empty());
    let mut invalid_sequence = project;
    invalid_sequence["sequence"] =
        json!({"prefix":"missing-","suffix":".exr","first":1,"last":1,"padding":4});
    admin
        .admin_send::<serde_json::Value>(
            reqwest::Method::PUT,
            "/api/workflows/projects",
            &cookie,
            Some(&invalid_sequence),
        )
        .unwrap();
    let mut request = request;
    request["operation_id"] = json!("durable-failure");
    let failed = agent.create_job(&request).unwrap();
    let failed_id = failed["job"]["id"].as_str().unwrap();
    wait(failed_id, "failed");
    assert!(agent.job_action(failed_id, "retry").is_ok());
    wait(failed_id, "failed");
    assert_eq!(
        agent.job_action(failed_id, "cancel").unwrap()["job"]["state"],
        "cancelled"
    );
    assert!(agent.job_action(job_id, "approve").is_err());
    ffi::revoke_automation_token(issued.automation_token.id).unwrap();
    assert!(matches!(
        agent.session(),
        Err(votport_client_core::Error::Server { status: 401, .. })
    ));
}
