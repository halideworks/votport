//! The shells are sources too. The Swift and C# surfaces have no test
//! runner in these gates, so the contracts that keep both shells honest
//! against the core are asserted here, on the source files themselves.

use std::fs;
use std::path::PathBuf;

fn shell_source(shell: &str, file: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(shell)
        .join("Votport")
        .join(file);
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn claim(source: &str, needle: &str, what: &str) {
    assert!(source.contains(needle), "not held: {what}");
}

/// A session response carries a role, and the shells gate their operator
/// screens on it: a viewer or auditor pressing Create must fold the screen,
/// not earn a 403 dressed up as a wrong password.
#[test]
fn the_shells_gate_operator_screens_on_the_admin_role() {
    let app = shell_source("macos", "VotportApp.swift");
    claim(
        &app,
        r#"Screen.allCases.filter { port.operating || !$0.operator_ }"#,
        "the macOS screens list filters on the role, not signed-in alone",
    );
    claim(
        &app,
        ".onChange(of: port.operating)",
        "the macOS screen list follows role changes",
    );
    let port_store = shell_source("macos", "PortStore.swift");
    claim(
        &port_store,
        r#"var operating: Bool { port?.role == "admin" }"#,
        "the macOS port store derives operating from the session role",
    );
    let main_window = shell_source("windows", "MainWindow.xaml.cs");
    claim(
        &main_window,
        "PortStore.Shared.CanOperate",
        "the Windows nav gates the operator items on the role",
    );
    let windows_store = shell_source("windows", "PortStore.cs");
    claim(
        &windows_store,
        r#"public bool CanOperate => Port?.Role == "admin";"#,
        "the Windows port store derives CanOperate from the session role",
    );
    assert!(
        !port_store.contains("var operating: Bool { port != nil }"),
        "operating must not mean signed-in"
    );
}

/// A 401 on the shells' own workflow calls must end the session the same
/// way a store-routed call does: the port clears and every screen folds,
/// instead of nav and settings reading as signed in.
#[test]
fn workflow_401s_fold_the_signed_in_shells() {
    let workflows = shell_source("macos", "WorkflowsView.swift");
    claim(
        &workflows,
        "if signedOut { port.sessionEnded() }",
        "the macOS workflows screen folds the session on a signed-out 401",
    );
    claim(
        &workflows,
        "port.sessionEnded()",
        "the macOS workflows screen calls the shared fold, not its own",
    );
    let port_store = shell_source("macos", "PortStore.swift");
    claim(
        &port_store,
        "func sessionEnded()",
        "the macOS port store exposes the fold for screens that call the core themselves",
    );
    let page = shell_source("windows", "WorkflowsPage.cs");
    claim(
        &page,
        "if (error.signedOut) PortStore.Shared.SessionEnded();",
        "the Windows workflows page folds the session on a signed-out 401",
    );
    claim(
        &page,
        "PortStore.Shared.Changed += RebuildForSession;",
        "the Windows workflows page rebuilds its signed-in half when the session changes",
    );
    let windows_store = shell_source("windows", "PortStore.cs");
    claim(
        &windows_store,
        "internal void SessionEnded()",
        "the Windows port store exposes the fold for pages that call the core themselves",
    );
}

/// While any transfer or library upload is active, the shells hold a power
/// assertion, from the first begin to the last end: an overnight send must
/// not die to idle sleep. Linux has no equivalent; the shell only runs on
/// macOS and Windows.
#[test]
fn active_transfers_hold_the_system_awake() {
    let transfer_store = shell_source("macos", "TransferStore.swift");
    claim(
        &transfer_store,
        "IOPMAssertionCreateWithName",
        "the macOS shell takes an IOPMAssertion while bytes move",
    );
    claim(
        &transfer_store,
        "kIOPMAssertionTypePreventUserIdleSystemSleep",
        "the macOS assertion prevents idle system sleep",
    );
    claim(
        &transfer_store,
        "IOPMAssertionRelease",
        "the macOS assertion is released with the last transfer",
    );
    claim(
        &transfer_store,
        "Power.transfer(true)",
        "the macOS transfer run holds the machine awake",
    );
    let port_store = shell_source("macos", "PortStore.swift");
    claim(
        &port_store,
        "Power.libraryUpload(true)",
        "the macOS library upload holds the machine awake too",
    );
    claim(
        &port_store,
        "Power.libraryUpload(false)",
        "the macOS library upload release also runs on the session reset path",
    );
    let windows_store = shell_source("windows", "TransferStore.cs");
    claim(
        &windows_store,
        "SetThreadExecutionState",
        "the Windows shell keeps the system awake with SetThreadExecutionState",
    );
    claim(
        &windows_store,
        "EsSystemRequired",
        "the Windows requirement is the system, not only the display",
    );
    claim(
        &windows_store,
        "Power.Transfer(ActiveCount > 0)",
        "the Windows transfer count drives the assertion",
    );
    let windows_port = shell_source("windows", "PortStore.cs");
    claim(
        &windows_port,
        "Power.Upload(true)",
        "the Windows library upload holds the machine awake too",
    );
    claim(
        &windows_port,
        "Power.Upload(false)",
        "the Windows library upload release also runs on the session reset path",
    );
}
