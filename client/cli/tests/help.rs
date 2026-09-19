//! `--version` and per-command `-h`/`--help` answer before positional
//! parsing, so the flags never run as file or link names (audit 484).

use std::process::{Command, Output, Stdio};

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_votport"))
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap()
}

#[test]
fn version_flag_prints_a_votport_version() {
    let output = cli(&["--version"]);
    assert!(output.status.success(), "{}", output.status);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("votport "), "{stdout}");
    assert!(
        stdout
            .trim_end()
            .chars()
            .last()
            .is_some_and(|c| c.is_ascii_digit()),
        "no version number: {stdout}"
    );
}

#[test]
fn help_flags_print_command_usage_instead_of_running() {
    for (args, needle) in [
        (&["send", "-h"][..], "votport send <link>"),
        (&["receive", "--help"], "votport receive <link>"),
        (&["inspect", "-h"], "votport inspect <link>"),
        (&["status", "-h"], "votport status"),
        (&["watch", "add", "--help"], "votport watch add"),
        (&["agent", "files", "-h"], "votport agent files"),
    ] {
        let output = cli(args);
        assert!(output.status.success(), "{args:?}: {}", output.status);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains(needle), "{args:?}:\n{stdout}");
        assert!(
            String::from_utf8_lossy(&output.stderr).is_empty(),
            "{args:?} wrote to stderr"
        );
    }
    // Without -h the same command runs instead of printing usage.
    let output = cli(&["status"]);
    assert!(output.status.success());
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("votport status"),
        "usage leaked into a plain run"
    );
}
