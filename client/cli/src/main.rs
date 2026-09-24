//! `votport` command line client.
//!
//! `votport send <link> <path>...` sends files and folders to a votport
//! request link, over QUIC push when the link offers it and the receiver's
//! carrier answers, over HTTP otherwise.

mod agent;
mod mcp;

use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

/// Prints one line to stdout, swallowing a broken pipe: a downstream filter
/// (`votport send --json | head`) takes its lines and exits, and the writes
/// that follow must end the output quietly rather than panic (exit 101)
/// behind a transfer still running, which would abort a send mid-flight.
macro_rules! out {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let stdout = std::io::stdout();
        let _ = writeln!(stdout.lock(), $($arg)*);
    }};
}

use votport_client_core::Transport;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|arg| arg == "--version") {
        out!("votport {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    // `-h`/`--help` on a command prints that command's usage before any
    // positional parsing can take the flag as a file or link name.
    if let Some(usage) = command_help(&args) {
        out!("{usage}");
        return ExitCode::SUCCESS;
    }
    if args.first().is_some_and(|arg| arg == "agent") {
        return match agent::run(&args[1..]) {
            Ok(value) => {
                out!("{value}");
                ExitCode::SUCCESS
            }
            Err(value) => {
                out!("{value}");
                ExitCode::from(agent::exit_code(&value))
            }
        };
    }
    if args.first().is_some_and(|arg| arg == "mcp") {
        return match mcp::run(&args[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("votport mcp: {error}");
                ExitCode::FAILURE
            }
        };
    }

    let result = if args.first().is_some_and(|arg| arg == "inspect") {
        inspect(&args[1..])
    } else {
        run(&args).map(|()| ExitCode::SUCCESS)
    };
    match result {
        Ok(status) => status,
        Err(message) => {
            if args.iter().any(|arg| arg == "--json") {
                out!(
                    "{}",
                    serde_json::json!({"error": message, "code": "command_failed", "retryable": false})
                );
            } else {
                eprintln!("votport: {message}");
            }
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("send") => send(&args[1..]),
        Some("receive") => receive(&args[1..]),
        Some("status") => status(&args[1..]),
        Some("evidence") => evidence(&args[1..]),
        Some("resume") => resume(&args[1..]),
        Some("signin") => signin(&args[1..]),
        Some("signout") => {
            if let Some(error) = takes_nothing("signout", &args[1..]) {
                return Err(error);
            }
            votport_client_core::port::sign_out();
            Ok(())
        }
        Some("port") => port_status(&args[1..]),
        Some("requests") => requests(&args[1..]),
        Some("issue-request") => issue_request(&args[1..]),
        Some("close-request") => close_request(&args[1..]),
        Some("deliveries") => deliveries(&args[1..]),
        Some("revoke-delivery") => revoke_delivery(&args[1..]),
        Some("library") => library(&args[1..]),
        Some("issue-delivery") => issue_delivery(&args[1..]),
        Some("upload") => upload(&args[1..]),
        Some("watch") => watch(&args[1..]),
        Some("help") | Some("--help") | Some("-h") | None => {
            print_usage();
            Ok(())
        }
        Some(other) => Err(format!("unknown command {other:?}; try `votport help`")),
    }
}

fn evidence(args: &[String]) -> Result<(), String> {
    use votport_client_core::evidence;
    let value = match args.first().map(String::as_str) {
        Some("list") if args.len() == 1 => serde_json::to_value(evidence::delivery_verifications())
            .map_err(|error| error.to_string())?,
        Some("device-key") if args.len() == 1 => {
            serde_json::json!({"holder": evidence::recipient_device_key().map_err(|error| error.to_string())?})
        }
        Some("retry") if args.len() == 1 => {
            let result = evidence::retry_evidence();
            serde_json::json!({"pending":result.pending,"recorded":result.recorded,"failed":result.failed})
        }
        Some("accept") if args.len() == 2 => {
            serde_json::json!({"status":evidence::accept_delivery(args[1].clone()).map_err(|error| error.to_string())?})
        }
        _ => {
            return Err(
                "evidence needs list, device-key, retry, or accept <verification-id>".into(),
            )
        }
    };
    out!("{value}");
    Ok(())
}

/// Usage lines for each command group, keyed by the word that heads the
/// command; `-h`/`--help` on a command prints its group's lines.
const USAGE: &[(&str, &str)] = &[
    (
        "agent",
        "votport agent session
votport agent notifications
votport agent files [<directory>] [--after <cursor>] [--limit <n>]
votport agent share <directory> --operation-id <id> [--expires-days <n>] [--label <label>] [--max-downloads <n>] [--notifications <json>]
votport agent recover <operation-id>
votport agent deliveries [--after <cursor>] [--limit <n>]
votport agent delivery <id> [--offset <n>] [--limit <n>]
votport agent revoke <id>
votport agent projects
votport agent jobs [--after <cursor>] [--limit <n>]
votport agent create-job <request.json | ->
votport agent job | retry-job | cancel-job <id>
votport agent events [--after <cursor>] [--limit <n>]
votport agent job-evidence <id> [--after <cursor>] [--limit <n>]",
    ),
    ("mcp", "votport mcp"),
    (
        "evidence",
        "votport evidence list | device-key | retry
votport evidence accept <verification-id>",
    ),
    (
        "send",
        "votport send <link> <path>...      [--password <p> | --password-file <path|->] [--json]",
    ),
    (
        "receive",
        "votport receive <link> <dir>       [--password <p> | --password-file <path|->] [--json]",
    ),
    ("inspect", "votport inspect <link>"),
    ("status", "votport status"),
    (
        "resume",
        "votport resume <id>                [--password <p> | --password-file <path|->] [--json]",
    ),
    (
        "signin",
        "votport signin <origin>            [--password <p> | --password-file <path|->]  (else read from stdin)",
    ),
    ("signout", "votport signout"),
    ("port", "votport port                       [--json]"),
    ("requests", "votport requests                   [--json]"),
    (
        "issue-request",
        "votport issue-request <label>      [--password <p>] [--expires-days <n>] [--max-bytes <n>] [--json]",
    ),
    ("close-request", "votport close-request <id>"),
    ("deliveries", "votport deliveries                 [--json]"),
    ("revoke-delivery", "votport revoke-delivery <id>"),
    (
        "library",
        "votport library [<dir>]            [--after <cursor>] [--json]",
    ),
    (
        "issue-delivery",
        "votport issue-delivery <label> <path>... [--password <p>] [--expires-days <n>] [--max-downloads <n>] [--json]",
    ),
    (
        "upload",
        "votport upload <path>...           [--into <dir>] [--json]",
    ),
    (
        "watch",
        "votport watch add <dir> <link>     [--password <p>]
votport watch list | remove <id> | run [--json]",
    ),
];

/// The usage lines for the command heading `args`, when `-h` or `--help`
/// asks for them; None leaves the arguments to the command itself.
fn command_help(args: &[String]) -> Option<&'static str> {
    if !args
        .iter()
        .skip(1)
        .any(|arg| arg == "-h" || arg == "--help")
    {
        return None;
    }
    let name = args.first()?;
    USAGE
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, lines)| *lines)
}

/// Help goes to stdout so `votport help | grep` sees it; only errors use
/// stderr.
fn print_usage() {
    for (_, lines) in USAGE {
        out!("{lines}");
    }
    out!("\nVerification reports are queued durably. Long-running desktop apps retry automatically;\nshort-lived CLI processes can flush pending reports with votport evidence retry.\nAgent commands always return JSON and use VOTPORT_URL and VOTPORT_AUTOMATION_TOKEN.");
    out!(
        " \nsend's <link> is a request URL, e.g. https://drop.example/r/TOKEN;\neach <path> is a file or folder, and a folder keeps its name.\nreceive's <link> is a delivery URL, e.g. https://drop.example/s/TOKEN;\n<dir> is where its files land, verified against their announced roots."
    );
}

fn send(args: &[String]) -> Result<(), String> {
    let (mut options, positional, json) = parse(args, &["--password", "--password-file"])?;
    let password = secret_from(&mut options, "--password-file", "--password")?;
    let (link, paths) = positional
        .split_first()
        .ok_or("send needs a link and at least one path")?;
    if paths.is_empty() {
        return Err("send needs at least one file or folder".to_owned());
    }
    // The journalled core path: a transfer cut by a kill or kept for a
    // retryable failure leaves a resume record for `votport status` and
    // `votport resume`.
    let sent = votport_client_core::ffi::send(
        link.clone(),
        password,
        paths.to_vec(),
        votport_client_core::ffi::Transfer::new(),
        Arc::new(ViewPrinter { json }),
    )
    .map_err(human)?;
    if matches!(sent.transport, Transport::Push) {
        if json {
            out!(
                "{}",
                serde_json::json!({"event":"done","via":"push","files":sent.files})
            );
        } else {
            out!(
                "done: {} {} pushed",
                sent.files,
                if sent.files == 1 { "file" } else { "files" }
            );
        }
    } else if json {
        out!(
            "{}",
            serde_json::json!({"event":"done","via":"http","upload_id":sent.upload_id,"files":sent.files})
        );
    } else {
        out!(
            "done: {} {} published (upload {})",
            sent.files,
            if sent.files == 1 { "file" } else { "files" },
            sent.upload_id.as_deref().unwrap_or_default()
        );
    }
    Ok(())
}

/// Prints what a link is as one JSON object, spending nothing on the server.
fn inspect(args: &[String]) -> Result<ExitCode, String> {
    if let Some(error) = no_options("inspect", args) {
        return Err(error);
    }
    let [link] = args else {
        return Err("inspect takes one link".to_owned());
    };
    let preview = votport_client_core::ffi::inspect(link.clone(), None);
    let files: Vec<serde_json::Value> = preview
        .files
        .iter()
        .map(|file| serde_json::json!({ "path": file.path, "bytes": file.bytes }))
        .collect();
    out!(
        "{}",
        serde_json::json!({
            "kind": preview.kind.map(|kind| format!("{kind:?}").to_lowercase()),
            "problem": preview.problem,
            "detail": preview.detail,
            "label": preview.label,
            "needs_password": preview.needs_password,
            "usable": preview.usable,
            "quic": preview.quic,
            "max_bytes": preview.max_bytes,
            "max_entries": preview.max_entries,
            "total_bytes": preview.total_bytes,
            "files": files,
        })
    );
    Ok(if preview.usable {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// Prints the journalled transfers, one JSON object per line, oldest first.
fn status(args: &[String]) -> Result<(), String> {
    if let Some(error) = takes_nothing("status", args) {
        return Err(error);
    }
    for entry in votport_client_core::ffi::pending() {
        out!(
            "{}",
            serde_json::json!({
                "id": entry.id,
                "kind": format!("{:?}", entry.kind).to_lowercase(),
                "link": entry.link,
                "paths": entry.paths,
                "dest": entry.dest,
                "needs_password": entry.needs_password,
                "started_unix": entry.started_unix,
            })
        );
    }
    Ok(())
}

/// Runs a journalled transfer again, through the same view the shells draw.
fn resume(args: &[String]) -> Result<(), String> {
    let (mut options, positional, json) = parse(args, &["--password", "--password-file"])?;
    let password = secret_from(&mut options, "--password-file", "--password")?;
    let [id] = positional.as_slice() else {
        return Err("resume needs one transfer id from `votport status`".to_owned());
    };
    let listener = std::sync::Arc::new(ViewPrinter { json });
    let report = votport_client_core::ffi::resume(
        id.clone(),
        password,
        None,
        votport_client_core::ffi::Transfer::new(),
        listener,
    )
    .map_err(human)?;
    let (kind, files) = match &report {
        votport_client_core::ffi::ResumeReport::Sent(sent) => ("send", sent.files),
        votport_client_core::ffi::ResumeReport::Received(received) => {
            ("receive", received.files.len() as u64)
        }
    };
    if json {
        out!(
            "{}",
            serde_json::json!({ "event": "done", "kind": kind, "files": files })
        );
    } else {
        out!(
            "done: {files} {}, {kind} complete",
            if files == 1 { "file" } else { "files" }
        );
    }
    Ok(())
}

/// Prints each view the core hands over: the JSON record, or one status line
/// per phase change.
struct ViewPrinter {
    json: bool,
}

impl votport_client_core::ffi::TransferListener for ViewPrinter {
    fn update(&self, view: votport_client_core::ffi::TransferView) {
        if self.json {
            out!(
                "{}",
                serde_json::json!({
                    "event": "view",
                    "phase": format!("{:?}", view.phase).to_lowercase(),
                    "moved": view.moved_bytes,
                    "total": view.total_bytes,
                    "rate": view.rate_bytes_per_second,
                    "eta": view.eta_seconds,
                    "headline": view.headline,
                    "detail": view.detail,
                    "status": view.status,
                    "route": view.route,
                })
            );
        } else if let Some(headline) = view.headline {
            eprintln!("{headline}");
        }
    }
}

fn receive(args: &[String]) -> Result<(), String> {
    let (mut options, positional, json) = parse(args, &["--password", "--password-file"])?;
    let password = secret_from(&mut options, "--password-file", "--password")?;
    let [link, dir] = positional.as_slice() else {
        return Err("receive needs one delivery link and one directory".to_owned());
    };
    // Journalled like send, so an interrupted receive is resumable too.
    let received = votport_client_core::ffi::receive(
        link.clone(),
        password,
        dir.clone(),
        votport_client_core::ffi::Transfer::new(),
        Arc::new(ViewPrinter { json }),
    )
    .map_err(human)?;
    if json {
        out!(
            "{{\"event\":\"done\",\"via\":\"receive\",\"files\":{}}}",
            received.files.len()
        );
    } else {
        out!(
            "done: {} {} received into {dir}",
            received.files.len(),
            if received.files.len() == 1 {
                "file"
            } else {
                "files"
            }
        );
    }
    Ok(())
}

/// The parsed `--flag value` options of a command.
type Options = std::collections::HashMap<String, String>;

/// The error for a command that takes positionals but no options, when one
/// was passed: it names the option instead of blaming the positional count.
fn no_options(command: &str, args: &[String]) -> Option<String> {
    let flag = args.iter().find(|arg| arg.starts_with('-'))?;
    Some(format!("{command} takes no options ({flag} was given)"))
}

/// The error for a command that takes nothing at all, when it was handed
/// something: it names what was given instead of running on.
fn takes_nothing(command: &str, args: &[String]) -> Option<String> {
    let given = args.first()?;
    Some(format!("{command} takes no arguments ({given} was given)"))
}

/// Splits `args` into `--flag value` options and positionals; `--json` is a
/// bare flag. Unknown `--` options are refused.
fn parse(args: &[String], valued: &[&str]) -> Result<(Options, Vec<String>, bool), String> {
    let mut options = Options::new();
    let mut positional = Vec::new();
    let mut json = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--json" => json = true,
            flag if valued.contains(&flag) => {
                let value = iter.next().ok_or_else(|| format!("{flag} needs a value"))?;
                options.insert(flag.to_owned(), value.clone());
            }
            value if value.starts_with("--") => return Err(format!("unknown option {value:?}")),
            value => positional.push(value.to_owned()),
        }
    }
    Ok((options, positional, json))
}

fn number<T: std::str::FromStr>(options: &Options, flag: &str) -> Result<Option<T>, String> {
    options
        .get(flag)
        .map(|value| value.parse().map_err(|_| format!("{flag} wants a number")))
        .transpose()
}

/// Reads a secret from `--password-file` (a path, or `-` for stdin) with
/// `--password` as the fallback. The file wins and says so on stderr; one
/// trailing newline is trimmed and an empty secret is refused, because an
/// empty password never authenticates.
fn secret_from(
    options: &mut Options,
    file_flag: &str,
    value_flag: &str,
) -> Result<Option<String>, String> {
    if let Some(path) = options.remove(file_flag) {
        if options.contains_key(value_flag) {
            eprintln!("votport: {value_flag} ignored; {file_flag} takes precedence");
        }
        let mut secret = if path == "-" {
            use std::io::Read;
            let mut secret = String::new();
            std::io::stdin()
                .read_to_string(&mut secret)
                .map_err(|error| format!("{file_flag}: {error}"))?;
            secret
        } else {
            std::fs::read_to_string(&path)
                .map_err(|error| format!("{file_flag} {path}: {error}"))?
        };
        if secret.ends_with('\n') {
            secret.pop();
            if secret.ends_with('\r') {
                secret.pop();
            }
        }
        if secret.is_empty() {
            return Err(format!("{file_flag} was empty"));
        }
        return Ok(Some(secret));
    }
    Ok(options.remove(value_flag))
}

fn human(error: votport_client_core::Error) -> String {
    format!("{} ({error})", error.headline())
}

/// `votport signin <origin> [--password <p>]`: the password is read from
/// stdin when not given, so it stays out of the shell history.
fn signin(args: &[String]) -> Result<(), String> {
    let (mut options, positional, _) = parse(args, &["--password", "--password-file"])?;
    let [base] = positional.as_slice() else {
        return Err("signin takes the votport's origin, e.g. https://drop.example".to_owned());
    };
    let password = match secret_from(&mut options, "--password-file", "--password")? {
        Some(password) => password,
        None => {
            eprint!("password: ");
            read_secret_line().map_err(|error| error.to_string())?
        }
    };
    let port = votport_client_core::port::sign_in(base, &password).map_err(human)?;
    out!("signed in to {}{}", port.base, tenant_suffix(&port.tenant));
    Ok(())
}

/// Reads one line with terminal echo off, so a typed password is neither
/// shown nor left in scrollback. Input that is not a terminal (a pipe) is
/// read as it is.
fn read_secret_line() -> std::io::Result<String> {
    let echo = EchoOff::new();
    let mut line = String::new();
    let read = std::io::stdin().read_line(&mut line);
    if echo.active() {
        // The Enter that ended the line was not echoed either.
        eprintln!();
    }
    drop(echo);
    read?;
    Ok(line.trim_end_matches(['\r', '\n']).to_owned())
}

/// Terminal echo held off until dropped.
#[cfg(unix)]
struct EchoOff(Option<rustix::termios::Termios>);

#[cfg(unix)]
impl EchoOff {
    fn new() -> Self {
        use rustix::termios::{tcgetattr, tcsetattr, LocalModes, OptionalActions};
        let stdin = std::io::stdin();
        let Ok(saved) = tcgetattr(&stdin) else {
            return Self(None);
        };
        let mut quiet = saved.clone();
        quiet.local_modes.remove(LocalModes::ECHO);
        match tcsetattr(&stdin, OptionalActions::Now, &quiet) {
            Ok(()) => Self(Some(saved)),
            Err(_) => Self(None),
        }
    }

    fn active(&self) -> bool {
        self.0.is_some()
    }
}

#[cfg(unix)]
impl Drop for EchoOff {
    fn drop(&mut self) {
        if let Some(saved) = &self.0 {
            let _ = rustix::termios::tcsetattr(
                std::io::stdin(),
                rustix::termios::OptionalActions::Now,
                saved,
            );
        }
    }
}

#[cfg(windows)]
struct EchoOff(Option<(windows_sys::Win32::Foundation::HANDLE, u32)>);

#[cfg(windows)]
impl EchoOff {
    fn new() -> Self {
        use windows_sys::Win32::System::Console::{
            GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_ECHO_INPUT, STD_INPUT_HANDLE,
        };
        // SAFETY: the standard input handle is owned by the process and the
        // mode is read into a local before it is written back.
        unsafe {
            let handle = GetStdHandle(STD_INPUT_HANDLE);
            let mut mode = 0;
            if GetConsoleMode(handle, &mut mode) == 0
                || SetConsoleMode(handle, mode & !ENABLE_ECHO_INPUT) == 0
            {
                return Self(None);
            }
            Self(Some((handle, mode)))
        }
    }

    fn active(&self) -> bool {
        self.0.is_some()
    }
}

#[cfg(windows)]
impl Drop for EchoOff {
    fn drop(&mut self) {
        if let Some((handle, mode)) = self.0 {
            // SAFETY: restores the mode read in `new` on the same handle.
            unsafe {
                windows_sys::Win32::System::Console::SetConsoleMode(handle, mode);
            }
        }
    }
}

fn tenant_suffix(tenant: &str) -> String {
    if tenant.is_empty() {
        String::new()
    } else {
        format!(" (tenant {tenant})")
    }
}

fn port_status(args: &[String]) -> Result<(), String> {
    let (_, _, json) = parse(args, &[])?;
    let port = votport_client_core::port::check().map_err(human)?;
    if json {
        out!(
            "{}",
            serde_json::json!({ "port": port.as_ref().map(|p| serde_json::json!({ "base": p.base, "tenant": p.tenant })) })
        );
    } else if let Some(port) = port {
        out!("signed in to {}{}", port.base, tenant_suffix(&port.tenant));
    } else {
        out!("not signed in");
    }
    Ok(())
}

fn requests(args: &[String]) -> Result<(), String> {
    let (_, _, json) = parse(args, &[])?;
    let links = votport_client_core::port::requests().map_err(human)?;
    if json {
        for link in &links {
            out!("{}", request_json(link));
        }
    } else if links.is_empty() {
        out!("no open request links");
    } else {
        for link in &links {
            out!("{}", request_line(link));
        }
    }
    Ok(())
}

fn request_json(link: &votport_client_core::port::RequestLink) -> serde_json::Value {
    serde_json::json!({
        "id": link.id, "label": link.label, "url": link.url, "has_password": link.has_password,
        "created_at": link.created_at, "expires_at": link.expires_at, "max_bytes": link.max_bytes,
        "usable": link.usable, "active": link.active, "drops": link.drops, "receiving": link.receiving,
    })
}

fn request_line(link: &votport_client_core::port::RequestLink) -> String {
    let mut parts = vec![link.label.clone(), link.url.clone()];
    if link.has_password {
        parts.push("password".to_owned());
    }
    parts.push(format!(
        "{} {}",
        link.drops,
        if link.drops == 1 { "drop" } else { "drops" }
    ));
    if link.receiving > 0 {
        parts.push(format!("{} shipping now", link.receiving));
    }
    parts.join("  ")
}

fn issue_request(args: &[String]) -> Result<(), String> {
    let (options, positional, json) =
        parse(args, &["--password", "--expires-days", "--max-bytes"])?;
    let [label] = positional.as_slice() else {
        return Err("issue-request takes a label".to_owned());
    };
    let link = votport_client_core::port::issue_request(votport_client_core::port::RequestSpec {
        label: label.clone(),
        password: options.get("--password").cloned(),
        expires_days: number(&options, "--expires-days")?,
        max_bytes: number(&options, "--max-bytes")?,
    })
    .map_err(human)?;
    if json {
        out!("{}", request_json(&link));
    } else {
        out!("{}", link.url);
    }
    Ok(())
}

fn close_request(args: &[String]) -> Result<(), String> {
    if let Some(error) = no_options("close-request", args) {
        return Err(error);
    }
    let [id] = args else {
        return Err("close-request takes a link id".to_owned());
    };
    votport_client_core::port::close_request(id).map_err(human)
}

fn delivery_json(delivery: &votport_client_core::port::Delivery) -> serde_json::Value {
    serde_json::json!({
        "id": delivery.id, "label": delivery.label, "name": delivery.name,
        "has_password": delivery.has_password, "created_at": delivery.created_at,
        "expires_at": delivery.expires_at, "revoked_at": delivery.revoked_at,
        "downloads": delivery.downloads, "max_downloads": delivery.max_downloads,
        "file_count": delivery.file_count,
    })
}

fn deliveries(args: &[String]) -> Result<(), String> {
    let (_, _, json) = parse(args, &[])?;
    let list = votport_client_core::port::deliveries().map_err(human)?;
    if json {
        for delivery in &list {
            out!("{}", delivery_json(delivery));
        }
    } else if list.is_empty() {
        out!("no deliveries");
    } else {
        for delivery in &list {
            let name = delivery
                .label
                .clone()
                .or_else(|| delivery.name.clone())
                .unwrap_or_else(|| delivery.id.clone());
            let state = if delivery.revoked_at.is_some() {
                "revoked"
            } else {
                "live"
            };
            out!(
                "{}  {}  {} {}  {} {}  {state}",
                delivery.id,
                name,
                delivery.file_count,
                if delivery.file_count == 1 {
                    "file"
                } else {
                    "files"
                },
                delivery.downloads,
                if delivery.downloads == 1 {
                    "download"
                } else {
                    "downloads"
                }
            );
        }
    }
    Ok(())
}

fn revoke_delivery(args: &[String]) -> Result<(), String> {
    if let Some(error) = no_options("revoke-delivery", args) {
        return Err(error);
    }
    let [id] = args else {
        return Err("revoke-delivery takes a delivery id".to_owned());
    };
    votport_client_core::port::revoke_delivery(id).map_err(human)
}

fn library(args: &[String]) -> Result<(), String> {
    let (options, positional, json) = parse(args, &["--after"])?;
    let directory = positional.first().cloned().unwrap_or_default();
    let listing =
        votport_client_core::port::library(&directory, options.get("--after").map(String::as_str))
            .map_err(human)?;
    if json {
        out!(
            "{}",
            serde_json::json!({
                "directory": listing.directory,
                "directories": listing.directories,
                "files": listing.files.iter().map(|f| serde_json::json!({ "path": f.path, "bytes": f.bytes })).collect::<Vec<_>>(),
                "truncated": listing.truncated,
                "next_cursor": listing.next_cursor,
            })
        );
    } else {
        for name in &listing.directories {
            out!("{name}/");
        }
        for file in &listing.files {
            out!("{}  {}", file.path, file.bytes);
        }
        if listing.truncated {
            out!(
                "(more not listed; use --after {})",
                listing.next_cursor.as_deref().unwrap_or_default()
            );
        }
    }
    Ok(())
}

fn issue_delivery(args: &[String]) -> Result<(), String> {
    let (options, positional, json) =
        parse(args, &["--password", "--expires-days", "--max-downloads"])?;
    let Some((label, paths)) = positional.split_first() else {
        return Err("issue-delivery takes a label and at least one library path".to_owned());
    };
    if paths.is_empty() {
        return Err("issue-delivery needs at least one library path".to_owned());
    }
    if let Some(path) = paths.iter().find(|path| is_absolute_filesystem_path(path)) {
        return Err(format!(
            "{path:?} is a local filesystem path. Upload it first with `votport upload <path>`, then use the printed library path."
        ));
    }
    let issued =
        votport_client_core::port::issue_delivery(votport_client_core::port::DeliverySpec {
            paths: paths.to_vec(),
            label: label.clone(),
            password: options.get("--password").cloned(),
            expires_days: number(&options, "--expires-days")?.unwrap_or(7),
            max_downloads: number(&options, "--max-downloads")?,
        })
        .map_err(human)?;
    if json {
        out!(
            "{}",
            serde_json::json!({ "url": issued.url, "delivery": delivery_json(&issued.delivery) })
        );
    } else {
        out!("{}", issued.url);
    }
    Ok(())
}

fn is_absolute_filesystem_path(value: &str) -> bool {
    Path::new(value).is_absolute()
        || value.starts_with(r"\\")
        || value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_alphabetic())
            && value.as_bytes().get(1) == Some(&b':')
            && matches!(value.as_bytes().get(2), Some(b'/' | b'\\'))
}

/// `votport upload <path>... [--into <dir>]`: each file or folder goes into
/// the library under `--into` (today's date when not given) and its library
/// paths are printed, ready for `issue-delivery`.
fn upload(args: &[String]) -> Result<(), String> {
    let (options, positional, json) = parse(args, &["--into"])?;
    if positional.is_empty() {
        return Err("upload takes at least one file or folder".to_owned());
    }
    struct Quiet;
    impl votport_client_core::port::UploadListener for Quiet {
        fn update(&self, _view: votport_client_core::port::UploadView) {}
    }
    let into = options.get("--into").cloned().unwrap_or_default();
    let made =
        votport_client_core::port::upload(&positional, &into, &|| false, &Quiet).map_err(human)?;
    if json {
        out!(
            "{}",
            serde_json::json!(made
                .iter()
                .map(|f| serde_json::json!({ "path": f.path, "bytes": f.bytes }))
                .collect::<Vec<_>>())
        );
    } else {
        for file in &made {
            out!("{}  {}", file.path, file.bytes);
        }
    }
    Ok(())
}

/// `votport watch add <dir> <link> [--password <p>]`, `watch list`,
/// `watch remove <id>`, and `watch run`, which scans every watched folder
/// and ships each settled drop in turn until interrupted.
fn watch(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("add") => {
            let (options, positional, json) = parse(&args[1..], &["--password"])?;
            let [dir, link] = positional.as_slice() else {
                return Err("watch add takes a folder and a request link".to_owned());
            };
            let added = votport_client_core::watch::add_watch(
                dir,
                link,
                options.get("--password").cloned(),
            )
            .map_err(human)?;
            if json {
                out!("{}", watch_json(&added));
            } else {
                out!("{}  {}  {}", added.id, added.dir, added.link);
            }
            Ok(())
        }
        Some("list") => {
            let (_, _, json) = parse(&args[1..], &[])?;
            for item in votport_client_core::watch::watches() {
                if json {
                    out!("{}", watch_json(&item));
                } else {
                    out!("{}  {}  {}", item.id, item.dir, item.link);
                }
            }
            Ok(())
        }
        Some("remove") => {
            let [_, id] = args else {
                return Err("watch remove takes a watch id".to_owned());
            };
            votport_client_core::watch::remove_watch(id).map_err(human)
        }
        Some("run") => {
            let (_, _, json) = parse(&args[1..], &[])?;
            if votport_client_core::watch::watches().is_empty() {
                return Err("no watched folders; add one with `votport watch add`".to_owned());
            }
            struct Ship {
                json: bool,
            }
            impl votport_client_core::watch::WatchListener for Ship {
                fn ready(
                    &self,
                    watch_id: String,
                    path: String,
                    admission: std::sync::Arc<votport_client_core::watch::WatchAdmission>,
                ) {
                    // ponytail: one drop at a time on the watcher's thread;
                    // a pool when a facility drops faster than it ships.
                    let listener = std::sync::Arc::new(ViewPrinter { json: self.json });
                    let transfer = votport_client_core::ffi::Transfer::new();
                    match votport_client_core::ffi::ship(
                        watch_id,
                        path.clone(),
                        admission,
                        transfer,
                        listener,
                    ) {
                        Ok(report) if self.json => out!(
                            "{}",
                            serde_json::json!({ "event": "shipped", "path": path, "files": report.files, "parked": report.parked, "park_problem": report.park_problem })
                        ),
                        Ok(report) => match report.park_problem {
                            Some(problem) => out!(
                                "shipped {path}: {} {}, left in place: {problem}",
                                report.files,
                                if report.files == 1 { "file" } else { "files" }
                            ),
                            None => out!(
                                "shipped {path}: {} {}",
                                report.files,
                                if report.files == 1 { "file" } else { "files" }
                            ),
                        },
                        Err(error) if self.json => out!(
                            "{}",
                            serde_json::json!({ "event": "failed", "path": path, "headline": error.headline(), "detail": error.to_string() })
                        ),
                        Err(error) => eprintln!("{path}: {}", human(error)),
                    }
                }
            }
            let _watcher =
                votport_client_core::watch::watch_all(std::sync::Arc::new(Ship { json }));
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        }
        _ => Err("watch takes add, list, remove, or run".to_owned()),
    }
}

fn watch_json(item: &votport_client_core::watch::Watch) -> serde_json::Value {
    serde_json::json!({ "id": item.id, "dir": item.dir, "link": item.link, "has_password": item.has_password })
}

#[cfg(test)]
mod tests {
    #[test]
    fn password_files_win_over_argv_and_trim_one_newline() {
        let directory = std::env::temp_dir().join(format!(
            "votport-cli-secret-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("secret");
        std::fs::write(&path, "hush\n").unwrap();
        let mut options = std::collections::HashMap::new();
        options.insert("--password-file".to_owned(), path.display().to_string());
        options.insert("--password".to_owned(), "argv".to_owned());
        // The file wins over the argv password, minus its one trailing newline.
        assert_eq!(
            super::secret_from(&mut options, "--password-file", "--password")
                .unwrap()
                .as_deref(),
            Some("hush")
        );
        // The argv password remains as the fallback once the file is read.
        assert_eq!(
            super::secret_from(&mut options, "--password-file", "--password")
                .unwrap()
                .as_deref(),
            Some("argv")
        );
        // An empty secret file is refused, not silently accepted.
        let empty = directory.join("empty");
        std::fs::write(&empty, "").unwrap();
        let mut options = std::collections::HashMap::new();
        options.insert("--password-file".to_owned(), empty.display().to_string());
        assert!(super::secret_from(&mut options, "--password-file", "--password").is_err());
        let _ = std::fs::remove_dir_all(&directory);
    }
}
