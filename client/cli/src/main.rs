//! `votport` command line client.
//!
//! `votport send <link> <path>...` sends files and folders to a votport
//! request link, over QUIC push when the link offers it and the receiver's
//! carrier answers, over HTTP otherwise.

mod agent;
mod mcp;

use std::path::Path;
use std::process::ExitCode;

use votport_client_core::progress::{Event, Observer};
use votport_client_core::{
    receive_with_device_or_http, split_link_as, Delivery, Device, Drop, LinkKind, Sent, Transport,
};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|arg| arg == "agent") {
        return match agent::run(&args[1..]) {
            Ok(value) => {
                println!("{value}");
                ExitCode::SUCCESS
            }
            Err(value) => {
                println!("{value}");
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
                println!(
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
        Some("status") => status(),
        Some("evidence") => evidence(&args[1..]),
        Some("resume") => resume(&args[1..]),
        Some("signin") => signin(&args[1..]),
        Some("signout") => {
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
    println!("{value}");
    Ok(())
}

fn print_usage() {
    eprintln!("votport agent session
votport agent files [<directory>] [--after <cursor>] [--limit <n>]
votport agent share <directory> --operation-id <id> [--expires-days <n>] [--label <label>] [--max-downloads <n>]
votport agent recover <operation-id>
votport agent deliveries [--after <cursor>] [--limit <n>]
votport agent delivery <id> [--offset <n>] [--limit <n>]
votport agent revoke <id>
votport agent projects
votport agent jobs [--after <cursor>] [--limit <n>]
votport agent create-job <request.json | ->
votport agent job | retry-job | cancel-job <id>
votport agent events [--after <cursor>] [--limit <n>]
votport agent job-evidence <id> [--after <cursor>] [--limit <n>]
votport evidence list | device-key | retry
votport evidence accept <verification-id>
votport mcp

Verification reports are queued durably. Long-running desktop apps retry automatically;
short-lived CLI processes can flush pending reports with votport evidence retry.
Agent commands always return JSON and use VOTPORT_URL and VOTPORT_AUTOMATION_TOKEN.
");
    eprintln!(
        "votport send <link> <path>...      [--password <p> | --password-file <path|->] [--json]\n\
         votport receive <link> <dir>       [--password <p> | --password-file <path|->] [--json]\n\
         votport inspect <link>\n\
         votport status\n\
         votport resume <id>                [--password <p> | --password-file <path|->] [--json]\n\
         votport signin <origin>            [--password <p> | --password-file <path|->]  (else read from stdin)\n\
         votport signout\n\
         votport port                       [--json]\n\
         votport requests                   [--json]\n\
         votport issue-request <label>      [--password <p>] [--expires-days <n>] [--max-bytes <n>] [--json]\n\
         votport close-request <id>\n\
         votport deliveries                 [--json]\n\
         votport revoke-delivery <id>\n\
         votport library [<dir>]            [--after <cursor>] [--json]\n\
         votport issue-delivery <label> <path>... [--password <p>] [--expires-days <n>] [--max-downloads <n>] [--json]\n\
         votport upload <path>...           [--into <dir>] [--json]\n\
         votport watch add <dir> <link>     [--password <p>]\n\
         votport watch list | remove <id> | run [--json]\n\
         \n\
         send's <link> is a request URL, e.g. https://drop.example/r/TOKEN;\n\
         each <path> is a file or folder, and a folder keeps its name.\n\
         receive's <link> is a delivery URL, e.g. https://drop.example/s/TOKEN;\n\
         <dir> is where its files land, verified against their announced roots."
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
    let link = split_link_as(link, LinkKind::Request).map_err(|error| error.to_string())?;
    let (base, token) = (link.base, link.token);
    let info = votport_client_core::api::Client::new(&base)
        .map_err(|error| error.to_string())?
        .link_info(&token)
        .map_err(|error| error.to_string())?;

    let mut files = Vec::new();
    for path in paths {
        votport_client_core::transfer::collect_for_link(
            Path::new(path),
            &mut files,
            info.allow_hidden,
        )
        .map_err(|error| format!("{path}: {error}"))?;
    }
    if files.is_empty() {
        return Err("none of the given paths held any files".to_owned());
    }

    let drop = Drop {
        token,
        password,
        files,
    };

    let device = Device::load_or_create().map_err(|error| error.to_string())?;
    let mut observer = CliObserver { json };
    let sent = votport_client_core::send(&base, drop, &device, &mut observer)
        .map_err(|error| error.to_string())?;
    match sent {
        Sent::Push { files } => {
            if json {
                println!("{{\"event\":\"done\",\"via\":\"push\",\"files\":{files}}}");
            } else {
                println!("done: {files} file(s) pushed");
            }
        }
        Sent::Http(report) => {
            if json {
                println!(
                    "{{\"event\":\"done\",\"via\":\"http\",\"upload_id\":{:?},\"files\":{}}}",
                    report.upload_id,
                    report.files.len()
                );
            } else {
                println!(
                    "done: {} file(s) published (upload {})",
                    report.files.len(),
                    report.upload_id
                );
            }
        }
    }
    Ok(())
}

/// Prints what a link is as one JSON object, spending nothing on the server.
fn inspect(args: &[String]) -> Result<ExitCode, String> {
    let [link] = args else {
        return Err("inspect takes one link".to_owned());
    };
    let preview = votport_client_core::ffi::inspect(link.clone(), None);
    let files: Vec<serde_json::Value> = preview
        .files
        .iter()
        .map(|file| serde_json::json!({ "path": file.path, "bytes": file.bytes }))
        .collect();
    println!(
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
fn status() -> Result<(), String> {
    for entry in votport_client_core::ffi::pending() {
        println!(
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
    .map_err(|error| error.to_string())?;
    let (kind, files) = match &report {
        votport_client_core::ffi::ResumeReport::Sent(sent) => ("send", sent.files),
        votport_client_core::ffi::ResumeReport::Received(received) => {
            ("receive", received.files.len() as u64)
        }
    };
    if json {
        println!(
            "{}",
            serde_json::json!({ "event": "done", "kind": kind, "files": files })
        );
    } else {
        println!("done: {files} file(s), {kind} complete");
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
            println!(
                "{}",
                serde_json::json!({
                    "event": "view",
                    "phase": format!("{:?}", view.phase).to_lowercase(),
                    "moved": view.moved_bytes,
                    "total": view.total_bytes,
                    "rate": view.rate_bytes_per_second,
                    "eta": view.eta_seconds,
                    "headline": view.headline,
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
    let link = split_link_as(link, LinkKind::Delivery).map_err(|error| error.to_string())?;
    let (base, token) = (link.base, link.token);

    let delivery = Delivery { token, password };
    let mut observer = CliObserver { json };
    let received = receive_with_device_or_http(&base, delivery, Path::new(dir), &mut observer)
        .map_err(|error| error.to_string())?;
    if json {
        println!(
            "{{\"event\":\"done\",\"via\":\"receive\",\"files\":{}}}",
            received.files.len()
        );
    } else {
        println!("done: {} file(s) received into {dir}", received.files.len());
    }
    Ok(())
}

fn transport_name(transport: Transport) -> &'static str {
    match transport {
        Transport::Push => "push",
        Transport::Http => "http",
        Transport::Fetch => "fetch",
    }
}

struct CliObserver {
    json: bool,
}

impl Observer for CliObserver {
    fn event(&mut self, event: Event) {
        if matches!(event, Event::Transferred { .. }) {
            return;
        }
        if self.json {
            use serde_json::json;
            let line = match &event {
                Event::Evidence { status } => {
                    json!({"event": "delivery_evidence", "status": status})
                }
                Event::Transferred { .. } => return,
                Event::Selected { files } | Event::Planned { files } => {
                    json!({"event": if matches!(event, Event::Selected { .. }) { "selected" } else { "planned" }, "files": files.iter().map(|f| json!({"index": f.index, "path": f.path, "bytes": f.bytes})).collect::<Vec<_>>()})
                }
                Event::Transport(transport) => {
                    json!({"event": "transport", "via": transport_name(*transport)})
                }
                Event::Bytes { moved, total } => {
                    json!({"event": "bytes", "moved": moved, "total": total})
                }
                Event::SessionCreated { session } => {
                    json!({"event": "session", "session": session})
                }
                Event::Chunk {
                    index,
                    covered,
                    total,
                } => json!({"event": "chunk", "entry": index, "covered": covered, "total": total}),
                Event::EntryComplete { index, path } => {
                    json!({"event": "entry", "index": index, "path": path})
                }
                Event::Rebegin => json!({"event": "rebegin"}),
                Event::Finished { files } => json!({"event": "finished", "files": files}),
                Event::Downloading {
                    index,
                    received,
                    total,
                } => {
                    json!({"event": "downloading", "index": index, "received": received, "total": total})
                }
                Event::FileVerified { index, path } => {
                    json!({"event": "verified", "index": index, "path": path})
                }
            };
            println!("{line}");
            return;
        }
        match event {
            Event::Evidence { status } => println!("  delivery evidence: {status}"),
            Event::Transport(_) | Event::Bytes { .. } | Event::Transferred { .. } => {}
            Event::Selected { .. } | Event::Planned { .. } => {}
            Event::SessionCreated { .. } => {}
            Event::Chunk { .. } => {}
            Event::EntryComplete { path, .. } => println!("  sent {path}"),
            Event::Rebegin => println!("  server restarted; resuming"),
            Event::Finished { .. } => {}
            Event::Downloading { .. } => {}
            Event::FileVerified { path, .. } => println!("  received {path}"),
        }
    }
}

/// The parsed `--flag value` options of a command.
type Options = std::collections::HashMap<String, String>;

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
            let mut line = String::new();
            std::io::stdin()
                .read_line(&mut line)
                .map_err(|error| error.to_string())?;
            line.trim_end_matches(['\r', '\n']).to_owned()
        }
    };
    let port = votport_client_core::port::sign_in(base, &password).map_err(human)?;
    println!("signed in to {}{}", port.base, tenant_suffix(&port.tenant));
    Ok(())
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
        println!(
            "{}",
            serde_json::json!({ "port": port.as_ref().map(|p| serde_json::json!({ "base": p.base, "tenant": p.tenant })) })
        );
    } else if let Some(port) = port {
        println!("signed in to {}{}", port.base, tenant_suffix(&port.tenant));
    } else {
        println!("not signed in");
    }
    Ok(())
}

fn requests(args: &[String]) -> Result<(), String> {
    let (_, _, json) = parse(args, &[])?;
    let links = votport_client_core::port::requests().map_err(human)?;
    if json {
        for link in &links {
            println!("{}", request_json(link));
        }
    } else if links.is_empty() {
        println!("no open request links");
    } else {
        for link in &links {
            println!("{}", request_line(link));
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
    parts.push(format!("{} drop(s)", link.drops));
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
        println!("{}", request_json(&link));
    } else {
        println!("{}", link.url);
    }
    Ok(())
}

fn close_request(args: &[String]) -> Result<(), String> {
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
            println!("{}", delivery_json(delivery));
        }
    } else if list.is_empty() {
        println!("no deliveries");
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
            println!(
                "{}  {}  {} file(s)  {} download(s)  {state}",
                delivery.id, name, delivery.file_count, delivery.downloads
            );
        }
    }
    Ok(())
}

fn revoke_delivery(args: &[String]) -> Result<(), String> {
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
        println!(
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
            println!("{name}/");
        }
        for file in &listing.files {
            println!("{}  {}", file.path, file.bytes);
        }
        if listing.truncated {
            println!(
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
        println!(
            "{}",
            serde_json::json!({ "url": issued.url, "delivery": delivery_json(&issued.delivery) })
        );
    } else {
        println!("{}", issued.url);
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
        println!(
            "{}",
            serde_json::json!(made
                .iter()
                .map(|f| serde_json::json!({ "path": f.path, "bytes": f.bytes }))
                .collect::<Vec<_>>())
        );
    } else {
        for file in &made {
            println!("{}  {}", file.path, file.bytes);
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
                println!("{}", watch_json(&added));
            } else {
                println!("{}  {}  {}", added.id, added.dir, added.link);
            }
            Ok(())
        }
        Some("list") => {
            let (_, _, json) = parse(&args[1..], &[])?;
            for item in votport_client_core::watch::watches() {
                if json {
                    println!("{}", watch_json(&item));
                } else {
                    println!("{}  {}  {}", item.id, item.dir, item.link);
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
                        Ok(report) if self.json => println!(
                            "{}",
                            serde_json::json!({ "event": "shipped", "path": path, "files": report.files, "parked": report.parked, "park_problem": report.park_problem })
                        ),
                        Ok(report) => match report.park_problem {
                            Some(problem) => println!(
                                "shipped {path}: {} file(s), left in place: {problem}",
                                report.files
                            ),
                            None => println!("shipped {path}: {} file(s)", report.files),
                        },
                        Err(error) if self.json => println!(
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
    use super::{is_absolute_filesystem_path, issue_delivery};

    #[test]
    fn transfer_commands_share_option_validation() {
        for command in ["send", "receive", "resume"] {
            for (arguments, expected) in [
                (vec![command, "--password"], "--password needs a value"),
                (vec![command, "--unknown"], "unknown option"),
            ] {
                let arguments = arguments.into_iter().map(str::to_owned).collect::<Vec<_>>();
                assert!(super::run(&arguments).unwrap_err().contains(expected));
            }
        }
        let args = [
            "link",
            "--password",
            "first",
            "a file",
            "--json",
            "--password",
            "last",
        ]
        .map(str::to_owned);
        let (options, positional, json) = super::parse(&args, &["--password"]).unwrap();
        assert_eq!(options["--password"], "last");
        assert_eq!(positional, ["link", "a file"]);
        assert!(json);
        for arguments in [
            vec!["receive", "link", "dir", "extra"],
            vec!["resume", "id", "extra"],
        ] {
            let args = arguments.into_iter().map(str::to_owned).collect::<Vec<_>>();
            assert!(super::run(&args).unwrap_err().contains("needs one"));
        }
    }

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

    #[test]
    fn issue_delivery_explains_unambiguous_local_paths_before_network() {
        for path in [
            "/tmp/clip.mov",
            r"C:\clips\clip.mov",
            "C:/clips/clip.mov",
            r"\\server\share\clip.mov",
        ] {
            let args = ["label".to_owned(), path.to_owned()];
            let error = issue_delivery(&args).expect_err(path);
            assert!(error.contains("votport upload"), "{error}");
            assert!(error.contains("local filesystem path"), "{error}");
        }
    }

    #[test]
    fn relative_library_paths_are_not_classified_by_local_shape() {
        for path in ["clip.mov", "./clip.mov", "folder/clip.mov", "C:clip.mov"] {
            assert!(!is_absolute_filesystem_path(path), "{path}");
        }
    }
}
