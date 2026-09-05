//! `votport` command line client.
//!
//! `votport send <link> <path>...` sends files and folders to a votport
//! request link, over QUIC push when the link offers it and the receiver's
//! carrier answers, over HTTP otherwise.

use std::path::Path;
use std::process::ExitCode;

use votport_client_core::progress::{Event, Observer};
use votport_client_core::{
    collect, receive_with_device_or_http, split_link_as, Delivery, Device, Drop, LinkKind, Sent,
    Transport,
};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("votport: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("send") => send(&args[1..]),
        Some("receive") => receive(&args[1..]),
        Some("inspect") => inspect(&args[1..]),
        Some("status") => status(),
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
        Some("watch") => watch(&args[1..]),
        Some("help") | Some("--help") | Some("-h") | None => {
            print_usage();
            Ok(())
        }
        Some(other) => Err(format!("unknown command {other:?}; try `votport help`")),
    }
}

fn print_usage() {
    eprintln!(
        "votport send <link> <path>...      [--password <p>] [--json]\n\
         votport receive <link> <dir>       [--password <p>] [--json]\n\
         votport inspect <link>\n\
         votport status\n\
         votport resume <id>                [--password <p>] [--json]\n\
         votport signin <origin>            [--password <p>]  (else read from stdin)\n\
         votport signout\n\
         votport port                       [--json]\n\
         votport requests                   [--json]\n\
         votport issue-request <label>      [--password <p>] [--expires-days <n>] [--max-bytes <n>] [--json]\n\
         votport close-request <id>\n\
         votport deliveries                 [--json]\n\
         votport revoke-delivery <id>\n\
         votport library [<dir>]            [--json]\n\
         votport issue-delivery <label> <path>... [--password <p>] [--expires-days <n>] [--max-downloads <n>] [--json]\n\
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
    let mut link: Option<String> = None;
    let mut password: Option<String> = None;
    let mut json = false;
    let mut paths: Vec<String> = Vec::new();

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--password" => {
                password = Some(iter.next().ok_or("--password needs a value")?.clone());
            }
            "--json" => json = true,
            value if value.starts_with("--") => {
                return Err(format!("unknown option {value:?}"));
            }
            value if link.is_none() => link = Some(value.to_owned()),
            value => paths.push(value.to_owned()),
        }
    }

    let link = link.ok_or("send needs a link and at least one path")?;
    if paths.is_empty() {
        return Err("send needs at least one file or folder".to_owned());
    }
    let link = split_link_as(&link, LinkKind::Request).map_err(|error| error.to_string())?;
    let (base, token) = (link.base, link.token);

    let mut files = Vec::new();
    for path in &paths {
        collect(Path::new(path), &mut files).map_err(|error| format!("{path}: {error}"))?;
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
fn inspect(args: &[String]) -> Result<(), String> {
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
    Ok(())
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
    let mut id: Option<String> = None;
    let mut password: Option<String> = None;
    let mut json = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--password" => {
                password = Some(iter.next().ok_or("--password needs a value")?.clone());
            }
            "--json" => json = true,
            value if value.starts_with("--") => return Err(format!("unknown option {value:?}")),
            value if id.is_none() => id = Some(value.to_owned()),
            value => return Err(format!("unexpected argument {value:?}")),
        }
    }
    let id = id.ok_or("resume needs a transfer id from `votport status`")?;
    let listener = std::sync::Arc::new(ViewPrinter { json });
    let report = votport_client_core::ffi::resume(
        id,
        password,
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
    let mut link: Option<String> = None;
    let mut dir: Option<String> = None;
    let mut password: Option<String> = None;
    let mut json = false;

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--password" => {
                password = Some(iter.next().ok_or("--password needs a value")?.clone());
            }
            "--json" => json = true,
            value if value.starts_with("--") => {
                return Err(format!("unknown option {value:?}"));
            }
            value if link.is_none() => link = Some(value.to_owned()),
            value if dir.is_none() => dir = Some(value.to_owned()),
            value => return Err(format!("unexpected argument {value:?}")),
        }
    }

    let link = link.ok_or("receive needs a delivery link and a directory")?;
    let dir = dir.ok_or("receive needs a directory to land the files in")?;
    let link = split_link_as(&link, LinkKind::Delivery).map_err(|error| error.to_string())?;
    let (base, token) = (link.base, link.token);

    let delivery = Delivery { token, password };
    let mut observer = CliObserver { json };
    let received = receive_with_device_or_http(&base, delivery, Path::new(&dir), &mut observer)
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
        if self.json {
            let line = match &event {
                Event::Selected { files } | Event::Planned { files } => {
                    let name = if matches!(event, Event::Selected { .. }) {
                        "selected"
                    } else {
                        "planned"
                    };
                    let files: Vec<String> = files
                        .iter()
                        .map(|file| {
                            format!(
                                "{{\"index\":{},\"path\":{:?},\"bytes\":{}}}",
                                file.index, file.path, file.bytes
                            )
                        })
                        .collect();
                    format!("{{\"event\":{name:?},\"files\":[{}]}}", files.join(","))
                }
                Event::Transport(transport) => {
                    format!("{{\"event\":\"transport\",\"via\":{:?}}}", transport_name(*transport))
                }
                Event::Bytes { moved, total } => match total {
                    Some(total) => format!("{{\"event\":\"bytes\",\"moved\":{moved},\"total\":{total}}}"),
                    None => format!("{{\"event\":\"bytes\",\"moved\":{moved}}}"),
                },
                Event::SessionCreated { session } => {
                    format!("{{\"event\":\"session\",\"session\":{session:?}}}")
                }
                Event::Chunk { index, covered, total } => format!(
                    "{{\"event\":\"chunk\",\"entry\":{index},\"covered\":{covered},\"total\":{total}}}"
                ),
                Event::EntryComplete { index, path } => {
                    format!("{{\"event\":\"entry\",\"index\":{index},\"path\":{path:?}}}")
                }
                Event::Rebegin => "{\"event\":\"rebegin\"}".to_owned(),
                Event::Finished { files } => format!("{{\"event\":\"finished\",\"files\":{files}}}"),
                Event::Downloading { index, received, total } => format!(
                    "{{\"event\":\"downloading\",\"index\":{index},\"received\":{received},\"total\":{total}}}"
                ),
                Event::FileVerified { index, path } => {
                    format!("{{\"event\":\"verified\",\"index\":{index},\"path\":{path:?}}}")
                }
            };
            println!("{line}");
            return;
        }
        match event {
            Event::Transport(_) | Event::Bytes { .. } => {}
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

fn human(error: votport_client_core::Error) -> String {
    format!("{} ({error})", error.headline())
}

/// `votport signin <origin> [--password <p>]`: the password is read from
/// stdin when not given, so it stays out of the shell history.
fn signin(args: &[String]) -> Result<(), String> {
    let (options, positional, _) = parse(args, &["--password"])?;
    let [base] = positional.as_slice() else {
        return Err("signin takes the votport's origin, e.g. https://drop.example".to_owned());
    };
    let password = match options.get("--password") {
        Some(password) => password.clone(),
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
    let (_, positional, json) = parse(args, &[])?;
    let directory = positional.first().cloned().unwrap_or_default();
    let listing = votport_client_core::port::library(&directory).map_err(human)?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "directory": listing.directory,
                "directories": listing.directories,
                "files": listing.files.iter().map(|f| serde_json::json!({ "path": f.path, "bytes": f.bytes })).collect::<Vec<_>>(),
                "truncated": listing.truncated,
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
            println!("(more not listed)");
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
                fn ready(&self, watch_id: String, path: String) {
                    // ponytail: one drop at a time on the watcher's thread;
                    // a pool when a facility drops faster than it ships.
                    let listener = std::sync::Arc::new(ViewPrinter { json: self.json });
                    let transfer = votport_client_core::ffi::Transfer::new();
                    match votport_client_core::ffi::ship(watch_id, path.clone(), transfer, listener)
                    {
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
