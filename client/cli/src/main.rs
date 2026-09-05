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
    let preview = votport_client_core::ffi::inspect(link.clone());
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
