//! `votport` command line client.
//!
//! `votport send <link> <path>...` sends files and folders to a votport
//! request link, over QUIC push when the link offers it and the receiver's
//! carrier answers, over HTTP otherwise.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use votport_client_core::progress::{Event, Observer};
use votport_client_core::{Delivery, Device, Drop, Selected, Sent};

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
    let (base, token) = split_link(&link)?;

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
    let (base, token) = split_link(&link)?;

    let delivery = Delivery { token, password };
    let mut observer = CliObserver { json };
    // A device key is needed only for the QUIC fetch. When the state directory
    // is not writable, receive over HTTP rather than failing outright.
    let received = match Device::load_or_create() {
        Ok(device) => {
            votport_client_core::receive(&base, delivery, &device, Path::new(&dir), &mut observer)
        }
        Err(_) => {
            votport_client_core::receive_over_http(&base, delivery, Path::new(&dir), &mut observer)
        }
    }
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

/// Splits a request or delivery link into its origin and token. Accepts
/// `/r/<token>` and `/api/r/<token>` (send), `/s/<token>` and
/// `/api/s/<token>` (receive), with or without a trailing path, query, or
/// fragment.
fn split_link(link: &str) -> Result<(String, String), String> {
    let trimmed = link.split(['?', '#']).next().unwrap_or(link);
    for marker in ["/api/r/", "/r/", "/api/s/", "/s/"] {
        if let Some(index) = trimmed.find(marker) {
            let base = &trimmed[..index];
            let rest = &trimmed[index + marker.len()..];
            let token = rest.split('/').next().unwrap_or("").trim();
            if base.is_empty() || token.is_empty() {
                break;
            }
            return Ok((base.to_owned(), token.to_owned()));
        }
    }
    Err(format!(
        "{link:?} is not a votport link (expected .../r/TOKEN or .../s/TOKEN)"
    ))
}

/// Collects files under `path` into selections. A file keeps its own name; a
/// folder keeps its name as the top component, like a browser folder drop.
fn collect(path: &Path, out: &mut Vec<Selected>) -> std::io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        // A symlink arg would otherwise be neither file nor dir and yield
        // nothing silently; the manifest build refuses symlinks anyway.
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "symlinks are not sent",
        ));
    }
    if metadata.is_file() {
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.to_string_lossy().into_owned());
        out.push(Selected {
            relative: name,
            source: path.to_path_buf(),
        });
        return Ok(());
    }
    if metadata.is_dir() {
        // `.` and `..` have no file name; canonicalize so the folder keeps its
        // real name instead of flattening into the drop root.
        let top = match path.file_name() {
            Some(name) => name.to_string_lossy().into_owned(),
            None => std::fs::canonicalize(path)?
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, "the folder has no name")
                })?,
        };
        walk(path, &top, out)?;
    }
    Ok(())
}

/// Recursively adds files under `dir`, each relative to `prefix`. Symlinks are
/// skipped, matching the manifest build's refusal of them.
fn walk(dir: &Path, prefix: &str, out: &mut Vec<Selected>) -> std::io::Result<()> {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)?
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .collect();
    entries.sort();
    for entry in entries {
        let metadata = std::fs::symlink_metadata(&entry)?;
        let name = entry
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
        let relative = format!("{prefix}/{name}");
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            walk(&entry, &relative, out)?;
        } else if metadata.is_file() {
            out.push(Selected {
                relative,
                source: entry,
            });
        }
    }
    Ok(())
}

struct CliObserver {
    json: bool,
}

impl Observer for CliObserver {
    fn event(&mut self, event: Event) {
        if self.json {
            let line = match &event {
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

#[cfg(test)]
mod tests {
    use super::split_link;

    #[test]
    fn splits_request_links_into_origin_and_token() {
        let cases = [
            ("https://drop.example/r/ABC", "https://drop.example", "ABC"),
            (
                "https://drop.example/api/r/XYZ",
                "https://drop.example",
                "XYZ",
            ),
            ("https://drop.example/r/ABC/", "https://drop.example", "ABC"),
            (
                "https://drop.example/r/ABC?x=1#f",
                "https://drop.example",
                "ABC",
            ),
            (
                "http://127.0.0.1:8080/r/tok",
                "http://127.0.0.1:8080",
                "tok",
            ),
            ("https://drop.example/s/DEL", "https://drop.example", "DEL"),
            (
                "https://drop.example/api/s/DEL",
                "https://drop.example",
                "DEL",
            ),
            (
                "https://drop.example/s/DEL/?x=1",
                "https://drop.example",
                "DEL",
            ),
        ];
        for (link, base, token) in cases {
            let (got_base, got_token) = split_link(link).expect(link);
            assert_eq!(got_base, base, "{link}");
            assert_eq!(got_token, token, "{link}");
        }
        assert!(split_link("https://drop.example/verify").is_err());
        assert!(split_link("not a url").is_err());
    }
}
