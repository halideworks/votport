//! Logging setup: the RUST_LOG filter, the optional AUDIT_LOG sink, and the
//! unidentifiable subject form used wherever a subject reaches the logs.
//!
//! Licensed under the VOTPORT PROPRIETARY LICENSE.

use tracing_subscriber::layer::{Layer, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// Filter used when RUST_LOG is unset. The global info is the baseline; the
/// named targets (`votport`, `audit`) exist so RUST_LOG can raise or lower
/// one of them, e.g. `RUST_LOG=info,votport=debug`.
pub const DEFAULT_FILTER: &str = "info,votport=info,audit=info";

/// The stdout layer's filter. RUST_LOG wins over the default. When audit
/// events are routed to their own file, audit is turned off here so every
/// event lands in exactly one sink.
pub fn stdout_filter(rust_log: Option<String>, audit_to_file: bool) -> EnvFilter {
    let text = rust_log.unwrap_or_else(|| DEFAULT_FILTER.to_owned());
    if audit_to_file {
        // Appended last so it overrides an audit directive in RUST_LOG.
        EnvFilter::new(format!("{text},audit=off"))
    } else {
        EnvFilter::new(text)
    }
}

/// The file sink's filter: audit-target events only, always, regardless of
/// RUST_LOG. The audit trail is the reason the file exists.
pub fn audit_filter() -> EnvFilter {
    EnvFilter::new("audit=info")
}

/// Unidentifiable form of a subject (an address under the email claim) for
/// log lines: the first two and last two characters with the length, e.g.
/// `ja..om (16)`. Values too short to hide anything collapse to `..(N)`.
/// Opaque identifiers (tenant keys, link ids, opaque subs) are not passed
/// through this; only address-shaped subjects are.
pub fn reduce_subject(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 4 {
        return format!("..({})", chars.len());
    }
    let head: String = chars[..2].iter().collect();
    let tail: String = chars[chars.len() - 2..].iter().collect();
    format!("{head}..{tail} ({})", chars.len())
}

pub fn init() {
    let json = std::env::var("VOTPORT_LOG_FORMAT").as_deref() == Ok("json");
    let audit_file = std::env::var_os("AUDIT_LOG")
        .map(std::path::PathBuf::from)
        .and_then(|path| {
            match std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
            {
                Ok(file) => Some(file),
                Err(error) => {
                    eprintln!(
                        "cannot open AUDIT_LOG {}: {error}; audit events stay on stdout",
                        path.display()
                    );
                    None
                }
            }
        });
    let stdout = stdout_filter(std::env::var("RUST_LOG").ok(), audit_file.is_some());
    match audit_file {
        Some(file) => {
            let writer = move || file.try_clone().expect("audit log writer");
            tracing_subscriber::registry()
                .with(audit_layer::<tracing_subscriber::Registry, _>(
                    audit_filter(),
                    writer,
                ))
                .with(stdout_layer(stdout, json))
                .init();
        }
        None => tracing_subscriber::registry()
            .with(stdout_layer::<tracing_subscriber::Registry>(stdout, json))
            .init(),
    }
}

/// The operational layer; fmt's default writer is stdout, as before.
fn stdout_layer<S>(filter: EnvFilter, json: bool) -> Box<dyn Layer<S> + Send + Sync>
where
    S: tracing::Subscriber,
    S: for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    let layer = tracing_subscriber::fmt::layer();
    if json {
        layer.json().with_filter(filter).boxed()
    } else {
        layer.with_filter(filter).boxed()
    }
}

/// The audit layer: the file only, append, no ansi escapes.
fn audit_layer<S, W>(filter: EnvFilter, writer: W) -> Box<dyn Layer<S> + Send + Sync>
where
    W: for<'a> tracing_subscriber::fmt::MakeWriter<'a> + Send + Sync + 'static,
    S: tracing::Subscriber,
    S: for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_writer(writer)
        .with_filter(filter)
        .boxed()
}

/// A temp file plus a live thread-local subscriber shaped like the
/// production layers, with the writer pointed at the file so tests can read
/// what was logged. Shared with the call-site tests in api and store; drop
/// the guard to restore the previous subscriber.
#[cfg(test)]
pub(crate) fn captured(
    filter: EnvFilter,
) -> (tempfile::NamedTempFile, tracing::subscriber::DefaultGuard) {
    let log = tempfile::NamedTempFile::new().unwrap();
    let writer = log.reopen().unwrap();
    let layer = tracing_subscriber::fmt::layer()
        .json()
        .without_time()
        .with_ansi(false)
        .with_writer(move || writer.try_clone().unwrap())
        .with_filter(filter);
    let guard = tracing::subscriber::set_default(tracing_subscriber::registry().with(layer));
    (log, guard)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn emit_both_sinks() {
        tracing::info!(target: "audit", event = "sso_login", "SSO sign-in succeeded");
        tracing::info!(target: "votport", "general event");
    }

    #[test]
    fn audit_events_reach_stdout_only_without_the_file_sink() {
        let (log, _guard) = captured(stdout_filter(None, false));
        emit_both_sinks();
        let text = std::fs::read_to_string(log.path()).unwrap();
        assert!(text.contains("sso_login"), "{text}");
        assert!(text.contains("general event"), "{text}");
    }

    #[test]
    fn audit_events_go_to_the_file_and_not_stdout_when_the_file_sink_is_set() {
        // One thread-local default at a time: first the file sink, then the
        // stdout sink with audit excluded, emitting the same events to each.
        let (audit_log, file_guard) = captured(audit_filter());
        emit_both_sinks();
        drop(file_guard);
        let (stdout_log, stdout_guard) = captured(stdout_filter(None, true));
        emit_both_sinks();
        drop(stdout_guard);
        let file_text = std::fs::read_to_string(audit_log.path()).unwrap();
        assert!(file_text.contains("sso_login"), "{file_text}");
        assert!(!file_text.contains("general event"), "{file_text}");
        let stdout_text = std::fs::read_to_string(stdout_log.path()).unwrap();
        assert!(!stdout_text.contains("sso_login"), "{stdout_text}");
        assert!(stdout_text.contains("general event"), "{stdout_text}");
    }

    #[test]
    fn rust_log_wins_over_the_default() {
        // Unset RUST_LOG: the default's global info carries a votport event.
        let (log, _guard) = captured(stdout_filter(None, false));
        tracing::info!(target: "votport", "default info");
        let text = std::fs::read_to_string(log.path()).unwrap();
        assert!(text.contains("default info"), "{text}");
        // RUST_LOG=off: nothing passes, proving the override wins.
        let (log, _guard) = captured(stdout_filter(Some("off".to_owned()), false));
        tracing::info!(target: "votport", "silenced");
        let text = std::fs::read_to_string(log.path()).unwrap();
        assert!(!text.contains("silenced"), "{text}");
    }

    #[test]
    fn reduced_subjects_keep_the_shape_but_drop_the_address() {
        assert_eq!(reduce_subject("jane@example.com"), "ja..om (16)");
        assert_eq!(reduce_subject("jo@x"), "..(4)");
        assert_eq!(reduce_subject("ab"), "..(2)");
        assert_eq!(reduce_subject(""), "..(0)");
        // Multi-byte characters count as one character.
        assert_eq!(reduce_subject("áé@éxample.com"), "áé..om (14)");
    }
}
