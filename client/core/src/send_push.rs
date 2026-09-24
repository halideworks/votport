//! The push send path: probe the receiver's carrier, preflight a capability,
//! and push from a server assembled over the files in place.
//!
//! A probe runs before any preflight so a network that will not carry QUIC
//! costs the client its budget and no reserved state on either end; the caller
//! then falls back to HTTP. Once a preflight has minted a capability the push
//! is committed: a failure aborts the reserved session rather than silently
//! re-sending over HTTP.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use vot_cli::authz::Holder;
use vot_cli::{
    parse_rendezvous, probe_serve, push_from_with_cancellation, BundleServer, Error as VotError,
    PushOptions,
};

use crate::api::{Client, PushPackageAnnouncement};
use crate::error::{Error, Result};
use crate::identity::Device;
use crate::package::Prepared;
use crate::progress::{with_progress, Event, Observer, Transport, PROGRESS_QUANTUM};

/// How long the probe waits for the receiver's handshake before falling back.
const PROBE_BUDGET: Duration = Duration::from_secs(2);

/// macOS loopback avoids contention in the shared UDP path with one rail.
pub(crate) fn direct_rails(address: SocketAddr, macos: bool) -> usize {
    if macos && address.ip().to_canonical().is_loopback() {
        1
    } else {
        4
    }
}

/// The outcome of an attempted push.
pub enum Outcome {
    /// The drop was pushed.
    Pushed,
    /// The receiver's carrier is not reachable (push is off, or the probe did
    /// not complete); the caller should send over HTTP instead.
    Unreachable,
}

/// Attempts to push `prepared` to `token`.
///
/// Returns [`Outcome::Unreachable`] only before any state is reserved, so the
/// caller can fall back to HTTP; after the preflight the push is committed and
/// a failure is an error.
///
/// # Errors
/// A serve identity mismatch, a preflight refusal, or a push failure.
pub fn try_push(
    client: &Client,
    token: &str,
    password: Option<&str>,
    device: &Device,
    prepared: &Prepared,
    observer: &mut dyn Observer,
) -> Result<Outcome> {
    // The probe target comes from the public push identity, which reserves
    // nothing. A server with push off answers 404.
    let identity = match client.push_identity() {
        Ok(identity) => identity,
        Err(Error::Server { status: 404, .. }) => return Ok(Outcome::Unreachable),
        Err(error) => return Err(error),
    };
    let probe_digest = decode_digest(&identity.certificate_digest)?;

    // The advertised address is often a hostname, so it is resolved. A name
    // that will not resolve, or resolves to addresses none of which answer,
    // means the carrier cannot be reached: a fall-back to HTTP, not an error.
    let Ok(addresses) = parse_rendezvous(&identity.address) else {
        return Ok(Outcome::Unreachable);
    };
    let reachable = match probe_any(&addresses, probe_digest) {
        Probe::Reachable(address) => address,
        Probe::Unreachable => return Ok(Outcome::Unreachable),
        Probe::Mismatch => return Err(Error::Package(VotError::ServeIdentityMismatch)),
    };

    if observer.cancelled() {
        return Err(Error::Cancelled);
    }
    // The carrier answered, so reserve a capability and commit to the push.
    let preflight = client.create_push_session(
        token,
        password,
        &device.holder_key_hex(),
        PushPackageAnnouncement {
            suite: 1,
            root: hex::encode(prepared.summary.root),
            length: prepared.summary.logical_length,
            entries: prepared.summary.entries,
        },
    )?;
    observer.event(Event::SessionCreated {
        session: preflight.session.clone(),
    });
    observer.event(Event::Transport(Transport::Push));

    let result = push(device, prepared, &preflight, reachable, observer);
    if result.is_err() {
        // A push that fails after the preflight leaves a reserved session and
        // staging on the receiver; abort releases them.
        client.abort(&preflight.session);
    }
    result?;
    observer.event(Event::Finished {
        files: usize::try_from(prepared.summary.entries).unwrap_or(usize::MAX),
    });
    Ok(Outcome::Pushed)
}

/// What a probe of a resolved address set found.
pub(crate) enum Probe {
    /// One address answered with the pinned identity.
    Reachable(SocketAddr),
    /// No address answered within the budget.
    Unreachable,
    /// An address answered with the wrong certificate.
    Mismatch,
}

/// Probes each address in turn, stopping at the first that answers. A wrong
/// certificate is decisive: the pin is wrong, so no other address is tried.
/// Every other failure (no route to a v6 address on a v4-only host, a refused
/// or silent port, a timeout) means this address did not answer, so the next
/// is tried; if none answer the carrier is unreachable.
pub(crate) fn probe_any(addresses: &[SocketAddr], digest: [u8; 32]) -> Probe {
    for address in addresses {
        match probe_serve(*address, digest, PROBE_BUDGET) {
            Ok(()) => return Probe::Reachable(*address),
            Err(VotError::ServeIdentityMismatch) => return Probe::Mismatch,
            Err(_) => {}
        }
    }
    Probe::Unreachable
}

/// Builds the holder and the served bundle and pushes to `reachable`, the
/// address the probe reached.
fn push(
    device: &Device,
    prepared: &Prepared,
    preflight: &crate::api::PushPreflight,
    reachable: SocketAddr,
    observer: &mut dyn Observer,
) -> Result<()> {
    let capability = base64_decode(&preflight.capability)?;
    let holder = Arc::new(
        Holder::new(capability, device.signing_key()).map_err(|error| {
            Error::Other(format!(
                "the device key does not match the capability: {error:?}"
            ))
        })?,
    );
    // The preflight names the same push endpoint the identity did, so the
    // address the probe reached is the one to push to.
    let address = reachable;
    let identity = decode_digest(&preflight.certificate_digest)?;

    let server = BundleServer::assemble(&prepared.manifest_root, prepared.served.clone())?;
    let mut bridge = EntryBridge::new(prepared, observer);
    let cancellation = vot_cli::CancellationHandle::default();
    if bridge.cancelled() {
        return Err(Error::Cancelled);
    }
    with_progress(&mut bridge, &cancellation, |progress| {
        push_from_with_cancellation(
            &server,
            PushOptions {
                address,
                holder,
                identity,
                rails: direct_rails(address, cfg!(target_os = "macos")),
                // push_from adds the PUSH extension; no FEC is offered here.
                extensions: BTreeSet::new(),
                progress: Some((PROGRESS_QUANTUM, progress)),
            },
            &cancellation,
        )
    })
    .map_err(|error| match error {
        VotError::Cancelled => Error::Cancelled,
        error => Error::Package(error),
    })?;
    Ok(())
}

/// The push carrier reports only cumulative carrier bytes with no total and
/// no per-entry marks, so a long push is silent and every file's row waits
/// for [`Event::Finished`]. This bridge fills the total from the prepared
/// summary and emits [`Event::EntryComplete`] as `moved` crosses each
/// entry's cumulative end, so push progress carries the same per-file marks
/// and the same total the HTTP path reports.
struct EntryBridge<'a> {
    inner: &'a mut dyn Observer,
    /// Cumulative byte end of each entry, in index order.
    ends: Vec<(u64, String)>,
    /// The package length the carrier never reports.
    total: u64,
    /// Next entry not yet reported complete.
    next: usize,
}

impl EntryBridge<'_> {
    fn new<'a>(prepared: &Prepared, observer: &'a mut dyn Observer) -> EntryBridge<'a> {
        Self::from_entries(
            prepared
                .objects
                .iter()
                .map(|entry| (entry.object.length, entry.path.clone())),
            prepared.summary.logical_length,
            observer,
        )
    }

    fn from_entries<'a>(
        entries: impl Iterator<Item = (u64, String)>,
        total: u64,
        observer: &'a mut dyn Observer,
    ) -> EntryBridge<'a> {
        let mut ends = Vec::new();
        let mut run = 0u64;
        for (length, path) in entries {
            run = run.saturating_add(length);
            ends.push((run, path));
        }
        EntryBridge {
            inner: observer,
            ends,
            total,
            next: 0,
        }
    }
}

impl Observer for EntryBridge<'_> {
    fn event(&mut self, event: Event) {
        let (moved, mut total) = match event {
            Event::Bytes { moved, total } => (moved, total),
            other => {
                self.inner.event(other);
                return;
            }
        };
        while self.next < self.ends.len() && moved >= self.ends[self.next].0 {
            let path = self.ends[self.next].1.clone();
            self.inner.event(Event::EntryComplete {
                index: self.next,
                path,
            });
            self.next += 1;
        }
        if total.is_none() {
            total = Some(self.total);
        }
        self.inner.event(Event::Bytes { moved, total });
    }

    fn cancelled(&self) -> bool {
        self.inner.cancelled()
    }

    fn paused(&self) -> bool {
        self.inner.paused()
    }
}

pub(crate) fn decode_digest(hex_digest: &str) -> Result<[u8; 32]> {
    hex::decode(hex_digest)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| Error::Other(format!("{hex_digest:?} is not a 32-byte digest")))
}

pub(crate) fn base64_decode(value: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|error| Error::Other(format!("the capability is not valid base64: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_rails_limits_only_macos_loopback() {
        for (address, loopback) in [
            ("127.0.0.1:443", true),
            ("[::1]:443", true),
            ("[::ffff:127.0.0.1]:443", true),
            ("192.168.1.2:443", false),
            ("[fd00::1]:443", false),
            ("[::ffff:192.168.1.2]:443", false),
        ] {
            let address = address.parse().unwrap();
            assert_eq!(super::direct_rails(address, false), 4, "{address}");
            assert_eq!(
                super::direct_rails(address, true),
                if loopback { 1 } else { 4 },
                "{address}"
            );
        }
    }

    struct Collector {
        events: Vec<Event>,
        cancelled: bool,
    }

    impl Observer for Collector {
        fn event(&mut self, event: Event) {
            self.events.push(event);
        }

        fn cancelled(&self) -> bool {
            self.cancelled
        }
    }

    fn bridge<'a>(observer: &'a mut Collector) -> EntryBridge<'a> {
        EntryBridge::from_entries(
            [(100, "a.bin".to_owned()), (50, "b.bin".to_owned())].into_iter(),
            150,
            observer,
        )
    }

    #[test]
    fn push_bridge_emits_entry_completion_and_fills_the_total() {
        let mut inner = Collector {
            events: Vec::new(),
            cancelled: false,
        };
        let mut push = bridge(&mut inner);
        push.event(Event::SessionCreated {
            session: "s".to_owned(),
        });
        push.event(Event::Bytes {
            moved: 60,
            total: None,
        });
        push.event(Event::Bytes {
            moved: 130,
            total: None,
        });
        push.event(Event::Bytes {
            moved: 200,
            total: None,
        });
        assert_eq!(inner.events.len(), 6, "{:?}", inner.events);
        assert!(matches!(&inner.events[0], Event::SessionCreated { session } if session == "s"));
        assert!(matches!(
            &inner.events[1],
            Event::Bytes {
                moved: 60,
                total: Some(150)
            }
        ));
        assert!(
            matches!(&inner.events[2], Event::EntryComplete { index: 0, path } if path == "a.bin")
        );
        assert!(matches!(
            &inner.events[3],
            Event::Bytes {
                moved: 130,
                total: Some(150)
            }
        ));
        assert!(
            matches!(&inner.events[4], Event::EntryComplete { index: 1, path } if path == "b.bin")
        );
        assert!(matches!(
            &inner.events[5],
            Event::Bytes {
                moved: 200,
                total: Some(150)
            }
        ));
    }
}
