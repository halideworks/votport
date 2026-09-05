//! The client's error type.

use std::path::PathBuf;

/// Anything that stops a send.
// Crosses the FFI flat: the shell sees the variant and the message, never the
// fields, so no wrapped reqwest or io value has to be representable there.
// Named VotportError there because a bare `Error` shadows Swift.Error.
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error, name = "VotportError")]
pub enum Error {
    #[error("network error talking to {url}: {source}")]
    Http {
        url: String,
        #[source]
        source: reqwest::Error,
    },

    #[error("the server answered {status} for {what}: {body}")]
    Server {
        status: u16,
        what: String,
        body: String,
    },

    /// The server lost the session's coverage after a restart and asked the
    /// sender to call begin again. Recoverable: the transfer re-begins.
    #[error("the server asked the sender to re-begin the session")]
    Rebegin,

    #[error("{link:?} is not a votport link (expected .../r/TOKEN or .../s/TOKEN)")]
    BadLink { link: String },

    /// A delivery link pasted where a request link goes, or the reverse.
    #[error("{link:?} is a {} link", match kind { crate::api::LinkKind::Request => "request", crate::api::LinkKind::Delivery => "delivery" })]
    WrongLink {
        link: String,
        kind: crate::api::LinkKind,
    },

    #[error("the link at {token} is not usable for a drop")]
    LinkUnusable { token: String },

    #[error("this link needs a password")]
    PasswordRequired,

    #[error("nothing to send: no files were selected")]
    Empty,

    #[error("{count} of the selected files were refused; first {first}")]
    Rejected {
        count: usize,
        first: crate::entries::Rejected,
    },

    #[error("the drop has more than the {limit} entries this link accepts")]
    TooManyEntries { limit: usize },

    #[error("the drop is {total} bytes, over this link's {limit}-byte cap")]
    TooLarge { total: u64, limit: u64 },

    #[error("reading {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// A received file's bytes did not hash to the root the delivery announced.
    #[error("{path} did not match its announced root (announced {announced}, got {got})")]
    Verify {
        path: PathBuf,
        announced: String,
        got: String,
    },

    /// The delivery named a file suite the client does not fetch.
    #[error("the delivery announced suite {suite:?}, which this client does not fetch")]
    UnknownSuite { suite: String },

    /// The delivery named a file whose path the client will not write, either
    /// because it would escape the destination or is otherwise not portable.
    #[error("the delivery named {name:?}, which cannot be written safely: {reason}")]
    BadName { name: String, reason: String },

    /// A file the delivery would land is already present, so a receive would
    /// overwrite it. The receiver picks an empty directory instead.
    #[error("{path} already exists; receive into a directory that does not hold it")]
    Exists { path: PathBuf },

    /// The caller asked the transfer to stop. Whatever landed stays; a partial
    /// file is kept for the next run to resume.
    #[error("the transfer was cancelled")]
    Cancelled,

    /// A resume named a transfer the journal does not hold.
    #[error("no journalled transfer {id}")]
    UnknownTransfer { id: String },

    /// The destination's filesystem cannot hold the delivery.
    #[error("{path} has {available} bytes free; the delivery needs {needed}")]
    NoSpace {
        path: PathBuf,
        needed: u64,
        available: u64,
    },

    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),

    #[error("building the package: {0:?}")]
    Package(vot_cli::Error),

    #[error("hashing an object: {0:?}")]
    Object(vot_object::Error),

    #[error("{0}")]
    Other(String),
}

impl Error {
    /// One short sentence for a person, without protocol words. The full
    /// text of the error (`to_string`) is the detail behind it.
    #[must_use]
    pub fn headline(&self) -> String {
        match self {
            Self::Http { .. } => "Could not reach the server.".to_owned(),
            Self::Server { status, .. } => match status {
                401 | 403 => "The password was not accepted.".to_owned(),
                404 | 410 => "This link is closed or has expired.".to_owned(),
                413 => "The drop is larger than this link accepts.".to_owned(),
                429 => "Too many tries. Wait a minute and try again.".to_owned(),
                _ => "The server refused the transfer.".to_owned(),
            },
            Self::Rebegin => "The server restarted. Send again to continue.".to_owned(),
            Self::BadLink { .. } => "That is not a votport link.".to_owned(),
            Self::WrongLink { kind, .. } => match kind {
                crate::api::LinkKind::Delivery => {
                    "That is a delivery link. Paste it into Receive.".to_owned()
                }
                crate::api::LinkKind::Request => {
                    "That is a request link. Paste it into Send.".to_owned()
                }
            },
            Self::LinkUnusable { .. } => "This link is closed.".to_owned(),
            Self::PasswordRequired => "This link needs a password.".to_owned(),
            Self::Empty => "Nothing was selected.".to_owned(),
            Self::Rejected { count, first } => {
                if *count == 1 {
                    format!("{} cannot be sent: {}.", name_of(&first.path), first.reason)
                } else {
                    format!(
                        "{count} files cannot be sent. First: {} ({}).",
                        name_of(&first.path),
                        first.reason
                    )
                }
            }
            Self::TooManyEntries { limit } => {
                format!("This link accepts at most {limit} files.")
            }
            Self::TooLarge { limit, .. } => {
                format!("This link accepts at most {}.", human_bytes(*limit))
            }
            Self::Read { path, .. } => format!("{} could not be read.", name_of_path(path)),
            Self::Verify { path, .. } => {
                format!("{} did not verify. Receive it again.", name_of_path(path))
            }
            Self::UnknownSuite { .. } => {
                "This delivery is in a format this app cannot receive.".to_owned()
            }
            Self::BadName { name, .. } => {
                format!("This delivery names {name:?}, which cannot be written here.")
            }
            Self::Exists { path } => format!(
                "{} is already in that folder. Choose an empty one.",
                name_of_path(path)
            ),
            Self::Cancelled => "Cancelled.".to_owned(),
            Self::UnknownTransfer { .. } => "That transfer is no longer on record.".to_owned(),
            Self::NoSpace {
                needed, available, ..
            } => format!(
                "Not enough space: {} needed, {} free.",
                human_bytes(*needed),
                human_bytes(*available)
            ),
            Self::Io(_) => "A file could not be written.".to_owned(),
            Self::Package(vot_cli::Error::SourceMutation) => {
                "A file changed while it was being read. Send it again.".to_owned()
            }
            Self::Package(vot_cli::Error::ServeIdentityMismatch) => {
                "The server did not prove its identity.".to_owned()
            }
            Self::Package(_) | Self::Object(_) | Self::Other(_) => {
                "The transfer could not continue.".to_owned()
            }
        }
    }
}

impl Error {
    /// Whether trying the same transfer again later could end differently:
    /// the network, the server, the disk, a missing password, a file in the
    /// way. A refusal of the input itself (a bad or closed link, a refused
    /// or oversized drop) fails the same way every time and is not worth
    /// keeping for a resume.
    #[must_use]
    pub fn worth_retrying(&self) -> bool {
        !matches!(
            self,
            // A closed, expired, or unknown link, or a drop the server will
            // not take at any size, answers the same way every time.
            Self::Server {
                status: 404 | 410 | 413,
                ..
            } | Self::BadLink { .. }
                | Self::WrongLink { .. }
                | Self::LinkUnusable { .. }
                | Self::Empty
                | Self::Rejected { .. }
                | Self::TooManyEntries { .. }
                | Self::TooLarge { .. }
                | Self::UnknownSuite { .. }
                | Self::BadName { .. }
                | Self::UnknownTransfer { .. }
                | Self::Cancelled
        )
    }
}

fn name_of(path: &str) -> String {
    let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    format!("{name:?}")
}

fn name_of_path(path: &std::path::Path) -> String {
    match path.file_name() {
        Some(name) => format!("{:?}", name.to_string_lossy()),
        None => format!("{:?}", path.display().to_string()),
    }
}

/// `1.5 GB`-style text for a headline. Decimal units, as Finder and the web
/// pages show them.
#[must_use]
pub fn human_bytes(value: u64) -> String {
    const UNITS: [&str; 5] = ["bytes", "KB", "MB", "GB", "TB"];
    let mut amount = value as f64;
    let mut unit = 0;
    while amount >= 1000.0 && unit < UNITS.len() - 1 {
        amount /= 1000.0;
        unit += 1;
    }
    // `{:.0}` rounds 999.5 and above to 1000, which the loop left one unit
    // short; carry it.
    if unit < UNITS.len() - 1 && amount >= 999.5 {
        amount /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        if value == 1 {
            "1 byte".to_owned()
        } else {
            format!("{value} bytes")
        }
    } else if amount >= 99.95 {
        format!("{amount:.0} {}", UNITS[unit])
    } else {
        format!("{amount:.1} {}", UNITS[unit])
    }
}

impl From<vot_cli::Error> for Error {
    fn from(error: vot_cli::Error) -> Self {
        Self::Package(error)
    }
}

impl From<vot_object::Error> for Error {
    fn from(error: vot_object::Error) -> Self {
        Self::Object(error)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_headline_is_one_plain_sentence() {
        let cases: Vec<(Error, &str)> = vec![
            (
                Error::Server {
                    status: 404,
                    what: "link info".into(),
                    body: String::new(),
                },
                "This link is closed or has expired.",
            ),
            (
                Error::Server {
                    status: 401,
                    what: "verify".into(),
                    body: String::new(),
                },
                "The password was not accepted.",
            ),
            (
                Error::Server {
                    status: 500,
                    what: "begin".into(),
                    body: "proof rejected".into(),
                },
                "The server refused the transfer.",
            ),
            (
                Error::Rejected {
                    count: 1,
                    first: crate::entries::Rejected {
                        path: "shots/.DS_Store".into(),
                        reason: "hidden files are not accepted".into(),
                    },
                },
                "\".DS_Store\" cannot be sent: hidden files are not accepted.",
            ),
            (
                Error::TooLarge {
                    total: 5_000_000_000,
                    limit: 2_500_000_000,
                },
                "This link accepts at most 2.5 GB.",
            ),
            (
                Error::Exists {
                    path: PathBuf::from("/dest/reel.mov"),
                },
                "\"reel.mov\" is already in that folder. Choose an empty one.",
            ),
            (
                Error::NoSpace {
                    path: PathBuf::from("/dest"),
                    needed: 120_000_000_000,
                    available: 8_000_000_000,
                },
                "Not enough space: 120 GB needed, 8.0 GB free.",
            ),
            (Error::Cancelled, "Cancelled."),
            (
                Error::Other("chunk too large".into()),
                "The transfer could not continue.",
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(error.headline(), expected, "{error}");
        }
    }

    #[test]
    fn only_a_transfer_that_could_go_differently_is_worth_retrying() {
        assert!(Error::PasswordRequired.worth_retrying());
        assert!(Error::Exists {
            path: PathBuf::from("/dest/reel.mov")
        }
        .worth_retrying());
        assert!(Error::Http {
            url: "x".into(),
            source: reqwest::blocking::get("http://[::1]:1/").unwrap_err(),
        }
        .worth_retrying());
        assert!(Error::Server {
            status: 401,
            what: "verify".into(),
            body: String::new()
        }
        .worth_retrying());
        assert!(!Error::Server {
            status: 404,
            what: "delivery metadata".into(),
            body: String::new()
        }
        .worth_retrying());
        assert!(!Error::Cancelled.worth_retrying());
        assert!(!Error::Empty.worth_retrying());
        assert!(!Error::BadLink { link: "x".into() }.worth_retrying());
    }

    #[test]
    fn human_bytes_rounds_the_way_a_person_reads() {
        assert_eq!(human_bytes(0), "0 bytes");
        assert_eq!(human_bytes(1), "1 byte");
        assert_eq!(human_bytes(999), "999 bytes");
        assert_eq!(human_bytes(1_000), "1.0 KB");
        assert_eq!(human_bytes(99_950), "100 KB");
        assert_eq!(human_bytes(999_499), "999 KB");
        assert_eq!(human_bytes(999_500), "1.0 MB");
        assert_eq!(human_bytes(999_950), "1.0 MB");
        assert_eq!(human_bytes(999_500_000), "1.0 GB");
        assert_eq!(human_bytes(1_536_000), "1.5 MB");
        assert_eq!(human_bytes(999_999_999), "1.0 GB");
        assert_eq!(human_bytes(250_000_000_000), "250 GB");
        assert_eq!(human_bytes(999_999_999_999_999), "1000 TB");
    }
}
