//! The client's error type.

use std::path::PathBuf;

/// Anything that stops a send.
#[derive(Debug, thiserror::Error)]
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

    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),

    #[error("building the package: {0:?}")]
    Package(vot_cli::Error),

    #[error("hashing an object: {0:?}")]
    Object(vot_object::Error),

    #[error("{0}")]
    Other(String),
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
