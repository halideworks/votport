//! Cross-platform core for the votport desktop client.
//!
//! One send path with two transports: a QUIC push, tried first when the link
//! offers it, and the HTTP session path the web sender uses as the fallback.

pub mod api;
pub mod entries;
pub mod error;
pub mod identity;
pub mod package;
pub mod progress;
pub mod send_http;
pub mod send_push;
pub mod transfer;

pub use error::{Error, Result};
pub use identity::Device;
pub use transfer::{send, send_http as send_over_http, Drop, Selected, Sent};
