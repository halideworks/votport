//! Cross-platform core for the votport desktop client.
//!
//! The send path has two transports: a QUIC push, tried first when the link
//! offers it, and the HTTP session path the web sender uses as the fallback.
//! The receive path pulls a delivery to a local directory, over a QUIC fetch
//! when the delivery serves and the carrier answers and over HTTP otherwise,
//! hashing every file to the root the delivery announced before it lands.

pub mod api;
pub mod entries;
pub mod error;
pub mod fetch;
pub mod ffi;
pub mod identity;
pub mod package;
pub mod progress;
pub mod receive;
pub mod send_http;
pub mod send_push;
pub mod transfer;

uniffi::setup_scaffolding!();

pub use api::split_link;
pub use error::{Error, Result};
pub use fetch::receive_over_fetch;
pub use identity::Device;
pub use receive::{receive, receive_over_http, receive_with_device_or_http, Delivery, Received};
pub use transfer::{collect, send, send_http as send_over_http, Drop, Selected, Sent};
