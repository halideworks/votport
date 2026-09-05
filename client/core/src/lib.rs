//! Cross-platform core for the votport desktop client.
//!
//! The HTTP send path lands first (no QUIC), then the push path behind the
//! wire feature.

pub mod api;
pub mod entries;
pub mod error;
pub mod package;
pub mod progress;
pub mod send_http;
pub mod transfer;

pub use error::{Error, Result};
pub use transfer::{send_http as send_over_http, Drop, Selected};
