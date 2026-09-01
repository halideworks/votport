//! votport library surface: everything the binary and integration tests use.
//!
//! Licensed under the VOTPORT PROPRIETARY LICENSE.

// The settings JSON object expands past the default macro recursion limit.
#![recursion_limit = "256"]

pub mod api;
pub mod app;
pub mod auth;
pub mod backup;
pub mod config;
pub mod notify;
pub mod paths;
pub mod receipt;
pub mod session;
pub mod store;
