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
#[path = "../../protocol/delivery.rs"]
pub mod delivery_protocol;
pub mod lease;
pub mod notify;
pub mod paths;
pub mod receipt;
pub mod receiving;
#[path = "../../protocol/routes.rs"]
pub mod route_protocol;
pub mod session;
pub mod standby;
pub mod store;

pub mod workflow;
