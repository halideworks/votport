//! votport: a password-protected file receive portal built on VOT.
//!
//! Copyright (C) 2026  votport contributors
//!
//! This program is free software: you can redistribute it and/or modify it
//! under the terms of the GNU Affero General Public License as published by
//! the Free Software Foundation, version 3.
//!
//! This program is distributed in the hope that it will be useful, but
//! WITHOUT ANY WARRANTY; without even the implied warranty of
//! MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Affero
//! General Public License for more details:
//! <https://www.gnu.org/licenses/agpl-3.0.html>.

use votport::{app, config};

#[tokio::main]
async fn main() {
    let config = match config::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("votport: {error}");
            std::process::exit(2);
        }
    };
    let bind = config.bind;
    let application = match app::build(config) {
        Ok(application) => application,
        Err(error) => {
            eprintln!("votport: {error}");
            std::process::exit(2);
        }
    };
    tokio::spawn(app::session_sweeper(application.clone()));
    let router = app::router(application.clone());
    let listener = match tokio::net::TcpListener::bind(bind).await {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("votport: bind {bind}: {error}");
            std::process::exit(2);
        }
    };
    println!(
        "votport listening on {bind}; receiving into {}",
        application.config.receive_dir.display()
    );
    // ConnectInfo carries the peer address to the per-IP link throttle.
    if let Err(error) = axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    {
        eprintln!("votport: server error: {error}");
        std::process::exit(1);
    }
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    println!("votport shutting down");
}
