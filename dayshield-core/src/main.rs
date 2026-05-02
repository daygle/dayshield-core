//! DayShield Core — backend orchestrator entry point.
//!
//! Initialises logging, builds the shared application state, wires up the
//! Axum router and starts the HTTP server on 0.0.0.0:3000.
//
// Suppress dead-code warnings for the many placeholder engine functions and
// config types that are defined here as stubs and will be wired up in future
// work.  This is intentional for an initial scaffold.
#![allow(dead_code)]
#![allow(unused_imports)]

use std::sync::Arc;

use axum::Router;
use tokio::net::TcpListener;
use tracing::info;

mod api;
mod backup;
mod config;
mod engine;
mod logs;
mod logging;
mod metrics;
mod notify;
mod ntp;
mod state;
mod utils;

use state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialise structured logging.
    logging::init();

    info!("Starting DayShield Core orchestrator");

    // Build shared application state.
    let (app_state_inner, notify_rx) = AppState::new();
    let app_state = Arc::new(app_state_inner);

    // Start the background metrics collector.
    metrics::collector::start_metrics_collector(Arc::clone(&app_state)).await;

    // Start the automatic backup scheduler.
    backup::scheduler::start_backup_scheduler(Arc::clone(&app_state)).await;

    // Start the background notification worker.
    notify::worker::start_notify_worker(Arc::clone(&app_state), notify_rx).await;

    // Build the Axum router.
    let app: Router = api::router(app_state);

    // Bind and serve.
    let addr = "0.0.0.0:3000";
    let listener = TcpListener::bind(addr).await?;
    info!("Listening on http://{}", addr);

    axum::serve(listener, app).await?;

    Ok(())
}
