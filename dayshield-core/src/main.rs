//! DayShield Core - backend orchestrator entry point.
//!
//! Initialises logging, builds the shared application state, wires up the
//! Axum router and starts the HTTP server on 0.0.0.0:8443 by default.
//
// Suppress dead-code warnings for the many placeholder engine functions and
// config types that are defined here as stubs and will be wired up in future
// work.  This is intentional for an initial scaffold.
#![allow(dead_code)]
#![allow(unused_imports)]

use std::sync::Arc;
use std::env;

use axum::Router;
use tokio::net::TcpListener;
use tracing::{info, warn};

mod api;
mod ai_engine;
mod ai_model;
mod auth;
mod backup;
mod config;
mod engine;
mod logs;
mod logging;
mod metrics;
mod nat;
mod notify;
mod ntp;
mod rules;
mod schedules;
mod state;
mod update;
mod utils;

use state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Handle one-shot subcommands before starting the server.
    let args: Vec<String> = env::args().collect();
    if args.get(1).map(String::as_str) == Some("init-admin") {
        let password = args.get(2).ok_or_else(|| {
            anyhow::anyhow!("usage: dayshield-core init-admin <password>")
        })?;
        let hash = auth::password::hash_password(password)
            .map_err(|e| anyhow::anyhow!("failed to hash password: {e}"))?;
        let user = auth::model::User::new("admin", hash);
        auth::storage::save_user(
            std::path::Path::new(auth::storage::DEFAULT_ADMIN_PATH),
            &user,
        )
        .map_err(|e| anyhow::anyhow!("failed to write admin.json: {e}"))?;
        println!(
            "Admin credentials initialised at {}",
            auth::storage::DEFAULT_ADMIN_PATH
        );
        return Ok(());
    }

    // Initialise structured logging with environment-variable defaults.
    // A second, more precise call below updates the filter once the
    // on-disk config has been loaded.
    logging::init();

    info!("Starting DayShield Core orchestrator");

    // Load config early so that the logging config can be applied before
    // the rest of the subsystems start up.
    let config_store = config::storage::ConfigStore::new();
    if let Ok(system_cfg) = config_store.load() {
        if let Some(log_cfg) = &system_cfg.logging {
            logging::update_filter(log_cfg);
        }
    }

    // Initialize the session signing key (creates it if missing or corrupted).
    // This must happen before the router is created so that the login endpoint
    // will have a valid key ready to use.
    if let Err(e) = auth::session::load_or_create_key(std::path::Path::new(auth::session::DEFAULT_KEY_PATH)) {
        warn!("failed to initialize session key: {}", e);
        // Don't exit - the key will be created lazily on first login attempt
    }

    // Build shared application state.
    let (app_state_inner, notify_rx) = AppState::new();
    let app_state = Arc::new(app_state_inner);

    // Start the background metrics collector.
    metrics::collector::start_metrics_collector(Arc::clone(&app_state)).await;

    // Start the automatic backup scheduler.
    backup::scheduler::start_backup_scheduler(Arc::clone(&app_state)).await;

    // Start system schedules (Dynamic DNS, ACME renew, and future jobs).
    schedules::start_scheduler(Arc::clone(&app_state)).await;

    // Start the periodic software update checker.
    update::start_update_checker(Arc::clone(&app_state)).await;

    // Start AI engine background maintenance.
    ai_engine::start_background_tasks(Arc::clone(&app_state)).await;

    // Start the background notification worker.
    notify::worker::start_notify_worker(Arc::clone(&app_state), notify_rx).await;

    // Build the Axum router.
    let app: Router = api::router(app_state);

    // Bind and serve.
    let addr = resolve_bind_addr();
    let listener = TcpListener::bind(&addr).await?;
    info!("Listening on http://{}", addr);

    axum::serve(listener, app).await?;

    Ok(())
}

fn default_bind_addr() -> &'static str {
    "0.0.0.0:8443"
}

fn resolve_bind_addr() -> String {
    if let Ok(addr) = env::var("DAYSHIELD_BIND_ADDR") {
        return addr;
    }

    if let Ok(port) = env::var("DAYSHIELD_PORT") {
        match port.parse::<u16>() {
            Ok(port) => return format!("0.0.0.0:{}", port),
            Err(_) => warn!("DAYSHIELD_PORT={} is not a valid port; using {}", port, default_bind_addr()),
        }
    }

    default_bind_addr().to_string()
}
