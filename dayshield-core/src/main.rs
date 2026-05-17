//! DayShield Core - backend orchestrator entry point.
//!
//! Initialises logging, builds the shared application state, wires up the
//! Axum router and starts the HTTP server on IPv4 by default, or IPv4/IPv6
//! when the global IPv6 setting is enabled.
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
mod captive_portal;
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

use config::models::{Dhcp6Config, DhcpConfig};
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

    // Apply the persisted IPv6 runtime switch before network-facing services
    // start doing work. Failure is logged rather than fatal so first boot on a
    // partially provisioned image can still reach the UI for repair.
    let ipv6_enabled = match app_state.config_store.load_system_settings() {
        Ok(settings) => {
            if let Err(e) = engine::ipv6::apply_ipv6_setting(settings.ipv6_enabled).await {
                warn!("failed to apply IPv6 runtime setting: {e:#}");
            }
            settings.ipv6_enabled
        }
        Err(e) => {
            warn!("failed to load system settings for IPv6 runtime switch: {e:#}");
            false
        }
    };

    // Reconcile Kea with the persisted DayShield config. Kea units can be
    // enabled independently by the package/rootfs, so startup must recreate
    // the distro config mirrors before those services are expected healthy.
    reconcile_dhcp_runtime(&app_state.config_store).await;

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

    // Start captive portal listener and session expiry maintenance.
    captive_portal::start_portal_server(Arc::clone(&app_state));
    captive_portal::start_session_reaper(Arc::clone(&app_state));

    // Start the background notification worker.
    notify::worker::start_notify_worker(Arc::clone(&app_state), notify_rx).await;

    // Build the Axum router.
    let app: Router = api::router(app_state);

    // Bind and serve.
    let addr = resolve_bind_addr(ipv6_enabled);
    let listener = TcpListener::bind(&addr).await?;
    info!("Listening on http://{}", addr);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;

    Ok(())
}

fn default_bind_addr(ipv6_enabled: bool) -> &'static str {
    if ipv6_enabled {
        "[::]:8443"
    } else {
        "0.0.0.0:8443"
    }
}

fn resolve_bind_addr(ipv6_enabled: bool) -> String {
    if let Ok(addr) = env::var("DAYSHIELD_BIND_ADDR") {
        return addr;
    }

    if let Ok(port) = env::var("DAYSHIELD_PORT") {
        match port.parse::<u16>() {
            Ok(port) if ipv6_enabled => return format!("[::]:{}", port),
            Ok(port) => return format!("0.0.0.0:{}", port),
            Err(_) => warn!(
                "DAYSHIELD_PORT={} is not a valid port; using {}",
                port,
                default_bind_addr(ipv6_enabled)
            ),
        }
    }

    default_bind_addr(ipv6_enabled).to_string()
}

async fn reconcile_dhcp_runtime(config_store: &config::ConfigStore) {
    match config_store.load_dhcp_config() {
        Ok(Some(cfg)) => {
            if let Err(err) = engine::dhcp::apply_config(&cfg).await {
                warn!("failed to reconcile DHCPv4 runtime config: {err:#}");
            }
        }
        Ok(None) => {
            let cfg = default_dhcp_cfg();
            if let Err(err) = engine::dhcp::apply_config(&cfg).await {
                warn!("failed to disable unconfigured DHCPv4 service: {err:#}");
            }
        }
        Err(err) => warn!("failed to load DHCPv4 config for startup reconcile: {err:#}"),
    }

    match config_store.load_dhcp6_config() {
        Ok(Some(cfg)) => {
            if let Err(err) = engine::dhcp6::apply_config(&cfg).await {
                warn!("failed to reconcile DHCPv6 runtime config: {err:#}");
            }
        }
        Ok(None) => {
            let cfg = default_dhcp6_cfg();
            if let Err(err) = engine::dhcp6::apply_config(&cfg).await {
                warn!("failed to disable unconfigured DHCPv6 service: {err:#}");
            }
        }
        Err(err) => warn!("failed to load DHCPv6 config for startup reconcile: {err:#}"),
    }
}

fn default_dhcp_cfg() -> DhcpConfig {
    DhcpConfig {
        enabled: false,
        interface: String::new(),
        scopes: vec![],
    }
}

fn default_dhcp6_cfg() -> Dhcp6Config {
    Dhcp6Config {
        enabled: false,
        interface: String::new(),
        scopes: vec![],
    }
}
