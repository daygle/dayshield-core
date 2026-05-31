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

use std::env;
use std::sync::Arc;

use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use tracing::{info, warn};

mod ai_engine;
mod ai_firewall;
mod ai_model;
mod api;
mod auth;
mod backup;
mod captive_portal;
mod config;
mod engine;
mod honeypot;
mod live_logs;
mod logging;
mod metrics;
mod nat;
mod notify;
mod ntp;
mod qos;
mod rootfs_update;
mod rules;
mod schedules;
mod state;
mod update;
mod utils;

use config::models::{Dhcp6Config, DhcpConfig, SystemSettings};
use state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Handle one-shot subcommands before starting the server.
    let args: Vec<String> = env::args().collect();
    if args.get(1).map(String::as_str) == Some("init-admin") {
        let password = args
            .get(2)
            .ok_or_else(|| anyhow::anyhow!("usage: dayshield-core init-admin <password>"))?;
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
    if args.get(1).map(String::as_str) == Some("signal-boot-success") {
        rootfs_update::signal_boot_success()
            .await
            .map_err(|e| anyhow::anyhow!("signal-boot-success failed: {e:#}"))?;
        println!("Boot success signalled.");
        return Ok(());
    }
    if args.get(1).map(String::as_str) == Some("rootfs-sync-identity") {
        let running = rootfs_update::detect_running_slot();
        rootfs_update::sync_identity_to_standby(running.other())
            .await
            .map_err(|e| anyhow::anyhow!("rootfs-sync-identity failed: {e:#}"))?;
        println!("Identity files mirrored from {} to standby.", running.as_str());
        return Ok(());
    }
    if args.get(1).map(String::as_str) == Some("rootfs-apply") {
        let result = rootfs_update::apply_update()
            .await
            .map_err(|e| anyhow::anyhow!("rootfs-apply failed: {e:#}"))?;
        println!("{}", result.message);
        for line in &result.details {
            println!("  {line}");
        }
        if !result.success {
            std::process::exit(1);
        }
        return Ok(());
    }
    if args.get(1).map(String::as_str) == Some("rootfs-rollback") {
        let result = rootfs_update::rollback()
            .await
            .map_err(|e| anyhow::anyhow!("rootfs-rollback failed: {e:#}"))?;
        println!("{}", result.message);
        for line in &result.details {
            println!("  {line}");
        }
        if !result.success {
            std::process::exit(1);
        }
        return Ok(());
    }
    if matches!(
        args.get(1).map(String::as_str),
        Some(
            "update-status"
                | "update-check"
                | "update-apply"
                | "update-rollback"
                | "update-validate"
        )
    ) {
        return run_update_cli(&args[1..]).await;
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
    if let Err(e) =
        auth::session::load_or_create_key(std::path::Path::new(auth::session::DEFAULT_KEY_PATH))
    {
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

    // Reconcile network interfaces.  After a rootfs update the rsync
    // extraction has wiped /etc/systemd/network/*.network (squashfs ships
    // an empty directory there); we rewrite them from the persisted config
    // so the user's WAN/LAN assignments and IPs survive every update.
    match app_state.config_store.load_interfaces() {
        Ok(interfaces) => {
            for iface in &interfaces {
                if let Err(err) =
                    engine::interfaces::apply_interface_with_ipv6(iface, ipv6_enabled).await
                {
                    warn!(
                        interface = %iface.name,
                        "failed to reconcile interface at startup: {err:#}"
                    );
                }
            }
        }
        Err(err) => warn!("failed to load interfaces for startup reconcile: {err:#}"),
    }

    // Reconcile Kea with the persisted DayShield config. Kea units can be
    // enabled independently by the package/rootfs, so startup must recreate
    // the distro config mirrors before those services are expected healthy.
    reconcile_dhcp_runtime(&app_state.config_store).await;

    if let Err(err) = captive_portal::apply_current_ruleset_nft(&app_state.config_store).await {
        warn!("failed to reconcile nftables runtime config: {err:#}");
    }

    match app_state.config_store.load_qos_config() {
        Ok(qos_cfg) => {
            if let Err(err) = engine::qos::apply_config(&qos_cfg).await {
                warn!("failed to reconcile QoS runtime config: {err:#}");
            }
        }
        Err(err) => warn!("failed to load QoS config for startup reconcile: {err:#}"),
    }

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
    ai_firewall::start_background_tasks(Arc::clone(&app_state)).await;

    // Start low-interaction honeypot listeners.
    honeypot::start_background_tasks(Arc::clone(&app_state)).await;

    // Start captive portal listener and session expiry maintenance.
    captive_portal::start_portal_server(Arc::clone(&app_state));
    captive_portal::start_session_reaper(Arc::clone(&app_state));

    // Start the background notification worker.
    notify::worker::start_notify_worker(Arc::clone(&app_state), notify_rx).await;

    // Build the Axum router.
    let app: Router = api::router(Arc::clone(&app_state));

    // Determine bind address from environment and persisted system settings.
    let system_settings = app_state
        .config_store
        .load_system_settings()
        .unwrap_or_default();
    let addr: std::net::SocketAddr = resolve_bind_addr(ipv6_enabled, &system_settings).parse()?;

    let make_service = app.into_make_service_with_connect_info::<std::net::SocketAddr>();

    if system_settings.management_https_enabled {
        match load_tls_config(&app_state.config_store, &system_settings) {
            Some((cert_path, key_path)) => {
                match RustlsConfig::from_pem_file(&cert_path, &key_path).await {
                    Ok(tls_config) => {
                        info!("Listening on https://{}", addr);
                        axum_server::bind_rustls(addr, tls_config)
                            .serve(make_service)
                            .await?;
                    }
                    Err(e) => {
                        warn!(
                            "Failed to load TLS certificate for management HTTPS ({}); \
                             falling back to HTTP: {e:#}",
                            cert_path.display()
                        );
                        info!("Listening on http://{}", addr);
                        axum_server::bind(addr).serve(make_service).await?;
                    }
                }
            }
            None => {
                warn!(
                    "management_https_enabled is true but no valid ACME domain/config found; \
                     falling back to HTTP"
                );
                info!("Listening on http://{}", addr);
                axum_server::bind(addr).serve(make_service).await?;
            }
        }
    } else {
        info!("Listening on http://{}", addr);
        axum_server::bind(addr).serve(make_service).await?;
    }

    Ok(())
}

async fn run_update_cli(args: &[String]) -> anyhow::Result<()> {
    let command = args[0].as_str();
    let component_arg = args
        .iter()
        .skip(1)
        .find(|arg| !arg.starts_with("--"))
        .map(String::as_str);
    let component = parse_update_component(component_arg)?;
    let force_partial = args.iter().any(|arg| arg == "--force-partial");

    let (state_inner, _notify_rx) = AppState::new();
    let state = Arc::new(state_inner);

    match command {
        "update-status" => {
            let status = update::get_status(&state).await;
            print_update_status(&status);
        }
        "update-check" => {
            let status = update::check_for_updates(&state).await?;
            print_update_status(&status);
        }
        "update-apply" => {
            let result = update::apply_updates(&state, component, force_partial).await?;
            print_update_action_result(&result);
        }
        "update-rollback" => {
            let result = update::rollback_updates(&state, component, force_partial).await?;
            print_update_action_result(&result);
        }
        "update-validate" => {
            let result = update::validate_updates(&state, component, force_partial).await?;
            print_update_action_result(&result);
        }
        _ => unreachable!(),
    }

    Ok(())
}

fn parse_update_component(value: Option<&str>) -> anyhow::Result<update::UpdateComponent> {
    match value.unwrap_or("both") {
        "core" => Ok(update::UpdateComponent::Core),
        "ui" => Ok(update::UpdateComponent::Ui),
        "both" => Ok(update::UpdateComponent::Both),
        other => {
            anyhow::bail!("invalid update component '{other}' (expected core, ui, or both)")
        }
    }
}

fn print_update_status(status: &update::UpdatesStatus) {
    println!("DayShield Update Status");
    println!(
        "  Last check:             {}",
        status.last_checked_at.as_deref().unwrap_or("never")
    );
    println!(
        "  Last applied update:    {}",
        status.last_applied_at.as_deref().unwrap_or("never")
    );
    println!(
        "  Reboot required:        {}",
        yes_no(status.pending_reboot)
    );
    println!(
        "  Appliance rebuild:      {}",
        yes_no(status.pending_appliance_rebuild)
    );
    if let Some(reason) = &status.appliance_rebuild_reason {
        println!("  Rebuild reason:         {reason}");
    }
    println!();
    println!("Components:");
    for component in &status.components {
        println!("  {}", component.component);
        println!(
            "    Current:   {}",
            component.current_version.as_deref().unwrap_or("unknown")
        );
        println!(
            "    Available: {}",
            component.remote_version.as_deref().unwrap_or("unknown")
        );
        println!("    Update:    {}", yes_no(component.update_available));
        if let Some(error) = component.last_error.as_deref() {
            if !error.trim().is_empty() {
                println!("    Error:     {error}");
            }
        }
    }
    if !status.operation_logs.is_empty() {
        println!();
        println!("Recent update log:");
        let start = status.operation_logs.len().saturating_sub(5);
        for entry in &status.operation_logs[start..] {
            println!("  {} [{}] {}", entry.timestamp, entry.level, entry.message);
        }
    }
}

fn print_update_action_result(result: &update::UpdatesActionResult) {
    println!("DayShield update {}", result.operation);
    println!("Success: {}", yes_no(result.success));
    println!("Message: {}", result.message);
    for detail in &result.details {
        println!("  - {detail}");
    }
    println!();
    print_update_status(&result.status);
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

/// Return the certificate and key paths for the management HTTPS listener, or `None` if
/// the settings do not specify a valid ACME domain or the ACME config is missing.
fn load_tls_config(
    config_store: &config::ConfigStore,
    settings: &config::models::SystemSettings,
) -> Option<(std::path::PathBuf, std::path::PathBuf)> {
    let domain = settings.management_tls_acme_domain.as_deref()?;
    let acme_config = config_store.load_acme_config().ok()??;
    let engine = engine::acme::AcmeEngine::new(acme_config);
    Some((engine.cert_path(domain), engine.key_path(domain)))
}

fn default_bind_addr(ipv6_enabled: bool) -> &'static str {
    if ipv6_enabled {
        "[::]:8443"
    } else {
        "0.0.0.0:8443"
    }
}

fn resolve_bind_addr(ipv6_enabled: bool, settings: &SystemSettings) -> String {
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

    if ipv6_enabled {
        format!("[::]:{}", settings.web_port)
    } else {
        format!("0.0.0.0:{}", settings.web_port)
    }
}

async fn reconcile_dhcp_runtime(config_store: &config::ConfigStore) {
    match config_store.load_dhcp_config() {
        Ok(Some(mut cfg)) => {
            match config_store.load_interfaces() {
                Ok(interfaces) => {
                    if engine::dhcp::apply_interface_defaults(&mut cfg, &interfaces) {
                        if let Err(err) = config_store.save_dhcp_config(cfg.clone()) {
                            warn!("failed to persist DHCPv4 interface defaults: {err:#}");
                        }
                    }
                }
                Err(err) => warn!("failed to load interfaces for DHCPv4 defaults: {err:#}"),
            }
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
