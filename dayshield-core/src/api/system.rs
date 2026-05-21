//! System endpoints.
//!
//! - `GET  /system/status`   - overall health and version
//! - `GET  /system/config`   - host-level settings (hostname, timezone, NTP…)
//! - `PUT  /system/config`   - update host-level settings
//! - `POST /system/reboot`   - schedule an immediate systemctl reboot
//! - `POST /system/shutdown` - schedule an immediate systemctl poweroff
//! - `GET  /system/updates/status`   - get artifact update status for core/ui
//! - `GET  /system/updates/settings` - get update settings
//! - `PUT  /system/updates/settings` - update settings (interval/reboot policy/registry)
//! - `POST /system/updates/check`    - force immediate update check
//! - `POST /system/updates/apply`    - apply updates from registry artifacts
//! - `POST /system/updates/rollback` - rollback latest applied update transaction
//! - `POST /system/updates/validate` - validate applied update state
//! - `POST /system/updates/appliance-rebuild-complete` - clear pending appliance rebuild status

use std::{collections::BTreeSet, fs, path::Path, sync::Arc};

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{info, warn};

use crate::{
    config::models::SystemSettings,
    engine::{
        dns::apply_config_with_ipv6 as apply_dns_config, interfaces::refresh_router_advertisements,
        ipv6::apply_ipv6_setting,
    },
    state::AppState,
    update::{self, UpdateComponent, UpdateSettings},
};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum SystemApiError {
    #[error("storage error: {0:#}")]
    StorageError(#[from] anyhow::Error),

    #[error("command error: {0}")]
    CommandError(String),
}

const SSHD_CONFIG_PATH: &str = "/etc/ssh/sshd_config";
const SSH_ROOT_DIR: &str = "/root/.ssh";
const SSH_AUTHORIZED_KEYS_PATH: &str = "/root/.ssh/authorized_keys";

impl IntoResponse for SystemApiError {
    fn into_response(self) -> axum::response::Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": self.to_string() })),
        )
            .into_response()
    }
}

// ---------------------------------------------------------------------------
// GET /system/status
// ---------------------------------------------------------------------------

/// Response body returned by `GET /system/status`.
#[derive(Serialize)]
pub struct SystemStatusResponse {
    pub name: &'static str,
    pub version: &'static str,
    pub timestamp: String,
    pub services_healthy: bool,
    pub service_count: usize,
}

/// Handler: return the current system status.
pub async fn get_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let svc_state = state.services.read().await;
    let all_healthy = svc_state.values().all(|&h| h);
    let count = svc_state.len();
    drop(svc_state);

    Json(SystemStatusResponse {
        name: "DayShield Core",
        version: env!("CARGO_PKG_VERSION"),
        timestamp: Utc::now().to_rfc3339(),
        services_healthy: all_healthy,
        service_count: count,
    })
}

// ---------------------------------------------------------------------------
// GET /system/config
// ---------------------------------------------------------------------------

/// Handler: return the current system settings.
pub async fn get_config(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, SystemApiError> {
    let settings = state
        .config_store
        .load_system_settings()
        .map_err(SystemApiError::StorageError)?;
    Ok(Json(settings))
}

// ---------------------------------------------------------------------------
// POST /system/config
// ---------------------------------------------------------------------------

/// Handler: replace the system settings.
pub async fn update_config(
    State(state): State<Arc<AppState>>,
    Json(settings): Json<SystemSettings>,
) -> Result<impl IntoResponse, SystemApiError> {
    validate_system_settings(&state, &settings)?;
    let previous = state
        .config_store
        .load_system_settings()
        .unwrap_or_default();

    state
        .config_store
        .save_system_settings(settings.clone())
        .map_err(SystemApiError::StorageError)?;

    apply_ssh_settings(&state, &settings).await?;

    if previous.ipv6_enabled != settings.ipv6_enabled {
        apply_ipv6_setting(settings.ipv6_enabled)
            .await
            .map_err(|e| {
                SystemApiError::CommandError(format!("failed to apply IPv6 setting: {e:#}"))
            })?;

        let full_cfg = state
            .config_store
            .load()
            .map_err(SystemApiError::StorageError)?;

        crate::captive_portal::apply_current_ruleset_nft(&state.config_store)
            .await
            .map_err(|e| {
                SystemApiError::CommandError(format!("failed to reapply firewall rules: {e}"))
            })?;

        if let Some(dns) = full_cfg.dns.as_ref() {
            apply_dns_config(dns, full_cfg.dot.as_ref(), settings.ipv6_enabled)
                .await
                .map_err(|e| {
                    SystemApiError::CommandError(format!("failed to reapply DNS config: {e:#}"))
                })?;
        }

        refresh_router_advertisements(&full_cfg.interfaces, settings.ipv6_enabled).await;
    }

    if previous.web_port != settings.web_port {
        warn!(
            previous_web_port = previous.web_port,
            new_web_port = settings.web_port,
            "system: web port changed; restart required to apply"
        );
    }

    info!(
        hostname = %settings.hostname,
        timezone = %settings.timezone,
        ssh_enabled = settings.ssh_enabled,
        ipv6_enabled = settings.ipv6_enabled,
        web_port = settings.web_port,
        "system: settings updated via API"
    );

    Ok(Json(settings))
}

fn validate_system_settings(state: &AppState, settings: &SystemSettings) -> Result<(), SystemApiError> {
    if settings.hostname.trim().is_empty() {
        return Err(SystemApiError::CommandError("hostname must not be empty".into()));
    }
    if settings.ssh_port == 0 {
        return Err(SystemApiError::CommandError("ssh_port must be between 1 and 65535".into()));
    }
    if settings.web_port == 0 {
        return Err(SystemApiError::CommandError("web_port must be between 1 and 65535".into()));
    }
    if settings.ssh_port == settings.web_port {
        return Err(SystemApiError::CommandError(
            "ssh_port and web_port must be different".into(),
        ));
    }

    let cfg = state.config_store.load().map_err(SystemApiError::StorageError)?;
    let known_interfaces = cfg
        .interfaces
        .iter()
        .filter(|iface| iface.enabled)
        .map(|iface| iface.name.as_str())
        .collect::<BTreeSet<_>>();
    for iface in &settings.ssh_listen_interfaces {
        if iface.trim().is_empty() {
            return Err(SystemApiError::CommandError(
                "ssh_listen_interfaces cannot contain empty interface names".into(),
            ));
        }
        if !known_interfaces.contains(iface.as_str()) {
            return Err(SystemApiError::CommandError(format!(
                "unknown SSH listen interface: {iface}"
            )));
        }
    }

    Ok(())
}

async fn apply_ssh_settings(
    state: &AppState,
    settings: &SystemSettings,
) -> Result<(), SystemApiError> {
    let full_cfg = state.config_store.load().map_err(SystemApiError::StorageError)?;
    let listen_addresses = resolve_ssh_listen_addresses(&settings.ssh_listen_interfaces, &full_cfg.interfaces).await;
    render_and_write_ssh_config(settings, &listen_addresses)?;
    write_authorized_keys(&settings.ssh_authorized_keys)?;

    if settings.ssh_enabled {
        run_systemctl(["enable", "--now", "ssh"]).await?;
        run_systemctl(["reload-or-restart", "ssh"]).await?;
    } else {
        run_systemctl(["disable", "--now", "ssh"]).await?;
    }

    Ok(())
}

fn render_and_write_ssh_config(
    settings: &SystemSettings,
    listen_addresses: &[String],
) -> Result<(), SystemApiError> {
    let mut rendered = String::new();
    rendered.push_str("# DayShield - managed sshd_config\n");
    rendered.push_str(&format!("Port {}\n", settings.ssh_port));
    rendered.push_str("AddressFamily any\n");
    for addr in listen_addresses {
        rendered.push_str(&format!("ListenAddress {}\n", addr));
    }
    rendered.push_str("\n# Authentication\n");
    rendered.push_str(&format!(
        "PermitRootLogin {}\n",
        if settings.ssh_permit_root_login { "yes" } else { "no" }
    ));
    rendered.push_str("PubkeyAuthentication yes\n");
    rendered.push_str("AuthorizedKeysFile .ssh/authorized_keys\n");
    rendered.push_str(&format!(
        "PasswordAuthentication {}\n",
        if settings.ssh_password_authentication { "yes" } else { "no" }
    ));
    rendered.push_str("PermitEmptyPasswords no\n");
    rendered.push_str("ChallengeResponseAuthentication no\n");
    rendered.push_str("KbdInteractiveAuthentication no\n");
    rendered.push_str("UsePAM yes\n");
    rendered.push_str("UseDNS no\n");
    rendered.push_str("PermitUserEnvironment no\n");
    rendered.push_str("LogLevel VERBOSE\n\n");
    rendered.push_str("# Forwarding\n");
    rendered.push_str("AllowAgentForwarding no\n");
    rendered.push_str("AllowTcpForwarding no\n");
    rendered.push_str("GatewayPorts no\n");
    rendered.push_str("X11Forwarding no\n");
    rendered.push_str("PermitTunnel no\n\n");
    rendered.push_str("# Session hardening\n");
    rendered.push_str("LoginGraceTime 30\n");
    rendered.push_str("MaxAuthTries 3\n");
    rendered.push_str("MaxStartups 10:30:60\n");
    rendered.push_str("MaxSessions 5\n");
    rendered.push_str("ClientAliveInterval 300\n");
    rendered.push_str("ClientAliveCountMax 2\n\n");
    rendered.push_str("Subsystem sftp /usr/lib/openssh/sftp-server\n");

    fs::write(SSHD_CONFIG_PATH, rendered).map_err(|err| {
        SystemApiError::CommandError(format!("failed to write sshd config: {err}"))
    })
}

fn write_authorized_keys(keys: &[String]) -> Result<(), SystemApiError> {
    fs::create_dir_all(SSH_ROOT_DIR).map_err(|err| {
        SystemApiError::CommandError(format!("failed to create SSH directory: {err}"))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(SSH_ROOT_DIR, fs::Permissions::from_mode(0o700));
    }

    let contents = if keys.is_empty() {
        String::new()
    } else {
        let mut normalized = keys
            .iter()
            .map(|key| key.trim())
            .filter(|key| !key.is_empty())
            .collect::<Vec<_>>()
            .join("\n");
        normalized.push('\n');
        normalized
    };

    fs::write(SSH_AUTHORIZED_KEYS_PATH, contents).map_err(|err| {
        SystemApiError::CommandError(format!("failed to write authorized_keys: {err}"))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(SSH_AUTHORIZED_KEYS_PATH, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

async fn resolve_ssh_listen_addresses(selected_interfaces: &[String], interfaces: &[crate::config::models::Interface]) -> Vec<String> {
    let mut addresses = BTreeSet::new();
    for iface_name in selected_interfaces {
        if let Ok(output) = tokio::process::Command::new("ip")
            .args(["-j", "addr", "show", "dev", iface_name])
            .output()
            .await
        {
            if output.status.success() {
                if let Ok(value) = serde_json::from_slice::<Value>(&output.stdout) {
                    if let Some(items) = value.as_array() {
                        for item in items {
                            if let Some(addr_info) = item.get("addr_info").and_then(Value::as_array) {
                                for addr in addr_info {
                                    if let Some(local) = addr.get("local").and_then(Value::as_str) {
                                        addresses.insert(local.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if let Some(iface) = interfaces.iter().find(|iface| iface.name == *iface_name) {
            for addr in &iface.addresses {
                if let Some(local) = addr.split('/').next().filter(|value| !value.is_empty()) {
                    addresses.insert(local.to_string());
                }
            }
        }
    }
    addresses.into_iter().collect()
}

async fn run_systemctl<const N: usize>(args: [&str; N]) -> Result<(), SystemApiError> {
    let output = tokio::process::Command::new("systemctl")
        .args(args)
        .output()
        .await
        .map_err(|err| SystemApiError::CommandError(format!("failed to spawn systemctl: {err}")))?;
    if output.status.success() {
        return Ok(());
    }
    if args.last() == Some(&"ssh") {
        let mut fallback = args.iter().map(|value| value.to_string()).collect::<Vec<_>>();
        if let Some(last) = fallback.last_mut() {
            *last = "sshd".to_string();
        }
        let fallback_output = tokio::process::Command::new("systemctl")
            .args(&fallback)
            .output()
            .await
            .map_err(|err| SystemApiError::CommandError(format!("failed to spawn systemctl fallback: {err}")))?;
        if fallback_output.status.success() {
            return Ok(());
        }
    }
    Err(SystemApiError::CommandError(format!(
        "systemctl {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    )))
}

// ---------------------------------------------------------------------------
// POST /system/reboot
// ---------------------------------------------------------------------------

/// Handler: trigger an immediate system reboot via systemctl.
pub async fn reboot(
    State(_state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, SystemApiError> {
    info!("system: reboot requested via API");
    tokio::process::Command::new("systemctl")
        .arg("reboot")
        .spawn()
        .map_err(|e| {
            SystemApiError::CommandError(format!("failed to spawn systemctl reboot: {e}"))
        })?
        .wait()
        .await
        .map_err(|e| SystemApiError::CommandError(format!("systemctl reboot failed: {e}")))?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// POST /system/shutdown
// ---------------------------------------------------------------------------

/// Handler: trigger an immediate system poweroff via systemctl.
pub async fn shutdown(
    State(_state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, SystemApiError> {
    info!("system: shutdown requested via API");
    tokio::process::Command::new("systemctl")
        .arg("poweroff")
        .spawn()
        .map_err(|e| {
            SystemApiError::CommandError(format!("failed to spawn systemctl poweroff: {e}"))
        })?
        .wait()
        .await
        .map_err(|e| SystemApiError::CommandError(format!("systemctl poweroff failed: {e}")))?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Software updates
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateActionRequest {
    #[serde(default = "default_update_component")]
    pub component: UpdateComponent,
    /// If true, allows applying updates to only a subset of components even when multiple have available updates
    #[serde(default)]
    pub force_partial_apply: bool,
}

fn default_update_component() -> UpdateComponent {
    UpdateComponent::Both
}

/// Handler: return software-update status for core and UI artifacts.
pub async fn get_updates_status(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, SystemApiError> {
    Ok(Json(update::get_status(&state).await))
}

/// Handler: return persisted software-update settings.
pub async fn get_update_settings(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, SystemApiError> {
    Ok(Json(update::load_settings(&state)))
}

/// Handler: update software-update settings.
pub async fn update_update_settings(
    State(state): State<Arc<AppState>>,
    Json(settings): Json<UpdateSettings>,
) -> Result<impl IntoResponse, SystemApiError> {
    update::save_settings(&state, &settings).map_err(SystemApiError::StorageError)?;
    Ok(Json(update::load_settings(&state)))
}

/// Handler: run an immediate check against configured update registry.
pub async fn check_updates(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, SystemApiError> {
    let status = update::check_for_updates(&state)
        .await
        .map_err(SystemApiError::StorageError)?;
    Ok(Json(status))
}

/// Handler: apply updates for selected component(s).
///
/// Spawns the update process in a background task and returns immediately with
/// 202 Accepted. The caller should poll `/system/updates/status` to monitor progress.
pub async fn apply_updates(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpdateActionRequest>,
) -> Result<impl IntoResponse, SystemApiError> {
    let component = req.component;
    if matches!(component, UpdateComponent::Rootfs) {
        let status = update::get_status(&state).await;
        if !status
            .rootfs_slot_status
            .as_ref()
            .map(|slot| slot.supported)
            .unwrap_or(false)
        {
            let reason = status
                .rootfs_slot_status
                .as_ref()
                .and_then(|slot| slot.reason.clone())
                .unwrap_or_else(|| "A/B rootfs layout is not available".to_string());
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "operation": "apply",
                    "success": false,
                    "message": reason,
                    "details": [],
                    "status": status
                })),
            ));
        }
    }
    let force_partial = req.force_partial_apply;
    let state_clone = Arc::clone(&state);

    // Spawn update in background - don't wait for completion
    tokio::spawn(async move {
        match update::apply_updates(&state_clone, component, force_partial).await {
            Ok(result) => {
                info!(
                    "updates: background apply_updates completed successfully: {}",
                    result.message
                );
            }
            Err(e) => {
                warn!("updates: background apply_updates failed: {}", e);
            }
        }
    });

    // Get current status to return immediately
    let current_status = update::get_status(&state).await;

    // Return 202 Accepted immediately with current status to prevent timeout
    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "operation": "apply",
            "success": true,
            "message": "Update process started. Progress is available in update status logs.",
            "details": [],
            "status": current_status
        })),
    ))
}

/// Handler: rollback selected component(s) to previous commit.
///
/// Spawns the rollback process in a background task and returns immediately.
/// The caller should poll `/system/updates/status` to monitor progress.
pub async fn rollback_updates(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpdateActionRequest>,
) -> Result<impl IntoResponse, SystemApiError> {
    let component = req.component;
    let force_partial = req.force_partial_apply;
    let state_clone = Arc::clone(&state);

    // Spawn rollback in background - don't wait for completion
    tokio::spawn(async move {
        match update::rollback_updates(&state_clone, component, force_partial).await {
            Ok(result) => {
                info!(
                    "updates: background rollback_updates completed successfully: {}",
                    result.message
                );
            }
            Err(e) => {
                warn!("updates: background rollback_updates failed: {}", e);
            }
        }
    });

    // Get current status to return immediately
    let current_status = update::get_status(&state).await;

    // Return 202 Accepted immediately with current status
    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "operation": "rollback",
            "success": true,
            "message": "Rollback process started. Progress is available in update status logs.",
            "details": [],
            "status": current_status
        })),
    ))
}

/// Handler: validate selected component(s) are at expected commit.
pub async fn validate_updates(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpdateActionRequest>,
) -> Result<impl IntoResponse, SystemApiError> {
    if matches!(req.component, UpdateComponent::Rootfs) {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "operation": "validate",
                "success": false,
                "message": "rootfs validation is reported through the A/B slot status",
                "details": [],
                "status": update::get_status(&state).await
            })),
        ));
    }

    let result = update::validate_updates(&state, req.component, req.force_partial_apply)
        .await
        .map_err(SystemApiError::StorageError)?;
    Ok((StatusCode::OK, Json(serde_json::json!(result))))
}

/// Handler: mark the appliance rebuild workflow as completed after rebuilding artifacts.
pub async fn mark_appliance_rebuild_complete(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, SystemApiError> {
    update::mark_appliance_rebuild_complete(&state).map_err(SystemApiError::StorageError)?;
    Ok(Json(update::get_status(&state).await))
}
