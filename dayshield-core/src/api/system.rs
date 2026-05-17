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

use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::{
    config::models::SystemSettings,
    engine::{
        dns::apply_config_with_ipv6 as apply_dns_config,
        interfaces::refresh_router_advertisements,
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
    let previous = state
        .config_store
        .load_system_settings()
        .unwrap_or_default();

    state
        .config_store
        .save_system_settings(settings.clone())
        .map_err(SystemApiError::StorageError)?;

    if previous.ipv6_enabled != settings.ipv6_enabled {
        apply_ipv6_setting(settings.ipv6_enabled)
            .await
            .map_err(|e| SystemApiError::CommandError(format!("failed to apply IPv6 setting: {e:#}")))?;

        let full_cfg = state
            .config_store
            .load()
            .map_err(SystemApiError::StorageError)?;

        crate::captive_portal::apply_current_ruleset_nft(&state.config_store)
            .await
            .map_err(|e| SystemApiError::CommandError(format!("failed to reapply firewall rules: {e}")))?;

        if let Some(dns) = full_cfg.dns.as_ref() {
            apply_dns_config(dns, full_cfg.dot.as_ref(), settings.ipv6_enabled)
                .await
                .map_err(|e| SystemApiError::CommandError(format!("failed to reapply DNS config: {e:#}")))?;
        }

        refresh_router_advertisements(&full_cfg.interfaces, settings.ipv6_enabled).await;
    }

    info!(
        hostname = %settings.hostname,
        timezone = %settings.timezone,
        ssh_enabled = settings.ssh_enabled,
        ipv6_enabled = settings.ipv6_enabled,
        "system: settings updated via API"
    );

    Ok(Json(settings))
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
        .map_err(|e| SystemApiError::CommandError(format!("failed to spawn systemctl reboot: {e}")))?
        .wait()
        .await
        .map_err(|e| SystemApiError::CommandError(format!("systemctl reboot failed: {e}")))?
        ;
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
        .map_err(|e| SystemApiError::CommandError(format!("failed to spawn systemctl poweroff: {e}")))?
        .wait()
        .await
        .map_err(|e| SystemApiError::CommandError(format!("systemctl poweroff failed: {e}")))?
        ;
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
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "operation": "apply",
                "success": false,
                "message": "rootfs updates are not supported on a running appliance; rebuild and publish appliance artifacts instead",
                "details": [],
                "status": update::get_status(&state).await
            })),
        ));
    }
    let force_partial = req.force_partial_apply;
    let state_clone = Arc::clone(&state);

    // Spawn update in background - don't wait for completion
    tokio::spawn(async move {
        match update::apply_updates(&state_clone, component, force_partial).await {
            Ok(result) => {
                info!("updates: background apply_updates completed successfully: {}", result.message);
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
        }))
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
    if matches!(component, UpdateComponent::Rootfs) {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "operation": "rollback",
                "success": false,
                "message": "rootfs rollback is not supported on a running appliance; rebuild and publish appliance artifacts instead",
                "details": [],
                "status": update::get_status(&state).await
            })),
        ));
    }
    let force_partial = req.force_partial_apply;
    let state_clone = Arc::clone(&state);

    // Spawn rollback in background - don't wait for completion
    tokio::spawn(async move {
        match update::rollback_updates(&state_clone, component, force_partial).await {
            Ok(result) => {
                info!("updates: background rollback_updates completed successfully: {}", result.message);
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
        }))
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
                "message": "rootfs validation is not supported on a running appliance; rebuild and publish appliance artifacts instead",
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
