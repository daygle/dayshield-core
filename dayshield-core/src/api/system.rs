//! System endpoints.
//!
//! - `GET  /system/status`   — overall health and version
//! - `GET  /system/config`   — host-level settings (hostname, timezone, NTP…)
//! - `PUT  /system/config`   — update host-level settings
//! - `POST /system/reboot`   — schedule an immediate systemctl reboot
//! - `POST /system/shutdown` — schedule an immediate systemctl poweroff
//! - `GET  /system/updates/status`   — get artifact update status for core/ui/rootfs
//! - `GET  /system/updates/settings` — get update settings
//! - `PUT  /system/updates/settings` — update settings (interval/reboot policy/registry)
//! - `POST /system/updates/check`    — force immediate update check
//! - `POST /system/updates/apply`    — apply updates from registry artifacts
//! - `POST /system/updates/rollback` — rollback latest applied update transaction
//! - `POST /system/updates/validate` — validate applied update state
//! - `POST /system/updates/appliance-rebuild-complete` — clear pending appliance rebuild status
//! - `POST /system/updates/rootfs-live-rollback` — rollback rootfs live update from latest backup snapshot

use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    config::models::SystemSettings,
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
    state
        .config_store
        .save_system_settings(settings.clone())
        .map_err(SystemApiError::StorageError)?;

    info!(
        hostname = %settings.hostname,
        timezone = %settings.timezone,
        ssh_enabled = settings.ssh_enabled,
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

/// Handler: return software-update status for core, UI, and rootfs artifacts.
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
pub async fn apply_updates(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpdateActionRequest>,
) -> Result<impl IntoResponse, SystemApiError> {
    let result = update::apply_updates(&state, req.component, req.force_partial_apply)
        .await
        .map_err(SystemApiError::StorageError)?;
    Ok(Json(result))
}

/// Handler: rollback selected component(s) to previous commit.
pub async fn rollback_updates(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpdateActionRequest>,
) -> Result<impl IntoResponse, SystemApiError> {
    let result = update::rollback_updates(&state, req.component, req.force_partial_apply)
        .await
        .map_err(SystemApiError::StorageError)?;
    Ok(Json(result))
}

/// Handler: validate selected component(s) are at expected commit.
pub async fn validate_updates(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpdateActionRequest>,
) -> Result<impl IntoResponse, SystemApiError> {
    let result = update::validate_updates(&state, req.component, req.force_partial_apply)
        .await
        .map_err(SystemApiError::StorageError)?;
    Ok(Json(result))
}

/// Handler: mark the appliance rebuild workflow as completed after rebuilding artifacts.
pub async fn mark_appliance_rebuild_complete(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, SystemApiError> {
    update::mark_appliance_rebuild_complete(&state).map_err(SystemApiError::StorageError)?;
    Ok(Json(update::get_status(&state).await))
}

/// Handler: rollback rootfs live update using the latest snapshot backup.
pub async fn rollback_rootfs_live_update(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, SystemApiError> {
    let result = update::rollback_rootfs_live_update(&state)
        .await
        .map_err(SystemApiError::StorageError)?;
    Ok(Json(result))
}
