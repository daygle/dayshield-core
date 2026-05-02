//! System endpoints.
//!
//! - `GET  /system/status`   — overall health and version
//! - `GET  /system/config`   — host-level settings (hostname, timezone, NTP…)
//! - `PUT  /system/config`   — update host-level settings
//! - `POST /system/reboot`   — schedule an immediate systemctl reboot
//! - `POST /system/shutdown` — schedule an immediate systemctl poweroff

use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use chrono::Utc;
use serde::Serialize;
use tracing::info;

use crate::{
    config::models::SystemSettings,
    state::AppState,
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
