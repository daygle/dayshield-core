//! NTP REST API endpoints.
//!
//! | Method | Path           | Description                                 |
//! |--------|----------------|---------------------------------------------|
//! | GET    | `/ntp/config`  | Get the current NTP configuration           |
//! | POST   | `/ntp/config`  | Update + apply the NTP configuration        |
//! | GET    | `/ntp/status`  | Get live NTP synchronisation status         |

use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use tracing::info;

use crate::ntp::{
    apply::{apply_ntp_config, NtpError},
    config as ntp_config,
    model::{NtpConfig, NtpStatus},
    status::ntp_status,
};
use crate::config::models::validate_ntp_config_with_ipv6;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum NtpApiError {
    #[error("validation error: {0}")]
    ValidationFailed(String),

    #[error("apply error: {0}")]
    ApplyFailed(String),

    #[error("storage error: {0:#}")]
    StorageError(#[from] anyhow::Error),
}

impl From<NtpError> for NtpApiError {
    fn from(e: NtpError) -> Self {
        NtpApiError::ApplyFailed(e.to_string())
    }
}

impl IntoResponse for NtpApiError {
    fn into_response(self) -> Response {
        let status = match &self {
            NtpApiError::ValidationFailed(_) => StatusCode::BAD_REQUEST,
            NtpApiError::ApplyFailed(_) | NtpApiError::StorageError(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        (
            status,
            Json(serde_json::json!({ "error": self.to_string() })),
        )
            .into_response()
    }
}

// ---------------------------------------------------------------------------
// GET /ntp/config
// ---------------------------------------------------------------------------

/// Return the current NTP configuration.
///
/// Returns a default (disabled) config when none has been saved yet.
pub async fn get_config(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, NtpApiError> {
    let cfg = ntp_config::load(&state.config_store).map_err(NtpApiError::StorageError)?;
    Ok(Json(cfg))
}

// ---------------------------------------------------------------------------
// POST /ntp/config
// ---------------------------------------------------------------------------

/// Replace the NTP configuration and apply it to the running system.
///
/// Validates before persisting. On success, the appropriate NTP daemon
/// config files are written and the daemon is restarted.
pub async fn update_config(
    State(state): State<Arc<AppState>>,
    Json(req): Json<NtpConfig>,
) -> Result<impl IntoResponse, NtpApiError> {
    let ipv6_enabled = state
        .config_store
        .load_system_settings()
        .map_err(NtpApiError::StorageError)?
        .ipv6_enabled;

    if let Err(msg) = validate_ntp_config_with_ipv6(&req, ipv6_enabled) {
        return Err(NtpApiError::ValidationFailed(msg));
    }

    info!(
        enabled = req.enabled,
        serve_clients = req.serve_clients,
        upstream_count = req.upstream_servers.len(),
        "NTP config updated via API - applying to system"
    );

    apply_ntp_config(&req).await.map_err(NtpApiError::from)?;

    // Persist only after successful runtime apply so UI/state stays consistent
    // with what is actually active on the appliance.
    ntp_config::save(&state.config_store, req.clone()).map_err(NtpApiError::StorageError)?;

    Ok(Json(req))
}

// ---------------------------------------------------------------------------
// GET /ntp/status
// ---------------------------------------------------------------------------

/// Return a live snapshot of the NTP synchronisation state.
pub async fn get_status() -> Json<NtpStatus> {
    Json(ntp_status().await)
}

// ---------------------------------------------------------------------------
// POST /ntp/resync
// ---------------------------------------------------------------------------

/// Trigger an immediate NTP time step resynchronisation.
///
/// Tries `chronyc makestep` first (chrony); falls back to restarting
/// `systemd-timesyncd` if chrony is not available.
pub async fn resync() -> impl IntoResponse {
    let chrony = tokio::process::Command::new("chronyc")
        .arg("makestep")
        .output()
        .await;

    if let Ok(out) = chrony {
        if out.status.success() {
            return Json(serde_json::json!({
                "success": true,
                "data": { "message": "NTP resync triggered via chronyc" }
            }));
        }
    }

    async fn restart_unit(unit: &str) -> bool {
        match tokio::process::Command::new("systemctl")
            .args(["restart", unit])
            .output()
            .await
        {
            Ok(out) if out.status.success() => true,
            _ => false,
        }
    }

    for unit in ["chronyd", "chrony", "systemd-timesyncd"] {
        if restart_unit(unit).await {
            return Json(serde_json::json!({
                "success": true,
                "data": { "message": format!("NTP resync triggered via systemctl restart {unit}") }
            }));
        }
    }

    Json(serde_json::json!({
        "success": false,
        "error": "NTP resync failed: no available NTP daemon restart path succeeded"
    }))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;

    #[test]
    fn error_status_codes() {
        assert_eq!(
            NtpApiError::ValidationFailed("bad server".into())
                .into_response()
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            NtpApiError::ApplyFailed("systemctl failed".into())
                .into_response()
                .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            NtpApiError::StorageError(anyhow::anyhow!("disk error"))
                .into_response()
                .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn ntp_error_mapping() {
        let ntp_err = NtpError::ServiceCommand {
            service: "chrony".into(),
            message: "restart failed".into(),
        };
        let api_err: NtpApiError = ntp_err.into();
        assert!(matches!(api_err, NtpApiError::ApplyFailed(_)));
    }
}
