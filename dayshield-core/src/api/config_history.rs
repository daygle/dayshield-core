//! Configuration history REST API endpoints.
//!
//! Exposes the OPNsense-style configuration revision history maintained by the
//! [`ConfigStore`](crate::config::ConfigStore): every committed configuration is
//! archived and can be listed, inspected and restored.
//!
//! | Method | Path                              | Description                          |
//! |--------|-----------------------------------|--------------------------------------|
//! | GET    | `/config/history`                 | List archived revisions (newest first) |
//! | GET    | `/config/history/{id}`            | Fetch the full config of one revision |
//! | POST   | `/config/history/{id}/restore`    | Restore a revision as the live config |

use std::sync::Arc;

use axum::{
    extract::{Path as AxumPath, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use tracing::info;

use crate::state::AppState;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum ConfigHistoryError {
    #[error("not found: {0}")]
    NotFound(String),

    #[error("storage error: {0:#}")]
    StorageError(anyhow::Error),
}

impl IntoResponse for ConfigHistoryError {
    fn into_response(self) -> Response {
        let status = match &self {
            ConfigHistoryError::NotFound(_) => StatusCode::NOT_FOUND,
            ConfigHistoryError::StorageError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (
            status,
            Json(serde_json::json!({ "error": self.to_string() })),
        )
            .into_response()
    }
}

/// Map a storage-layer error to either `404` (unknown revision id) or `500`.
fn classify(err: anyhow::Error) -> ConfigHistoryError {
    let msg = err.to_string();
    if msg.contains("not found") || msg.contains("invalid revision id") {
        ConfigHistoryError::NotFound(msg)
    } else {
        ConfigHistoryError::StorageError(err)
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /config/history`
///
/// Returns the list of archived configuration revisions, newest first.
pub async fn list_handler(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, ConfigHistoryError> {
    let revisions = state
        .config_store
        .list_revisions()
        .map_err(ConfigHistoryError::StorageError)?;
    Ok(Json(revisions))
}

/// `GET /config/history/{id}`
///
/// Returns the full [`SystemConfig`](crate::config::SystemConfig) captured in
/// the given revision, migrated to the current schema if necessary.
pub async fn get_handler(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
) -> Result<impl IntoResponse, ConfigHistoryError> {
    let config = state.config_store.load_revision(&id).map_err(classify)?;
    Ok(Json(config))
}

/// `POST /config/history/{id}/restore`
///
/// Restores the configuration captured in the given revision, making it the
/// live configuration. The restore is validated, applied to running services,
/// and itself archived as a new revision.
pub async fn restore_handler(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
) -> Result<impl IntoResponse, ConfigHistoryError> {
    state.config_store.restore_revision(&id).map_err(classify)?;
    info!(revision = %id, "config revision restored via API");
    Ok(Json(
        serde_json::json!({ "status": "ok", "restored": id }),
    ))
}
