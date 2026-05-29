//! QoS REST API handlers.
//!
//! | Method | Path          | Description                         |
//! |--------|---------------|-------------------------------------|
//! | GET    | `/qos/config` | Return persisted QoS config         |
//! | PUT    | `/qos/config` | Replace QoS config and apply `tc`   |
//! | GET    | `/qos/status` | Read live `tc -s qdisc` status      |
//! | POST   | `/qos/apply`  | Re-apply the persisted QoS config   |

use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Serialize;
use tracing::{info, warn};

use crate::{
    config::models::{validate_qos_config, QosConfig},
    engine::qos::{self as qos_engine, QosEngineError},
    state::AppState,
};

#[derive(Debug, thiserror::Error)]
pub enum QosApiError {
    #[error("validation error: {0}")]
    ValidationFailed(String),

    #[error("storage error: {0:#}")]
    StorageError(#[from] anyhow::Error),

    #[error("engine error: {0}")]
    EngineError(String),
}

impl IntoResponse for QosApiError {
    fn into_response(self) -> axum::response::Response {
        let status = match &self {
            QosApiError::ValidationFailed(_) => StatusCode::UNPROCESSABLE_ENTITY,
            QosApiError::StorageError(_) | QosApiError::EngineError(_) => {
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionResponse {
    pub message: String,
}

pub async fn get_config(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, QosApiError> {
    let cfg = state
        .config_store
        .load_qos_config()
        .map_err(QosApiError::StorageError)?;

    Ok(Json(cfg))
}

pub async fn put_config(
    State(state): State<Arc<AppState>>,
    Json(cfg): Json<QosConfig>,
) -> Result<impl IntoResponse, QosApiError> {
    validate_qos_config(&cfg).map_err(QosApiError::ValidationFailed)?;

    let previous = state
        .config_store
        .load_qos_config()
        .map_err(QosApiError::StorageError)?;

    state
        .config_store
        .save_qos_config(cfg.clone())
        .map_err(QosApiError::StorageError)?;

    if let Err(apply_err) = qos_engine::apply_config_replacing(Some(&previous), &cfg).await {
        warn!(error = %apply_err, "qos: apply failed after save; rolling back config");
        if let Err(restore_err) = state.config_store.save_qos_config(previous.clone()) {
            warn!(error = %restore_err, "qos: failed to restore previous config after apply failure");
            return Err(QosApiError::EngineError(format!(
                "{}; failed to restore previous QoS config: {:#}",
                apply_err, restore_err
            )));
        }
        if let Err(reapply_err) = qos_engine::apply_config_replacing(Some(&cfg), &previous).await {
            warn!(error = %reapply_err, "qos: failed to reapply previous config after rollback");
        }
        return Err(qos_engine_error(apply_err));
    }

    info!(
        enabled = cfg.enabled,
        interfaces = cfg.interfaces.len(),
        "qos: configuration updated"
    );

    Ok(Json(cfg))
}

pub async fn apply(State(state): State<Arc<AppState>>) -> Result<impl IntoResponse, QosApiError> {
    let cfg = state
        .config_store
        .load_qos_config()
        .map_err(QosApiError::StorageError)?;

    qos_engine::apply_config(&cfg)
        .await
        .map_err(qos_engine_error)?;

    Ok(Json(ActionResponse {
        message: "QoS configuration applied".to_string(),
    }))
}

pub async fn get_status(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, QosApiError> {
    let cfg = state
        .config_store
        .load_qos_config()
        .map_err(QosApiError::StorageError)?;

    Ok(Json(qos_engine::read_status(&cfg).await))
}

fn qos_engine_error(error: QosEngineError) -> QosApiError {
    QosApiError::EngineError(error.to_string())
}
