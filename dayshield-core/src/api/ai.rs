use std::{net::IpAddr, sync::Arc};

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use crate::state::AppState;

#[derive(Debug, thiserror::Error)]
pub enum AiApiError {
    #[error("invalid request: {0}")]
    BadRequest(String),
    #[error("not found")]
    NotFound,
    #[error("internal error: {0:#}")]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for AiApiError {
    fn into_response(self) -> Response {
        let status = match self {
            AiApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AiApiError::NotFound => StatusCode::NOT_FOUND,
            AiApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        (
            status,
            Json(serde_json::json!({ "error": self.to_string() })),
        )
            .into_response()
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct ListThreatsQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    100
}

/// GET /api/ai/threats
pub async fn list_threats(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListThreatsQuery>,
) -> Result<impl IntoResponse, AiApiError> {
    let limit = query.limit.clamp(1, 1000);
    let events = state.ai_runtime.recent_threat_events(limit)?;
    Ok(Json(events))
}

/// GET /api/ai/threats/{id}
pub async fn get_threat(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AiApiError> {
    let event = state.ai_runtime.get_threat_event(&id)?;
    match event {
        Some(evt) => Ok(Json(evt).into_response()),
        None => Err(AiApiError::NotFound),
    }
}

/// POST /api/ai/unblock/{ip}
pub async fn unblock_ip(
    State(state): State<Arc<AppState>>,
    Path(ip): Path<String>,
) -> Result<impl IntoResponse, AiApiError> {
    let parsed = ip
        .parse::<IpAddr>()
        .map_err(|_| AiApiError::BadRequest(format!("invalid IP address: {ip}")))?;

    let removed = state.ai_runtime.unblock_ip(&state, parsed).await?;
    Ok(Json(serde_json::json!({
        "ip": ip,
        "unblocked": removed,
    })))
}

/// GET /api/ai/blocked
pub async fn list_blocked(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, AiApiError> {
    let blocked = state.ai_runtime.list_blocked().await;
    Ok(Json(blocked))
}
