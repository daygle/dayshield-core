use std::{net::IpAddr, sync::Arc};

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use crate::ai_policy::models::{ApplySuggestionRequest, ModeRequest, SetIntentsRequest};
use crate::config::models::{validate_ai_engine_config, AiEngineConfig};
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

#[derive(Debug, serde::Deserialize)]
pub struct FeedbackRequest {
    pub feedback: String,
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

/// POST /api/ai/feedback/{id}
pub async fn submit_feedback(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<FeedbackRequest>,
) -> Result<impl IntoResponse, AiApiError> {
    let feedback =
        crate::ai_engine::FeedbackKind::parse(req.feedback.as_str()).ok_or_else(|| {
            AiApiError::BadRequest(format!("invalid feedback value: {}", req.feedback))
        })?;

    let event = state
        .ai_runtime
        .apply_feedback(&state, &id, feedback)
        .await?;
    match event {
        Some(evt) => Ok(Json(evt).into_response()),
        None => Err(AiApiError::NotFound),
    }
}

/// GET /api/ai/config
pub async fn get_config(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, AiApiError> {
    let config = state.config_store.load_ai_engine_config()?;
    Ok(Json(config))
}

/// POST /api/ai/config
pub async fn update_config(
    State(state): State<Arc<AppState>>,
    Json(config): Json<AiEngineConfig>,
) -> Result<impl IntoResponse, AiApiError> {
    validate_ai_engine_config(&config).map_err(|e| AiApiError::BadRequest(e))?;

    state.config_store.save_ai_engine_config(config.clone())?;
    state.ai_runtime.update_model_config(&config).await?;
    Ok(Json(config))
}

/// GET /api/ai/suggestions
pub async fn get_suggestions(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, AiApiError> {
    let suggestions = state.ai_policy_engine.list_suggestions(&state).await?;
    Ok(Json(suggestions))
}

/// GET /api/ai/traffic_candidates
pub async fn get_traffic_candidates(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, AiApiError> {
    Ok(Json(state.ai_policy_engine.list_traffic_candidates().await))
}

/// POST /api/ai/apply
pub async fn apply_suggestion(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ApplySuggestionRequest>,
) -> Result<impl IntoResponse, AiApiError> {
    let response = state
        .ai_policy_engine
        .apply_suggestion(&state, req, false)
        .await?;
    Ok(Json(response))
}

/// GET /api/ai/intents
pub async fn get_intents(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, AiApiError> {
    Ok(Json(state.ai_policy_engine.get_intents().await))
}

/// POST /api/ai/intents
pub async fn set_intents(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SetIntentsRequest>,
) -> Result<impl IntoResponse, AiApiError> {
    let intents = state.ai_policy_engine.set_intents(req).await?;
    Ok(Json(intents))
}

/// GET /api/ai/mode
pub async fn get_mode(State(state): State<Arc<AppState>>) -> Result<impl IntoResponse, AiApiError> {
    Ok(Json(state.ai_policy_engine.get_mode().await))
}

/// POST /api/ai/mode
pub async fn set_mode(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ModeRequest>,
) -> Result<impl IntoResponse, AiApiError> {
    let mode = state.ai_policy_engine.set_mode(req).await?;
    Ok(Json(mode))
}

/// POST /api/ai/undo_last_action
pub async fn undo_last_action(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, AiApiError> {
    let response = state.ai_policy_engine.undo_last_action(&state).await?;
    Ok(Json(response))
}
