use std::{net::IpAddr, sync::Arc};

use axum::{
    extract::{Path, Query, State},
    http::{header::REFERER, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};

use crate::ai_policy::models::{
    ApplySuggestionRequest, AutomationSettings, ModeRequest, SetIntentsRequest,
    ZeroTrustBootstrapRequest,
};
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

#[derive(Debug, serde::Deserialize)]
pub struct ModeQuery {
    pub iface: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct InterfaceQuery {
    pub iface: Option<String>,
}

fn selected_iface(iface: Option<String>, headers: &HeaderMap) -> Option<String> {
    iface.or_else(|| {
        headers
            .get(REFERER)
            .and_then(|value| value.to_str().ok())
            .and_then(iface_from_referer)
    })
}

fn iface_from_referer(referer: &str) -> Option<String> {
    let query = referer.split_once('?')?.1.split('#').next().unwrap_or("");
    query.split('&').find_map(|part| {
        let (key, value) = part.split_once('=')?;
        (key == "iface" && !value.trim().is_empty()).then(|| value.trim().to_string())
    })
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
    headers: HeaderMap,
    Query(query): Query<InterfaceQuery>,
) -> Result<impl IntoResponse, AiApiError> {
    let suggestions = state
        .ai_policy_engine
        .list_suggestions(&state, selected_iface(query.iface, &headers))
        .await?;
    Ok(Json(suggestions))
}

/// GET /api/ai/traffic_candidates
pub async fn get_traffic_candidates(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<InterfaceQuery>,
) -> Result<impl IntoResponse, AiApiError> {
    Ok(Json(
        state
            .ai_policy_engine
            .list_traffic_candidates(selected_iface(query.iface, &headers))
            .await,
    ))
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
    headers: HeaderMap,
    Query(query): Query<InterfaceQuery>,
) -> Result<impl IntoResponse, AiApiError> {
    Ok(Json(
        state
            .ai_policy_engine
            .get_intents(selected_iface(query.iface, &headers))
            .await,
    ))
}

/// POST /api/ai/intents
pub async fn set_intents(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<InterfaceQuery>,
    Json(req): Json<SetIntentsRequest>,
) -> Result<impl IntoResponse, AiApiError> {
    let intents = state
        .ai_policy_engine
        .set_intents(req, selected_iface(query.iface, &headers))
        .await?;
    Ok(Json(intents))
}

/// GET /api/ai/automation_settings
pub async fn get_automation_settings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<InterfaceQuery>,
) -> Result<impl IntoResponse, AiApiError> {
    Ok(Json(
        state
            .ai_policy_engine
            .get_automation_settings(selected_iface(query.iface, &headers))
            .await,
    ))
}

/// POST /api/ai/automation_settings
pub async fn set_automation_settings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<InterfaceQuery>,
    Json(settings): Json<AutomationSettings>,
) -> Result<impl IntoResponse, AiApiError> {
    let settings = state
        .ai_policy_engine
        .set_automation_settings(settings, selected_iface(query.iface, &headers))
        .await?;
    Ok(Json(settings))
}

/// GET /api/ai/mode
pub async fn get_mode(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<ModeQuery>,
) -> Result<impl IntoResponse, AiApiError> {
    Ok(Json(
        state
            .ai_policy_engine
            .get_mode(selected_iface(query.iface, &headers))
            .await,
    ))
}

/// POST /api/ai/mode
pub async fn set_mode(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<ModeQuery>,
    Json(req): Json<ModeRequest>,
) -> Result<impl IntoResponse, AiApiError> {
    let mode = state
        .ai_policy_engine
        .set_mode(req, selected_iface(query.iface, &headers))
        .await?;
    Ok(Json(mode))
}

/// POST /api/ai/bootstrap_zero_trust
pub async fn bootstrap_zero_trust(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<InterfaceQuery>,
) -> Result<impl IntoResponse, AiApiError> {
    let response = state
        .ai_policy_engine
        .bootstrap_zero_trust(
            &state,
            ZeroTrustBootstrapRequest::default(),
            selected_iface(query.iface, &headers),
        )
        .await?;
    Ok(Json(response))
}

/// POST /api/ai/undo_last_action
pub async fn undo_last_action(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<InterfaceQuery>,
) -> Result<impl IntoResponse, AiApiError> {
    let response = state
        .ai_policy_engine
        .undo_last_action(&state, selected_iface(query.iface, &headers))
        .await?;
    Ok(Json(response))
}

/// GET /api/ai/action_history
pub async fn get_action_history(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<InterfaceQuery>,
) -> Result<impl IntoResponse, AiApiError> {
    Ok(Json(
        state
            .ai_policy_engine
            .list_action_history(selected_iface(query.iface, &headers))
            .await,
    ))
}
