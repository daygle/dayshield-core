//! Metrics REST API handlers.
//!
//! Endpoints:
//! - `GET /metrics`                — returns the latest [`MetricsSnapshot`]
//! - `GET /metrics/history?seconds=N` — returns the last N seconds of history
//! - `GET /metrics/ws`             — WebSocket upgrade for live streaming

use std::sync::Arc;

use axum::{
    extract::{ws::WebSocketUpgrade, Query, State},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{metrics::websocket::metrics_websocket, state::AppState};

// ---------------------------------------------------------------------------
// GET /metrics
// ---------------------------------------------------------------------------

/// Return the latest metrics snapshot.
///
/// Returns HTTP 204 (no content) if the collector has not produced a snapshot
/// yet.
pub async fn get_latest(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let buf = state.metrics_buffer.read().await;
    match buf.latest() {
        Some(snapshot) => Json(json!(snapshot)).into_response(),
        None => axum::http::StatusCode::NO_CONTENT.into_response(),
    }
}

// ---------------------------------------------------------------------------
// GET /metrics/history?seconds=N
// ---------------------------------------------------------------------------

/// Query parameters for the history endpoint.
#[derive(Deserialize)]
pub struct HistoryQuery {
    /// Number of seconds of history to return (default: 300).
    #[serde(default = "default_seconds")]
    pub seconds: u64,
}

fn default_seconds() -> u64 {
    300
}

/// Return the last `seconds` seconds of metric snapshots.
pub async fn get_history(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HistoryQuery>,
) -> Json<Value> {
    let buf = state.metrics_buffer.read().await;
    let snapshots = buf.last_n(params.seconds);
    Json(json!(snapshots))
}

// ---------------------------------------------------------------------------
// GET /metrics/ws
// ---------------------------------------------------------------------------

/// Upgrade to WebSocket and start streaming live metrics.
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| metrics_websocket(socket, state))
}
