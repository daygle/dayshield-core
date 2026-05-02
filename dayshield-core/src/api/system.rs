//! System status endpoint — `GET /system/status`.

use std::sync::Arc;

use axum::{extract::State, response::IntoResponse, Json};
use chrono::Utc;
use serde::Serialize;

use crate::state::AppState;

/// Response body returned by `GET /system/status`.
#[derive(Serialize)]
pub struct SystemStatusResponse {
    /// Human-readable product name.
    pub name: &'static str,
    /// Crate version from `Cargo.toml`.
    pub version: &'static str,
    /// ISO-8601 server timestamp at time of request.
    pub timestamp: String,
    /// Aggregate health of all tracked services.
    pub services_healthy: bool,
    /// Number of services currently being tracked.
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
