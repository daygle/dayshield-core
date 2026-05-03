//! Gateway endpoints.
//!
//! - `GET    /gateways`        — list configured gateways with live routing and health state
//! - `POST   /gateways`        — create or update a gateway
//! - `DELETE /gateways/{name}` — delete a gateway by name

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Serialize;
use tracing::{info, warn};

use crate::{
    config::models::Gateway,
    engine::gateway::{apply_gateway, list_kernel_gateways, probe_all_gateways, GatewayState},
    state::AppState,
};

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// A gateway entry with live kernel and health information.
#[derive(Serialize)]
pub struct GatewayStatus {
    /// The persisted gateway configuration.
    #[serde(flatten)]
    pub gateway: Gateway,
    /// Health state from the most recent probe.
    pub state: GatewayState,
    /// Current gateway IP as reported by the kernel routing table.
    ///
    /// For DHCP / PPPoE gateways this will be populated even when
    /// `gateway_ip` in the config is `None`.
    pub active_ip: Option<String>,
}

/// Response body for `GET /gateways`.
#[derive(Serialize)]
pub struct ListGatewaysResponse {
    pub gateways: Vec<GatewayStatus>,
    /// The interface carrying the primary default IPv4 route, if any.
    pub default_interface: Option<String>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Handler: list configured gateways with live routing table and health state.
pub async fn list_gateways(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let configured = state.config_store.load_gateways().unwrap_or_default();

    let kernel_routes = list_kernel_gateways().await;
    let probed = probe_all_gateways(&configured).await;

    let default_interface = kernel_routes.first().map(|r| r.interface.clone());

    let gateways = probed
        .into_iter()
        .map(|(gw, gw_state)| {
            let active_ip = kernel_routes
                .iter()
                .find(|r| r.interface == gw.interface)
                .and_then(|r| r.gateway_ip.clone());

            GatewayStatus {
                gateway: gw.clone(),
                state: gw_state,
                active_ip,
            }
        })
        .collect();

    Json(ListGatewaysResponse {
        gateways,
        default_interface,
    })
}

/// Handler: create or update a gateway (upsert by `name`).
pub async fn upsert_gateway(
    State(state): State<Arc<AppState>>,
    Json(gateway): Json<Gateway>,
) -> impl IntoResponse {
    // Validate name.
    if gateway.name.is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "error": "gateway name must not be empty" })),
        )
            .into_response();
    }

    // Validate IPs when present.
    if let Some(ip) = &gateway.gateway_ip {
        if ip.parse::<std::net::IpAddr>().is_err() {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({ "error": format!("invalid gateway_ip: {ip}") })),
            )
                .into_response();
        }
    }
    if let Some(ip) = &gateway.monitor_ip {
        if ip.parse::<std::net::IpAddr>().is_err() {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({ "error": format!("invalid monitor_ip: {ip}") })),
            )
                .into_response();
        }
    }

    // Upsert in persistent storage.
    let mut gateways = state.config_store.load_gateways().unwrap_or_default();
    if let Some(pos) = gateways.iter().position(|g| g.name == gateway.name) {
        gateways[pos] = gateway.clone();
    } else {
        gateways.push(gateway.clone());
    }

    if let Err(e) = state.config_store.save_gateways(gateways) {
        warn!(error = %e, "gateways: failed to save");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response();
    }

    // Apply to kernel (no-op for DHCP/PPPoE gateways).
    if let Err(e) = apply_gateway(&gateway).await {
        warn!(error = %e, "gateways: failed to apply route");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response();
    }

    info!(name = %gateway.name, "gateways: upserted");
    (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response()
}

/// Handler: delete a gateway by name.
pub async fn delete_gateway(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let mut gateways = state.config_store.load_gateways().unwrap_or_default();
    let before = gateways.len();
    gateways.retain(|g| g.name != name);

    if gateways.len() == before {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": format!("gateway {name:?} not found") })),
        )
            .into_response();
    }

    if let Err(e) = state.config_store.save_gateways(gateways) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response();
    }

    info!(name = %name, "gateways: deleted");
    (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response()
}
