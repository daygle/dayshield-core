//! Live Logs API endpoint — `GET /logs/ws`.
//!
//! Upgrades the HTTP connection to a WebSocket and delegates to
//! [`crate::logs::websocket::logs_websocket`].

use axum::{
    extract::ws::WebSocketUpgrade,
    response::IntoResponse,
};

use crate::logs::websocket::logs_websocket;

/// Handler: upgrade to WebSocket and start streaming live log events.
///
/// Clients connect to `GET /logs/ws`.  After the upgrade they receive a
/// continuous stream of newline-delimited JSON objects, one per log event.
pub async fn ws_handler(ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(logs_websocket)
}
