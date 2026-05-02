//! WebSocket streaming endpoint for live metrics.
//!
//! [`metrics_websocket`] is called after a successful WebSocket upgrade.  It
//! reads the latest [`MetricsSnapshot`] from the shared buffer every second
//! and sends it as a JSON text frame to the connected client.
//!
//! Disconnects are detected when the send call fails, at which point the loop
//! exits cleanly.

use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use tokio::time::{interval, Duration};
use tracing::{info, warn};

use crate::state::AppState;

/// How often to push a new snapshot to connected clients.
const PUSH_INTERVAL: Duration = Duration::from_secs(1);

/// Handle an upgraded WebSocket connection for the live-metrics endpoint.
///
/// Sends a serialised [`MetricsSnapshot`] every second until the client
/// disconnects or an error occurs.
pub async fn metrics_websocket(mut ws: WebSocket, state: Arc<AppState>) {
    info!("metrics/ws: client connected");

    let mut ticker = interval(PUSH_INTERVAL);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let snapshot = {
                    let buf = state.metrics_buffer.read().await;
                    buf.latest().cloned()
                };

                let json = match snapshot {
                    Some(s) => match serde_json::to_string(&s) {
                        Ok(j) => j,
                        Err(e) => {
                            warn!(error = %e, "metrics/ws: serialisation error");
                            continue;
                        }
                    },
                    None => {
                        // Buffer is empty on startup — send a minimal placeholder.
                        r#"{"error":"no data yet"}"#.to_string()
                    }
                };

                if ws.send(Message::Text(json.into())).await.is_err() {
                    info!("metrics/ws: client disconnected (send failed)");
                    break;
                }
            }

            // Drain client messages to detect clean close frames.
            msg = ws.recv() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => {
                        info!("metrics/ws: client disconnected (close frame / EOF)");
                        break;
                    }
                    Some(Err(e)) => {
                        warn!(error = %e, "metrics/ws: receive error");
                        break;
                    }
                    _ => {} // Ignore ping/pong/text/binary from client.
                }
            }
        }
    }

    info!("metrics/ws: connection closed");
}
