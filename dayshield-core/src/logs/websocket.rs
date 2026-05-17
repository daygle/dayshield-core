//! WebSocket handler that merges the three live-log streams into a single
//! connection.
//!
//! [`logs_websocket`] is called by the Axum WebSocket upgrade handler.  It:
//!
//! 1. Creates a shared [`mpsc`] channel (the *merge channel*).
//! 2. Spawns three tasks - one per log source - each of which writes to the
//!    merge channel.
//! 3. Reads from the merge channel in a loop, serialising each [`LogEvent`] to
//!    JSON and sending it as a WebSocket text frame.
//! 4. On client disconnect (send returns an error) all three source tasks are
//!    aborted via their [`JoinHandle`]s.

use axum::extract::ws::{Message, WebSocket};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::logs::{
    firewall::stream_firewall, suricata::stream_suricata, system::stream_system, LogEvent,
};

/// Capacity of the merge channel.  Large enough to absorb short bursts without
/// dropping events, but bounded to prevent unbounded memory growth.
const MERGE_CHANNEL_CAPACITY: usize = 512;

/// Handle an upgraded WebSocket connection for the live-logs endpoint.
///
/// Spawns the three log-source tasks, merges their output, and forwards every
/// event as a JSON text frame until the client disconnects.
pub async fn logs_websocket(mut ws: WebSocket) {
    info!("logs/ws: client connected");

    let (tx, mut rx) = mpsc::channel::<LogEvent>(MERGE_CHANNEL_CAPACITY);

    // Spawn the three source tasks.
    let h_suricata = tokio::spawn({
        let tx = tx.clone();
        async move { stream_suricata(tx).await }
    });

    let h_firewall = tokio::spawn({
        let tx = tx.clone();
        async move { stream_firewall(tx).await }
    });

    let h_system = tokio::spawn({
        let tx = tx.clone();
        async move { stream_system(tx).await }
    });

    // Drop the original sender so the channel closes when all three tasks
    // have finished (which in practice only happens if we abort them).
    drop(tx);

    // Forward events to the WebSocket.
    loop {
        tokio::select! {
            // New log event available.
            maybe_event = rx.recv() => {
                match maybe_event {
                    Some(event) => {
                        let json = match serde_json::to_string(&event) {
                            Ok(j) => j,
                            Err(e) => {
                                warn!(error = %e, "logs/ws: failed to serialise event");
                                continue;
                            }
                        };
                        if ws.send(Message::Text(json.into())).await.is_err() {
                            info!("logs/ws: client disconnected (send failed)");
                            break;
                        }
                    }
                    None => {
                        // All senders dropped - should not happen in normal operation.
                        info!("logs/ws: merge channel closed");
                        break;
                    }
                }
            }

            // Client sent a message (we don't process inbound messages but
            // we need to drain them to detect clean close frames).
            msg = ws.recv() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => {
                        info!("logs/ws: client disconnected (close frame / EOF)");
                        break;
                    }
                    Some(Err(e)) => {
                        warn!(error = %e, "logs/ws: receive error");
                        break;
                    }
                    _ => {} // Ignore ping/pong/text/binary from client.
                }
            }
        }
    }

    // Abort all source tasks to free resources.
    h_suricata.abort();
    h_firewall.abort();
    h_system.abort();

    info!("logs/ws: connection closed, source tasks aborted");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::logs::{suricata::parse_eve_line, LogEvent};

    /// Verify that `LogEvent` variants serialise to JSON with the expected
    /// `"type"` discriminant and field names.
    #[test]
    fn test_log_event_suricata_serialisation() {
        let event = LogEvent::SuricataAlert {
            timestamp: "2024-01-15T12:00:00+00:00".into(),
            src_ip: "10.0.0.1".into(),
            dest_ip: "10.0.0.2".into(),
            src_port: Some(12345),
            dest_port: Some(443),
            proto: "TCP".into(),
            signature: "ET SCAN".into(),
            severity: 2,
            category: Some("Attempted Information Leak".into()),
        };
        let json = serde_json::to_string(&event).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["type"], "suricata_alert");
        assert_eq!(v["src_ip"], "10.0.0.1");
        assert_eq!(v["src_port"], 12345);
        assert_eq!(v["dest_port"], 443);
        assert_eq!(v["severity"], 2);
        assert_eq!(v["category"], "Attempted Information Leak");
    }

    #[test]
    fn test_log_event_firewall_serialisation() {
        let event = LogEvent::FirewallEvent {
            timestamp: "2024-01-15T12:00:00+00:00".into(),
            action: "DROP".into(),
            src_ip: "192.168.1.1".into(),
            dest_ip: "10.0.0.1".into(),
            sport: 54321,
            dport: 80,
            proto: "TCP".into(),
            iface: "eth0".into(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["type"], "firewall_event");
        assert_eq!(v["action"], "DROP");
        assert_eq!(v["sport"], 54321);
        assert_eq!(v["proto"], "TCP");
    }

    #[test]
    fn test_log_event_system_serialisation() {
        let event = LogEvent::SystemEvent {
            timestamp: "2024-01-15T12:00:00+00:00".into(),
            unit: "sshd.service".into(),
            message: "Failed login".into(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["type"], "system_event");
        assert_eq!(v["unit"], "sshd.service");
    }

    #[test]
    fn test_parse_and_serialise_suricata_alert() {
        let line = r#"{"timestamp":"2024-01-15T12:00:00.000000+0000","event_type":"alert","src_ip":"10.0.0.1","dest_ip":"10.0.0.2","src_port":51515,"dest_port":22,"proto":"TCP","alert":{"signature":"ET SCAN Nmap","severity":1,"category":"Attempted Information Leak"}}"#;
        let event = parse_eve_line(line).unwrap();
        let json = serde_json::to_string(&event).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["type"], "suricata_alert");
        assert_eq!(v["severity"], 1);
        assert_eq!(v["src_port"], 51515);
        assert_eq!(v["dest_port"], 22);
        assert_eq!(v["category"], "Attempted Information Leak");
    }
}
