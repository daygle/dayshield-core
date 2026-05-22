//! Live Logs subsystem.
//!
//! This module provides real-time streaming of log events from three sources:
//! - **Suricata** (`/var/log/suricata/eve.json`) - IDS/IPS alerts.
//! - **Firewall** (journald, `SYSLOG_IDENTIFIER=nftables`) - nftables events.
//! - **System** (journald, `PRIORITY<=6`) - system events through info level.
//!
//! All three streams are merged and forwarded to connected WebSocket clients
//! via [`websocket::logs_websocket`].

pub mod firewall;
pub mod suricata;
pub mod system;
pub mod tail;
pub mod websocket;

use serde::Serialize;

// ---------------------------------------------------------------------------
// Unified log event
// ---------------------------------------------------------------------------

/// A single log event emitted by one of the three live-log sources.
///
/// The enum variant identifies the source; each variant carries its own
/// strongly-typed payload.  The `#[serde(tag = "type")]` annotation ensures
/// the JSON wire format includes a `"type"` discriminant field so clients can
/// branch on the event kind.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LogEvent {
    /// An alert raised by Suricata IDS/IPS.
    SuricataAlert {
        /// ISO-8601 timestamp from the eve.json record.
        timestamp: String,
        /// Source IPv4 address (dotted-decimal).
        src_ip: String,
        /// Destination IPv4 address (dotted-decimal).
        dest_ip: String,
        /// Source port, if reported by Suricata.
        src_port: Option<u16>,
        /// Destination port, if reported by Suricata.
        dest_port: Option<u16>,
        /// Transport protocol (e.g. "TCP", "UDP").
        proto: String,
        /// Suricata alert signature text.
        signature: String,
        /// Alert severity level (1 = high, 3 = low).
        severity: u8,
        /// Optional alert category from Suricata.
        category: Option<String>,
    },

    /// An event logged by the nftables firewall via journald.
    FirewallEvent {
        /// ISO-8601 timestamp (from journald `__REALTIME_TIMESTAMP`).
        timestamp: String,
        /// Action derived from the nftables log prefix (e.g. `"DROP"`, `"ACCEPT"`).
        action: String,
        /// Source IPv4 address.
        src_ip: String,
        /// Destination IPv4 address.
        dest_ip: String,
        /// Source port (0 when not available).
        sport: u16,
        /// Destination port (0 when not available).
        dport: u16,
        /// Network protocol token if present (e.g. "TCP", "UDP").
        proto: String,
        /// Network interface name (e.g. `"eth0"`).
        iface: String,
    },

    /// A system-level log entry (warning / error / critical) from journald.
    SystemEvent {
        /// ISO-8601 timestamp.
        timestamp: String,
        /// systemd unit name (e.g. `"sshd.service"`).
        unit: String,
        /// Journald/syslog priority when available (0 = emerg, 6 = info).
        priority: Option<u8>,
        /// Human-readable log message.
        message: String,
    },
}

/// Read a journald JSON field as text.
///
/// `journalctl --output=json` usually emits fields as strings, but can emit
/// arrays for duplicate fields or byte arrays for values it cannot represent
/// directly as JSON strings. Treating those as absent makes the log views look
/// empty even though journal entries are present.
pub(crate) fn journald_field_text(value: Option<&serde_json::Value>) -> Option<String> {
    match value? {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Array(items) => decode_journald_array(items),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn decode_journald_array(items: &[serde_json::Value]) -> Option<String> {
    if items.iter().all(|item| item.as_u64().is_some()) {
        let bytes = items
            .iter()
            .filter_map(|item| item.as_u64())
            .filter_map(|n| u8::try_from(n).ok())
            .collect::<Vec<_>>();
        return String::from_utf8(bytes).ok();
    }

    items.iter().find_map(|item| match item {
        serde_json::Value::String(s) => Some(s.clone()),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::journald_field_text;

    #[test]
    fn journald_field_text_decodes_string() {
        let value = serde_json::json!("hello");
        assert_eq!(journald_field_text(Some(&value)).as_deref(), Some("hello"));
    }

    #[test]
    fn journald_field_text_decodes_byte_array() {
        let value = serde_json::json!([68, 82, 79, 80]);
        assert_eq!(journald_field_text(Some(&value)).as_deref(), Some("DROP"));
    }

    #[test]
    fn journald_field_text_uses_first_string_from_duplicate_array() {
        let value = serde_json::json!(["sshd", "other"]);
        assert_eq!(journald_field_text(Some(&value)).as_deref(), Some("sshd"));
    }
}
