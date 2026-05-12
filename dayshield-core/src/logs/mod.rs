//! Live Logs subsystem.
//!
//! This module provides real-time streaming of log events from three sources:
//! - **Suricata** (`/var/log/suricata/eve.json`) - IDS/IPS alerts.
//! - **Firewall** (journald, `SYSLOG_IDENTIFIER=nftables`) - nftables events.
//! - **System** (journald, `PRIORITY<=4`) - warnings and errors.
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
        /// Transport protocol (e.g. `"TCP"`, `"UDP"`).
        proto: String,
        /// Suricata alert signature text.
        signature: String,
        /// Alert severity level (1 = high, 3 = low).
        severity: u8,
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
        /// Network interface name (e.g. `"eth0"`).
        iface: String,
    },

    /// A system-level log entry (warning / error / critical) from journald.
    SystemEvent {
        /// ISO-8601 timestamp.
        timestamp: String,
        /// systemd unit name (e.g. `"sshd.service"`).
        unit: String,
        /// Human-readable log message.
        message: String,
    },
}
