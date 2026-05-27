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
pub mod ui;
pub mod websocket;

use serde::Serialize;
use serde_json::{json, Value};

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

    /// A browser/UI event captured by the management interface.
    UiEvent {
        /// ISO-8601 timestamp.
        timestamp: String,
        /// UI component or reporter name.
        component: String,
        /// Log level emitted by the browser client.
        level: String,
        /// Human-readable log message.
        message: String,
        /// Current route path when the event was captured.
        route: Option<String>,
        /// Optional page or resource URL for context.
        url: Option<String>,
        /// Optional stack trace or exception string.
        stack: Option<String>,
        /// Additional structured details supplied by the browser.
        details: Option<Value>,
    },

    /// An update operation event emitted directly by the update engine.
    UpdateEvent {
        /// ISO-8601 timestamp.
        timestamp: String,
        /// Operation name: "check", "apply", "stage", "rollback".
        operation: String,
        /// Log level: "info", "success", "warning", "error".
        level: String,
        /// Human-readable message.
        message: String,
        /// Affected component if known (e.g. "core", "ui", "rootfs").
        component: Option<String>,
    },
}

impl LogEvent {
    pub fn to_client_payload(&self) -> Value {
        match self {
            LogEvent::SuricataAlert {
                timestamp,
                src_ip,
                dest_ip,
                src_port,
                dest_port,
                proto,
                signature,
                severity,
                category,
            } => {
                let proto_upper = proto.to_uppercase();
                let flow = if !src_ip.is_empty() && !dest_ip.is_empty() {
                    format!(
                        " ({} -> {}{})",
                        src_ip,
                        dest_ip,
                        if proto_upper.is_empty() {
                            String::new()
                        } else {
                            format!(" {proto_upper}")
                        }
                    )
                } else {
                    String::new()
                };
                let level = if *severity <= 1 {
                    "error"
                } else if *severity == 2 {
                    "warning"
                } else {
                    "info"
                };

                json!({
                    "type": "suricata_alert",
                    "timestamp": timestamp,
                    "source": "suricata",
                    "level": level,
                    "message": format!("{signature}{flow}"),
                    "src_ip": src_ip,
                    "dest_ip": dest_ip,
                    "src_port": src_port,
                    "dest_port": dest_port,
                    "proto": proto,
                    "signature": signature,
                    "severity": severity,
                    "category": category,
                    "meta": {
                        "src_ip": src_ip,
                        "dest_ip": dest_ip,
                        "src_port": src_port,
                        "dest_port": dest_port,
                        "proto": proto,
                        "signature": signature,
                        "severity": severity,
                        "category": category,
                    }
                })
            }
            LogEvent::FirewallEvent {
                timestamp,
                action,
                src_ip,
                dest_ip,
                sport,
                dport,
                proto,
                iface,
            } => {
                let action_upper = action.to_uppercase();
                let endpoint = format_socket(src_ip, *sport);
                let target = format_socket(dest_ip, *dport);
                let route = match (endpoint, target) {
                    (Some(endpoint), Some(target)) => format!(" {endpoint} -> {target}"),
                    (Some(endpoint), None) => format!(" {endpoint}"),
                    (None, Some(target)) => format!(" -> {target}"),
                    (None, None) => String::new(),
                };
                let iface_suffix = if iface.is_empty() {
                    String::new()
                } else {
                    format!(" on {iface}")
                };

                json!({
                    "type": "firewall_event",
                    "timestamp": timestamp,
                    "source": "firewall",
                    "level": if action_upper.contains("DROP") || action_upper.contains("BLOCK") { "warning" } else { "info" },
                    "message": format!("{action}{iface_suffix}{route}"),
                    "action": action,
                    "src_ip": src_ip,
                    "dest_ip": dest_ip,
                    "sport": sport,
                    "dport": dport,
                    "proto": proto,
                    "iface": iface,
                    "meta": {
                        "action": action,
                        "src_ip": src_ip,
                        "dest_ip": dest_ip,
                        "sport": sport,
                        "dport": dport,
                        "proto": proto,
                        "iface": iface,
                    }
                })
            }
            LogEvent::SystemEvent {
                timestamp,
                unit,
                priority,
                message,
            } => {
                let safe_message = if message.trim().is_empty() {
                    "(empty system log message)".to_string()
                } else {
                    message.trim().to_string()
                };

                json!({
                    "type": "system_event",
                    "timestamp": timestamp,
                    "source": classify_system_source(unit, &safe_message),
                    "level": classify_system_level(&safe_message, *priority),
                    "message": safe_message,
                    "unit": unit,
                    "priority": priority,
                    "meta": {
                        "unit": unit,
                        "priority": priority,
                    }
                })
            }
            LogEvent::UiEvent {
                timestamp,
                component,
                level,
                message,
                route,
                url,
                stack,
                details,
            } => {
                json!({
                    "type": "ui_event",
                    "timestamp": timestamp,
                    "source": "ui",
                    "level": classify_ui_level(level),
                    "message": message,
                    "component": component,
                    "route": route,
                    "url": url,
                    "stack": stack,
                    "meta": details,
                })
            }
            LogEvent::UpdateEvent {
                timestamp,
                operation,
                level,
                message,
                component,
            } => {
                json!({
                    "type": "update_event",
                    "timestamp": timestamp,
                    "source": "updates",
                    "level": classify_update_level(level),
                    "message": message,
                    "meta": {
                        "operation": operation,
                        "component": component,
                    }
                })
            }
        }
    }
}

fn classify_ui_level(level: &str) -> &str {
    match level.trim().to_lowercase().as_str() {
        "debug" => "debug",
        "info" => "info",
        "warning" | "warn" => "warning",
        "error" => "error",
        "critical" => "critical",
        _ => "info",
    }
}

fn classify_update_level(level: &str) -> &str {
    match level.trim().to_lowercase().as_str() {
        "success" => "info",
        "warning" | "warn" => "warning",
        "error" => "error",
        _ => "info",
    }
}

fn format_socket(ip: &str, port: u16) -> Option<String> {
    if ip.is_empty() {
        return None;
    }

    if port == 0 {
        Some(ip.to_string())
    } else {
        Some(format!("{ip}:{port}"))
    }
}

fn classify_system_source(unit: &str, message: &str) -> &'static str {
    let hay = format!("{unit} {message}").to_lowercase();
    if hay.contains("suricata") {
        "suricata"
    } else if hay.contains("ai threat engine")
        || hay.contains("ai engine")
        || hay.contains("ai-threat")
        || hay.contains("ai threat")
    {
        "ai"
    } else if hay.contains("nft") || hay.contains("firewall") {
        "firewall"
    } else if hay.contains("pppoe")
        || hay.contains("pppd")
        || hay.contains("rp-pppoe")
        || hay.contains(" lcp")
        || hay.contains(" ipcp")
        || hay.contains(" pap")
        || hay.contains(" chap")
        || hay.contains("padi")
        || hay.contains("pado")
        || hay.contains("padr")
        || hay.contains("pads")
    {
        "pppoe"
    } else if hay.contains("crowdsec") {
        "crowdsec"
    } else if hay.contains("ntp")
        || hay.contains("chrony")
        || hay.contains("chronyd")
        || hay.contains("timesyncd")
        || hay.contains("systemd-timesyncd")
    {
        "ntp"
    } else if hay.contains("unbound")
        || hay.contains("resolver")
        || hay.contains("dns ")
        || hay.contains("dns:")
    {
        "dns"
    } else if hay.contains("kea") || hay.contains("dhcp") || hay.contains("dnsmasq") {
        "dhcp"
    } else if hay.contains("wireguard") || hay.contains("wg-") || hay.contains("vpn") {
        "vpn"
    } else if hay.contains("gateway")
        || hay.contains("default route")
        || hay.contains("ip route")
        || hay.contains("route update")
    {
        "gateways"
    } else if hay.contains("interface")
        || hay.contains("link up")
        || hay.contains("link down")
        || hay.contains("networkd")
        || hay.contains("netplan")
    {
        "interfaces"
    } else if hay.contains("honeypot") {
        "honeypot"
    } else if hay.contains("captive-portal") || hay.contains("captive_portal") {
        "captive_portal"
    } else if hay.contains("backup") || hay.contains("restore") || hay.contains("snapshot") {
        "backup_restore"
    } else if hay.contains("update")
        || hay.contains("updater")
        || hay.contains("upgrade")
        || hay.contains("rollback")
    {
        "updates"
    } else if hay.contains("cloudflared") {
        "cloudflared"
    } else if hay.contains("acme") || hay.contains("cert") || hay.contains("letsencrypt") {
        "acme"
    } else {
        "system"
    }
}

fn classify_system_level(message: &str, priority: Option<u8>) -> &'static str {
    if let Some(level) = explicit_system_level(message) {
        return level;
    }

    if let Some(level) = journal_priority_level(priority) {
        return level;
    }

    let upper = message.to_uppercase();
    if upper.contains("CRITICAL") || upper.contains("PANIC") {
        "critical"
    } else if upper.contains("ERROR")
        || upper.contains("ERR")
        || upper.contains("FAILED")
        || upper.contains("FAILURE")
    {
        "error"
    } else if upper.contains("WARN") || upper.contains("WARNING") {
        "warning"
    } else if upper.contains("DEBUG") || upper.contains("TRACE") {
        "debug"
    } else {
        "info"
    }
}

fn explicit_system_level(message: &str) -> Option<&'static str> {
    let upper = message.trim().to_uppercase();
    for prefix in [
        "CRITICAL", "PANIC", "ERROR", "ERR", "WARNING", "WARN", "INFO", "DEBUG", "TRACE",
    ] {
        let has_plain = upper.starts_with(prefix);
        let has_syslog = upper
            .strip_prefix('<')
            .and_then(|value| value.split_once('>'))
            .map(|(_, rest)| rest.trim_start().starts_with(prefix))
            .unwrap_or(false);

        if has_plain || has_syslog {
            return Some(match prefix {
                "CRITICAL" | "PANIC" => "critical",
                "ERROR" | "ERR" => "error",
                "WARNING" | "WARN" => "warning",
                "DEBUG" | "TRACE" => "debug",
                _ => "info",
            });
        }
    }

    None
}

fn journal_priority_level(priority: Option<u8>) -> Option<&'static str> {
    match priority? {
        0..=2 => Some("critical"),
        3 => Some("error"),
        4 => Some("warning"),
        7..=u8::MAX => Some("debug"),
        _ => Some("info"),
    }
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
    use super::LogEvent;

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

    #[test]
    fn client_payload_formats_firewall_message_without_zero_ports() {
        let event = LogEvent::FirewallEvent {
            timestamp: "2026-05-23T02:03:04Z".into(),
            action: "DROP".into(),
            src_ip: "192.0.2.10".into(),
            dest_ip: "198.51.100.7".into(),
            sport: 0,
            dport: 443,
            proto: "tcp".into(),
            iface: "wan".into(),
        };

        let payload = event.to_client_payload();
        assert_eq!(payload["source"], "firewall");
        assert_eq!(payload["level"], "warning");
        assert_eq!(
            payload["message"],
            "DROP on wan 192.0.2.10 -> 198.51.100.7:443"
        );
    }

    #[test]
    fn client_payload_classifies_system_logs_like_ui() {
        let event = LogEvent::SystemEvent {
            timestamp: "2026-05-23T02:03:04Z".into(),
            unit: "dayshield-core.service".into(),
            priority: Some(6),
            message: "WireGuard handshake established".into(),
        };

        let payload = event.to_client_payload();
        assert_eq!(payload["source"], "vpn");
        assert_eq!(payload["level"], "info");
        assert_eq!(payload["message"], "WireGuard handshake established");
    }

    #[test]
    fn wireguard_message_containing_interface_classifies_as_vpn_not_interfaces() {
        let event = LogEvent::SystemEvent {
            timestamp: "2026-05-23T02:03:04Z".into(),
            unit: "dayshield_core::api::wireguard".into(),
            priority: Some(4),
            message: "wireguard: invalid interface name".into(),
        };
        let payload = event.to_client_payload();
        assert_eq!(payload["source"], "vpn");
    }

    #[test]
    fn interface_rename_message_classifies_as_interfaces_not_dns() {
        let event = LogEvent::SystemEvent {
            timestamp: "2026-05-23T02:03:04Z".into(),
            unit: "kernel".into(),
            priority: Some(6),
            message: "renamed network interface eth0 to wan0".into(),
        };
        let payload = event.to_client_payload();
        assert_eq!(payload["source"], "interfaces");
    }
}
