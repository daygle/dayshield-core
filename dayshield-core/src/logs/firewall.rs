//! Firewall (nftables) log parser — reads from journald via
//! `systemd-journal-gateway` or the `/run/log/journal` socket.
//!
//! Because linking against `libsystemd` is undesirable in a portable crate,
//! this module reads journald entries by spawning `journalctl` as a child
//! process with `--output=json --follow --identifier=nftables`.
//!
//! Each JSON line from journalctl is parsed for nftables key=value fields
//! embedded in the `MESSAGE` field and mapped to a [`LogEvent::FirewallEvent`].
//!
//! # Message format
//!
//! nftables writes log lines such as:
//!
//! ```text
//! IN=eth0 OUT= MAC=... SRC=192.168.1.100 DST=10.0.0.1 ... SPT=54321 DPT=80 ...
//! ```
//!
//! The log prefix (e.g. `"DROP "`, `"ACCEPT "`) appears at the beginning of the
//! message before the `IN=` field.  This module extracts the prefix and
//! normalises it to the `action` field.

use std::collections::HashMap;

use chrono::{DateTime, TimeZone, Utc};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
    sync::mpsc::Sender,
};
use tracing::{info, warn};

use crate::logs::LogEvent;

// ---------------------------------------------------------------------------
// Public streaming function
// ---------------------------------------------------------------------------

/// Stream nftables firewall log events from journald to `tx`.
///
/// Spawns `journalctl --output=json --follow --identifier=nftables` and
/// processes its output line by line.  Restarts automatically when the
/// process exits unexpectedly.
pub async fn stream_firewall(tx: Sender<LogEvent>) {
    loop {
        info!("firewall: starting journalctl nftables stream");

        let mut child = match Command::new("journalctl")
            .args([
                "--output=json",
                "--follow",
                "--lines=50",
                "--identifier=nftables",
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "firewall: failed to spawn journalctl, retrying in 5s");
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                continue;
            }
        };

        let stdout = child.stdout.take().expect("stdout piped");
        let mut reader = BufReader::new(stdout).lines();

        loop {
            match reader.next_line().await {
                Ok(Some(line)) => {
                    if let Some(event) = parse_journald_firewall_line(&line) {
                        if tx.send(event).await.is_err() {
                            // Receiver dropped — shut down.
                            let _ = child.kill().await;
                            return;
                        }
                    }
                }
                Ok(None) => {
                    // Process ended — restart.
                    info!("firewall: journalctl exited, restarting");
                    break;
                }
                Err(e) => {
                    warn!(error = %e, "firewall: journalctl read error");
                    break;
                }
            }
        }

        let _ = child.kill().await;
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

/// Parse a single JSON line from `journalctl --output=json` for an nftables
/// message and return a [`LogEvent::FirewallEvent`], or `None` if the line
/// cannot be interpreted.
pub(crate) fn parse_journald_firewall_line(line: &str) -> Option<LogEvent> {
    let obj: serde_json::Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "firewall: failed to parse journald JSON line");
            return None;
        }
    };

    // Journald encodes MESSAGE as either a plain string or a base64-encoded
    // byte array (for binary logs).  We only handle the string case.
    let message = match obj.get("MESSAGE").and_then(|v| v.as_str()) {
        Some(m) => m.to_string(),
        None => return None,
    };

    // Parse the __REALTIME_TIMESTAMP field (microseconds since epoch).
    let timestamp = parse_realtime_timestamp(obj.get("__REALTIME_TIMESTAMP").and_then(|v| v.as_str()));

    parse_nftables_message(&message, &timestamp)
}

/// Convert a journald `__REALTIME_TIMESTAMP` string (microseconds since the
/// Unix epoch) to an ISO-8601 string.  Falls back to the current time if
/// parsing fails.
fn parse_realtime_timestamp(raw: Option<&str>) -> String {
    raw.and_then(|s| s.parse::<i64>().ok())
        .and_then(|us| {
            let secs = us / 1_000_000;
            let nanos = ((us % 1_000_000) * 1000) as u32;
            Utc.timestamp_opt(secs, nanos).single()
        })
        .map(|dt: DateTime<Utc>| dt.to_rfc3339())
        .unwrap_or_else(|| Utc::now().to_rfc3339())
}

/// Parse the nftables `IN=... SRC=... DST=...` key=value message.
///
/// Returns `None` if the minimum required fields (`SRC`, `DST`) are absent.
pub(crate) fn parse_nftables_message(message: &str, timestamp: &str) -> Option<LogEvent> {
    // The log prefix appears before the first `IN=` token.  Extract it as
    // the action (trimmed).
    let action = message
        .split("IN=")
        .next()
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    let kv = parse_kv(message);

    let src_ip = kv.get("SRC").cloned().unwrap_or_default();
    let dest_ip = kv.get("DST").cloned().unwrap_or_default();

    // Require at least src and dst to emit an event.
    if src_ip.is_empty() && dest_ip.is_empty() {
        return None;
    }

    let sport: u16 = kv.get("SPT").and_then(|v| v.parse().ok()).unwrap_or(0);
    let dport: u16 = kv.get("DPT").and_then(|v| v.parse().ok()).unwrap_or(0);
    let iface = kv.get("IN").cloned().unwrap_or_default();

    Some(LogEvent::FirewallEvent {
        timestamp: timestamp.to_string(),
        action,
        src_ip,
        dest_ip,
        sport,
        dport,
        iface,
    })
}

/// Parse a space-separated `KEY=VALUE` string into a map.
fn parse_kv(s: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for token in s.split_whitespace() {
        if let Some((k, v)) = token.split_once('=') {
            map.insert(k.to_string(), v.to_string());
        }
    }
    map
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_MESSAGE: &str =
        "DROP IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff SRC=192.168.1.100 DST=10.0.0.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP SPT=54321 DPT=80 WINDOW=65535 RES=0x00 SYN URGP=0";

    #[test]
    fn test_parse_nftables_message_basic() {
        let event = parse_nftables_message(SAMPLE_MESSAGE, "2024-01-15T12:00:00+00:00")
            .expect("should parse");
        match event {
            LogEvent::FirewallEvent {
                action,
                src_ip,
                dest_ip,
                sport,
                dport,
                iface,
                ..
            } => {
                assert_eq!(action, "DROP");
                assert_eq!(src_ip, "192.168.1.100");
                assert_eq!(dest_ip, "10.0.0.1");
                assert_eq!(sport, 54321);
                assert_eq!(dport, 80);
                assert_eq!(iface, "eth0");
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn test_parse_nftables_message_accept() {
        let msg = "ACCEPT IN=eth1 OUT= SRC=10.1.2.3 DST=8.8.8.8 PROTO=UDP SPT=1234 DPT=53";
        let event = parse_nftables_message(msg, "2024-01-15T12:00:00+00:00").expect("should parse");
        match event {
            LogEvent::FirewallEvent { action, .. } => assert_eq!(action, "ACCEPT"),
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn test_parse_nftables_message_custom_prefix_action() {
        let msg = "DEFAULT-BLOCK INPUT IN=eth0 OUT= SRC=203.0.113.20 DST=10.0.0.1 PROTO=TCP SPT=55555 DPT=22";
        let event = parse_nftables_message(msg, "2024-01-15T12:00:00+00:00").expect("should parse");
        match event {
            LogEvent::FirewallEvent { action, src_ip, .. } => {
                assert_eq!(action, "DEFAULT-BLOCK INPUT");
                assert_eq!(src_ip, "203.0.113.20");
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn test_parse_nftables_message_missing_src_dst_returns_none() {
        let msg = "DROP IN=eth0 OUT=";
        assert!(parse_nftables_message(msg, "2024-01-15T12:00:00+00:00").is_none());
    }

    #[test]
    fn test_parse_kv_basic() {
        let m = parse_kv("IN=eth0 SRC=1.2.3.4 DPT=80");
        assert_eq!(m.get("IN").map(String::as_str), Some("eth0"));
        assert_eq!(m.get("SRC").map(String::as_str), Some("1.2.3.4"));
        assert_eq!(m.get("DPT").map(String::as_str), Some("80"));
    }

    #[test]
    fn test_parse_journald_firewall_line_valid() {
        let line = format!(
            r#"{{"__REALTIME_TIMESTAMP":"1705320000000000","MESSAGE":"DROP IN=eth0 OUT= SRC=192.168.1.1 DST=10.0.0.1 SPT=1234 DPT=443","SYSLOG_IDENTIFIER":"nftables"}}"#
        );
        let event = parse_journald_firewall_line(&line).expect("should parse");
        match event {
            LogEvent::FirewallEvent { action, src_ip, .. } => {
                assert_eq!(action, "DROP");
                assert_eq!(src_ip, "192.168.1.1");
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn test_parse_journald_firewall_line_invalid_json() {
        assert!(parse_journald_firewall_line("not json").is_none());
    }

    #[test]
    fn test_parse_journald_firewall_line_no_message_field() {
        let line = r#"{"__REALTIME_TIMESTAMP":"1705320000000000","SYSLOG_IDENTIFIER":"nftables"}"#;
        assert!(parse_journald_firewall_line(line).is_none());
    }
}
