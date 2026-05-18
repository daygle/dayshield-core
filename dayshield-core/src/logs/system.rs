//! System log parser - reads journald entries up to info level
//! (PRIORITY ≤ 6, i.e. emergency through info).
//!
//! Like [`crate::logs::firewall`] this module spawns `journalctl` as a child
//! process using `--output=json --follow --priority=warn` (syslog priority 4
//! and below) to avoid a hard dependency on `libsystemd`.
//!
//! Each JSON line is parsed to extract the unit name and log message and is
//! forwarded as a [`LogEvent::SystemEvent`].

use chrono::{TimeZone, Utc};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
    sync::mpsc::Sender,
};
use tracing::{info, warn};

use crate::logs::LogEvent;
use crate::logs::firewall::parse_nftables_message;

// ---------------------------------------------------------------------------
// Public streaming function
// ---------------------------------------------------------------------------

/// Stream system log events (PRIORITY ≤ 6) from journald to `tx`.
///
/// Spawns `journalctl --output=json --follow --priority=info --lines=0` and
/// processes its output line by line.  Restarts automatically on exit.
pub async fn stream_system(tx: Sender<LogEvent>) {
    loop {
        info!("system: starting journalctl system stream");

        let mut child = match Command::new("journalctl")
            .args([
                "--output=json",
                "--follow",
                "--lines=50",
                "--priority=info",
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "system: failed to spawn journalctl, retrying in 5s");
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                continue;
            }
        };

        let stdout = child.stdout.take().expect("stdout piped");
        let mut reader = BufReader::new(stdout).lines();

        loop {
            match reader.next_line().await {
                Ok(Some(line)) => {
                    if let Some(event) = parse_journald_system_line(&line) {
                        if tx.send(event).await.is_err() {
                            let _ = child.kill().await;
                            return;
                        }
                    }
                }
                Ok(None) => {
                    info!("system: journalctl exited, restarting");
                    break;
                }
                Err(e) => {
                    warn!(error = %e, "system: journalctl read error");
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

/// Parse a single JSON line from `journalctl --output=json` and return a
/// [`LogEvent::SystemEvent`], or `None` if the line cannot be interpreted.
pub(crate) fn parse_journald_system_line(line: &str) -> Option<LogEvent> {
    let obj: serde_json::Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "system: failed to parse journald JSON line");
            return None;
        }
    };

    let message = match obj.get("MESSAGE").and_then(|v| v.as_str()) {
        Some(m) => m.to_string(),
        None => return None,
    };

    let syslog_identifier = obj.get("SYSLOG_IDENTIFIER").and_then(|v| v.as_str());

    // nftables-tagged events are handled by the dedicated firewall stream.
    if matches!(syslog_identifier, Some("nftables")) {
        return None;
    }

    let timestamp = parse_realtime_timestamp(
        obj.get("__REALTIME_TIMESTAMP").and_then(|v| v.as_str()),
    );

    // Some firewall drops are emitted by the kernel logger (SYSLOG_IDENTIFIER=kernel)
    // while still carrying nftables key=value message format.
    if matches!(syslog_identifier, Some("kernel")) && looks_like_nftables_message(&message) {
        if let Some(event) = parse_nftables_message(&message, &timestamp) {
            return Some(event);
        }
    }

    // Unit name: prefer _SYSTEMD_UNIT, fall back to SYSLOG_IDENTIFIER.
    let unit = obj
        .get("_SYSTEMD_UNIT")
        .and_then(|v| v.as_str())
        .or_else(|| obj.get("SYSLOG_IDENTIFIER").and_then(|v| v.as_str()))
        .unwrap_or("unknown")
        .to_string();

    Some(LogEvent::SystemEvent {
        timestamp,
        unit,
        message,
    })
}

fn looks_like_nftables_message(message: &str) -> bool {
    message.contains("IN=")
        && message.contains("SRC=")
        && message.contains("DST=")
        && message.contains("PROTO=")
}

/// Convert a journald `__REALTIME_TIMESTAMP` (microseconds since epoch) to an
/// ISO-8601 string.
fn parse_realtime_timestamp(raw: Option<&str>) -> String {
    raw.and_then(|s| s.parse::<i64>().ok())
        .and_then(|us| {
            let secs = us / 1_000_000;
            let nanos = ((us % 1_000_000) * 1000) as u32;
            Utc.timestamp_opt(secs, nanos).single()
        })
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| Utc::now().to_rfc3339())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_system_line_with_unit() {
        let line = r#"{"__REALTIME_TIMESTAMP":"1705320000000000","_SYSTEMD_UNIT":"sshd.service","MESSAGE":"Failed password for invalid user admin"}"#;
        let event = parse_journald_system_line(line).expect("should parse");
        match event {
            LogEvent::SystemEvent { unit, message, .. } => {
                assert_eq!(unit, "sshd.service");
                assert_eq!(message, "Failed password for invalid user admin");
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn test_parse_system_line_fallback_to_syslog_identifier() {
        let line = r#"{"__REALTIME_TIMESTAMP":"1705320000000000","SYSLOG_IDENTIFIER":"kernel","MESSAGE":"Out of memory: Kill process"}"#;
        let event = parse_journald_system_line(line).expect("should parse");
        match event {
            LogEvent::SystemEvent { unit, .. } => assert_eq!(unit, "kernel"),
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn test_parse_system_line_unknown_unit() {
        let line = r#"{"__REALTIME_TIMESTAMP":"1705320000000000","MESSAGE":"some message"}"#;
        let event = parse_journald_system_line(line).expect("should parse");
        match event {
            LogEvent::SystemEvent { unit, .. } => assert_eq!(unit, "unknown"),
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn test_parse_system_line_no_message_returns_none() {
        let line = r#"{"__REALTIME_TIMESTAMP":"1705320000000000","_SYSTEMD_UNIT":"sshd.service"}"#;
        assert!(parse_journald_system_line(line).is_none());
    }

    #[test]
    fn test_parse_system_line_invalid_json_returns_none() {
        assert!(parse_journald_system_line("not json").is_none());
    }

    #[test]
    fn test_parse_system_line_kernel_nft_message_reclassified_to_firewall() {
        let line = r#"{"__REALTIME_TIMESTAMP":"1705320000000000","SYSLOG_IDENTIFIER":"kernel","MESSAGE":"DEFAULT-BLOCK INPUT IN=ens18 OUT= SRC=192.168.20.2 DST=192.168.20.255 PROTO=UDP SPT=9801 DPT=9801"}"#;
        let event = parse_journald_system_line(line).expect("should parse");
        match event {
            LogEvent::FirewallEvent {
                action,
                src_ip,
                dest_ip,
                dport,
                ..
            } => {
                assert_eq!(action, "DEFAULT-BLOCK INPUT");
                assert_eq!(src_ip, "192.168.20.2");
                assert_eq!(dest_ip, "192.168.20.255");
                assert_eq!(dport, 9801);
            }
            _ => panic!("expected firewall event"),
        }
    }

    #[test]
    fn test_parse_system_line_nftables_identifier_is_ignored() {
        let line = r#"{"__REALTIME_TIMESTAMP":"1705320000000000","SYSLOG_IDENTIFIER":"nftables","MESSAGE":"DROP IN=eth0 OUT= SRC=192.168.1.1 DST=10.0.0.1 PROTO=TCP SPT=1234 DPT=443"}"#;
        assert!(parse_journald_system_line(line).is_none());
    }
}
