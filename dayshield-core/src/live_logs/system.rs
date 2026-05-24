//! System log parser - reads journald entries up to info level
//! (PRIORITY <= 6, i.e. emergency through info).
//!
//! Like [`crate::live_logs::firewall`] this module spawns `journalctl` as a child
//! process using `--output=json --follow --priority=info` to avoid a hard
//! dependency on `libsystemd`.
//! When journald is present but has no entries, it falls back to DayShield's
//! own durable log file at `/var/log/dayshield/core.log`.
//!
//! Each JSON line is parsed to extract the unit name and log message and is
//! forwarded as a [`LogEvent::SystemEvent`].

use chrono::{DateTime, TimeZone, Utc};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
    sync::mpsc::{self, Sender},
};
use tracing::{info, warn};

use crate::live_logs::firewall::parse_nftables_message;
use crate::live_logs::{journald_field_text, tail::FileTailer, LogEvent};

const DAYSHIELD_CORE_LOG_PATH: &str = "/var/log/dayshield/core.log";

// ---------------------------------------------------------------------------
// Public streaming function
// ---------------------------------------------------------------------------

/// Stream system log events (PRIORITY <= 6) from journald to `tx`.
///
/// Spawns `journalctl --output=json --follow --priority=info --lines=0` and
/// processes its output line by line.  Restarts automatically on exit.
pub async fn stream_system(tx: Sender<LogEvent>) {
    if !journal_has_system_entries().await {
        warn!(
            path = DAYSHIELD_CORE_LOG_PATH,
            "system: journald has no readable entries; tailing DayShield log file"
        );
        stream_core_log_file(tx).await;
        return;
    }

    stream_journal_system(tx).await;
}

async fn journal_has_system_entries() -> bool {
    match Command::new("journalctl")
        .args(["--output=json", "--priority=info", "--lines=1"])
        .output()
        .await
    {
        Ok(output) => !String::from_utf8_lossy(&output.stdout).trim().is_empty(),
        Err(error) => {
            warn!(error = %error, "system: failed to probe journalctl; using log file fallback");
            false
        }
    }
}

async fn stream_core_log_file(tx: Sender<LogEvent>) {
    let (line_tx, mut line_rx) = mpsc::channel::<String>(256);

    tokio::spawn(async move {
        FileTailer::new(DAYSHIELD_CORE_LOG_PATH).run(line_tx).await;
    });

    while let Some(line) = line_rx.recv().await {
        if let Some(event) = parse_system_text_line(&line) {
            if tx.send(event).await.is_err() {
                break;
            }
        }
    }
}

async fn stream_journal_system(tx: Sender<LogEvent>) {
    loop {
        info!("system: starting journalctl system stream");

        let mut child = match Command::new("journalctl")
            .args(["--output=json", "--follow", "--lines=50", "--priority=info"])
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

    let message = match journald_field_text(obj.get("MESSAGE")) {
        Some(m) => m.to_string(),
        None => return None,
    };
    let message = strip_ansi_codes(&message);

    let syslog_identifier = journald_field_text(obj.get("SYSLOG_IDENTIFIER"));
    let syslog_identifier = syslog_identifier.as_deref();

    // nftables-tagged events are handled by the dedicated firewall stream.
    if matches!(syslog_identifier, Some("nftables")) {
        return None;
    }

    let timestamp =
        parse_realtime_timestamp(journald_field_text(obj.get("__REALTIME_TIMESTAMP")).as_deref());
    let priority = parse_priority(obj.get("PRIORITY"));

    // Some firewall drops are emitted by the kernel logger (SYSLOG_IDENTIFIER=kernel)
    // while still carrying nftables key=value message format.
    if matches!(syslog_identifier, Some("kernel")) && looks_like_nftables_message(&message) {
        if let Some(event) = parse_nftables_message(&message, &timestamp) {
            return Some(event);
        }
    }

    // Unit name: prefer _SYSTEMD_UNIT, fall back to SYSLOG_IDENTIFIER.
    let mut unit = obj
        .get("_SYSTEMD_UNIT")
        .and_then(|v| journald_field_text(Some(v)))
        .or_else(|| {
            obj.get("SYSLOG_IDENTIFIER")
                .and_then(|v| journald_field_text(Some(v)))
        })
        .unwrap_or_else(|| "unknown".to_string());
    let mut priority = priority;
    let mut message = message;

    if let Some(formatted) = parse_tracing_formatted_line(&message) {
        unit = formatted.target;
        priority = Some(formatted.priority);
        message = formatted.message;
    }

    Some(LogEvent::SystemEvent {
        timestamp,
        unit,
        priority,
        message,
    })
}

/// Parse a DayShield-owned text/JSON log line from `/var/log/dayshield/core.log`.
pub(crate) fn parse_system_text_line(line: &str) -> Option<LogEvent> {
    let message = strip_ansi_codes(line).trim().to_string();
    if message.is_empty() {
        return None;
    }

    if let Some(event) = parse_tracing_json_line(&message) {
        return Some(event);
    }

    if let Some(formatted) = parse_tracing_formatted_line(&message) {
        return Some(LogEvent::SystemEvent {
            timestamp: formatted.timestamp,
            unit: formatted.target,
            priority: Some(formatted.priority),
            message: formatted.message,
        });
    }

    Some(LogEvent::SystemEvent {
        timestamp: Utc::now().to_rfc3339(),
        unit: "dayshield-core".to_string(),
        priority: None,
        message,
    })
}

fn parse_tracing_json_line(line: &str) -> Option<LogEvent> {
    let obj: serde_json::Value = serde_json::from_str(line).ok()?;
    let timestamp = obj
        .get("timestamp")
        .and_then(|value| journald_field_text(Some(value)))
        .and_then(|raw| DateTime::parse_from_rfc3339(&raw).ok())
        .map(|dt| dt.with_timezone(&Utc).to_rfc3339())
        .unwrap_or_else(|| Utc::now().to_rfc3339());
    let level = obj
        .get("level")
        .and_then(|value| journald_field_text(Some(value)))
        .unwrap_or_else(|| "INFO".to_string());
    let priority = tracing_level_priority(&level);
    let unit = obj
        .get("target")
        .and_then(|value| journald_field_text(Some(value)))
        .unwrap_or_else(|| "dayshield-core".to_string());
    let message = obj
        .get("fields")
        .and_then(|fields| fields.get("message"))
        .and_then(|value| journald_field_text(Some(value)))
        .or_else(|| {
            obj.get("message")
                .and_then(|value| journald_field_text(Some(value)))
        })?;

    Some(LogEvent::SystemEvent {
        timestamp,
        unit,
        priority,
        message,
    })
}

fn looks_like_nftables_message(message: &str) -> bool {
    message.contains("IN=")
        && message.contains("SRC=")
        && message.contains("DST=")
        && message.contains("PROTO=")
}

struct TracingFormattedLine {
    timestamp: String,
    target: String,
    priority: u8,
    message: String,
}

fn parse_tracing_formatted_line(message: &str) -> Option<TracingFormattedLine> {
    let trimmed = message.trim_start();
    let (timestamp, rest) = split_first_token(trimmed)?;
    let timestamp = DateTime::parse_from_rfc3339(timestamp)
        .ok()?
        .with_timezone(&Utc)
        .to_rfc3339();

    let (level, rest) = split_first_token(rest.trim_start())?;
    let priority = tracing_level_priority(level)?;

    let (target, message) = rest.trim_start().split_once(": ")?;
    if target.contains(char::is_whitespace) || target.is_empty() {
        return None;
    }

    Some(TracingFormattedLine {
        timestamp,
        target: target.to_string(),
        priority,
        message: message.trim().to_string(),
    })
}

fn split_first_token(value: &str) -> Option<(&str, &str)> {
    let idx = value.find(char::is_whitespace)?;
    Some((&value[..idx], &value[idx..]))
}

fn tracing_level_priority(level: &str) -> Option<u8> {
    match level {
        "ERROR" => Some(3),
        "WARN" => Some(4),
        "INFO" => Some(6),
        "DEBUG" | "TRACE" => Some(7),
        _ => None,
    }
}

fn strip_ansi_codes(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch != '\u{1b}' {
            out.push(ch);
            continue;
        }

        match chars.peek().copied() {
            Some('[') => {
                chars.next();
                for code in chars.by_ref() {
                    if ('@'..='~').contains(&code) {
                        break;
                    }
                }
            }
            Some(']') => {
                chars.next();
                while let Some(code) = chars.next() {
                    if code == '\u{7}' {
                        break;
                    }
                    if code == '\u{1b}' && matches!(chars.peek(), Some('\\')) {
                        chars.next();
                        break;
                    }
                }
            }
            _ => {}
        }
    }

    out
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

fn parse_priority(raw: Option<&serde_json::Value>) -> Option<u8> {
    raw.and_then(|v| {
        v.as_u64()
            .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
            .and_then(|n| u8::try_from(n).ok())
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_system_line_with_unit() {
        let line = r#"{"__REALTIME_TIMESTAMP":"1705320000000000","_SYSTEMD_UNIT":"sshd.service","PRIORITY":"4","MESSAGE":"Failed password for invalid user admin"}"#;
        let event = parse_journald_system_line(line).expect("should parse");
        match event {
            LogEvent::SystemEvent {
                unit,
                priority,
                message,
                ..
            } => {
                assert_eq!(unit, "sshd.service");
                assert_eq!(priority, Some(4));
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

    #[test]
    fn test_parse_system_line_byte_array_message() {
        let line = r#"{"__REALTIME_TIMESTAMP":"1705320000000000","_SYSTEMD_UNIT":"sshd.service","PRIORITY":"4","MESSAGE":[70,97,105,108,101,100,32,112,97,115,115,119,111,114,100]}"#;
        let event = parse_journald_system_line(line).expect("should parse");
        match event {
            LogEvent::SystemEvent { message, .. } => assert_eq!(message, "Failed password"),
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn test_parse_system_line_strips_ansi_tracing_format() {
        let line = r#"{"__REALTIME_TIMESTAMP":"1779501788101989","_SYSTEMD_UNIT":"dayshield-core.service","PRIORITY":"6","MESSAGE":"\u001b[2m2026-05-23T12:22:28.101989Z\u001b[0m \u001b[32m INFO\u001b[0m \u001b[2mdayshield_core::engine::nftables\u001b[0m\u001b[2m:\u001b[0m nftables: ruleset generated (1449 bytes) \u001b[3mfw_rules\u001b[0m\u001b[2m=\u001b[0m1 \u001b[3mnat_rules\u001b[0m\u001b[2m=\u001b[0m1"}"#;
        let event = parse_journald_system_line(line).expect("should parse");
        match event {
            LogEvent::SystemEvent {
                unit,
                priority,
                message,
                ..
            } => {
                assert_eq!(unit, "dayshield_core::engine::nftables");
                assert_eq!(priority, Some(6));
                assert_eq!(
                    message,
                    "nftables: ruleset generated (1449 bytes) fw_rules=1 nat_rules=1"
                );
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn test_parse_system_line_extracts_warn_priority_from_tracing_format() {
        let line = r#"{"__REALTIME_TIMESTAMP":"1779501818858069","_SYSTEMD_UNIT":"dayshield-core.service","PRIORITY":"6","MESSAGE":"2026-05-23T12:23:38.858069Z  WARN dayshield_core::api::wireguard: wireguard: invalid interface name name="}"#;
        let event = parse_journald_system_line(line).expect("should parse");
        match event {
            LogEvent::SystemEvent {
                unit,
                priority,
                message,
                ..
            } => {
                assert_eq!(unit, "dayshield_core::api::wireguard");
                assert_eq!(priority, Some(4));
                assert_eq!(message, "wireguard: invalid interface name name=");
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn test_parse_system_text_line_extracts_tracing_format() {
        let line =
            "2026-05-24T12:20:56.123456Z  INFO dayshield_core::engine::dhcp: dhcp: engine apply complete";
        let event = parse_system_text_line(line).expect("should parse");
        match event {
            LogEvent::SystemEvent {
                timestamp,
                unit,
                priority,
                message,
            } => {
                assert_eq!(timestamp, "2026-05-24T12:20:56.123456+00:00");
                assert_eq!(unit, "dayshield_core::engine::dhcp");
                assert_eq!(priority, Some(6));
                assert_eq!(message, "dhcp: engine apply complete");
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn test_parse_system_text_line_extracts_json_format() {
        let line = r#"{"timestamp":"2026-05-24T12:20:56.123456Z","level":"WARN","target":"dayshield_core::api::dhcp","fields":{"message":"dhcp: lease csv has no data rows"}}"#;
        let event = parse_system_text_line(line).expect("should parse");
        match event {
            LogEvent::SystemEvent {
                timestamp,
                unit,
                priority,
                message,
            } => {
                assert_eq!(timestamp, "2026-05-24T12:20:56.123456+00:00");
                assert_eq!(unit, "dayshield_core::api::dhcp");
                assert_eq!(priority, Some(4));
                assert_eq!(message, "dhcp: lease csv has no data rows");
            }
            _ => panic!("unexpected variant"),
        }
    }
}
