//! Firewall (nftables) log parser - reads from journald via
//! `systemd-journal-gateway` or the `/run/log/journal` socket.
//!
//! Because linking against `libsystemd` is undesirable in a portable crate,
//! this module reads journald entries by spawning `journalctl` as a child
//! process with `--output=json --follow`, matching both nftables-tagged
//! messages and kernel-transport firewall logs.
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

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        OnceLock,
    },
};

use chrono::{DateTime, TimeZone, Utc};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
    sync::{broadcast, mpsc::Sender},
    time::{Duration, Instant},
};
use tracing::{info, warn};

use crate::live_logs::{journald_field_text, LogEvent};

static FIREWALL_JOURNAL_FALLBACK_WARNED: AtomicBool = AtomicBool::new(false);
static FIREWALL_DMESG_UNAVAILABLE_WARNED: AtomicBool = AtomicBool::new(false);
static FIREWALL_EVENTS: OnceLock<broadcast::Sender<LogEvent>> = OnceLock::new();
const FIREWALL_BROADCAST_CAPACITY: usize = 1024;

// ---------------------------------------------------------------------------
// Public streaming function
// ---------------------------------------------------------------------------

/// Stream nftables firewall log events from journald to `tx`.
///
/// Spawns `journalctl --output=json --follow` for nftables/kernel messages and
/// processes its output line by line.  Restarts automatically when the
/// process exits unexpectedly.
pub async fn stream_firewall(tx: Sender<LogEvent>) {
    let mut rx = shared_firewall_events().subscribe();

    loop {
        match rx.recv().await {
            Ok(event) => {
                if tx.send(event).await.is_err() {
                    return;
                }
            }
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                warn!(
                    skipped,
                    "firewall: live log consumer lagged; skipped firewall events"
                );
            }
            Err(broadcast::error::RecvError::Closed) => return,
        }
    }
}

fn shared_firewall_events() -> broadcast::Sender<LogEvent> {
    FIREWALL_EVENTS
        .get_or_init(|| {
            let (broadcast_tx, _) = broadcast::channel(FIREWALL_BROADCAST_CAPACITY);
            let forward_tx = broadcast_tx.clone();

            tokio::spawn(async move {
                let (source_tx, mut source_rx) =
                    tokio::sync::mpsc::channel::<LogEvent>(FIREWALL_BROADCAST_CAPACITY);

                tokio::spawn(async move {
                    stream_firewall_source(source_tx).await;
                });

                while let Some(event) = source_rx.recv().await {
                    let _ = forward_tx.send(event);
                }

                warn!("firewall: shared live log source stopped");
            });

            broadcast_tx
        })
        .clone()
}

async fn stream_firewall_source(tx: Sender<LogEvent>) {
    if !journal_can_stream_firewall().await {
        if !FIREWALL_JOURNAL_FALLBACK_WARNED.swap(true, Ordering::Relaxed) {
            warn!("firewall: journalctl is unavailable for nftables/kernel logs; using dmesg fallback");
        }
        stream_dmesg_firewall(tx).await;
        return;
    }

    stream_journal_firewall(tx).await;
}

async fn journal_can_stream_firewall() -> bool {
    match Command::new("journalctl")
        .args([
            "--output=json",
            "--lines=0",
            "SYSLOG_IDENTIFIER=nftables",
            "+",
            "_TRANSPORT=kernel",
        ])
        .output()
        .await
    {
        Ok(output) if output.status.success() => true,
        Ok(output) => {
            warn!(
                status = %output.status,
                stderr = %String::from_utf8_lossy(&output.stderr),
                "firewall: journalctl probe failed; using dmesg fallback"
            );
            false
        }
        Err(error) => {
            warn!(error = %error, "firewall: failed to probe journalctl; using dmesg fallback");
            false
        }
    }
}

async fn stream_journal_firewall(tx: Sender<LogEvent>) {
    loop {
        info!("firewall: starting journalctl nftables stream");

        let mut child = match Command::new("journalctl")
            .args([
                "--output=json",
                "--follow",
                "--lines=50",
                "SYSLOG_IDENTIFIER=nftables",
                "+",
                "_TRANSPORT=kernel",
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
                            // Receiver dropped - shut down.
                            let _ = child.kill().await;
                            return;
                        }
                    }
                }
                Ok(None) => {
                    // Process ended - restart.
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

async fn stream_dmesg_firewall(tx: Sender<LogEvent>) {
    let mut immediate_exit_count: u32 = 0;

    loop {
        info!("firewall: starting dmesg fallback stream");

        let started_at = Instant::now();
        let mut saw_any_line = false;

        let mut child = match Command::new("dmesg")
            .args(["--follow", "--time-format=iso"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "firewall: failed to spawn dmesg, retrying in 5s");
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        let stdout = child.stdout.take().expect("stdout piped");
        let mut reader = BufReader::new(stdout).lines();

        loop {
            match reader.next_line().await {
                Ok(Some(line)) => {
                    saw_any_line = true;
                    if let Some(event) = parse_dmesg_firewall_line(&line) {
                        if tx.send(event).await.is_err() {
                            let _ = child.kill().await;
                            return;
                        }
                    }
                }
                Ok(None) => {
                    let immediate_exit =
                        !saw_any_line && started_at.elapsed() < Duration::from_secs(2);
                    if immediate_exit {
                        immediate_exit_count = immediate_exit_count.saturating_add(1);
                        let delay_secs = 2_u64.pow(immediate_exit_count.min(8));
                        if !FIREWALL_DMESG_UNAVAILABLE_WARNED.swap(true, Ordering::Relaxed) {
                            warn!(
                                attempt = immediate_exit_count,
                                delay_secs,
                                "firewall: dmesg exited immediately; likely unavailable (permissions/kernel access), backing off"
                            );
                        }
                        let _ = child.kill().await;
                        tokio::time::sleep(Duration::from_secs(delay_secs)).await;
                    } else {
                        immediate_exit_count = 0;
                        FIREWALL_DMESG_UNAVAILABLE_WARNED.store(false, Ordering::Relaxed);
                        info!("firewall: dmesg exited, restarting");
                        let _ = child.kill().await;
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                    break;
                }
                Err(e) => {
                    warn!(error = %e, "firewall: dmesg read error");
                    break;
                }
            }
        }

        let _ = child.kill().await;
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

    // Journald usually encodes MESSAGE as a string, but some entries arrive as
    // arrays. Decode both so valid journal entries are not silently dropped.
    let message = match journald_field_text(obj.get("MESSAGE")) {
        Some(m) => m.to_string(),
        None => return None,
    };

    // Parse the __REALTIME_TIMESTAMP field (microseconds since epoch).
    let timestamp =
        parse_realtime_timestamp(journald_field_text(obj.get("__REALTIME_TIMESTAMP")).as_deref());

    parse_nftables_message(&message, &timestamp)
}

/// Parse one `dmesg` output line carrying an nftables/kernel firewall log.
pub(crate) fn parse_dmesg_firewall_line(line: &str) -> Option<LogEvent> {
    let message = normalize_dmesg_firewall_message(line)?;
    let timestamp = parse_dmesg_timestamp(line);
    parse_nftables_message(&message, &timestamp)
}

fn normalize_dmesg_firewall_message(line: &str) -> Option<String> {
    let line = line.trim();
    if !line.contains("IN=") || !line.contains("SRC=") || !line.contains("DST=") {
        return None;
    }

    let in_idx = line.find("IN=")?;
    let mut action = &line[..in_idx];
    if let Some((_, rest)) = action.rsplit_once("kernel:") {
        action = rest;
    }
    let trimmed = action.trim_start();
    if let Some(rest) = trimmed
        .strip_prefix('[')
        .and_then(|value| value.split_once(']').map(|(_, rest)| rest))
    {
        action = rest;
    } else {
        action = trimmed;
    }

    let action = action.trim_matches(|ch: char| ch.is_whitespace() || ch == ':');
    let kv = &line[in_idx..];
    if action.is_empty() {
        Some(kv.to_string())
    } else {
        Some(format!("{action} {kv}"))
    }
}

fn parse_dmesg_timestamp(line: &str) -> String {
    line.split_whitespace()
        .next()
        .map(|token| token.replacen(',', ".", 1))
        .and_then(|token| DateTime::parse_from_rfc3339(&token).ok())
        .map(|dt| dt.with_timezone(&Utc).to_rfc3339())
        .unwrap_or_else(|| Utc::now().to_rfc3339())
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
    let proto = kv.get("PROTO").cloned().unwrap_or_default();
    let iface = kv.get("IN").cloned().unwrap_or_default();

    Some(LogEvent::FirewallEvent {
        timestamp: timestamp.to_string(),
        action,
        src_ip,
        dest_ip,
        sport,
        dport,
        proto,
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
        let line = r#"{"__REALTIME_TIMESTAMP":"1705320000000000","MESSAGE":"DROP IN=eth0 OUT= SRC=192.168.1.1 DST=10.0.0.1 SPT=1234 DPT=443","SYSLOG_IDENTIFIER":"nftables"}"#.to_string();
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

    #[test]
    fn test_parse_journald_firewall_line_byte_array_message() {
        let line = r#"{"__REALTIME_TIMESTAMP":"1705320000000000","MESSAGE":[68,82,79,80,32,73,78,61,101,116,104,48,32,79,85,84,61,32,83,82,67,61,49,57,50,46,49,54,56,46,49,46,49,32,68,83,84,61,49,48,46,48,46,48,46,49,32,80,82,79,84,79,61,84,67,80,32,83,80,84,61,49,50,51,52,32,68,80,84,61,52,52,51],"SYSLOG_IDENTIFIER":"nftables"}"#;
        let event = parse_journald_firewall_line(line).expect("should parse");
        match event {
            LogEvent::FirewallEvent { action, dport, .. } => {
                assert_eq!(action, "DROP");
                assert_eq!(dport, 443);
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn test_parse_dmesg_firewall_line_with_kernel_prefix() {
        let line = "2026-05-24T12:34:56,123456+00:00 kernel: DEFAULT-BLOCK INPUT IN=ens19 OUT= SRC=192.168.20.2 DST=192.168.20.255 PROTO=UDP SPT=9801 DPT=9801";
        let event = parse_dmesg_firewall_line(line).expect("should parse");
        match event {
            LogEvent::FirewallEvent {
                timestamp,
                action,
                src_ip,
                dest_ip,
                dport,
                ..
            } => {
                assert_eq!(timestamp, "2026-05-24T12:34:56.123456+00:00");
                assert_eq!(action, "DEFAULT-BLOCK INPUT");
                assert_eq!(src_ip, "192.168.20.2");
                assert_eq!(dest_ip, "192.168.20.255");
                assert_eq!(dport, 9801);
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn test_parse_dmesg_firewall_line_with_bracket_prefix() {
        let line = "[  123.456789] DROP IN=eth0 OUT= SRC=10.0.0.5 DST=10.0.0.1 PROTO=TCP SPT=12345 DPT=443";
        let event = parse_dmesg_firewall_line(line).expect("should parse");
        match event {
            LogEvent::FirewallEvent {
                action,
                src_ip,
                dport,
                ..
            } => {
                assert_eq!(action, "DROP");
                assert_eq!(src_ip, "10.0.0.5");
                assert_eq!(dport, 443);
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn test_parse_dmesg_firewall_line_keeps_rule_id_prefix_action() {
        let line = "[  123.456789] DROP dayshield[5a2f]: IN=eth0 OUT= SRC=10.0.0.5 DST=10.0.0.1 PROTO=TCP SPT=12345 DPT=443";
        let event = parse_dmesg_firewall_line(line).expect("should parse");
        match event {
            LogEvent::FirewallEvent { action, .. } => {
                assert_eq!(action, "DROP dayshield[5a2f]");
            }
            _ => panic!("unexpected variant"),
        }
    }
}
