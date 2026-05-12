//! Suricata eve.json log parser.
//!
//! [`stream_suricata`] tails `/var/log/suricata/eve.json`, parses each
//! JSON-Lines record, and emits [`LogEvent::SuricataAlert`] events for every
//! `"alert"` event type found in the file.
//!
//! Non-alert event types (`"flow"`, `"dns"`, `"http"`, …) are silently
//! skipped.  JSON parse errors are logged and skipped to keep the stream
//! running.

use tokio::sync::mpsc::Sender;
use tracing::{debug, warn};

use crate::logs::{tail::FileTailer, LogEvent};

/// Path to the Suricata EVE JSON log file.
const EVE_JSON_PATH: &str = "/var/log/suricata/eve.json";

// ---------------------------------------------------------------------------
// Raw eve.json structures (deserialised, not sent over the wire)
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize, Debug)]
struct EveRecord {
    timestamp: Option<String>,
    src_ip: Option<String>,
    dest_ip: Option<String>,
    proto: Option<String>,
    event_type: Option<String>,
    alert: Option<EveAlert>,
}

#[derive(serde::Deserialize, Debug)]
struct EveAlert {
    signature: Option<String>,
    severity: Option<u8>,
}

// ---------------------------------------------------------------------------
// Public streaming function
// ---------------------------------------------------------------------------

/// Tail `/var/log/suricata/eve.json` and forward parsed alert events to `tx`.
///
/// This function runs indefinitely and only returns when `tx` is closed.
pub async fn stream_suricata(tx: Sender<LogEvent>) {
    let (line_tx, mut line_rx) = tokio::sync::mpsc::channel::<String>(256);

    // Spawn the file tailer.
    tokio::spawn(async move {
        FileTailer::new(EVE_JSON_PATH).run(line_tx).await;
    });

    while let Some(line) = line_rx.recv().await {
        match parse_eve_line(&line) {
            Some(event) => {
                if tx.send(event).await.is_err() {
                    break;
                }
            }
            None => {
                debug!("suricata: skipped non-alert or unparseable line");
            }
        }
    }
}

/// Parse a single eve.json line and return a [`LogEvent::SuricataAlert`] if
/// the line represents an alert, or `None` otherwise.
pub(crate) fn parse_eve_line(line: &str) -> Option<LogEvent> {
    let record: EveRecord = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "suricata: failed to parse eve.json line");
            return None;
        }
    };

    // Only forward alert events.
    if record.event_type.as_deref() != Some("alert") {
        return None;
    }

    let alert = record.alert?;

    Some(LogEvent::SuricataAlert {
        timestamp: record.timestamp.unwrap_or_default(),
        src_ip: record.src_ip.unwrap_or_default(),
        dest_ip: record.dest_ip.unwrap_or_default(),
        proto: record.proto.unwrap_or_default(),
        signature: alert.signature.unwrap_or_default(),
        severity: alert.severity.unwrap_or(3),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn alert_json(extra: &str) -> String {
        format!(
            r#"{{"timestamp":"2024-01-15T12:00:00.000000+0000","event_type":"alert","src_ip":"10.0.0.1","dest_ip":"10.0.0.2","proto":"TCP","alert":{{"signature":"ET SCAN Nmap","severity":2{}}}}}"#,
            extra
        )
    }

    #[test]
    fn test_parse_alert_line() {
        let line = alert_json("");
        let event = parse_eve_line(&line).expect("should parse alert");
        match event {
            LogEvent::SuricataAlert {
                src_ip,
                dest_ip,
                proto,
                signature,
                severity,
                ..
            } => {
                assert_eq!(src_ip, "10.0.0.1");
                assert_eq!(dest_ip, "10.0.0.2");
                assert_eq!(proto, "TCP");
                assert_eq!(signature, "ET SCAN Nmap");
                assert_eq!(severity, 2);
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn test_parse_non_alert_returns_none() {
        let line = r#"{"timestamp":"2024-01-15T12:00:00.000000+0000","event_type":"flow","src_ip":"10.0.0.1","dest_ip":"10.0.0.2","proto":"TCP"}"#;
        assert!(parse_eve_line(line).is_none());
    }

    #[test]
    fn test_parse_invalid_json_returns_none() {
        assert!(parse_eve_line("not json").is_none());
    }

    #[test]
    fn test_parse_alert_missing_optional_fields() {
        // Minimal alert - all optional fields absent → defaults used.
        let line = r#"{"event_type":"alert","alert":{"signature":"test"}}"#;
        let event = parse_eve_line(line).expect("should parse minimal alert");
        match event {
            LogEvent::SuricataAlert {
                src_ip,
                dest_ip,
                severity,
                ..
            } => {
                assert_eq!(src_ip, "");
                assert_eq!(dest_ip, "");
                assert_eq!(severity, 3); // default
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn test_parse_alert_missing_alert_block_returns_none() {
        // event_type = "alert" but no "alert" object → should return None.
        let line = r#"{"event_type":"alert","src_ip":"1.2.3.4"}"#;
        assert!(parse_eve_line(line).is_none());
    }
}
