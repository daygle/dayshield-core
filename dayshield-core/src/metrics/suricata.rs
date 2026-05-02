//! Suricata alert-rate metrics collector.
//!
//! Counts the number of `event_type=alert` entries in
//! `/var/log/suricata/eve.json` whose `timestamp` field falls within the last
//! 60 seconds (or 300 seconds for the 5-minute window).
//!
//! The file is read from disk on every collection tick.  On systems with
//! very high alert rates the file may be large; in practice the file is
//! rotated regularly by logrotate, so this is acceptable for a 1-second
//! polling interval.

use tokio::fs;
use tracing::warn;

use crate::metrics::SuricataMetrics;

/// Path to the Suricata EVE JSON log.
const EVE_JSON_PATH: &str = "/var/log/suricata/eve.json";

// ---------------------------------------------------------------------------
// Alert-rate calculation
// ---------------------------------------------------------------------------

/// Parse `timestamp` fields from alert lines in `content` and return
/// `(alerts_last_minute, alerts_last_5min)` relative to `now_secs` (Unix
/// timestamp).
///
/// Only lines with `"event_type":"alert"` are counted.  Parse errors are
/// silently skipped so a single malformed line does not break the counter.
pub fn count_alerts(content: &str, now_secs: u64) -> (u64, u64) {
    let mut last_minute: u64 = 0;
    let mut last_5min: u64 = 0;

    let cutoff_1min = now_secs.saturating_sub(60);
    let cutoff_5min = now_secs.saturating_sub(300);

    for line in content.lines() {
        // Fast pre-filter to avoid JSON parsing every line.
        if !line.contains("\"alert\"") {
            continue;
        }

        let record: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if record.get("event_type").and_then(|v| v.as_str()) != Some("alert") {
            continue;
        }

        let ts_str = match record.get("timestamp").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => continue,
        };

        let ts_secs = parse_eve_timestamp(ts_str);

        if ts_secs >= cutoff_5min {
            last_5min += 1;
        }
        if ts_secs >= cutoff_1min {
            last_minute += 1;
        }
    }

    (last_minute, last_5min)
}

/// Parse an EVE JSON timestamp string (ISO 8601 / RFC 3339) into a Unix
/// timestamp (seconds).
///
/// Returns 0 on failure so the entry is simply not counted within any window.
pub fn parse_eve_timestamp(ts: &str) -> u64 {
    // Suricata uses "2024-01-15T12:00:00.000000+0000" format.
    // We need to normalise the timezone offset "+0000" → "+00:00".
    let normalised = if ts.len() >= 5 {
        let suffix = &ts[ts.len() - 5..];
        if !suffix.contains(':') && (suffix.starts_with('+') || suffix.starts_with('-')) {
            // Insert colon: "+0000" → "+00:00"
            format!("{}:{}", &ts[..ts.len() - 2], &ts[ts.len() - 2..])
        } else {
            ts.to_string()
        }
    } else {
        ts.to_string()
    };

    chrono::DateTime::parse_from_rfc3339(&normalised)
        .map(|dt| dt.timestamp() as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Top-level collector
// ---------------------------------------------------------------------------

/// Collect [`SuricataMetrics`] by scanning the EVE JSON log.
pub async fn collect_suricata(now_secs: u64) -> SuricataMetrics {
    let content = match fs::read_to_string(EVE_JSON_PATH).await {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "metrics/suricata: cannot read eve.json, reporting zeros");
            return SuricataMetrics::default();
        }
    };

    let (last_minute, last_5min) = count_alerts(&content, now_secs);
    SuricataMetrics {
        alerts_last_minute: last_minute,
        alerts_last_5min: last_5min,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn alert_line(ts: &str) -> String {
        format!(
            r#"{{"timestamp":"{ts}","event_type":"alert","src_ip":"1.2.3.4","dest_ip":"5.6.7.8","proto":"TCP","alert":{{"signature":"test","severity":1}}}}"#
        )
    }

    fn flow_line(ts: &str) -> String {
        format!(r#"{{"timestamp":"{ts}","event_type":"flow","src_ip":"1.2.3.4"}}"#)
    }

    #[test]
    fn test_count_alerts_basic() {
        let now = 1_000_000_000u64;
        let lines = vec![
            alert_line("2001-09-09T01:46:40+00:00"), // exactly now → in 1min window
            alert_line("2001-09-09T01:46:10+00:00"), // 30s ago → in 1min window
            alert_line("2001-09-09T01:41:40+00:00"), // 300s ago (cutoff_5min) → in 5min window
            alert_line("2001-09-09T01:41:39+00:00"), // 301s ago → outside both windows
            flow_line("2001-09-09T01:46:40+00:00"),  // flow, not alert
        ];
        let content = lines.join("\n");
        let (last_min, last_5min) = count_alerts(&content, now);
        assert_eq!(last_min, 2, "expected 2 alerts in last minute");
        assert_eq!(last_5min, 3, "expected 3 alerts in last 5 minutes");
    }

    #[test]
    fn test_count_alerts_empty_file() {
        let (m, f) = count_alerts("", 1_000_000);
        assert_eq!(m, 0);
        assert_eq!(f, 0);
    }

    #[test]
    fn test_count_alerts_malformed_line() {
        let content = "not json\n{\"event_type\":\"alert\"}\n"; // second line has no timestamp → ts=0
        let (m, _) = count_alerts(&content, 1_000_000);
        assert_eq!(m, 0); // ts=0 is too old
    }

    #[test]
    fn test_parse_eve_timestamp_with_colon() {
        // Standard RFC 3339 with colon in offset.
        let ts = parse_eve_timestamp("2001-09-09T01:46:40+00:00");
        assert_eq!(ts, 1_000_000_000);
    }

    #[test]
    fn test_parse_eve_timestamp_without_colon() {
        // Suricata style: no colon in offset.
        let ts = parse_eve_timestamp("2001-09-09T01:46:40.000000+0000");
        assert_eq!(ts, 1_000_000_000);
    }

    #[test]
    fn test_parse_eve_timestamp_invalid() {
        assert_eq!(parse_eve_timestamp("not-a-date"), 0);
        assert_eq!(parse_eve_timestamp(""), 0);
    }
}
