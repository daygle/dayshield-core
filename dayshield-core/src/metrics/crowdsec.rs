//! CrowdSec decision-rate metrics collector.
//!
//! Queries the CrowdSec Local API (LAPI) for the list of current decisions and
//! counts those whose `start_ip_at` falls within the last 60 or 300 seconds.
//!
//! The LAPI URL and API key are read from the DayShield config store.  If the
//! config is unavailable the collector falls back to sensible defaults and
//! logs a warning.
//!
//! On any error (LAPI unreachable, bad response, …) the collector returns
//! zero-valued metrics so the rest of the subsystem continues normally.

use tracing::warn;

use crate::metrics::CrowdSecMetrics;

// ---------------------------------------------------------------------------
// Decision-rate calculation
// ---------------------------------------------------------------------------

/// Count decisions from a JSON array (the LAPI `/v1/decisions` response body)
/// whose `start_ip_at` timestamp falls within the last `seconds_1min` or
/// `seconds_5min` seconds relative to `now_secs`.
///
/// The LAPI returns `null` when there are no decisions; this is handled
/// gracefully.
pub fn count_decisions(body: &str, now_secs: u64) -> (u64, u64) {
    let cutoff_1min = now_secs.saturating_sub(60);
    let cutoff_5min = now_secs.saturating_sub(300);

    let decisions: Vec<serde_json::Value> = match serde_json::from_str(body) {
        Ok(serde_json::Value::Array(arr)) => arr,
        Ok(serde_json::Value::Null) => return (0, 0),
        Ok(_) => {
            warn!("metrics/crowdsec: unexpected JSON type in decisions response");
            return (0, 0);
        }
        Err(e) => {
            warn!(error = %e, "metrics/crowdsec: failed to parse decisions JSON");
            return (0, 0);
        }
    };

    let mut last_minute: u64 = 0;
    let mut last_5min: u64 = 0;

    for decision in &decisions {
        let ts_str = match decision.get("start_ip_at").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => continue,
        };

        let ts = parse_crowdsec_timestamp(ts_str);

        if ts >= cutoff_5min {
            last_5min += 1;
        }
        if ts >= cutoff_1min {
            last_minute += 1;
        }
    }

    (last_minute, last_5min)
}

/// Parse a CrowdSec LAPI timestamp (RFC 3339) into a Unix timestamp.
///
/// Returns 0 on failure.
pub fn parse_crowdsec_timestamp(ts: &str) -> u64 {
    chrono::DateTime::parse_from_rfc3339(ts)
        .map(|dt| dt.timestamp() as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Top-level collector
// ---------------------------------------------------------------------------

/// Default CrowdSec LAPI base URL.
const DEFAULT_LAPI_URL: &str = "http://127.0.0.1:8080";
/// Default CrowdSec bouncer API key (empty — must be configured).
const DEFAULT_API_KEY: &str = "";

/// Collect [`CrowdSecMetrics`] by querying the CrowdSec LAPI.
///
/// `lapi_url` should be something like `"http://127.0.0.1:8080"`.
/// `api_key`  is the bouncer API key used for authentication.
pub async fn collect_crowdsec(lapi_url: &str, api_key: &str, now_secs: u64) -> CrowdSecMetrics {
    let url = format!("{}/v1/decisions", lapi_url);

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "metrics/crowdsec: failed to build HTTP client");
            return CrowdSecMetrics::default();
        }
    };

    let resp = match client
        .get(&url)
        .header("X-Api-Key", api_key)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "metrics/crowdsec: LAPI request failed");
            return CrowdSecMetrics::default();
        }
    };

    if !resp.status().is_success() {
        warn!(status = %resp.status(), "metrics/crowdsec: LAPI returned non-success status");
        return CrowdSecMetrics::default();
    }

    let body = match resp.text().await {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "metrics/crowdsec: failed to read LAPI response body");
            return CrowdSecMetrics::default();
        }
    };

    let (last_minute, last_5min) = count_decisions(&body, now_secs);
    CrowdSecMetrics {
        decisions_last_minute: last_minute,
        decisions_last_5min: last_5min,
    }
}

/// Collect CrowdSec metrics using the default LAPI URL and empty API key.
///
/// This is a convenience wrapper used by the background collector when no
/// config is provided.
pub async fn collect_crowdsec_default(now_secs: u64) -> CrowdSecMetrics {
    collect_crowdsec(DEFAULT_LAPI_URL, DEFAULT_API_KEY, now_secs).await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn decision(ts_rfc3339: &str) -> serde_json::Value {
        serde_json::json!({
            "id": 1,
            "origin": "crowdsec",
            "type": "ban",
            "scope": "Ip",
            "value": "1.2.3.4",
            "duration": "24h",
            "start_ip_at": ts_rfc3339
        })
    }

    #[test]
    fn test_count_decisions_basic() {
        let now = 1_000_000_000u64;
        let decisions = serde_json::json!([
            decision("2001-09-09T01:46:40+00:00"), // exactly now → in 1min
            decision("2001-09-09T01:46:10+00:00"), // 30s ago → in 1min
            decision("2001-09-09T01:41:40+00:00"), // 300s ago → cutoff_5min exactly
            decision("2001-09-09T01:41:39+00:00"), // 301s ago → outside both
        ]);
        let body = decisions.to_string();
        let (m, f) = count_decisions(&body, now);
        assert_eq!(m, 2, "expected 2 in last minute");
        assert_eq!(f, 3, "expected 3 in last 5 minutes");
    }

    #[test]
    fn test_count_decisions_null_response() {
        let (m, f) = count_decisions("null", 1_000_000);
        assert_eq!(m, 0);
        assert_eq!(f, 0);
    }

    #[test]
    fn test_count_decisions_empty_array() {
        let (m, f) = count_decisions("[]", 1_000_000);
        assert_eq!(m, 0);
        assert_eq!(f, 0);
    }

    #[test]
    fn test_count_decisions_invalid_json() {
        let (m, f) = count_decisions("not json", 1_000_000);
        assert_eq!(m, 0);
        assert_eq!(f, 0);
    }

    #[test]
    fn test_parse_crowdsec_timestamp() {
        let ts = parse_crowdsec_timestamp("2001-09-09T01:46:40+00:00");
        assert_eq!(ts, 1_000_000_000);
    }

    #[test]
    fn test_parse_crowdsec_timestamp_invalid() {
        assert_eq!(parse_crowdsec_timestamp("bad"), 0);
    }
}
