//! Logs API endpoints.
//!
//! - `GET /logs/ws` upgrades to a WebSocket for live streaming.
//! - `GET /logs/search` returns historical logs for a selected time range.

use axum::{
    extract::{ws::WebSocketUpgrade, Query},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::process::Command;
use tracing::warn;

use crate::live_logs::{
    firewall::{parse_dmesg_firewall_line, parse_journald_firewall_line},
    suricata::parse_eve_line,
    system::{parse_journald_system_line, parse_system_text_line},
    websocket::logs_websocket,
    LogEvent,
};

const DAYSHIELD_CORE_LOG_PATH: &str = "/var/log/dayshield/core.log";
static LOGS_DMESG_FALLBACK_WARNED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Deserialize)]
pub struct SearchLogsQuery {
    pub from: Option<String>,
    pub to: Option<String>,
    pub source: Option<String>,
    pub q: Option<String>,
    pub query: Option<String>,
    pub search: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, thiserror::Error)]
pub enum LogsApiError {
    #[error("validation error: {0}")]
    Validation(String),
    #[error("search failed: {0}")]
    Search(String),
}

impl IntoResponse for LogsApiError {
    fn into_response(self) -> axum::response::Response {
        let status = match self {
            LogsApiError::Validation(_) => StatusCode::BAD_REQUEST,
            LogsApiError::Search(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (
            status,
            Json(serde_json::json!({ "success": false, "error": self.to_string() })),
        )
            .into_response()
    }
}

fn parse_log_timestamp(value: &str, field: &str) -> Result<DateTime<Utc>, LogsApiError> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .or_else(|_| parse_unix_timestamp(value).ok_or(()))
        .map_err(|_| {
            LogsApiError::Validation(format!(
                "invalid {field} timestamp (expected RFC3339 or Unix timestamp): {value}"
            ))
        })
}

fn parse_unix_timestamp(value: &str) -> Option<DateTime<Utc>> {
    let parsed = value.parse::<i64>().ok()?;
    let seconds = if parsed.abs() >= 1_000_000_000_000 {
        parsed / 1000
    } else {
        parsed
    };

    DateTime::from_timestamp(seconds, 0)
}

fn resolve_search_range(
    query: &SearchLogsQuery,
) -> Result<(DateTime<Utc>, DateTime<Utc>), LogsApiError> {
    let to = match query.to.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
        Some(value) => parse_log_timestamp(value, "to")?,
        None => Utc::now(),
    };
    let from = match query
        .from
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        Some(value) => parse_log_timestamp(value, "from")?,
        None => to - Duration::hours(24),
    };

    Ok((from, to))
}

fn search_needle(query: &SearchLogsQuery) -> Option<String> {
    query
        .q
        .as_ref()
        .or(query.query.as_ref())
        .or(query.search.as_ref())
        .map(|value| value.trim().to_lowercase())
        .filter(|value| !value.is_empty())
}

fn parse_event_ts(event: &LogEvent) -> Option<DateTime<Utc>> {
    let raw = match event {
        LogEvent::SuricataAlert { timestamp, .. } => timestamp,
        LogEvent::FirewallEvent { timestamp, .. } => timestamp,
        LogEvent::SystemEvent { timestamp, .. } => timestamp,
    };

    DateTime::parse_from_rfc3339(raw)
        .map(|dt| dt.with_timezone(&Utc))
        .or_else(|_| {
            DateTime::parse_from_str(raw, "%Y-%m-%dT%H:%M:%S%.f%z").map(|dt| dt.with_timezone(&Utc))
        })
        .ok()
}

fn event_matches_source(event: &LogEvent, source: &str) -> bool {
    match (source, event) {
        ("all", _) => true,
        ("suricata", LogEvent::SuricataAlert { .. }) => true,
        ("firewall", LogEvent::FirewallEvent { .. }) => true,
        ("system", LogEvent::SystemEvent { .. }) => true,
        _ => false,
    }
}

fn event_search_text(event: &LogEvent) -> String {
    match event {
        LogEvent::SuricataAlert {
            src_ip,
            dest_ip,
            proto,
            signature,
            ..
        } => format!("{src_ip} {dest_ip} {proto} {signature}"),
        LogEvent::FirewallEvent {
            action,
            src_ip,
            dest_ip,
            iface,
            ..
        } => format!("{action} {src_ip} {dest_ip} {iface}"),
        LogEvent::SystemEvent { unit, message, .. } => format!("{unit} {message}"),
    }
}

fn journal_has_no_files(stderr: &[u8]) -> bool {
    String::from_utf8_lossy(stderr).contains("No journal files were found")
}

async fn query_journal_system(from: &str, to: &str) -> Result<Vec<LogEvent>, LogsApiError> {
    let out = Command::new("journalctl")
        .args([
            "--output=json",
            "--priority=info",
            "--since",
            from,
            "--until",
            to,
        ])
        .output()
        .await
        .map_err(|e| {
            LogsApiError::Search(format!("failed to run journalctl for system logs: {e}"))
        })?;

    if !out.status.success() {
        if journal_has_no_files(&out.stderr) {
            return Ok(vec![]);
        }
        return Err(LogsApiError::Search(format!(
            "journalctl system query failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    Ok(stdout
        .lines()
        .filter_map(parse_journald_system_line)
        .collect::<Vec<_>>())
}

async fn query_core_log_range(
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> Result<Vec<LogEvent>, LogsApiError> {
    let content = match tokio::fs::read_to_string(DAYSHIELD_CORE_LOG_PATH).await {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, path = DAYSHIELD_CORE_LOG_PATH, "logs/search: could not read DayShield core log");
            return Ok(vec![]);
        }
    };

    Ok(content
        .lines()
        .filter_map(parse_system_text_line)
        .filter(|event| {
            parse_event_ts(event)
                .map(|ts| ts >= from && ts <= to)
                .unwrap_or(true)
        })
        .collect())
}

async fn query_journal_firewall(from: &str, to: &str) -> Result<Vec<LogEvent>, LogsApiError> {
    let mut cmd = Command::new("journalctl");
    cmd.args(["--output=json", "--since", from, "--until", to])
        .args(["--identifier=nftables", "--identifier=kernel"]);

    let out = cmd.output().await.map_err(|e| {
        LogsApiError::Search(format!("failed to run journalctl for firewall logs: {e}"))
    })?;
    if !out.status.success() {
        if journal_has_no_files(&out.stderr) {
            return Ok(vec![]);
        }
        return Err(LogsApiError::Search(format!(
            "journalctl firewall query failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    Ok(stdout
        .lines()
        .filter_map(|line| {
            parse_journald_firewall_line(line).or_else(|| match parse_journald_system_line(line) {
                Some(event @ LogEvent::FirewallEvent { .. }) => Some(event),
                _ => None,
            })
        })
        .collect::<Vec<_>>())
}

async fn query_dmesg_firewall_range(
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> Result<Vec<LogEvent>, LogsApiError> {
    let out = match Command::new("dmesg")
        .args(["--time-format=iso"])
        .output()
        .await
    {
        Ok(output) => output,
        Err(e) => {
            warn!(error = %e, "logs/search: failed to run dmesg fallback");
            return Ok(vec![]);
        }
    };

    if !out.status.success() {
        if !LOGS_DMESG_FALLBACK_WARNED.swap(true, Ordering::Relaxed) {
            warn!(
                stderr = %String::from_utf8_lossy(&out.stderr),
                "logs/search: dmesg fallback returned non-zero status"
            );
        }
        return Ok(vec![]);
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    Ok(stdout
        .lines()
        .filter_map(parse_dmesg_firewall_line)
        .filter(|event| {
            parse_event_ts(event)
                .map(|ts| ts >= from && ts <= to)
                .unwrap_or(true)
        })
        .collect::<Vec<_>>())
}

async fn query_suricata_range(
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> Result<Vec<LogEvent>, LogsApiError> {
    let content = match tokio::fs::read_to_string("/var/log/suricata/eve.json").await {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "logs/search: could not read suricata eve.json");
            return Ok(vec![]);
        }
    };

    let mut events = Vec::new();
    for line in content.lines() {
        if let Some(event) = parse_eve_line(line) {
            if let Some(ts) = parse_event_ts(&event) {
                if ts >= from && ts <= to {
                    events.push(event);
                }
            }
        }
    }
    Ok(events)
}

/// Handler: upgrade to WebSocket and start streaming live log events.
///
/// Clients connect to `GET /logs/ws`.  After the upgrade they receive a
/// continuous stream of newline-delimited JSON objects, one per log event.
pub async fn ws_handler(ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(logs_websocket)
}

/// Handler: search historical logs in a selected date/time range.
///
/// Query params:
/// - `from` (optional, RFC3339 or Unix timestamp; defaults to 24 hours before `to`)
/// - `to` (optional, RFC3339 or Unix timestamp; defaults to now)
/// - `source` (optional: all|system|firewall|suricata, default all)
/// - `q`, `query`, or `search` (optional case-insensitive contains search)
/// - `limit` (optional max items, default 5000, hard cap 20000)
pub async fn search_logs(
    Query(query): Query<SearchLogsQuery>,
) -> Result<impl IntoResponse, LogsApiError> {
    let (from, to) = resolve_search_range(&query)?;
    if to < from {
        return Err(LogsApiError::Validation(
            "to must be greater than or equal to from".to_string(),
        ));
    }

    let source = query.source.as_deref().unwrap_or("all").to_lowercase();
    if !matches!(source.as_str(), "all" | "system" | "firewall" | "suricata") {
        return Err(LogsApiError::Validation(format!(
            "invalid source: {} (expected all|system|firewall|suricata)",
            source
        )));
    }

    let q = search_needle(&query);
    let limit = query.limit.unwrap_or(5000).min(20000);

    let mut events = Vec::<LogEvent>::new();
    let from_s = from.format("%Y-%m-%d %H:%M:%S UTC").to_string();
    let to_s = to.format("%Y-%m-%d %H:%M:%S UTC").to_string();

    if matches!(source.as_str(), "all" | "system") {
        let journal_events = query_journal_system(&from_s, &to_s).await?;
        if journal_events.is_empty() {
            events.extend(query_core_log_range(from, to).await?);
        } else {
            events.extend(journal_events);
        }
    }
    if matches!(source.as_str(), "all" | "firewall") {
        let journal_events = query_journal_firewall(&from_s, &to_s).await?;
        if journal_events.is_empty() {
            events.extend(query_dmesg_firewall_range(from, to).await?);
        } else {
            events.extend(journal_events);
        }
    }
    if matches!(source.as_str(), "all" | "suricata") {
        events.extend(query_suricata_range(from, to).await?);
    }

    events.retain(|event| {
        if let Some(ts) = parse_event_ts(event) {
            if ts < from || ts > to {
                return false;
            }
        }
        if !event_matches_source(event, &source) {
            return false;
        }
        if let Some(ref needle) = q {
            let hay = event_search_text(event).to_lowercase();
            if !hay.contains(needle) {
                return false;
            }
        }
        true
    });

    events.sort_by_key(parse_event_ts);
    if events.len() > limit {
        events = events.split_off(events.len() - limit);
    }

    let events = events
        .iter()
        .map(LogEvent::to_client_payload)
        .collect::<Vec<_>>();
    let count = events.len();

    Ok(Json(serde_json::json!({
        "success": true,
        "data": events.clone(),
        "logs": events,
        "count": count,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_log_timestamp_accepts_rfc3339() {
        let parsed = parse_log_timestamp("2026-05-23T02:03:04Z", "from").unwrap();
        assert_eq!(parsed.to_rfc3339(), "2026-05-23T02:03:04+00:00");
    }

    #[test]
    fn parse_log_timestamp_accepts_unix_millis() {
        let parsed = parse_log_timestamp("1779501784000", "from").unwrap();
        assert_eq!(parsed.to_rfc3339(), "2026-05-23T02:03:04+00:00");
    }

    #[test]
    fn resolve_search_range_defaults_from_to_last_24_hours() {
        let query = SearchLogsQuery {
            from: None,
            to: Some("2026-05-23T02:03:04Z".to_string()),
            source: None,
            q: None,
            query: None,
            search: None,
            limit: None,
        };

        let (from, to) = resolve_search_range(&query).unwrap();
        assert_eq!(to.to_rfc3339(), "2026-05-23T02:03:04+00:00");
        assert_eq!((to - from).num_hours(), 24);
    }

    #[test]
    fn search_needle_accepts_compat_query_names() {
        let query = SearchLogsQuery {
            from: None,
            to: None,
            source: None,
            q: None,
            query: Some(" DROP ".to_string()),
            search: None,
            limit: None,
        };

        assert_eq!(search_needle(&query).as_deref(), Some("drop"));
    }
}
