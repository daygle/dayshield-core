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
use chrono::{DateTime, Utc};
use serde::Deserialize;
use tokio::process::Command;
use tracing::warn;

use crate::logs::{
    firewall::parse_journald_firewall_line,
    suricata::parse_eve_line,
    system::parse_journald_system_line,
    websocket::logs_websocket,
    LogEvent,
};

#[derive(Debug, Deserialize)]
pub struct SearchLogsQuery {
    pub from: String,
    pub to: String,
    pub source: Option<String>,
    pub q: Option<String>,
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

fn parse_iso8601(value: &str, field: &str) -> Result<DateTime<Utc>, LogsApiError> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| {
            LogsApiError::Validation(format!(
                "invalid {field} timestamp (expected RFC3339): {value}"
            ))
        })
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
            DateTime::parse_from_str(raw, "%Y-%m-%dT%H:%M:%S%.f%z")
                .map(|dt| dt.with_timezone(&Utc))
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
        .map_err(|e| LogsApiError::Search(format!("failed to run journalctl for system logs: {e}")))?;

    if !out.status.success() {
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

async fn query_journal_firewall(from: &str, to: &str) -> Result<Vec<LogEvent>, LogsApiError> {
    let out = Command::new("journalctl")
        .args([
            "--output=json",
            "--identifier=nftables",
            "--since",
            from,
            "--until",
            to,
        ])
        .output()
        .await
        .map_err(|e| LogsApiError::Search(format!("failed to run journalctl for firewall logs: {e}")))?;

    if !out.status.success() {
        return Err(LogsApiError::Search(format!(
            "journalctl firewall query failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    Ok(stdout
        .lines()
        .filter_map(parse_journald_firewall_line)
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
/// - `from` (required, RFC3339)
/// - `to` (required, RFC3339)
/// - `source` (optional: all|system|firewall|suricata, default all)
/// - `q` (optional case-insensitive contains search)
/// - `limit` (optional max items, default 5000, hard cap 20000)
pub async fn search_logs(
    Query(query): Query<SearchLogsQuery>,
) -> Result<impl IntoResponse, LogsApiError> {
    let from = parse_iso8601(&query.from, "from")?;
    let to = parse_iso8601(&query.to, "to")?;
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

    let q = query.q.as_ref().map(|v| v.to_lowercase());
    let limit = query.limit.unwrap_or(5000).min(20000);

    let mut events = Vec::<LogEvent>::new();
    let from_s = from.format("%Y-%m-%d %H:%M:%S UTC").to_string();
    let to_s = to.format("%Y-%m-%d %H:%M:%S UTC").to_string();

    if matches!(source.as_str(), "all" | "system") {
        events.extend(query_journal_system(&from_s, &to_s).await?);
    }
    if matches!(source.as_str(), "all" | "firewall") {
        events.extend(query_journal_firewall(&from_s, &to_s).await?);
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

    Ok(Json(serde_json::json!({
        "success": true,
        "data": events,
        "count": events.len(),
    })))
}
