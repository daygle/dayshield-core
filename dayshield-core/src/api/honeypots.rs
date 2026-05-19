//! Honeypot API endpoints.
//!
//! - `GET /honeypots/config` - get persisted honeypot listener configuration
//! - `POST /honeypots/config` - replace and apply honeypot listener configuration
//! - `GET /honeypots/events` - list recent captured honeypot events
//! - `GET /honeypots/ips` - list source IPs collected by honeypots
//! - `GET /honeypots/recommendations` - list suggested honeypot templates

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{
    config::models::{validate_honeypot_config, HoneypotConfig, HoneypotType},
    state::AppState,
};

#[derive(Debug, thiserror::Error)]
pub enum HoneypotApiError {
    #[error("invalid request: {0}")]
    BadRequest(String),
    #[error("internal error: {0:#}")]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for HoneypotApiError {
    fn into_response(self) -> Response {
        let status = match self {
            HoneypotApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            HoneypotApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        (
            status,
            Json(serde_json::json!({ "error": self.to_string() })),
        )
            .into_response()
    }
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HoneypotRecommendation {
    pub honeypot_type: HoneypotType,
    pub name: &'static str,
    pub default_port: u16,
    pub description: &'static str,
    pub expected_signals: &'static [&'static str],
}

fn default_limit() -> usize {
    100
}

/// GET /honeypots/config
pub async fn get_config(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, HoneypotApiError> {
    let config = state.config_store.load_honeypot_config()?;
    Ok(Json(config))
}

/// POST /honeypots/config
pub async fn update_config(
    State(state): State<Arc<AppState>>,
    Json(config): Json<HoneypotConfig>,
) -> Result<impl IntoResponse, HoneypotApiError> {
    validate_honeypot_config(&config).map_err(HoneypotApiError::BadRequest)?;

    state.config_store.save_honeypot_config(config.clone())?;
    state
        .honeypot_runtime
        .apply_config(Arc::clone(&state), config.clone())
        .await?;

    Ok(Json(config))
}

/// GET /honeypots/events
pub async fn list_events(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListQuery>,
) -> Result<impl IntoResponse, HoneypotApiError> {
    let limit = query.limit.clamp(1, 1000);
    let events = state.honeypot_runtime.recent_events(limit)?;
    Ok(Json(events))
}

/// GET /honeypots/ips
pub async fn list_source_ips(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListQuery>,
) -> Result<impl IntoResponse, HoneypotApiError> {
    let limit = query.limit.clamp(1, 5000);
    let ips = state.honeypot_runtime.source_ips(limit)?;
    Ok(Json(ips))
}

/// GET /honeypots/recommendations
pub async fn recommendations() -> impl IntoResponse {
    Json(vec![
        HoneypotRecommendation {
            honeypot_type: HoneypotType::Ssh,
            name: "SSH",
            default_port: HoneypotType::Ssh.default_port(),
            description: "Catches password spraying, botnet scanners, and exposed-admin probing.",
            expected_signals: &[
                "scanner source IP",
                "client SSH banner",
                "credential attempt payloads",
            ],
        },
        HoneypotRecommendation {
            honeypot_type: HoneypotType::Telnet,
            name: "Telnet",
            default_port: HoneypotType::Telnet.default_port(),
            description: "Useful for IoT botnets and legacy device takeover attempts.",
            expected_signals: &["default credential attempts", "Mirai-like probes"],
        },
        HoneypotRecommendation {
            honeypot_type: HoneypotType::Http,
            name: "HTTP admin",
            default_port: HoneypotType::Http.default_port(),
            description:
                "Mimics a small admin surface and records web scanners and exploit probes.",
            expected_signals: &["user agent", "requested path", "web exploit probes"],
        },
        HoneypotRecommendation {
            honeypot_type: HoneypotType::Ftp,
            name: "FTP",
            default_port: HoneypotType::Ftp.default_port(),
            description:
                "Catches anonymous-login checks and old file-transfer brute-force tooling.",
            expected_signals: &["login command", "scanner source IP"],
        },
        HoneypotRecommendation {
            honeypot_type: HoneypotType::Smtp,
            name: "SMTP",
            default_port: HoneypotType::Smtp.default_port(),
            description: "Finds relay abuse, spam infrastructure, and mail-server enumeration.",
            expected_signals: &["HELO/EHLO", "relay attempt", "spam source IP"],
        },
        HoneypotRecommendation {
            honeypot_type: HoneypotType::Mysql,
            name: "MySQL",
            default_port: HoneypotType::Mysql.default_port(),
            description: "Flags exposed database scans and database brute-force tooling.",
            expected_signals: &["database scanner source IP", "TCP connection fingerprint"],
        },
        HoneypotRecommendation {
            honeypot_type: HoneypotType::Rdp,
            name: "RDP",
            default_port: HoneypotType::Rdp.default_port(),
            description:
                "Catches Windows remote-desktop sweep traffic and credential attack staging.",
            expected_signals: &["RDP scanner source IP", "TCP connection fingerprint"],
        },
    ])
}
