//! Caddy reverse-proxy API endpoints.
//!
//! Provides configuration, status, log access, and service control for the
//! Caddy reverse proxy. Caddy fronts user-defined sites and terminates TLS
//! automatically (Let's Encrypt) using its built-in ACME client.

use std::path::Path;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::{
    config::models::{validate_caddy_config, CaddyConfig, CaddySite},
    state::AppState,
};

const CADDY_CONFIG_DIR: &str = "/etc/caddy";
const CADDY_CONFIG_PATH: &str = "/etc/caddy/Caddyfile";
const CADDY_SERVICE: &str = "caddy.service";

#[derive(Debug, thiserror::Error)]
pub enum CaddyApiError {
    #[error("validation error: {0}")]
    ValidationFailed(String),

    #[error("storage error: {0:#}")]
    StorageError(#[from] anyhow::Error),

    #[error("service error: {0}")]
    ServiceError(String),
}

impl IntoResponse for CaddyApiError {
    fn into_response(self) -> Response {
        let status = match &self {
            CaddyApiError::ValidationFailed(_) => StatusCode::BAD_REQUEST,
            CaddyApiError::StorageError(_) | CaddyApiError::ServiceError(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };

        (
            status,
            Json(serde_json::json!({ "error": self.to_string() })),
        )
            .into_response()
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaddyConfigResponse {
    pub enabled: bool,
    pub acme_email: String,
    pub log_level: String,
    pub sites: Vec<CaddySite>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaddyStatusResponse {
    pub configured: bool,
    pub enabled: bool,
    pub running: bool,
    pub unit_enabled: bool,
    pub binary_present: bool,
    pub active_state: String,
    pub sub_state: String,
    pub version: Option<String>,
    pub site_count: usize,
    pub last_error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateCaddyConfigRequest {
    pub enabled: bool,
    #[serde(default)]
    pub acme_email: String,
    #[serde(default)]
    pub log_level: String,
    #[serde(default)]
    pub sites: Vec<CaddySite>,
}

#[derive(Debug, Deserialize)]
pub struct LogsQuery {
    pub lines: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct LogsResponse {
    pub lines: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ActionResponse {
    pub message: String,
}

pub async fn get_config(
    State(state): State<std::sync::Arc<AppState>>,
) -> Result<impl IntoResponse, CaddyApiError> {
    let cfg = state
        .config_store
        .load_caddy_config()
        .map_err(CaddyApiError::StorageError)?
        .unwrap_or_default();

    Ok(Json(to_response(cfg)))
}

pub async fn update_config(
    State(state): State<std::sync::Arc<AppState>>,
    Json(req): Json<UpdateCaddyConfigRequest>,
) -> Result<impl IntoResponse, CaddyApiError> {
    let log_level = if req.log_level.trim().is_empty() {
        "info".to_string()
    } else {
        req.log_level.trim().to_lowercase()
    };

    let cfg = CaddyConfig {
        enabled: req.enabled,
        acme_email: req.acme_email.trim().to_string(),
        log_level,
        sites: req
            .sites
            .into_iter()
            .map(|site| CaddySite {
                domain: site.domain.trim().to_string(),
                upstream: site.upstream.trim().to_string(),
                enabled: site.enabled,
            })
            .collect(),
    };

    if let Err(msg) = validate_caddy_config(&cfg) {
        return Err(CaddyApiError::ValidationFailed(msg));
    }

    state
        .config_store
        .save_caddy_config(cfg.clone())
        .map_err(CaddyApiError::StorageError)?;

    info!(
        enabled = cfg.enabled,
        site_count = cfg.sites.len(),
        "caddy: configuration updated"
    );

    apply_caddy_config(&cfg).await?;

    Ok(Json(to_response(cfg)))
}

pub async fn get_status(
    State(state): State<std::sync::Arc<AppState>>,
) -> Result<impl IntoResponse, CaddyApiError> {
    let cfg = state
        .config_store
        .load_caddy_config()
        .map_err(CaddyApiError::StorageError)?
        .unwrap_or_default();

    Ok(Json(read_caddy_status(&cfg).await))
}

pub async fn restart_service() -> Result<impl IntoResponse, CaddyApiError> {
    run_systemctl(["restart", CADDY_SERVICE]).await?;
    Ok(Json(ActionResponse {
        message: "caddy service restarted".to_string(),
    }))
}

pub async fn get_logs(
    Query(query): Query<LogsQuery>,
) -> Result<impl IntoResponse, CaddyApiError> {
    let lines = query.lines.unwrap_or(100).clamp(1, 500);
    let output = tokio::process::Command::new("journalctl")
        .args([
            "-u",
            CADDY_SERVICE,
            "-n",
            &lines.to_string(),
            "--no-pager",
            "-o",
            "cat",
        ])
        .output()
        .await
        .map_err(|err| CaddyApiError::ServiceError(format!("failed to read journal: {err}")))?;

    if !output.status.success() {
        return Err(CaddyApiError::ServiceError(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }

    let lines = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| line.trim_end().to_string())
        .filter(|line| !line.is_empty())
        .collect();

    Ok(Json(LogsResponse { lines }))
}

fn to_response(cfg: CaddyConfig) -> CaddyConfigResponse {
    CaddyConfigResponse {
        enabled: cfg.enabled,
        acme_email: cfg.acme_email,
        log_level: cfg.log_level,
        sites: cfg.sites,
    }
}

async fn apply_caddy_config(cfg: &CaddyConfig) -> Result<(), CaddyApiError> {
    std::fs::create_dir_all(CADDY_CONFIG_DIR).map_err(|err| {
        CaddyApiError::ServiceError(format!("failed to create config directory: {err}"))
    })?;

    std::fs::write(CADDY_CONFIG_PATH, render_caddyfile(cfg)).map_err(|err| {
        CaddyApiError::ServiceError(format!("failed to write Caddyfile: {err}"))
    })?;

    let _ = run_systemctl(["daemon-reload"]).await;

    if cfg.enabled {
        run_systemctl(["enable", "--now", CADDY_SERVICE]).await?;
        // Caddy supports live config reload without dropping connections.
        let _ = run_systemctl(["reload", CADDY_SERVICE]).await;
    } else {
        let _ = run_systemctl(["stop", CADDY_SERVICE]).await;
        let _ = run_systemctl(["disable", CADDY_SERVICE]).await;
    }

    Ok(())
}

/// Render a Caddyfile from the persisted configuration.
///
/// A global options block sets the ACME contact email and default log level.
/// Each enabled site becomes a virtual-host block that reverse-proxies to its
/// upstream; Caddy provisions a certificate for the host automatically.
fn render_caddyfile(cfg: &CaddyConfig) -> String {
    let mut out = String::new();

    out.push_str("# Managed by DayShield. Manual edits will be overwritten.\n");
    out.push_str("{\n");
    if !cfg.acme_email.trim().is_empty() {
        out.push_str(&format!("\temail {}\n", caddy_token(&cfg.acme_email)));
    }
    out.push_str("\tlog {\n");
    out.push_str(&format!("\t\tlevel {}\n", caddy_token(&cfg.log_level)));
    out.push_str("\t}\n");
    out.push_str("}\n\n");

    for site in cfg.sites.iter().filter(|s| s.enabled) {
        out.push_str(&format!("{} {{\n", caddy_token(&site.domain)));
        out.push_str(&format!("\treverse_proxy {}\n", caddy_token(&site.upstream)));
        out.push_str("}\n\n");
    }

    out
}

/// Quote a Caddyfile token when it contains whitespace, otherwise emit it bare.
///
/// Values are already validated as domains, URLs, or emails, so they cannot
/// contain Caddyfile control characters; quoting only guards against stray
/// whitespace.
fn caddy_token(value: &str) -> String {
    if value.chars().any(char::is_whitespace) {
        format!("\"{}\"", value.replace('"', "\\\""))
    } else {
        value.to_string()
    }
}

async fn run_systemctl<const N: usize>(args: [&str; N]) -> Result<String, CaddyApiError> {
    let output = tokio::process::Command::new("systemctl")
        .args(args)
        .output()
        .await
        .map_err(|err| CaddyApiError::ServiceError(format!("failed to run systemctl: {err}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let msg = if !stderr.is_empty() { stderr } else { stdout };
        return Err(CaddyApiError::ServiceError(if msg.is_empty() {
            format!("systemctl {:?} failed", args)
        } else {
            msg
        }));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

async fn read_caddy_status(cfg: &CaddyConfig) -> CaddyStatusResponse {
    let binary_present =
        Path::new("/usr/bin/caddy").exists() || Path::new("/usr/local/bin/caddy").exists();
    let site_count = cfg.sites.iter().filter(|s| s.enabled).count();
    let configured = site_count > 0;

    let mut active_state = "unknown".to_string();
    let mut sub_state = "unknown".to_string();
    let mut unit_enabled = false;
    let mut running = false;

    match tokio::process::Command::new("systemctl")
        .args([
            "show",
            CADDY_SERVICE,
            "--property=ActiveState,SubState,UnitFileState",
            "--no-page",
        ])
        .output()
        .await
    {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if let Some(value) = line.strip_prefix("ActiveState=") {
                    active_state = value.trim().to_string();
                } else if let Some(value) = line.strip_prefix("SubState=") {
                    sub_state = value.trim().to_string();
                } else if let Some(value) = line.strip_prefix("UnitFileState=") {
                    unit_enabled = value.trim() == "enabled";
                }
            }
            running = active_state == "active";
        }
        Ok(output) => {
            warn!(
                stderr = %String::from_utf8_lossy(&output.stderr),
                "caddy: systemctl show did not succeed"
            );
        }
        Err(err) => {
            warn!(error = %err, "caddy: failed to query service status");
        }
    }

    let version = match tokio::process::Command::new("caddy")
        .arg("version")
        .output()
        .await
    {
        Ok(output) if output.status.success() => {
            Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
        }
        _ => None,
    };

    let last_error = match tokio::process::Command::new("journalctl")
        .args([
            "-u",
            CADDY_SERVICE,
            "-n",
            "20",
            "--no-pager",
            "-p",
            "err..alert",
            "-o",
            "cat",
        ])
        .output()
        .await
    {
        Ok(output) if output.status.success() => {
            let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if text.is_empty() {
                None
            } else {
                Some(text)
            }
        }
        _ => None,
    };

    CaddyStatusResponse {
        configured,
        enabled: cfg.enabled,
        running,
        unit_enabled,
        binary_present,
        active_state,
        sub_state,
        version,
        site_count,
        last_error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site(domain: &str, upstream: &str) -> CaddySite {
        CaddySite {
            domain: domain.to_string(),
            upstream: upstream.to_string(),
            enabled: true,
        }
    }

    #[test]
    fn disabled_config_is_always_valid() {
        let cfg = CaddyConfig {
            enabled: false,
            ..CaddyConfig::default()
        };
        assert!(validate_caddy_config(&cfg).is_ok());
    }

    #[test]
    fn enabled_config_requires_email_and_site() {
        let cfg = CaddyConfig {
            enabled: true,
            ..CaddyConfig::default()
        };
        assert!(validate_caddy_config(&cfg).is_err());

        let cfg = CaddyConfig {
            enabled: true,
            acme_email: "admin@example.com".into(),
            sites: vec![site("app.example.com", "http://10.0.0.5:8080")],
            ..CaddyConfig::default()
        };
        assert!(validate_caddy_config(&cfg).is_ok());
    }

    #[test]
    fn duplicate_domains_are_rejected() {
        let cfg = CaddyConfig {
            enabled: true,
            acme_email: "admin@example.com".into(),
            sites: vec![
                site("app.example.com", "http://10.0.0.5:8080"),
                site("APP.example.com", "http://10.0.0.6:8080"),
            ],
            ..CaddyConfig::default()
        };
        assert!(validate_caddy_config(&cfg).is_err());
    }

    #[test]
    fn rendered_caddyfile_contains_email_and_reverse_proxy() {
        let cfg = CaddyConfig {
            enabled: true,
            acme_email: "admin@example.com".into(),
            log_level: "info".into(),
            sites: vec![
                site("app.example.com", "http://10.0.0.5:8080"),
                CaddySite {
                    domain: "off.example.com".into(),
                    upstream: "http://10.0.0.9:80".into(),
                    enabled: false,
                },
            ],
        };

        let rendered = render_caddyfile(&cfg);
        assert!(rendered.contains("email admin@example.com"));
        assert!(rendered.contains("level info"));
        assert!(rendered.contains("app.example.com {"));
        assert!(rendered.contains("reverse_proxy http://10.0.0.5:8080"));
        // Disabled sites must not be emitted.
        assert!(!rendered.contains("off.example.com"));
    }
}
