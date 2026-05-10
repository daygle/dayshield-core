//! Cloudflared API endpoints.
//!
//! Provides configuration, status, and service control for the Cloudflare
//! Tunnel agent (cloudflared).

use std::{fs, path::Path};

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::{
    config::models::{
        validate_cloudflared_config, CloudflaredConfig, CloudflaredIngressRule,
    },
    state::AppState,
};

const CLOUDFLARED_CONFIG_DIR: &str = "/etc/cloudflared";
const CLOUDFLARED_CONFIG_PATH: &str = "/etc/cloudflared/config.yml";
const CLOUDFLARED_ENV_PATH: &str = "/etc/default/cloudflared";
const CLOUDFLARED_SERVICE: &str = "cloudflared.service";

#[derive(Debug, thiserror::Error)]
pub enum CloudflaredApiError {
    #[error("validation error: {0}")]
    ValidationFailed(String),

    #[error("storage error: {0:#}")]
    StorageError(#[from] anyhow::Error),

    #[error("service error: {0}")]
    ServiceError(String),
}

impl IntoResponse for CloudflaredApiError {
    fn into_response(self) -> Response {
        let status = match &self {
            CloudflaredApiError::ValidationFailed(_) => StatusCode::BAD_REQUEST,
            CloudflaredApiError::StorageError(_) | CloudflaredApiError::ServiceError(_) => {
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
pub struct CloudflaredConfigResponse {
    pub enabled: bool,
    pub tunnel_name: String,
    pub tunnel_token: String,
    pub tunnel_token_configured: bool,
    pub metrics_address: String,
    pub log_level: String,
    pub ingress: Vec<CloudflaredIngressRule>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudflaredStatusResponse {
    pub configured: bool,
    pub enabled: bool,
    pub running: bool,
    pub unit_enabled: bool,
    pub binary_present: bool,
    pub active_state: String,
    pub sub_state: String,
    pub version: Option<String>,
    pub ingress_count: usize,
    pub last_error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateCloudflaredConfigRequest {
    pub enabled: bool,
    pub tunnel_name: String,
    pub tunnel_token: String,
    pub metrics_address: String,
    pub log_level: String,
    #[serde(default)]
    pub ingress: Vec<CloudflaredIngressRule>,
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
) -> Result<impl IntoResponse, CloudflaredApiError> {
    let cfg = state
        .config_store
        .load_cloudflared_config()
        .map_err(CloudflaredApiError::StorageError)?
        .unwrap_or_default();

    Ok(Json(redact_config(cfg)))
}

pub async fn update_config(
    State(state): State<std::sync::Arc<AppState>>,
    Json(req): Json<UpdateCloudflaredConfigRequest>,
) -> Result<impl IntoResponse, CloudflaredApiError> {
    let existing = state
        .config_store
        .load_cloudflared_config()
        .map_err(CloudflaredApiError::StorageError)?
        .unwrap_or_default();

    let tunnel_token = if req.tunnel_token.trim().is_empty() {
        existing.tunnel_token.clone()
    } else {
        req.tunnel_token.trim().to_string()
    };

    let cfg = CloudflaredConfig {
        enabled: req.enabled,
        tunnel_name: req.tunnel_name.trim().to_string(),
        tunnel_token,
        metrics_address: req.metrics_address.trim().to_string(),
        log_level: req.log_level.trim().to_lowercase(),
        ingress: req.ingress,
    };

    if let Err(msg) = validate_cloudflared_config(&cfg) {
        return Err(CloudflaredApiError::ValidationFailed(msg));
    }

    state
        .config_store
        .save_cloudflared_config(cfg.clone())
        .map_err(CloudflaredApiError::StorageError)?;

    info!(
        enabled = cfg.enabled,
        tunnel_name = %cfg.tunnel_name,
        ingress_count = cfg.ingress.len(),
        "cloudflared: configuration updated"
    );

    apply_cloudflared_config(&cfg).await?;

    Ok(Json(redact_config(cfg)))
}

pub async fn get_status(
    State(state): State<std::sync::Arc<AppState>>,
) -> Result<impl IntoResponse, CloudflaredApiError> {
    let cfg = state
        .config_store
        .load_cloudflared_config()
        .map_err(CloudflaredApiError::StorageError)?
        .unwrap_or_default();

    Ok(Json(read_cloudflared_status(&cfg).await))
}

pub async fn restart_service() -> Result<impl IntoResponse, CloudflaredApiError> {
    run_systemctl(["restart", CLOUDFLARED_SERVICE]).await?;
    Ok(Json(ActionResponse {
        message: "cloudflared service restarted".to_string(),
    }))
}

pub async fn get_logs(
    Query(query): Query<LogsQuery>,
) -> Result<impl IntoResponse, CloudflaredApiError> {
    let lines = query.lines.unwrap_or(100).clamp(1, 500);
    let output = tokio::process::Command::new("journalctl")
        .args([
            "-u",
            CLOUDFLARED_SERVICE,
            "-n",
            &lines.to_string(),
            "--no-pager",
            "-o",
            "cat",
        ])
        .output()
        .await
        .map_err(|err| CloudflaredApiError::ServiceError(format!("failed to read journal: {err}")))?;

    if !output.status.success() {
        return Err(CloudflaredApiError::ServiceError(
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

fn redact_config(cfg: CloudflaredConfig) -> CloudflaredConfigResponse {
    CloudflaredConfigResponse {
        enabled: cfg.enabled,
        tunnel_name: cfg.tunnel_name,
        tunnel_token: String::new(),
        tunnel_token_configured: !cfg.tunnel_token.trim().is_empty(),
        metrics_address: cfg.metrics_address,
        log_level: cfg.log_level,
        ingress: cfg.ingress,
    }
}

async fn apply_cloudflared_config(cfg: &CloudflaredConfig) -> Result<(), CloudflaredApiError> {
    fs::create_dir_all(CLOUDFLARED_CONFIG_DIR)
        .map_err(|err| CloudflaredApiError::ServiceError(format!("failed to create config directory: {err}")))?;

    fs::create_dir_all("/etc/default")
        .map_err(|err| CloudflaredApiError::ServiceError(format!("failed to create /etc/default: {err}")))?;

    fs::write(CLOUDFLARED_CONFIG_PATH, render_cloudflared_yaml(cfg)).map_err(|err| {
        CloudflaredApiError::ServiceError(format!("failed to write cloudflared config: {err}"))
    })?;

    fs::write(CLOUDFLARED_ENV_PATH, render_cloudflared_env(cfg)).map_err(|err| {
        CloudflaredApiError::ServiceError(format!("failed to write cloudflared env file: {err}"))
    })?;

    let _ = run_systemctl(["daemon-reload"]).await;

    if cfg.enabled {
        run_systemctl(["enable", "--now", CLOUDFLARED_SERVICE]).await?;
    } else {
        let _ = run_systemctl(["stop", CLOUDFLARED_SERVICE]).await;
        let _ = run_systemctl(["disable", CLOUDFLARED_SERVICE]).await;
    }

    Ok(())
}

fn render_cloudflared_yaml(cfg: &CloudflaredConfig) -> String {
    let mut out = String::new();
    out.push_str(&format!("metrics: {}\n", yaml_quote(&cfg.metrics_address)));
    out.push_str(&format!("loglevel: {}\n", yaml_quote(&cfg.log_level)));
    out.push_str("ingress:\n");

    for rule in &cfg.ingress {
        out.push_str(&format!("  - hostname: {}\n", yaml_quote(&rule.hostname)));
        out.push_str(&format!("    service: {}\n", yaml_quote(&rule.service)));
    }

    out.push_str("  - service: 'http_status:404'\n");
    out
}

fn render_cloudflared_env(cfg: &CloudflaredConfig) -> String {
    let mut out = String::new();
    out.push_str(&format!("TUNNEL_TOKEN={}\n", shell_quote(&cfg.tunnel_token)));
    out.push_str(&format!("TUNNEL_NAME={}\n", shell_quote(&cfg.tunnel_name)));
    out
}

fn yaml_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

async fn run_systemctl<const N: usize>(args: [&str; N]) -> Result<String, CloudflaredApiError> {
    let output = tokio::process::Command::new("systemctl")
        .args(args)
        .output()
        .await
        .map_err(|err| CloudflaredApiError::ServiceError(format!("failed to run systemctl: {err}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let msg = if !stderr.is_empty() { stderr } else { stdout };
        return Err(CloudflaredApiError::ServiceError(if msg.is_empty() {
            format!("systemctl {:?} failed", args)
        } else {
            msg
        }));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

async fn read_cloudflared_status(cfg: &CloudflaredConfig) -> CloudflaredStatusResponse {
    let binary_present = Path::new("/usr/bin/cloudflared").exists()
        || Path::new("/usr/local/bin/cloudflared").exists();
    let configured = !cfg.tunnel_token.trim().is_empty();

    let mut active_state = "unknown".to_string();
    let mut sub_state = "unknown".to_string();
    let mut unit_enabled = false;
    let mut running = false;

    match tokio::process::Command::new("systemctl")
        .args([
            "show",
            CLOUDFLARED_SERVICE,
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
                "cloudflared: systemctl show did not succeed"
            );
        }
        Err(err) => {
            warn!(error = %err, "cloudflared: failed to query service status");
        }
    }

    let version = match tokio::process::Command::new("cloudflared")
        .arg("--version")
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
            CLOUDFLARED_SERVICE,
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
            if text.is_empty() { None } else { Some(text) }
        }
        _ => None,
    };

    CloudflaredStatusResponse {
        configured,
        enabled: cfg.enabled,
        running,
        unit_enabled,
        binary_present,
        active_state,
        sub_state,
        version,
        ingress_count: cfg.ingress.len(),
        last_error,
    }
}
