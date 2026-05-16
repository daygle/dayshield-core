//! Dynamic DNS API endpoints.
//!
//! Provides persisted Dynamic DNS configuration and on-demand record updates.

use std::{net::Ipv4Addr, path::Path};

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use crate::{
    config::models::{
        validate_dynamic_dns_config, DynamicDnsConfig, DynamicDnsEntry, DynamicDnsProvider,
        Interface,
    },
    state::AppState,
};

const STATUS_PATH: &str = "/var/lib/dayshield/dynamic_dns/status.json";

#[derive(Debug, thiserror::Error)]
pub enum DynamicDnsApiError {
    #[error("validation error: {0}")]
    ValidationFailed(String),

    #[error("storage error: {0:#}")]
    StorageError(#[from] anyhow::Error),

    #[error("runtime error: {0}")]
    RuntimeError(String),
}

impl IntoResponse for DynamicDnsApiError {
    fn into_response(self) -> Response {
        let status = match &self {
            DynamicDnsApiError::ValidationFailed(_) => StatusCode::BAD_REQUEST,
            DynamicDnsApiError::StorageError(_) | DynamicDnsApiError::RuntimeError(_) => {
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
pub struct DynamicDnsEntryResponse {
    pub id: Uuid,
    pub enabled: bool,
    pub provider: DynamicDnsProvider,
    pub interface: String,
    pub hostname: String,
    pub username: Option<String>,
    pub password: String,
    pub password_configured: bool,
    pub update_url: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DynamicDnsConfigResponse {
    pub enabled: bool,
    pub check_interval_seconds: u32,
    pub entries: Vec<DynamicDnsEntryResponse>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DynamicDnsEntryRequest {
    pub id: Option<Uuid>,
    pub enabled: bool,
    pub provider: DynamicDnsProvider,
    pub interface: String,
    pub hostname: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub update_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateDynamicDnsConfigRequest {
    pub enabled: bool,
    pub check_interval_seconds: u32,
    #[serde(default)]
    pub entries: Vec<DynamicDnsEntryRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DynamicDnsRuntimeEntryStatus {
    pub id: Uuid,
    pub hostname: String,
    pub provider: DynamicDnsProvider,
    pub interface: String,
    pub ip: Option<String>,
    pub success: bool,
    pub message: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct DynamicDnsPersistedStatus {
    pub last_run_at: Option<String>,
    pub entries: Vec<DynamicDnsRuntimeEntryStatus>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DynamicDnsStatusResponse {
    pub enabled: bool,
    pub last_run_at: Option<String>,
    pub entries: Vec<DynamicDnsRuntimeEntryStatus>,
}

pub async fn get_config(
    State(state): State<std::sync::Arc<AppState>>,
) -> Result<impl IntoResponse, DynamicDnsApiError> {
    let cfg = state
        .config_store
        .load_dynamic_dns_config()
        .map_err(DynamicDnsApiError::StorageError)?
        .unwrap_or_default();

    Ok(Json(to_response(cfg)))
}

pub async fn update_config(
    State(state): State<std::sync::Arc<AppState>>,
    Json(req): Json<UpdateDynamicDnsConfigRequest>,
) -> Result<impl IntoResponse, DynamicDnsApiError> {
    let existing = state
        .config_store
        .load_dynamic_dns_config()
        .map_err(DynamicDnsApiError::StorageError)?
        .unwrap_or_default();

    let entries = req
        .entries
        .into_iter()
        .map(|entry| {
            let id = entry.id.unwrap_or_else(Uuid::new_v4);
            let existing_password = existing
                .entries
                .iter()
                .find(|e| e.id == id)
                .and_then(|e| e.password.clone());

            let password = entry
                .password
                .as_ref()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .or(existing_password);

            DynamicDnsEntry {
                id,
                enabled: entry.enabled,
                provider: entry.provider,
                interface: entry.interface.trim().to_string(),
                hostname: entry.hostname.trim().to_string(),
                username: entry
                    .username
                    .as_ref()
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty()),
                password,
                update_url: entry
                    .update_url
                    .as_ref()
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty()),
            }
        })
        .collect::<Vec<_>>();

    let cfg = DynamicDnsConfig {
        enabled: req.enabled,
        check_interval_seconds: req.check_interval_seconds,
        entries,
    };

    if let Err(msg) = validate_dynamic_dns_config(&cfg) {
        return Err(DynamicDnsApiError::ValidationFailed(msg));
    }

    state
        .config_store
        .save_dynamic_dns_config(cfg.clone())
        .map_err(DynamicDnsApiError::StorageError)?;

    info!(
        enabled = cfg.enabled,
        entry_count = cfg.entries.len(),
        "dynamic-dns: configuration updated"
    );

    Ok(Json(to_response(cfg)))
}

pub async fn get_status(
    State(state): State<std::sync::Arc<AppState>>,
) -> Result<impl IntoResponse, DynamicDnsApiError> {
    let cfg = state
        .config_store
        .load_dynamic_dns_config()
        .map_err(DynamicDnsApiError::StorageError)?
        .unwrap_or_default();

    let persisted = load_status_file().unwrap_or_default();

    Ok(Json(DynamicDnsStatusResponse {
        enabled: cfg.enabled,
        last_run_at: persisted.last_run_at,
        entries: persisted.entries,
    }))
}

pub async fn trigger_update(
    State(state): State<std::sync::Arc<AppState>>,
) -> Result<impl IntoResponse, DynamicDnsApiError> {
    let result = run_update_now(&state).await?;
    Ok(Json(result))
}

pub(crate) async fn run_update_now(
    state: &std::sync::Arc<AppState>,
) -> Result<DynamicDnsStatusResponse, DynamicDnsApiError> {
    let cfg = state
        .config_store
        .load_dynamic_dns_config()
        .map_err(DynamicDnsApiError::StorageError)?
        .unwrap_or_default();

    if !cfg.enabled {
        return Err(DynamicDnsApiError::ValidationFailed(
            "dynamic DNS is disabled".into(),
        ));
    }

    let statuses = run_update_cycle(&state, &cfg).await?;
    let payload = DynamicDnsPersistedStatus {
        last_run_at: Some(Utc::now().to_rfc3339()),
        entries: statuses.clone(),
    };

    save_status_file(&payload)?;

    Ok(DynamicDnsStatusResponse {
        enabled: cfg.enabled,
        last_run_at: payload.last_run_at,
        entries: statuses,
    })
}

fn to_response(cfg: DynamicDnsConfig) -> DynamicDnsConfigResponse {
    DynamicDnsConfigResponse {
        enabled: cfg.enabled,
        check_interval_seconds: cfg.check_interval_seconds,
        entries: cfg.entries.into_iter().map(redact_entry).collect(),
    }
}

fn redact_entry(entry: DynamicDnsEntry) -> DynamicDnsEntryResponse {
    DynamicDnsEntryResponse {
        id: entry.id,
        enabled: entry.enabled,
        provider: entry.provider,
        interface: entry.interface,
        hostname: entry.hostname,
        username: entry.username,
        password: String::new(),
        password_configured: entry
            .password
            .as_ref()
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false),
        update_url: entry.update_url,
    }
}

async fn run_update_cycle(
    state: &std::sync::Arc<AppState>,
    cfg: &DynamicDnsConfig,
) -> Result<Vec<DynamicDnsRuntimeEntryStatus>, DynamicDnsApiError> {
    let interfaces = state
        .config_store
        .load_interfaces()
        .map_err(DynamicDnsApiError::StorageError)?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(12))
        .build()
        .map_err(|err| DynamicDnsApiError::RuntimeError(format!("failed to create HTTP client: {err}")))?;

    let mut statuses = Vec::new();

    for entry in cfg.entries.iter().filter(|entry| entry.enabled) {
        let now = Utc::now().to_rfc3339();
        let ip = match interface_ipv4(&interfaces, &entry.interface) {
            Some(addr) => addr,
            None => {
                statuses.push(DynamicDnsRuntimeEntryStatus {
                    id: entry.id,
                    hostname: entry.hostname.clone(),
                    provider: entry.provider.clone(),
                    interface: entry.interface.clone(),
                    ip: None,
                    success: false,
                    message: "interface does not have an IPv4 address".into(),
                    updated_at: now,
                });
                continue;
            }
        };

        let result = apply_entry_update(&client, entry, &ip).await;
        match result {
            Ok(message) => statuses.push(DynamicDnsRuntimeEntryStatus {
                id: entry.id,
                hostname: entry.hostname.clone(),
                provider: entry.provider.clone(),
                interface: entry.interface.clone(),
                ip: Some(ip),
                success: true,
                message,
                updated_at: now,
            }),
            Err(message) => {
                warn!(entry_id = %entry.id, provider = ?entry.provider, hostname = %entry.hostname, "dynamic-dns update failed: {message}");
                statuses.push(DynamicDnsRuntimeEntryStatus {
                    id: entry.id,
                    hostname: entry.hostname.clone(),
                    provider: entry.provider.clone(),
                    interface: entry.interface.clone(),
                    ip: Some(ip),
                    success: false,
                    message,
                    updated_at: now,
                });
            }
        }
    }

    Ok(statuses)
}

fn interface_ipv4(interfaces: &[Interface], name: &str) -> Option<String> {
    interfaces
        .iter()
        .find(|iface| iface.name == name)
        .and_then(|iface| {
            iface.addresses.iter().find_map(|cidr| {
                let ip = cidr.split('/').next()?.trim();
                ip.parse::<Ipv4Addr>().ok().map(|addr| addr.to_string())
            })
        })
}

async fn apply_entry_update(
    client: &reqwest::Client,
    entry: &DynamicDnsEntry,
    ip: &str,
) -> Result<String, String> {
    let username = entry.username.as_deref().unwrap_or("").trim();
    let password = entry.password.as_deref().unwrap_or("").trim();

    let mut request = match entry.provider {
        DynamicDnsProvider::DuckDns => {
            let url = format!(
                "https://www.duckdns.org/update?domains={}&token={}&ip={}",
                entry.hostname.trim(),
                password,
                ip
            );
            client.get(url)
        }
        DynamicDnsProvider::NoIp => {
            let url = format!(
                "https://dynupdate.no-ip.com/nic/update?hostname={}&myip={}",
                entry.hostname.trim(),
                ip
            );
            client.get(url).basic_auth(username.to_string(), Some(password.to_string()))
        }
        DynamicDnsProvider::Dynu => {
            let url = format!(
                "https://api.dynu.com/nic/update?hostname={}&myip={}",
                entry.hostname.trim(),
                ip
            );
            client.get(url).basic_auth(username.to_string(), Some(password.to_string()))
        }
        DynamicDnsProvider::FreeDns => {
            let url = format!(
                "https://freedns.afraid.org/dynamic/update.php?{}&address={}",
                password,
                ip
            );
            client.get(url)
        }
        DynamicDnsProvider::Custom => {
            let template = entry
                .update_url
                .as_deref()
                .ok_or_else(|| "custom provider requires update_url".to_string())?;
            let url = template
                .replace("{hostname}", entry.hostname.trim())
                .replace("{username}", username)
                .replace("{password}", password)
                .replace("{ip}", ip);
            client.get(url)
        }
    };

    request = request.header("User-Agent", "dayshield-dynamic-dns/1.0");

    let response = request
        .send()
        .await
        .map_err(|err| format!("request failed: {err}"))?;

    let status = response.status();
    let body = response
        .text()
        .await
        .unwrap_or_else(|_| String::new())
        .trim()
        .to_string();

    let lower = body.to_lowercase();
    let provider_error = lower.contains("badauth")
        || lower.contains("nohost")
        || lower.contains("dnserr")
        || lower.contains("abuse")
        || lower.contains("!yours")
        || lower.contains("911")
        || lower.contains("error");

    if !status.is_success() || provider_error {
        let message = if body.is_empty() {
            format!("provider returned HTTP {}", status.as_u16())
        } else {
            truncate_message(body)
        };
        return Err(message);
    }

    if body.is_empty() {
        Ok("update accepted".into())
    } else {
        Ok(truncate_message(body))
    }
}

fn truncate_message(value: String) -> String {
    const MAX: usize = 240;
    if value.len() <= MAX {
        value
    } else {
        format!("{}...", &value[..MAX])
    }
}

fn load_status_file() -> Option<DynamicDnsPersistedStatus> {
    let path = Path::new(STATUS_PATH);
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str::<DynamicDnsPersistedStatus>(&raw).ok()
}

fn save_status_file(status: &DynamicDnsPersistedStatus) -> Result<(), DynamicDnsApiError> {
    let path = Path::new(STATUS_PATH);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| {
            DynamicDnsApiError::RuntimeError(format!("failed to create status directory: {err}"))
        })?;
    }

    let raw = serde_json::to_string_pretty(status).map_err(|err| {
        DynamicDnsApiError::RuntimeError(format!("failed to serialize status: {err}"))
    })?;

    std::fs::write(path, raw)
        .map_err(|err| DynamicDnsApiError::RuntimeError(format!("failed to write status file: {err}")))
}
