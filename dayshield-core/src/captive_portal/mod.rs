//! Captive portal runtime, public portal handlers, and admin API support.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use axum::{
    extract::{ConnectInfo, Path as AxumPath, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{
    config::{
        models::{
            is_valid_ip, is_valid_mac, validate_captive_portal_config_with_ipv6,
            CaptivePortalAuthMode, CaptivePortalConfig, CaptivePortalSession,
        },
        ConfigStore,
    },
    engine::nftables::{apply_rules_with_captive, NftError},
    state::{AppState, SVC_CAPTIVE_PORTAL},
};

const DEFAULT_SESSION_PATH: &str = "/var/lib/dayshield/captive_portal/sessions.json";
const DEFAULT_CONFIG_DIR: &str = "/etc/dayshield/config";
const REAPER_INTERVAL_SECONDS: u64 = 60;
const LISTENER_CONFIG_POLL_SECONDS: u64 = 30;

#[derive(Debug, thiserror::Error)]
pub enum CaptivePortalError {
    #[error("validation error: {0}")]
    ValidationFailed(String),

    #[error("not authorised: {0}")]
    Forbidden(String),

    #[error("session not found: {0}")]
    NotFound(Uuid),

    #[error("storage error: {0:#}")]
    StorageError(#[from] anyhow::Error),

    #[error("engine error: {0}")]
    EngineError(String),
}

impl IntoResponse for CaptivePortalError {
    fn into_response(self) -> Response {
        let status = match &self {
            CaptivePortalError::ValidationFailed(_) => StatusCode::UNPROCESSABLE_ENTITY,
            CaptivePortalError::Forbidden(_) => StatusCode::FORBIDDEN,
            CaptivePortalError::NotFound(_) => StatusCode::NOT_FOUND,
            CaptivePortalError::StorageError(_) | CaptivePortalError::EngineError(_) => {
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct CaptivePortalSessionStore {
    sessions: Vec<CaptivePortalSession>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicPortalConfigResponse {
    pub enabled: bool,
    pub auth_mode: CaptivePortalAuthMode,
    pub portal_title: String,
    pub portal_message: String,
    pub terms_required: bool,
    pub success_redirect_url: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalStatusResponse {
    pub enabled: bool,
    pub authorized: bool,
    pub client_ip: String,
    pub session: Option<CaptivePortalSession>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizePortalRequest {
    #[serde(default)]
    pub voucher_code: Option<String>,
    #[serde(default)]
    pub accept_terms: bool,
    #[serde(default)]
    pub client_ip: Option<String>,
    #[serde(default)]
    pub client_mac: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizePortalResponse {
    pub authorized: bool,
    pub session: CaptivePortalSession,
    pub redirect_url: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptivePortalStatusResponse {
    pub enabled: bool,
    pub interfaces: Vec<String>,
    pub listen_address: String,
    pub listen_port: u16,
    pub redirect_http: bool,
    pub auth_mode: CaptivePortalAuthMode,
    pub sessions_total: usize,
    pub sessions_active: usize,
    pub sessions_expired: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptivePortalSessionResponse {
    #[serde(flatten)]
    pub session: CaptivePortalSession,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptivePortalSessionsResponse {
    pub sessions: Vec<CaptivePortalSessionResponse>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSessionRequest {
    pub client_ip: String,
    #[serde(default)]
    pub client_mac: Option<String>,
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
}

pub fn portal_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(portal_page))
        .route("/portal", get(portal_page))
        .route("/portal/config", get(public_config))
        .route("/portal/status", get(public_status))
        .route("/portal/authorize", post(public_authorize))
        .route("/portal/logout", post(public_logout))
        .fallback(get(portal_page))
        .with_state(state)
}

pub fn start_portal_server(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut active: Option<(SocketAddr, tokio::task::JoinHandle<()>)> = None;

        loop {
            let cfg = state
                .config_store
                .load_captive_portal_config()
                .ok()
                .flatten()
                .unwrap_or_default();
            let addr = parse_listen_addr(&cfg).unwrap_or_else(|err| {
                warn!(error = %err, "captive-portal: invalid listen address; using 0.0.0.0:8080");
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080)
            });

            if active
                .as_ref()
                .map(|(active_addr, _)| *active_addr == addr)
                .unwrap_or(false)
            {
                tokio::time::sleep(Duration::from_secs(LISTENER_CONFIG_POLL_SECONDS)).await;
                continue;
            }

            if let Some((old_addr, handle)) = active.take() {
                info!(%old_addr, "captive-portal: restarting public portal listener");
                handle.abort();
                state.set_unhealthy(SVC_CAPTIVE_PORTAL).await;
            }

            match TcpListener::bind(addr).await {
                Ok(listener) => {
                    info!(%addr, "captive-portal: public portal listener started");
                    state.set_healthy(SVC_CAPTIVE_PORTAL).await;
                    let server_state = Arc::clone(&state);
                    let handle = tokio::spawn(async move {
                        let app = portal_router(Arc::clone(&server_state));
                        if let Err(err) = axum::serve(
                            listener,
                            app.into_make_service_with_connect_info::<SocketAddr>(),
                        )
                        .await
                        {
                            error!(error = %err, "captive-portal: public portal listener stopped");
                        }
                        server_state.set_unhealthy(SVC_CAPTIVE_PORTAL).await;
                    });
                    active = Some((addr, handle));
                }
                Err(err) => {
                    warn!(%addr, error = %err, "captive-portal: failed to bind public portal listener");
                    state.set_unhealthy(SVC_CAPTIVE_PORTAL).await;
                }
            }

            tokio::time::sleep(Duration::from_secs(LISTENER_CONFIG_POLL_SECONDS)).await;
        }
    });
}

pub fn start_session_reaper(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(REAPER_INTERVAL_SECONDS));
        loop {
            interval.tick().await;
            let cfg = match state.config_store.load_captive_portal_config() {
                Ok(Some(cfg)) if cfg.enabled => cfg,
                Ok(_) => continue,
                Err(err) => {
                    warn!(error = %err, "captive-portal: failed to load config for session reaper");
                    continue;
                }
            };

            let mut sessions = match load_sessions(&state.config_store) {
                Ok(sessions) => sessions,
                Err(err) => {
                    warn!(error = %err, "captive-portal: failed to load sessions for reaper");
                    continue;
                }
            };

            if prune_expired_sessions(&cfg, &mut sessions) {
                if let Err(err) = save_sessions(&state.config_store, &sessions) {
                    warn!(error = %err, "captive-portal: failed to save pruned sessions");
                    continue;
                }
                if let Err(err) = apply_current_ruleset(&state.config_store).await {
                    warn!(error = %err, "captive-portal: failed to reapply rules after pruning");
                }
            }
        }
    });
}

pub async fn get_admin_config(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, CaptivePortalError> {
    let cfg = state
        .config_store
        .load_captive_portal_config()
        .map_err(CaptivePortalError::StorageError)?
        .unwrap_or_default();

    Ok(Json(cfg))
}

pub async fn update_admin_config(
    State(state): State<Arc<AppState>>,
    Json(cfg): Json<CaptivePortalConfig>,
) -> Result<impl IntoResponse, CaptivePortalError> {
    let cfg = normalize_config(cfg);
    let ipv6_enabled = state
        .config_store
        .load_system_settings()
        .map_err(CaptivePortalError::StorageError)?
        .ipv6_enabled;

    if let Err(msg) = validate_captive_portal_config_with_ipv6(&cfg, ipv6_enabled) {
        return Err(CaptivePortalError::ValidationFailed(msg));
    }

    state
        .config_store
        .save_captive_portal_config(cfg.clone())
        .map_err(CaptivePortalError::StorageError)?;

    let mut sessions = load_sessions(&state.config_store)?;
    if prune_expired_sessions(&cfg, &mut sessions) {
        save_sessions(&state.config_store, &sessions)?;
    }
    apply_current_ruleset(&state.config_store).await?;

    info!(
        enabled = cfg.enabled,
        interfaces = cfg.interfaces.len(),
        auth_mode = ?cfg.auth_mode,
        "captive-portal: configuration updated"
    );

    Ok(Json(cfg))
}

pub async fn get_admin_status(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, CaptivePortalError> {
    let cfg = state
        .config_store
        .load_captive_portal_config()
        .map_err(CaptivePortalError::StorageError)?
        .unwrap_or_default();
    let sessions = load_sessions(&state.config_store)?;
    let active = active_sessions(&cfg, &sessions).len();

    Ok(Json(CaptivePortalStatusResponse {
        enabled: cfg.enabled,
        interfaces: cfg.interfaces,
        listen_address: cfg.listen_address,
        listen_port: cfg.listen_port,
        redirect_http: cfg.redirect_http,
        auth_mode: cfg.auth_mode,
        sessions_total: sessions.len(),
        sessions_active: active,
        sessions_expired: sessions.len().saturating_sub(active),
    }))
}

pub async fn list_admin_sessions(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, CaptivePortalError> {
    let cfg = state
        .config_store
        .load_captive_portal_config()
        .map_err(CaptivePortalError::StorageError)?
        .unwrap_or_default();
    let sessions = load_sessions(&state.config_store)?;
    let now = Utc::now();
    let sessions = sessions
        .into_iter()
        .map(|session| CaptivePortalSessionResponse {
            active: session_is_active(&cfg, &session, now),
            session,
        })
        .collect();

    Ok(Json(CaptivePortalSessionsResponse { sessions }))
}

pub async fn create_admin_session(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateSessionRequest>,
) -> Result<impl IntoResponse, CaptivePortalError> {
    if !is_valid_ip(&req.client_ip) {
        return Err(CaptivePortalError::ValidationFailed(
            "clientIp must be a valid IP address".into(),
        ));
    }
    if let Some(mac) = &req.client_mac {
        if !is_valid_mac(mac) {
            return Err(CaptivePortalError::ValidationFailed(
                "clientMac must be a valid MAC address".into(),
            ));
        }
    }

    let cfg = state
        .config_store
        .load_captive_portal_config()
        .map_err(CaptivePortalError::StorageError)?
        .unwrap_or_default();
    let ttl = req.ttl_seconds.unwrap_or(cfg.session_ttl_seconds);
    if ttl < 60 {
        return Err(CaptivePortalError::ValidationFailed(
            "ttlSeconds must be at least 60".into(),
        ));
    }

    let now = Utc::now();
    let session = CaptivePortalSession {
        id: Uuid::new_v4(),
        client_ip: req.client_ip.trim().to_string(),
        client_mac: req.client_mac.map(|mac| mac.trim().to_lowercase()),
        authorized_at: now,
        last_seen_at: now,
        expires_at: now + chrono_seconds(ttl),
        voucher_id: None,
        user_agent: None,
    };

    let mut sessions = load_sessions(&state.config_store)?;
    sessions.retain(|existing| existing.client_ip != session.client_ip);
    sessions.push(session.clone());
    save_sessions(&state.config_store, &sessions)?;
    apply_current_ruleset(&state.config_store).await?;

    Ok((StatusCode::CREATED, Json(session)))
}

pub async fn revoke_admin_session(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<Uuid>,
) -> Result<impl IntoResponse, CaptivePortalError> {
    let mut sessions = load_sessions(&state.config_store)?;
    let before = sessions.len();
    sessions.retain(|session| session.id != id);

    if sessions.len() == before {
        return Err(CaptivePortalError::NotFound(id));
    }

    save_sessions(&state.config_store, &sessions)?;
    apply_current_ruleset(&state.config_store).await?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn portal_page(State(state): State<Arc<AppState>>) -> Html<String> {
    let cfg = state
        .config_store
        .load_captive_portal_config()
        .ok()
        .flatten()
        .unwrap_or_default();
    Html(render_portal_html(&cfg))
}

pub async fn public_config(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, CaptivePortalError> {
    let cfg = state
        .config_store
        .load_captive_portal_config()
        .map_err(CaptivePortalError::StorageError)?
        .unwrap_or_default();

    Ok(Json(public_config_response(cfg)))
}

pub async fn public_status(
    State(state): State<Arc<AppState>>,
    connect_info: ConnectInfo<SocketAddr>,
) -> Result<impl IntoResponse, CaptivePortalError> {
    let cfg = state
        .config_store
        .load_captive_portal_config()
        .map_err(CaptivePortalError::StorageError)?
        .unwrap_or_default();
    let client_ip = client_ip(connect_info, None)?;
    let mut sessions = load_sessions(&state.config_store)?;
    let now = Utc::now();
    let session = sessions
        .iter_mut()
        .find(|session| session.client_ip == client_ip && session_is_active(&cfg, session, now))
        .map(|session| {
            session.last_seen_at = now;
            session.clone()
        });

    if session.is_some() {
        save_sessions(&state.config_store, &sessions)?;
    }

    Ok(Json(PortalStatusResponse {
        enabled: cfg.enabled,
        authorized: session.is_some(),
        client_ip,
        expires_at: session.as_ref().map(|session| session.expires_at),
        session,
    }))
}

pub async fn public_authorize(
    State(state): State<Arc<AppState>>,
    connect_info: ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<AuthorizePortalRequest>,
) -> Result<impl IntoResponse, CaptivePortalError> {
    let mut cfg = state
        .config_store
        .load_captive_portal_config()
        .map_err(CaptivePortalError::StorageError)?
        .unwrap_or_default();

    if !cfg.enabled {
        return Err(CaptivePortalError::Forbidden(
            "captive portal is disabled".into(),
        ));
    }

    if cfg.terms_required && !req.accept_terms {
        return Err(CaptivePortalError::ValidationFailed(
            "terms must be accepted".into(),
        ));
    }

    let client_ip = client_ip(connect_info, req.client_ip.as_deref())?;
    if let Some(mac) = &req.client_mac {
        if !is_valid_mac(mac) {
            return Err(CaptivePortalError::ValidationFailed(
                "clientMac must be a valid MAC address".into(),
            ));
        }
    }

    let now = Utc::now();
    let voucher_id = redeem_voucher(&mut cfg, req.voucher_code.as_deref(), now)?;
    if voucher_id.is_some() {
        state
            .config_store
            .save_captive_portal_config(cfg.clone())
            .map_err(CaptivePortalError::StorageError)?;
    }

    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(truncate_user_agent);

    let session = CaptivePortalSession {
        id: Uuid::new_v4(),
        client_ip,
        client_mac: req.client_mac.map(|mac| mac.trim().to_lowercase()),
        authorized_at: now,
        last_seen_at: now,
        expires_at: now + chrono_seconds(cfg.session_ttl_seconds),
        voucher_id,
        user_agent,
    };

    let mut sessions = load_sessions(&state.config_store)?;
    sessions.retain(|existing| existing.client_ip != session.client_ip);
    sessions.push(session.clone());
    save_sessions(&state.config_store, &sessions)?;
    apply_current_ruleset(&state.config_store).await?;

    info!(client_ip = %session.client_ip, "captive-portal: client authorised");

    Ok(Json(AuthorizePortalResponse {
        authorized: true,
        session,
        redirect_url: cfg.success_redirect_url,
    }))
}

pub async fn public_logout(
    State(state): State<Arc<AppState>>,
    connect_info: ConnectInfo<SocketAddr>,
) -> Result<impl IntoResponse, CaptivePortalError> {
    let client_ip = client_ip(connect_info, None)?;
    let mut sessions = load_sessions(&state.config_store)?;
    sessions.retain(|session| session.client_ip != client_ip);
    save_sessions(&state.config_store, &sessions)?;
    apply_current_ruleset(&state.config_store).await?;

    Ok(StatusCode::NO_CONTENT)
}

pub fn load_sessions(config_store: &ConfigStore) -> Result<Vec<CaptivePortalSession>> {
    let path = sessions_path(config_store);
    if !path.exists() {
        return Ok(vec![]);
    }

    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read captive portal sessions {}", path.display()))?;
    let store: CaptivePortalSessionStore = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse captive portal sessions {}", path.display()))?;
    Ok(store.sessions)
}

fn save_sessions(config_store: &ConfigStore, sessions: &[CaptivePortalSession]) -> Result<()> {
    let path = sessions_path(config_store);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let raw = serde_json::to_string_pretty(&CaptivePortalSessionStore {
        sessions: sessions.to_vec(),
    })
    .context("failed to serialize captive portal sessions")?;

    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, raw)
        .with_context(|| format!("failed to write {}", tmp.display()))?;
    std::fs::rename(&tmp, &path).with_context(|| {
        format!(
            "failed to rename {} to {}",
            tmp.display(),
            path.display()
        )
    })?;

    Ok(())
}

pub fn active_sessions(
    config: &CaptivePortalConfig,
    sessions: &[CaptivePortalSession],
) -> Vec<CaptivePortalSession> {
    let now = Utc::now();
    sessions
        .iter()
        .filter(|session| session_is_active(config, session, now))
        .cloned()
        .collect()
}

pub fn prune_expired_sessions(
    config: &CaptivePortalConfig,
    sessions: &mut Vec<CaptivePortalSession>,
) -> bool {
    let before = sessions.len();
    let now = Utc::now();
    sessions.retain(|session| session_is_active(config, session, now));
    sessions.len() != before
}

pub async fn apply_current_ruleset(
    config_store: &ConfigStore,
) -> Result<(), CaptivePortalError> {
    apply_current_ruleset_nft(config_store)
        .await
        .map_err(nft_error_to_portal_error)
}

pub async fn apply_current_ruleset_nft(config_store: &ConfigStore) -> Result<(), NftError> {
    let cfg = config_store
        .load()
        .map_err(NftError::StorageError)?;
    let mut sessions = load_sessions(config_store).map_err(NftError::StorageError)?;
    let active_sessions = if let Some(portal) = cfg.captive_portal.as_ref() {
        if prune_expired_sessions(portal, &mut sessions) {
            save_sessions(config_store, &sessions).map_err(NftError::StorageError)?;
        }
        active_sessions(portal, &sessions)
    } else {
        vec![]
    };

    apply_rules_with_captive(
        &cfg.firewall_rules,
        cfg.nat.as_ref(),
        &cfg.firewall_aliases,
        cfg.firewall_settings.as_ref(),
        cfg.system_settings
            .as_ref()
            .map(|settings| settings.ipv6_enabled)
            .unwrap_or(false),
        cfg.captive_portal.as_ref(),
        &active_sessions,
    )
    .await
}

fn nft_error_to_portal_error(err: NftError) -> CaptivePortalError {
    CaptivePortalError::EngineError(err.to_string())
}

fn sessions_path(config_store: &ConfigStore) -> PathBuf {
    let config_path = config_store.config_path();
    if config_path.starts_with(Path::new(DEFAULT_CONFIG_DIR)) {
        PathBuf::from(DEFAULT_SESSION_PATH)
    } else {
        config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("captive_portal_sessions.json")
    }
}

fn parse_listen_addr(config: &CaptivePortalConfig) -> Result<SocketAddr> {
    let ip = config
        .listen_address
        .parse::<IpAddr>()
        .with_context(|| format!("invalid listen address {:?}", config.listen_address))?;
    Ok(SocketAddr::new(ip, config.listen_port))
}

fn client_ip(
    connect_info: ConnectInfo<SocketAddr>,
    fallback: Option<&str>,
) -> Result<String, CaptivePortalError> {
    let ConnectInfo(addr) = connect_info;
    if !addr.ip().is_unspecified() {
        return Ok(addr.ip().to_string());
    }

    let Some(ip) = fallback.map(str::trim).filter(|value| !value.is_empty()) else {
        return Err(CaptivePortalError::ValidationFailed(
            "could not determine client IP address".into(),
        ));
    };

    if !is_valid_ip(ip) {
        return Err(CaptivePortalError::ValidationFailed(
            "clientIp must be a valid IP address".into(),
        ));
    }

    Ok(ip.to_string())
}

fn session_is_active(
    config: &CaptivePortalConfig,
    session: &CaptivePortalSession,
    now: DateTime<Utc>,
) -> bool {
    if session.expires_at <= now {
        return false;
    }

    if config.idle_timeout_seconds == 0 {
        return true;
    }

    session.last_seen_at + chrono_seconds(config.idle_timeout_seconds) > now
}

fn redeem_voucher(
    config: &mut CaptivePortalConfig,
    code: Option<&str>,
    now: DateTime<Utc>,
) -> Result<Option<Uuid>, CaptivePortalError> {
    if !matches!(config.auth_mode, CaptivePortalAuthMode::Voucher) {
        return Ok(None);
    }

    let code = code
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CaptivePortalError::ValidationFailed("voucherCode is required".into())
        })?;

    let voucher = config
        .vouchers
        .iter_mut()
        .find(|voucher| voucher.code.trim() == code)
        .ok_or_else(|| CaptivePortalError::Forbidden("invalid voucher code".into()))?;

    if !voucher.enabled {
        return Err(CaptivePortalError::Forbidden(
            "voucher code is disabled".into(),
        ));
    }
    if voucher
        .expires_at
        .map(|expires_at| expires_at <= now)
        .unwrap_or(false)
    {
        return Err(CaptivePortalError::Forbidden(
            "voucher code has expired".into(),
        ));
    }
    if voucher
        .max_uses
        .map(|max_uses| voucher.uses >= max_uses)
        .unwrap_or(false)
    {
        return Err(CaptivePortalError::Forbidden(
            "voucher code has no uses remaining".into(),
        ));
    }

    voucher.uses = voucher.uses.saturating_add(1);
    Ok(Some(voucher.id))
}

fn normalize_config(mut config: CaptivePortalConfig) -> CaptivePortalConfig {
    config.interfaces = config
        .interfaces
        .into_iter()
        .map(|iface| iface.trim().to_string())
        .filter(|iface| !iface.is_empty())
        .collect();
    config.listen_address = config.listen_address.trim().to_string();
    config.portal_title = config.portal_title.trim().to_string();
    config.portal_message = config.portal_message.trim().to_string();
    config.success_redirect_url = config
        .success_redirect_url
        .map(|url| url.trim().to_string())
        .filter(|url| !url.is_empty());
    config.walled_garden_ips = config
        .walled_garden_ips
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect();
    config.bypass_macs = config
        .bypass_macs
        .into_iter()
        .map(|mac| mac.trim().to_lowercase())
        .filter(|mac| !mac.is_empty())
        .collect();
    config.vouchers = config
        .vouchers
        .into_iter()
        .map(|mut voucher| {
            voucher.code = voucher.code.trim().to_string();
            voucher.description = voucher
                .description
                .map(|description| description.trim().to_string())
                .filter(|description| !description.is_empty());
            voucher
        })
        .collect();
    config
}

fn public_config_response(config: CaptivePortalConfig) -> PublicPortalConfigResponse {
    PublicPortalConfigResponse {
        enabled: config.enabled,
        auth_mode: config.auth_mode,
        portal_title: config.portal_title,
        portal_message: config.portal_message,
        terms_required: config.terms_required,
        success_redirect_url: config.success_redirect_url,
    }
}

fn chrono_seconds(seconds: u64) -> ChronoDuration {
    ChronoDuration::seconds(seconds.min(i64::MAX as u64) as i64)
}

fn truncate_user_agent(value: &str) -> String {
    const MAX_LEN: usize = 240;
    value.chars().take(MAX_LEN).collect()
}

fn render_portal_html(config: &CaptivePortalConfig) -> String {
    let title = html_escape(&config.portal_title);
    let message = html_escape(&config.portal_message);
    let voucher_style = if matches!(config.auth_mode, CaptivePortalAuthMode::Voucher) {
        "block"
    } else {
        "none"
    };
    let terms_style = if config.terms_required { "block" } else { "none" };
    let terms_checked = if config.terms_required { "" } else { "checked" };
    let form_style = if config.enabled { "block" } else { "none" };
    let submit_disabled = if config.enabled { "" } else { "disabled" };
    let enabled_json = if config.enabled { "true" } else { "false" };
    let disabled = if config.enabled {
        String::new()
    } else {
        "<p class=\"notice\">Captive portal access is currently disabled.</p>".to_string()
    };

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title}</title>
  <style>
    :root {{ color-scheme: light dark; font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }}
    body {{ margin: 0; min-height: 100vh; display: grid; place-items: center; background: #101820; color: #f7fbff; }}
    main {{ width: min(92vw, 420px); padding: 28px; border: 1px solid rgba(255,255,255,.18); border-radius: 8px; background: rgba(16,24,32,.92); }}
    h1 {{ margin: 0 0 12px; font-size: 1.7rem; line-height: 1.2; }}
    p {{ line-height: 1.5; color: #d7e2ea; }}
    label {{ display: block; margin: 16px 0; color: #d7e2ea; }}
    input[type="text"] {{ width: 100%; box-sizing: border-box; margin-top: 6px; padding: 11px 12px; border-radius: 6px; border: 1px solid #7b8b99; background: #fff; color: #111; }}
    button {{ width: 100%; padding: 12px 14px; border: 0; border-radius: 6px; background: #18a999; color: #001b18; font-weight: 700; cursor: pointer; }}
    button:disabled {{ opacity: .55; cursor: progress; }}
    #logout {{ display: none; margin-top: 12px; background: #d7e2ea; color: #101820; }}
    .notice {{ color: #ffd166; }}
    #status {{ min-height: 1.4em; margin-top: 14px; }}
  </style>
</head>
<body>
  <main>
    <h1>{title}</h1>
    <p>{message}</p>
    {disabled}
    <form id="portal-form" style="display: {form_style};">
      <label id="voucher-wrap" style="display: {voucher_style};">Voucher code
        <input id="voucher" name="voucherCode" type="text" autocomplete="one-time-code">
      </label>
      <label id="terms-wrap" style="display: {terms_style};">
        <input id="terms" name="acceptTerms" type="checkbox" {terms_checked}>
        I accept the network access terms.
      </label>
      <button id="submit" type="submit" {submit_disabled}>Connect</button>
    </form>
    <button id="logout" type="button">Disconnect</button>
    <p id="status"></p>
  </main>
  <script>
    const portalEnabled = {enabled_json};
    const form = document.getElementById('portal-form');
    const statusEl = document.getElementById('status');
    const submit = document.getElementById('submit');
    const logout = document.getElementById('logout');
    const voucher = document.getElementById('voucher');
    const terms = document.getElementById('terms');

    function setConnected(session) {{
      form.style.display = 'none';
      logout.style.display = 'block';
      const expires = session && session.expiresAt ? new Date(session.expiresAt) : null;
      statusEl.textContent = expires && !Number.isNaN(expires.getTime())
        ? 'Connected until ' + expires.toLocaleString() + '.'
        : 'Connected.';
    }}

    function setDisconnected(message) {{
      form.style.display = portalEnabled ? 'block' : 'none';
      logout.style.display = 'none';
      statusEl.textContent = message || '';
    }}

    async function refreshStatus() {{
      if (!portalEnabled) return;
      try {{
        const res = await fetch('/portal/status');
        const body = await res.json().catch(() => ({{}}));
        if (res.ok && body.authorized) {{
          setConnected(body.session);
        }}
      }} catch (_) {{
        // Status is advisory; form submission remains the source of truth.
      }}
    }}

    form.addEventListener('submit', async (event) => {{
      event.preventDefault();
      submit.disabled = true;
      statusEl.textContent = 'Authorising...';
      try {{
        const res = await fetch('/portal/authorize', {{
          method: 'POST',
          headers: {{ 'content-type': 'application/json' }},
          body: JSON.stringify({{
            voucherCode: voucher.value,
            acceptTerms: terms.checked
          }})
        }});
        const body = await res.json().catch(() => ({{}}));
        if (!res.ok) throw new Error(body.error || 'Access was not authorised');
        setConnected(body.session);
        if (body.redirectUrl) window.location.assign(body.redirectUrl);
      }} catch (error) {{
        statusEl.textContent = error.message;
      }} finally {{
        submit.disabled = false;
      }}
    }});

    logout.addEventListener('click', async () => {{
      logout.disabled = true;
      try {{
        await fetch('/portal/logout', {{ method: 'POST' }});
        setDisconnected('Disconnected.');
      }} catch (error) {{
        statusEl.textContent = error.message;
      }} finally {{
        logout.disabled = false;
      }}
    }});

    refreshStatus();
  </script>
</body>
</html>"#
    )
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
