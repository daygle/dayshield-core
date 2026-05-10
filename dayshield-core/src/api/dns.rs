//! DNS endpoints — `GET /dns/config` and `POST /dns/config`.
//!
//! # GET /dns/config
//!
//! Returns the persisted [`DnsConfig`].  When no DNS configuration has been
//! saved yet, returns a default (disabled) configuration.
//!
//! # POST /dns/config
//!
//! Accepts a full [`DnsConfig`] JSON body, validates all fields, atomically
//! persists it, and triggers the DNS engine to regenerate and apply the Unbound
//! configuration.

use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use tracing::{info, warn};

use crate::{
    config::models::{
        is_valid_domain, is_valid_interface_name, is_valid_ip, DnsConfig, DnsLocalRecord,
    },
    engine::dns::apply_config,
    state::AppState,
};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by the DNS API handlers.
#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    /// A field failed validation.
    #[error("validation error: {0}")]
    ValidationFailed(String),

    /// A persistent-storage operation failed.
    #[error("storage error: {0:#}")]
    StorageError(#[from] anyhow::Error),

    /// The DNS engine failed to apply the configuration.
    #[error("engine error: {0:#}")]
    EngineError(String),
}

impl IntoResponse for DnsError {
    fn into_response(self) -> axum::response::Response {
        let status = match &self {
            DnsError::ValidationFailed(_) => StatusCode::UNPROCESSABLE_ENTITY,
            DnsError::StorageError(_) | DnsError::EngineError(_) => {
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

// ---------------------------------------------------------------------------
// Request body
// ---------------------------------------------------------------------------

/// Request body for `POST /dns/config`.
#[derive(serde::Deserialize)]
pub struct UpdateDnsConfigRequest {
    pub enabled: bool,
    pub listen_addresses: Vec<String>,
    pub port: u16,
    pub forwarders: Vec<String>,
    pub dnssec: bool,
    pub local_records: Vec<DnsLocalRecord>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Handler: return the current DNS configuration.
///
/// Loads the DNS config from persistent storage.  If no configuration has been
/// saved yet, returns the clean-install default config.
pub async fn get_config(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, DnsError> {
    let cfg = state
        .config_store
        .load_dns_config()
        .map_err(DnsError::StorageError)?
        .unwrap_or_default();

    info!(enabled = cfg.enabled, "dns: loaded config");

    Ok(Json(serde_json::json!({ "success": true, "data": cfg })))
}

/// Handler: update the DNS configuration.
///
/// Validates all fields, persists atomically, then triggers the DNS engine to
/// regenerate and apply the Unbound configuration.  Returns the saved config
/// with `200 OK` on success.
pub async fn update_config(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpdateDnsConfigRequest>,
) -> Result<impl IntoResponse, DnsError> {
    // --- Validation --------------------------------------------------------

    if req.port == 0 {
        return Err(DnsError::ValidationFailed(
            "DNS port must be non-zero".into(),
        ));
    }

    for addr in &req.listen_addresses {
        // Accept plain IPs or interface names (e.g. "eth0").
        if !is_valid_ip(addr) && !is_valid_interface_name(addr) {
            warn!(addr = %addr, "dns: invalid listen address");
            return Err(DnsError::ValidationFailed(format!(
                "invalid listen address: {addr} (expected IP address or interface name)"
            )));
        }
    }

    for fwd in &req.forwarders {
        if !is_valid_ip(fwd) {
            warn!(fwd = %fwd, "dns: invalid forwarder");
            return Err(DnsError::ValidationFailed(format!(
                "invalid forwarder: {fwd} (expected IPv4 or IPv6 address)"
            )));
        }
    }

    for rec in &req.local_records {
        if rec.name.is_empty() {
            return Err(DnsError::ValidationFailed(
                "local record name must not be empty".into(),
            ));
        }
        let rtype = rec.record_type.to_uppercase();
        match rtype.as_str() {
            "A" => {
                if rec.value.parse::<std::net::Ipv4Addr>().is_err() {
                    return Err(DnsError::ValidationFailed(format!(
                        "A record {:?} value must be an IPv4 address, got: {}",
                        rec.name, rec.value
                    )));
                }
            }
            "AAAA" => {
                if rec.value.parse::<std::net::Ipv6Addr>().is_err() {
                    return Err(DnsError::ValidationFailed(format!(
                        "AAAA record {:?} value must be an IPv6 address, got: {}",
                        rec.name, rec.value
                    )));
                }
            }
            "CNAME" | "PTR" => {
                if !is_valid_domain(&rec.value) {
                    return Err(DnsError::ValidationFailed(format!(
                        "{} record {:?} value must be a valid domain name, got: {}",
                        rtype, rec.name, rec.value
                    )));
                }
            }
            "MX" => {
                // MX value: "<priority> <domain>" e.g. "10 mail.example.com"
                let parts: Vec<&str> = rec.value.splitn(2, ' ').collect();
                let valid = parts.len() == 2
                    && parts[0].parse::<u16>().is_ok()
                    && is_valid_domain(parts[1]);
                if !valid {
                    return Err(DnsError::ValidationFailed(format!(
                        "MX record {:?} value must be \"<priority> <domain>\", got: {}",
                        rec.name, rec.value
                    )));
                }
            }
            "TXT" => {
                // TXT records are freeform; only check non-empty.
                if rec.value.is_empty() {
                    return Err(DnsError::ValidationFailed(format!(
                        "TXT record {:?} value must not be empty",
                        rec.name
                    )));
                }
            }
            _ => {
                return Err(DnsError::ValidationFailed(format!(
                    "unsupported DNS record type: {} (supported: A, AAAA, CNAME, PTR, MX, TXT)",
                    rec.record_type
                )));
            }
        }
    }

    // --- Build config ------------------------------------------------------

    let cfg = DnsConfig {
        enabled: req.enabled,
        listen_addresses: req.listen_addresses,
        port: req.port,
        forwarders: req.forwarders,
        dnssec: req.dnssec,
        local_records: req.local_records,
    };

    info!(
        enabled = cfg.enabled,
        port = cfg.port,
        dnssec = cfg.dnssec,
        "dns: received update config request"
    );

    // --- Persist -----------------------------------------------------------

    state
        .config_store
        .save_dns_config(cfg.clone())
        .map_err(DnsError::StorageError)?;

    info!("dns: config persisted");

    // --- Apply -------------------------------------------------------------

    apply_config(&cfg)
        .await
        .map_err(|e| DnsError::EngineError(e.to_string()))?;

    info!("dns: engine apply complete");

    Ok(Json(serde_json::json!({ "success": true, "data": cfg })))
}
