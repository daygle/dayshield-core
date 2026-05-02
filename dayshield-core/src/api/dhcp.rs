//! DHCP endpoints — `GET /dhcp/config` and `POST /dhcp/config`.
//!
//! # GET /dhcp/config
//!
//! Returns the persisted [`DhcpConfig`].  When no DHCP configuration has been
//! saved yet, returns a default (disabled) configuration.
//!
//! # POST /dhcp/config
//!
//! Accepts a full [`DhcpConfig`] JSON body, validates all fields, atomically
//! persists it, and triggers the DHCP engine to regenerate and apply the
//! dnsmasq configuration.

use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use tracing::{info, warn};

use crate::{
    config::models::{
        is_valid_cidr, is_valid_ip, is_valid_ipv4_range, is_valid_mac,
        DhcpConfig, DhcpScope,
    },
    engine::dhcp::apply_config,
    state::AppState,
};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by the DHCP API handlers.
#[derive(Debug, thiserror::Error)]
pub enum DhcpError {
    /// A field failed validation.
    #[error("validation error: {0}")]
    ValidationFailed(String),

    /// A persistent-storage operation failed.
    #[error("storage error: {0:#}")]
    StorageError(#[from] anyhow::Error),

    /// The DHCP engine failed to apply the configuration.
    #[error("engine error: {0:#}")]
    EngineError(String),
}

impl IntoResponse for DhcpError {
    fn into_response(self) -> axum::response::Response {
        let status = match &self {
            DhcpError::ValidationFailed(_) => StatusCode::UNPROCESSABLE_ENTITY,
            DhcpError::StorageError(_) | DhcpError::EngineError(_) => {
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

/// Request body for `POST /dhcp/config`.
#[derive(serde::Deserialize)]
pub struct UpdateDhcpConfigRequest {
    pub enabled: bool,
    pub scopes: Vec<DhcpScope>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Handler: return the current DHCP configuration.
///
/// Loads the DHCP config from persistent storage.  If no configuration has
/// been saved yet, returns a sensible default (disabled, no scopes).
pub async fn get_config(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, DhcpError> {
    let cfg = state
        .config_store
        .load_dhcp_config()
        .map_err(DhcpError::StorageError)?
        .unwrap_or_else(|| DhcpConfig {
            enabled: false,
            scopes: vec![],
        });

    info!(enabled = cfg.enabled, scopes = cfg.scopes.len(), "dhcp: loaded config");

    Ok(Json(cfg))
}

/// Handler: update the DHCP configuration.
///
/// Validates all fields, persists atomically, then triggers the DHCP engine to
/// regenerate and apply the dnsmasq configuration.  Returns the saved config
/// with `200 OK` on success.
pub async fn update_config(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpdateDhcpConfigRequest>,
) -> Result<impl IntoResponse, DhcpError> {
    // --- Validation --------------------------------------------------------

    for scope in &req.scopes {
        // Subnet must be a valid CIDR.
        if !is_valid_cidr(&scope.subnet) {
            warn!(subnet = %scope.subnet, "dhcp: invalid subnet");
            return Err(DhcpError::ValidationFailed(format!(
                "invalid subnet: {} (expected CIDR notation, e.g. 192.168.1.0/24)",
                scope.subnet
            )));
        }

        // Pool start and end must be valid IPs.
        if !is_valid_ip(&scope.pool_start) {
            return Err(DhcpError::ValidationFailed(format!(
                "invalid pool_start: {}",
                scope.pool_start
            )));
        }
        if !is_valid_ip(&scope.pool_end) {
            return Err(DhcpError::ValidationFailed(format!(
                "invalid pool_end: {}",
                scope.pool_end
            )));
        }

        // pool_start ≤ pool_end (IPv4 only; IPv6 pools are unsupported).
        if !is_valid_ipv4_range(&scope.pool_start, &scope.pool_end) {
            return Err(DhcpError::ValidationFailed(format!(
                "pool_start {} must be ≤ pool_end {}",
                scope.pool_start, scope.pool_end
            )));
        }

        // Gateway, if provided, must be a valid IP.
        if let Some(gw) = &scope.gateway {
            if !is_valid_ip(gw) {
                return Err(DhcpError::ValidationFailed(format!(
                    "invalid gateway: {gw}"
                )));
            }
        }

        // DNS servers must be valid IPs.
        for dns in &scope.dns_servers {
            if !is_valid_ip(dns) {
                return Err(DhcpError::ValidationFailed(format!(
                    "invalid DNS server: {dns}"
                )));
            }
        }

        // Reservations: MAC and IP must be valid.
        for res in &scope.reservations {
            if !is_valid_mac(&res.mac_address) {
                warn!(mac = %res.mac_address, "dhcp: invalid MAC in reservation");
                return Err(DhcpError::ValidationFailed(format!(
                    "invalid MAC address: {} (expected format aa:bb:cc:dd:ee:ff)",
                    res.mac_address
                )));
            }
            if !is_valid_ip(&res.ip_address) {
                return Err(DhcpError::ValidationFailed(format!(
                    "invalid reservation IP: {}",
                    res.ip_address
                )));
            }
        }
    }

    // --- Build config ------------------------------------------------------

    let cfg = DhcpConfig {
        enabled: req.enabled,
        scopes: req.scopes,
    };

    info!(
        enabled = cfg.enabled,
        scopes = cfg.scopes.len(),
        "dhcp: received update config request"
    );

    // --- Persist -----------------------------------------------------------

    state
        .config_store
        .save_dhcp_config(cfg.clone())
        .map_err(DhcpError::StorageError)?;

    info!("dhcp: config persisted");

    // --- Apply -------------------------------------------------------------

    apply_config(&cfg)
        .await
        .map_err(|e| DhcpError::EngineError(e.to_string()))?;

    info!("dhcp: engine apply complete");

    Ok(Json(cfg))
}
