//! DNS override endpoints.
//!
//! - `GET  /dns/overrides`                        - list all overrides
//! - `POST /dns/overrides`                        - create a host or domain override
//! - `DELETE /dns/overrides/{hostname_or_domain}` - remove an override by hostname or domain

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::{
    config::models::{
        is_valid_ip, validate_dns_domain, validate_dns_hostname, DnsDomainOverride,
        DnsHostOverride,
    },
    engine::dns::apply_config,
    state::AppState,
};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by the DNS overrides API handlers.
#[derive(Debug, thiserror::Error)]
pub enum DnsOverrideError {
    /// A field failed validation.
    #[error("validation error: {0}")]
    ValidationFailed(String),

    /// A persistent-storage operation failed.
    #[error("storage error: {0:#}")]
    StorageError(#[from] anyhow::Error),

    /// The DNS engine failed to apply the updated configuration.
    #[error("engine error: {0:#}")]
    EngineError(String),

    /// The requested override was not found.
    #[error("override not found: {0}")]
    NotFound(String),
}

impl IntoResponse for DnsOverrideError {
    fn into_response(self) -> axum::response::Response {
        let status = match &self {
            DnsOverrideError::ValidationFailed(_) => StatusCode::UNPROCESSABLE_ENTITY,
            DnsOverrideError::NotFound(_) => StatusCode::NOT_FOUND,
            DnsOverrideError::StorageError(_) | DnsOverrideError::EngineError(_) => {
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
// Shared response type
// ---------------------------------------------------------------------------

/// The combined list of DNS overrides returned by `GET /dns/overrides`.
#[derive(Serialize)]
pub struct DnsOverridesResponse {
    pub host_overrides: Vec<DnsHostOverride>,
    pub domain_overrides: Vec<DnsDomainOverride>,
}

// ---------------------------------------------------------------------------
// Request bodies
// ---------------------------------------------------------------------------

/// The type of DNS override to create.
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OverrideKind {
    /// Host override: maps a hostname to an IP address.
    Host,
    /// Domain override: forwards all queries for a domain to a specific resolver.
    Domain,
}

/// Request body for `POST /dns/overrides`.
#[derive(Deserialize)]
pub struct CreateDnsOverrideRequest {
    /// Whether this is a host or domain override.
    pub kind: OverrideKind,
    /// Hostname (for `kind = host`) or domain (for `kind = domain`).
    pub name: String,
    /// For host overrides: the A/AAAA address.
    /// For domain overrides: the IP of the forwarding DNS server.
    pub target: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Handler: return all persisted DNS overrides.
pub async fn list_overrides(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, DnsOverrideError> {
    let (host_overrides, domain_overrides) = state
        .config_store
        .load_dns_overrides()
        .map_err(DnsOverrideError::StorageError)?;

    info!(
        host = host_overrides.len(),
        domain = domain_overrides.len(),
        "dns_overrides: loaded from storage"
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "data": DnsOverridesResponse { host_overrides, domain_overrides }
    })))
}

/// Handler: create a new DNS override (host or domain).
///
/// Validates all fields, checks for duplicate names, persists, then triggers
/// the DNS engine to regenerate and apply the Unbound configuration.
/// Returns `201 Created` with the created override on success.
pub async fn create_override(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateDnsOverrideRequest>,
) -> Result<impl IntoResponse, DnsOverrideError> {
    let (mut host_overrides, mut domain_overrides) = state
        .config_store
        .load_dns_overrides()
        .map_err(DnsOverrideError::StorageError)?;

    #[derive(Serialize)]
    #[serde(untagged)]
    enum Created {
        Host(DnsHostOverride),
        Domain(DnsDomainOverride),
    }

    let created: Created = match req.kind {
        OverrideKind::Host => {
            if !validate_dns_hostname(&req.name) {
                warn!(name = %req.name, "dns_overrides: invalid hostname");
                return Err(DnsOverrideError::ValidationFailed(format!(
                    "invalid hostname {:?}: must be RFC-1035 compliant",
                    req.name
                )));
            }
            if !is_valid_ip(&req.target) {
                warn!(target = %req.target, "dns_overrides: invalid IP address for host override");
                return Err(DnsOverrideError::ValidationFailed(format!(
                    "invalid address {:?}: must be a valid IPv4 or IPv6 address",
                    req.target
                )));
            }
            if host_overrides.iter().any(|h| h.hostname == req.name) {
                return Err(DnsOverrideError::ValidationFailed(format!(
                    "host override for {:?} already exists",
                    req.name
                )));
            }
            let ov = DnsHostOverride {
                hostname: req.name,
                address: req.target,
            };
            info!(hostname = %ov.hostname, address = %ov.address, "dns_overrides: creating host override");
            host_overrides.push(ov.clone());
            Created::Host(ov)
        }
        OverrideKind::Domain => {
            if !validate_dns_domain(&req.name) {
                warn!(name = %req.name, "dns_overrides: invalid domain");
                return Err(DnsOverrideError::ValidationFailed(format!(
                    "invalid domain {:?}: must be a valid domain name",
                    req.name
                )));
            }
            if !is_valid_ip(&req.target) {
                warn!(target = %req.target, "dns_overrides: invalid IP for domain override");
                return Err(DnsOverrideError::ValidationFailed(format!(
                    "invalid forward_to {:?}: must be a valid IPv4 or IPv6 address",
                    req.target
                )));
            }
            if domain_overrides.iter().any(|d| d.domain == req.name) {
                return Err(DnsOverrideError::ValidationFailed(format!(
                    "domain override for {:?} already exists",
                    req.name
                )));
            }
            let ov = DnsDomainOverride {
                domain: req.name,
                forward_to: req.target,
            };
            info!(domain = %ov.domain, forward_to = %ov.forward_to, "dns_overrides: creating domain override");
            domain_overrides.push(ov.clone());
            Created::Domain(ov)
        }
    };

    // --- Persist -----------------------------------------------------------

    state
        .config_store
        .save_dns_overrides(host_overrides, domain_overrides)
        .map_err(DnsOverrideError::StorageError)?;

    info!("dns_overrides: persisted");

    // --- Apply -------------------------------------------------------------

    if let Some(dns_cfg) = state
        .config_store
        .load_dns_config()
        .map_err(DnsOverrideError::StorageError)?
    {
        apply_config(&dns_cfg)
            .await
            .map_err(|e| DnsOverrideError::EngineError(e.to_string()))?;
        info!("dns_overrides: dns engine apply complete");
    }

    Ok((StatusCode::CREATED, Json(created)))
}

/// Handler: delete a DNS override by hostname or domain.
///
/// Searches host overrides first, then domain overrides.  Returns `204 No
/// Content` on success or `404 Not Found` when neither list contains the name.
pub async fn delete_override(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, DnsOverrideError> {
    let (mut host_overrides, mut domain_overrides) = state
        .config_store
        .load_dns_overrides()
        .map_err(DnsOverrideError::StorageError)?;

    let host_before = host_overrides.len();
    host_overrides.retain(|h| h.hostname != name);

    let domain_before = domain_overrides.len();
    domain_overrides.retain(|d| d.domain != name);

    if host_overrides.len() == host_before && domain_overrides.len() == domain_before {
        return Err(DnsOverrideError::NotFound(name));
    }

    state
        .config_store
        .save_dns_overrides(host_overrides, domain_overrides)
        .map_err(DnsOverrideError::StorageError)?;

    info!(name = %name, "dns_overrides: deleted override");

    // Re-apply DNS config.
    if let Some(dns_cfg) = state
        .config_store
        .load_dns_config()
        .map_err(DnsOverrideError::StorageError)?
    {
        apply_config(&dns_cfg)
            .await
            .map_err(|e| DnsOverrideError::EngineError(e.to_string()))?;
        info!("dns_overrides: dns engine apply complete after delete");
    }

    Ok(StatusCode::NO_CONTENT)
}
