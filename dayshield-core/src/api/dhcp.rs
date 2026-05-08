//! DHCP endpoints.
//!
//! | Method | Path                          | Description                          |
//! |--------|-------------------------------|--------------------------------------|
//! | GET    | `/dhcp/config`                | Get flat DHCP configuration          |
//! | POST   | `/dhcp/config`                | Update flat DHCP configuration       |
//! | GET    | `/dhcp/static-leases`         | List all static MAC → IP bindings    |
//! | POST   | `/dhcp/static-leases`         | Add a static lease                   |
//! | DELETE | `/dhcp/static-leases/{id}`    | Remove a static lease by UUID        |
//! | GET    | `/dhcp/leases`                | List active leases from dnsmasq      |
//! | GET    | `/dhcp/pools`                 | List DHCP scopes as pool view        |

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use crate::{
    config::models::{
        is_valid_ip, is_valid_ipv4_range, is_valid_mac,
        DhcpConfig, DhcpReservation, DhcpScope,
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
// API DTO types (camelCase for UI compatibility)
// ---------------------------------------------------------------------------

/// Flat DHCP config response matching the TypeScript `DhcpConfig` interface.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DhcpFlatConfigResponse {
    pub enabled: bool,
    pub interface: String,
    /// Subnet in CIDR notation (e.g. `192.168.1.0/24`).
    pub subnet: String,
    pub range_start: String,
    pub range_end: String,
    pub subnet_mask: String,
    pub gateway: String,
    pub dns_servers: Vec<String>,
    pub lease_time: u32,
    pub domain_name: String,
}

/// Request body for `POST /dhcp/config` (flat format matching UI).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateDhcpFlatRequest {
    pub enabled: Option<bool>,
    pub interface: Option<String>,
    /// Subnet in CIDR notation (e.g. `192.168.1.0/24`).  Must be provided
    /// when creating the first scope; ignored if left empty.
    pub subnet: Option<String>,
    pub range_start: Option<String>,
    pub range_end: Option<String>,
    pub gateway: Option<String>,
    pub dns_servers: Option<Vec<String>>,
    pub lease_time: Option<u32>,
    pub domain_name: Option<String>,
}

/// Response for a single static lease (UUID id as string).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DhcpStaticLeaseResponse {
    pub id: String,
    pub mac: String,
    pub ip_address: String,
    pub hostname: String,
    pub description: String,
}

/// Request body for `POST /dhcp/static-leases`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateStaticLeaseRequest {
    pub mac: String,
    pub ip_address: String,
    pub hostname: Option<String>,
    pub description: Option<String>,
}

/// Response for a single active lease parsed from dnsmasq.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DhcpLeaseResponse {
    pub mac: String,
    pub ip_address: String,
    pub hostname: String,
    pub starts: String,
    pub ends: String,
    pub state: String,
}

/// Pool view response (one per DhcpScope).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DhcpPoolResponse {
    pub id: String,
    pub interface: String,
    pub range_start: String,
    pub range_end: String,
    pub description: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_dhcp_cfg() -> DhcpConfig {
    DhcpConfig {
        enabled: false,
        interface: String::new(),
        scopes: vec![],
    }
}

/// Convert the first scope of a DhcpConfig into a flat response.
fn to_flat_response(cfg: &DhcpConfig) -> DhcpFlatConfigResponse {
    if let Some(scope) = cfg.scopes.first() {
        DhcpFlatConfigResponse {
            enabled: cfg.enabled,
            interface: cfg.interface.clone(),
            subnet: scope.subnet.clone(),
            range_start: scope.pool_start.clone(),
            range_end: scope.pool_end.clone(),
            subnet_mask: cidr_to_mask(&scope.subnet),
            gateway: scope.gateway.clone().unwrap_or_default(),
            dns_servers: scope.dns_servers.clone(),
            lease_time: scope.lease_seconds,
            domain_name: scope.domain_name.clone().unwrap_or_default(),
        }
    } else {
        DhcpFlatConfigResponse {
            enabled: cfg.enabled,
            interface: cfg.interface.clone(),
            subnet: String::new(),
            range_start: String::new(),
            range_end: String::new(),
            subnet_mask: String::new(),
            gateway: String::new(),
            dns_servers: vec![],
            lease_time: 86400,
            domain_name: String::new(),
        }
    }
}

/// Derive a /24 subnet CIDR from a host address (e.g. `192.168.1.100` → `192.168.1.0/24`).
/// Used as a fallback when the subnet cannot be determined any other way.
fn derive_subnet_from_addr(addr: &str) -> String {
    let parts: Vec<&str> = addr.split('.').collect();
    if parts.len() == 4 {
        format!("{}.{}.{}.0/24", parts[0], parts[1], parts[2])
    } else {
        "192.168.1.0/24".to_string()
    }
}

/// Derive a /24 subnet mask from a CIDR prefix, e.g. `192.168.1.0/24` → `255.255.255.0`.
fn cidr_to_mask(cidr: &str) -> String {
    let prefix: u8 = cidr
        .split('/')
        .nth(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or(24);
    let mask: u32 = if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix as u32)
    };
    format!(
        "{}.{}.{}.{}",
        (mask >> 24) & 0xFF,
        (mask >> 16) & 0xFF,
        (mask >> 8) & 0xFF,
        mask & 0xFF
    )
}

// ---------------------------------------------------------------------------
// GET /dhcp/config
// ---------------------------------------------------------------------------

/// Return the DHCP configuration in a flat format compatible with the UI.
pub async fn get_config(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, DhcpError> {
    let cfg = state
        .config_store
        .load_dhcp_config()
        .map_err(DhcpError::StorageError)?
        .unwrap_or_else(default_dhcp_cfg);

    info!(enabled = cfg.enabled, scopes = cfg.scopes.len(), "dhcp: loaded config");

    Ok(Json(serde_json::json!({
        "success": true,
        "data": to_flat_response(&cfg)
    })))
}

// ---------------------------------------------------------------------------
// POST /dhcp/config
// ---------------------------------------------------------------------------

/// Update the DHCP configuration from a flat request body.
///
/// Maps the flat UI model onto the first scope (creating it if necessary),
/// validates, persists, and applies via the engine.
pub async fn update_config(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpdateDhcpFlatRequest>,
) -> Result<impl IntoResponse, DhcpError> {
    let mut cfg = state
        .config_store
        .load_dhcp_config()
        .map_err(DhcpError::StorageError)?
        .unwrap_or_else(default_dhcp_cfg);

    // Apply top-level fields.
    if let Some(v) = req.enabled    { cfg.enabled   = v; }
    if let Some(v) = req.interface  { cfg.interface  = v; }

    // Ensure at least one scope exists to hold the pool settings.
    if cfg.scopes.is_empty() {
        // Determine the best subnet we can for the new scope:
        // 1. Use the explicitly provided subnet from the request.
        // 2. Derive a /24 from the pool start address if provided.
        // 3. Fall back to a /24 based on the gateway if provided.
        // 4. Last resort: use the gateway/range to derive, or 192.168.1.0/24.
        let subnet = req.subnet
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(String::from)
            .or_else(|| {
                req.range_start
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .map(derive_subnet_from_addr)
            })
            .or_else(|| {
                req.gateway
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .map(derive_subnet_from_addr)
            })
            .unwrap_or_else(|| "192.168.1.0/24".to_string());

        cfg.scopes.push(DhcpScope {
            id: Uuid::new_v4(),
            subnet,
            pool_start: String::new(),
            pool_end: String::new(),
            gateway: None,
            dns_servers: vec![],
            lease_seconds: 86400,
            domain_name: None,
            reservations: vec![],
        });
    }

    let scope = &mut cfg.scopes[0];
    // Subnet can be updated explicitly; otherwise preserve the existing value.
    if let Some(v) = req.subnet.filter(|s| !s.is_empty()) { scope.subnet = v; }
    if let Some(v) = req.range_start  { scope.pool_start    = v; }
    if let Some(v) = req.range_end    { scope.pool_end      = v; }
    if let Some(v) = req.gateway      { scope.gateway       = if v.is_empty() { None } else { Some(v) }; }
    if let Some(v) = req.dns_servers  { scope.dns_servers   = v; }
    if let Some(v) = req.lease_time   { scope.lease_seconds = v; }
    if let Some(v) = req.domain_name  { scope.domain_name   = if v.is_empty() { None } else { Some(v) }; }

    // --- Validation --------------------------------------------------------

    let scope = &cfg.scopes[0];

    if !scope.pool_start.is_empty() && !is_valid_ip(&scope.pool_start) {
        return Err(DhcpError::ValidationFailed(format!(
            "invalid rangeStart: {}", scope.pool_start
        )));
    }
    if !scope.pool_end.is_empty() && !is_valid_ip(&scope.pool_end) {
        return Err(DhcpError::ValidationFailed(format!(
            "invalid rangeEnd: {}", scope.pool_end
        )));
    }
    if !scope.pool_start.is_empty()
        && !scope.pool_end.is_empty()
        && !is_valid_ipv4_range(&scope.pool_start, &scope.pool_end)
    {
        return Err(DhcpError::ValidationFailed(format!(
            "rangeStart {} must be ≤ rangeEnd {}", scope.pool_start, scope.pool_end
        )));
    }
    if let Some(gw) = &scope.gateway {
        if !is_valid_ip(gw) {
            return Err(DhcpError::ValidationFailed(format!("invalid gateway: {gw}")));
        }
    }
    for dns in &scope.dns_servers {
        if !is_valid_ip(dns) {
            return Err(DhcpError::ValidationFailed(format!("invalid DNS server: {dns}")));
        }
    }

    info!(
        enabled = cfg.enabled,
        interface = %cfg.interface,
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

    Ok(Json(serde_json::json!({
        "success": true,
        "data": to_flat_response(&cfg)
    })))
}

// ---------------------------------------------------------------------------
// GET /dhcp/static-leases
// ---------------------------------------------------------------------------

/// Return all static MAC → IP reservations across all scopes.
pub async fn list_static_leases(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, DhcpError> {
    let cfg = state
        .config_store
        .load_dhcp_config()
        .map_err(DhcpError::StorageError)?
        .unwrap_or_else(default_dhcp_cfg);

    let leases: Vec<DhcpStaticLeaseResponse> = cfg
        .scopes
        .iter()
        .flat_map(|s| s.reservations.iter())
        .map(|r| DhcpStaticLeaseResponse {
            id: r.id.to_string(),
            mac: r.mac_address.clone(),
            ip_address: r.ip_address.clone(),
            hostname: r.hostname.clone().unwrap_or_default(),
            description: r.description.clone(),
        })
        .collect();

    Ok(Json(serde_json::json!({
        "success": true,
        "data": leases
    })))
}

// ---------------------------------------------------------------------------
// POST /dhcp/static-leases
// ---------------------------------------------------------------------------

/// Add a static MAC → IP reservation to the first DHCP scope.
///
/// Creates a default scope if none exists.
pub async fn create_static_lease(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateStaticLeaseRequest>,
) -> Result<impl IntoResponse, DhcpError> {
    // --- Validation --------------------------------------------------------

    if !is_valid_mac(&req.mac) {
        warn!(mac = %req.mac, "dhcp: invalid MAC in static lease");
        return Err(DhcpError::ValidationFailed(format!(
            "invalid MAC address: {} (expected aa:bb:cc:dd:ee:ff)",
            req.mac
        )));
    }
    if !is_valid_ip(&req.ip_address) {
        return Err(DhcpError::ValidationFailed(format!(
            "invalid IP address: {}",
            req.ip_address
        )));
    }

    let mut cfg = state
        .config_store
        .load_dhcp_config()
        .map_err(DhcpError::StorageError)?
        .unwrap_or_else(default_dhcp_cfg);

    // Ensure at least one scope.
    if cfg.scopes.is_empty() {
        cfg.scopes.push(DhcpScope {
            id: Uuid::new_v4(),
            // Derive subnet from the reservation IP as best-effort fallback.
            subnet: derive_subnet_from_addr(&req.ip_address),
            pool_start: String::new(),
            pool_end: String::new(),
            gateway: None,
            dns_servers: vec![],
            lease_seconds: 86400,
            domain_name: None,
            reservations: vec![],
        });
    }

    let reservation = DhcpReservation {
        id: Uuid::new_v4(),
        hostname: req.hostname.filter(|h| !h.is_empty()),
        mac_address: req.mac.clone(),
        ip_address: req.ip_address.clone(),
        description: req.description.unwrap_or_default(),
    };

    let resp = DhcpStaticLeaseResponse {
        id: reservation.id.to_string(),
        mac: reservation.mac_address.clone(),
        ip_address: reservation.ip_address.clone(),
        hostname: reservation.hostname.clone().unwrap_or_default(),
        description: reservation.description.clone(),
    };

    cfg.scopes[0].reservations.push(reservation);

    state
        .config_store
        .save_dhcp_config(cfg.clone())
        .map_err(DhcpError::StorageError)?;

    apply_config(&cfg)
        .await
        .map_err(|e| DhcpError::EngineError(e.to_string()))?;

    info!(mac = %req.mac, ip = %req.ip_address, "dhcp: static lease created");

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "success": true, "data": resp })),
    ))
}

// ---------------------------------------------------------------------------
// DELETE /dhcp/static-leases/{id}
// ---------------------------------------------------------------------------

/// Remove a static reservation by UUID string.
pub async fn delete_static_lease(
    Path(id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, DhcpError> {
    let target = id.parse::<Uuid>().map_err(|_| {
        DhcpError::ValidationFailed(format!("invalid lease ID: {id}"))
    })?;

    let mut cfg = state
        .config_store
        .load_dhcp_config()
        .map_err(DhcpError::StorageError)?
        .unwrap_or_else(default_dhcp_cfg);

    let mut found = false;
    for scope in &mut cfg.scopes {
        let before = scope.reservations.len();
        scope.reservations.retain(|r| r.id != target);
        if scope.reservations.len() < before {
            found = true;
        }
    }

    if !found {
        return Err(DhcpError::ValidationFailed(format!(
            "static lease {id} not found"
        )));
    }

    state
        .config_store
        .save_dhcp_config(cfg.clone())
        .map_err(DhcpError::StorageError)?;

    apply_config(&cfg)
        .await
        .map_err(|e| DhcpError::EngineError(e.to_string()))?;

    info!(%id, "dhcp: static lease deleted");

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// GET /dhcp/leases
// ---------------------------------------------------------------------------

/// Return currently active DHCP leases parsed from the Kea memfile lease database.
///
/// Kea CSV format (one lease per line, first line is header):
/// `address,hwaddr,client-id,valid-lifetime,expire,subnet-id,fqdn-fwd,fqdn-rev,hostname,state,user-context`
///
/// Returns an empty array when the file does not exist.
pub async fn list_active_leases(
    State(_state): State<Arc<AppState>>,
) -> impl IntoResponse {
    use crate::engine::dhcp::KEA_LEASES_PATH;

    let content = match tokio::fs::read_to_string(KEA_LEASES_PATH).await {
        Ok(c) => c,
        Err(_) => {
            return Json(serde_json::json!({ "success": true, "data": serde_json::json!([]) }));
        }
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Skip the CSV header line.
    let leases: Vec<DhcpLeaseResponse> = content
        .lines()
        .filter(|l| !l.starts_with("address") && !l.is_empty())
        .filter_map(|line| {
            // address,hwaddr,client-id,valid-lifetime,expire,subnet-id,
            //   fqdn-fwd,fqdn-rev,hostname,state,user-context
            let mut cols = line.splitn(11, ',');
            let address       = cols.next()?.to_string();
            let hwaddr        = cols.next()?.to_string();
            let _client_id    = cols.next();
            let _valid_life   = cols.next();
            let expire: u64   = cols.next()?.parse().ok()?;
            let _subnet_id    = cols.next();
            let _fqdn_fwd     = cols.next();
            let _fqdn_rev     = cols.next();
            let hostname      = cols.next().unwrap_or("").to_string();
            let state_col: u8 = cols.next().unwrap_or("0").trim().parse().unwrap_or(0);
            // Kea state: 0=default(active), 1=declined, 2=expired-reclaimed
            let state_str = match state_col {
                0 if expire > now => "active",
                0                 => "expired",
                1                 => "declined",
                _                 => "reclaimed",
            };
            Some(DhcpLeaseResponse {
                mac: hwaddr,
                ip_address: address,
                hostname,
                starts: String::new(),
                ends: expire.to_string(),
                state: state_str.to_string(),
            })
        })
        .collect();

    Json(serde_json::json!({ "success": true, "data": leases }))
}

// ---------------------------------------------------------------------------
// GET /dhcp/pools
// ---------------------------------------------------------------------------

/// Return all DHCP scopes as a pool view (for UI compatibility).
pub async fn list_pools(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, DhcpError> {
    let cfg = state
        .config_store
        .load_dhcp_config()
        .map_err(DhcpError::StorageError)?
        .unwrap_or_else(default_dhcp_cfg);

    let pools: Vec<DhcpPoolResponse> = cfg
        .scopes
        .iter()
        .map(|s| DhcpPoolResponse {
            id: s.id.to_string(),
            interface: cfg.interface.clone(),
            range_start: s.pool_start.clone(),
            range_end: s.pool_end.clone(),
            description: s.subnet.clone(),
        })
        .collect();

    Ok(Json(serde_json::json!({ "success": true, "data": pools })))
}
