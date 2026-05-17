//! DHCP endpoints.
//!
//! | Method | Path                                      | Description                          |
//! |--------|-------------------------------------------|--------------------------------------|
//! | GET    | `/dhcp/config`                            | Get flat DHCP configuration          |
//! | POST   | `/dhcp/config`                            | Update flat DHCP configuration       |
//! | GET    | `/interfaces/{name}/dhcp/config`          | Get DHCP config for interface        |
//! | POST   | `/interfaces/{name}/dhcp/config`          | Update DHCP config for interface     |
//! | GET    | `/interfaces/{name}/dhcp/static-leases`   | List static leases for interface     |
//! | POST   | `/interfaces/{name}/dhcp/static-leases`   | Add static lease for interface       |
//! | DELETE | `/interfaces/{name}/dhcp/static-leases/{id}` | Delete static lease from interface |
//! | GET    | `/dhcp/static-leases`                     | List all static MAC → IP bindings    |
//! | POST   | `/dhcp/static-leases`                     | Add a static lease                   |
//! | DELETE | `/dhcp/static-leases/{id}`                | Remove a static lease by UUID        |
//! | GET    | `/dhcp/leases`                            | List active leases from dnsmasq      |
//! | GET    | `/dhcp/pools`                             | List DHCP scopes as pool view        |

use std::{net::Ipv6Addr, sync::Arc};

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
        is_valid_duid, is_valid_ipv4_addr, is_valid_ipv4_range, is_valid_ipv6_addr,
        is_valid_ipv6_cidr, is_valid_mac, Dhcp6Config, Dhcp6Reservation, Dhcp6Scope, DhcpConfig,
        DhcpReservation, DhcpScope,
    },
    engine::{dhcp::apply_config as apply_dhcp4_config, dhcp6::apply_config as apply_dhcp6_config},
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

    if !scope.pool_start.is_empty() && !is_valid_ipv4_addr(&scope.pool_start) {
        return Err(DhcpError::ValidationFailed(format!(
            "invalid rangeStart: {}", scope.pool_start
        )));
    }
    if !scope.pool_end.is_empty() && !is_valid_ipv4_addr(&scope.pool_end) {
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
        if !is_valid_ipv4_addr(gw) {
            return Err(DhcpError::ValidationFailed(format!("invalid gateway: {gw}")));
        }
    }
    for dns in &scope.dns_servers {
        if !is_valid_ipv4_addr(dns) {
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

    apply_dhcp4_config(&cfg)
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
    if !is_valid_ipv4_addr(&req.ip_address) {
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

    apply_dhcp4_config(&cfg)
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

    apply_dhcp4_config(&cfg)
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

// ---------------------------------------------------------------------------
// GET /interfaces/{name}/dhcp/config
// ---------------------------------------------------------------------------

/// Get DHCP configuration for a specific interface.
///
/// Returns the DHCP configuration if the interface is enabled for DHCP,
/// otherwise returns an empty/disabled config.
pub async fn get_interface_dhcp_config(
    State(state): State<Arc<AppState>>,
    Path(interface_name): Path<String>,
) -> Result<impl IntoResponse, DhcpError> {
    let cfg = state
        .config_store
        .load_dhcp_config()
        .map_err(DhcpError::StorageError)?
        .unwrap_or_else(default_dhcp_cfg);

    // If the global config is for a different interface, return empty config
    if cfg.interface != interface_name && !cfg.interface.is_empty() {
        let empty_response = DhcpFlatConfigResponse {
            enabled: false,
            interface: interface_name.clone(),
            subnet: String::new(),
            range_start: String::new(),
            range_end: String::new(),
            subnet_mask: String::new(),
            gateway: String::new(),
            dns_servers: vec![],
            lease_time: 86400,
            domain_name: String::new(),
        };
        return Ok(Json(serde_json::json!({
            "success": true,
            "data": empty_response
        })));
    }

    info!(interface = %interface_name, "dhcp: loaded config for interface");

    Ok(Json(serde_json::json!({
        "success": true,
        "data": to_flat_response(&cfg)
    })))
}

// ---------------------------------------------------------------------------
// POST /interfaces/{name}/dhcp/config
// ---------------------------------------------------------------------------

/// Update DHCP configuration for a specific interface.
///
/// This sets the interface field in the global DHCP config to the provided
/// interface name, allowing per-interface DHCP management through the UI.
pub async fn update_interface_dhcp_config(
    State(state): State<Arc<AppState>>,
    Path(interface_name): Path<String>,
    Json(req): Json<UpdateDhcpFlatRequest>,
) -> Result<impl IntoResponse, DhcpError> {
    let mut cfg = state
        .config_store
        .load_dhcp_config()
        .map_err(DhcpError::StorageError)?
        .unwrap_or_else(default_dhcp_cfg);

    // Set the interface name explicitly
    cfg.interface = interface_name.clone();

    // Apply top-level fields.
    if let Some(v) = req.enabled    { cfg.enabled   = v; }

    // Ensure at least one scope exists to hold the pool settings.
    if cfg.scopes.is_empty() {
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

    if !scope.pool_start.is_empty() && !is_valid_ipv4_addr(&scope.pool_start) {
        return Err(DhcpError::ValidationFailed(format!(
            "invalid rangeStart: {}", scope.pool_start
        )));
    }
    if !scope.pool_end.is_empty() && !is_valid_ipv4_addr(&scope.pool_end) {
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
        if !is_valid_ipv4_addr(gw) {
            return Err(DhcpError::ValidationFailed(format!("invalid gateway: {gw}")));
        }
    }
    for dns in &scope.dns_servers {
        if !is_valid_ipv4_addr(dns) {
            return Err(DhcpError::ValidationFailed(format!("invalid DNS server: {dns}")));
        }
    }

    info!(
        enabled = cfg.enabled,
        interface = %cfg.interface,
        "dhcp: received update config request for interface"
    );

    // --- Persist -----------------------------------------------------------

    state
        .config_store
        .save_dhcp_config(cfg.clone())
        .map_err(DhcpError::StorageError)?;

    info!("dhcp: config persisted for interface");

    // --- Apply -------------------------------------------------------------

    apply_dhcp4_config(&cfg)
        .await
        .map_err(|e| DhcpError::EngineError(e.to_string()))?;

    info!("dhcp: engine apply complete for interface");

    Ok(Json(serde_json::json!({
        "success": true,
        "data": to_flat_response(&cfg)
    })))
}

// ---------------------------------------------------------------------------
// GET /interfaces/{name}/dhcp/static-leases
// ---------------------------------------------------------------------------

/// List static MAC → IP reservations for a specific interface.
///
/// Returns all reservations from scopes belonging to this interface.
pub async fn list_interface_static_leases(
    State(state): State<Arc<AppState>>,
    Path(interface_name): Path<String>,
) -> Result<impl IntoResponse, DhcpError> {
    let cfg = state
        .config_store
        .load_dhcp_config()
        .map_err(DhcpError::StorageError)?
        .unwrap_or_else(default_dhcp_cfg);

    // Only return leases if this config is for the requested interface
    let leases: Vec<DhcpStaticLeaseResponse> = if cfg.interface == interface_name {
        cfg.scopes
            .iter()
            .flat_map(|s| s.reservations.iter())
            .map(|r| DhcpStaticLeaseResponse {
                id: r.id.to_string(),
                mac: r.mac_address.clone(),
                ip_address: r.ip_address.clone(),
                hostname: r.hostname.clone().unwrap_or_default(),
                description: r.description.clone(),
            })
            .collect()
    } else {
        vec![]
    };

    Ok(Json(serde_json::json!({
        "success": true,
        "data": leases
    })))
}

// ---------------------------------------------------------------------------
// POST /interfaces/{name}/dhcp/static-leases
// ---------------------------------------------------------------------------

/// Add a static MAC → IP reservation for a specific interface.
///
/// Only allows creating leases for the interface specified in the URL.
/// Appends to the first scope of the interface's DHCP config.
pub async fn create_interface_static_lease(
    State(state): State<Arc<AppState>>,
    Path(interface_name): Path<String>,
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
    if !is_valid_ipv4_addr(&req.ip_address) {
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

    // Check that this config is for the requested interface
    if cfg.interface != interface_name {
        // If interface is empty, set it; otherwise reject
        if cfg.interface.is_empty() {
            cfg.interface = interface_name.clone();
        } else {
            return Err(DhcpError::ValidationFailed(format!(
                "DHCP config is for interface {}, not {}",
                cfg.interface, interface_name
            )));
        }
    }

    // Ensure at least one scope
    if cfg.scopes.is_empty() {
        cfg.scopes.push(DhcpScope {
            id: Uuid::new_v4(),
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

    apply_dhcp4_config(&cfg)
        .await
        .map_err(|e| DhcpError::EngineError(e.to_string()))?;

    info!(mac = %req.mac, ip = %req.ip_address, interface = %interface_name, "dhcp: static lease created for interface");

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "success": true, "data": resp })),
    ))
}

// ---------------------------------------------------------------------------
// DELETE /interfaces/{name}/dhcp/static-leases/{id}
// ---------------------------------------------------------------------------

/// Remove a static reservation by UUID for a specific interface.
///
/// Only removes leases from the specified interface's DHCP config.
pub async fn delete_interface_static_lease(
    State(state): State<Arc<AppState>>,
    Path((interface_name, id)): Path<(String, String)>,
) -> Result<impl IntoResponse, DhcpError> {
    let target = id.parse::<Uuid>().map_err(|_| {
        DhcpError::ValidationFailed(format!("invalid lease ID: {id}"))
    })?;

    let mut cfg = state
        .config_store
        .load_dhcp_config()
        .map_err(DhcpError::StorageError)?
        .unwrap_or_else(default_dhcp_cfg);

    // Check that this config is for the requested interface
    if cfg.interface != interface_name {
        return Err(DhcpError::ValidationFailed(format!(
            "DHCP config is for interface {}, not {}",
            cfg.interface, interface_name
        )));
    }

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
            "static lease {id} not found in interface {interface_name}"
        )));
    }

    state
        .config_store
        .save_dhcp_config(cfg.clone())
        .map_err(DhcpError::StorageError)?;

    apply_dhcp4_config(&cfg)
        .await
        .map_err(|e| DhcpError::EngineError(e.to_string()))?;

    info!(%id, interface = %interface_name, "dhcp: static lease deleted from interface");

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// DHCPv6 API DTO types (camelCase for UI compatibility)
// ---------------------------------------------------------------------------

/// Response for a single DHCPv6 static lease.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Dhcp6StaticLeaseResponse {
    pub id: String,
    pub duid: String,
    pub ip_address: String,
    pub hostname: String,
    pub description: String,
}

/// Request body for `POST /dhcp6/static-leases`.
/// Accepts either a raw DUID or a MAC address (which is auto-converted to DUID-LL).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateDhcp6StaticLeaseRequest {
    /// Raw DUID (colon-separated hex). Takes precedence over `mac` if both provided.
    pub duid: Option<String>,
    /// MAC address (aa:bb:cc:dd:ee:ff). Converted to DUID-LL: 00:03:00:01:<mac>.
    pub mac: Option<String>,
    pub ip_address: String,
    pub hostname: Option<String>,
    pub description: Option<String>,
}

/// Response for a single active DHCPv6 lease.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Dhcp6LeaseResponse {
    pub ip_address: String,
    pub duid: String,
    pub hostname: String,
    pub ends: String,
    pub state: String,
}

/// Flat DHCPv6 config response matching the TypeScript `Dhcp6Config` interface.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Dhcp6FlatConfigResponse {
    pub enabled: bool,
    pub interface: String,
    /// Subnet in CIDR notation (e.g. `fd00::/64`).
    pub subnet: String,
    pub range_start: String,
    pub range_end: String,
    pub dns_servers: Vec<String>,
    pub lease_time: u32,
    pub domain_name: String,
}

/// Request body for `POST /dhcp6/config`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateDhcp6FlatRequest {
    pub enabled: Option<bool>,
    pub interface: Option<String>,
    pub subnet: Option<String>,
    pub range_start: Option<String>,
    pub range_end: Option<String>,
    pub dns_servers: Option<Vec<String>>,
    pub lease_time: Option<u32>,
    pub domain_name: Option<String>,
}

fn default_dhcp6_cfg() -> Dhcp6Config {
    Dhcp6Config {
        enabled: false,
        interface: String::new(),
        scopes: vec![],
    }
}

fn to_flat_response_v6(cfg: &Dhcp6Config) -> Dhcp6FlatConfigResponse {
    if let Some(scope) = cfg.scopes.first() {
        Dhcp6FlatConfigResponse {
            enabled: cfg.enabled,
            interface: cfg.interface.clone(),
            subnet: scope.subnet.clone(),
            range_start: scope.pool_start.clone(),
            range_end: scope.pool_end.clone(),
            dns_servers: scope.dns_servers.clone(),
            lease_time: scope.lease_seconds,
            domain_name: scope.domain_name.clone().unwrap_or_default(),
        }
    } else {
        Dhcp6FlatConfigResponse {
            enabled: cfg.enabled,
            interface: cfg.interface.clone(),
            subnet: String::new(),
            range_start: String::new(),
            range_end: String::new(),
            dns_servers: vec![],
            lease_time: 86400,
            domain_name: String::new(),
        }
    }
}

fn derive_subnet_from_ipv6_addr(addr: &str) -> String {
    if let Ok(ip) = addr.parse::<Ipv6Addr>() {
        let seg = ip.segments();
        return format!("{:x}:{:x}:{:x}:{:x}::/64", seg[0], seg[1], seg[2], seg[3]);
    }
    "fd00::/64".to_string()
}

fn is_valid_ipv6_range(start: &str, end: &str) -> bool {
    match (start.parse::<Ipv6Addr>(), end.parse::<Ipv6Addr>()) {
        (Ok(s), Ok(e)) => u128::from(s) <= u128::from(e),
        _ => false,
    }
}

fn validate_dhcp6_scope(scope: &Dhcp6Scope) -> Result<(), DhcpError> {
    if scope.subnet.trim().is_empty() {
        return Err(DhcpError::ValidationFailed(
            "subnet is required when a DHCPv6 scope is configured".to_string(),
        ));
    }
    if !is_valid_ipv6_cidr(&scope.subnet) {
        return Err(DhcpError::ValidationFailed(format!(
            "invalid subnet: {}",
            scope.subnet
        )));
    }
    if scope.pool_start.trim().is_empty() {
        return Err(DhcpError::ValidationFailed(
            "rangeStart is required when a DHCPv6 scope is configured".to_string(),
        ));
    }
    if !is_valid_ipv6_addr(&scope.pool_start) {
        return Err(DhcpError::ValidationFailed(format!(
            "invalid rangeStart: {}",
            scope.pool_start
        )));
    }
    if scope.pool_end.trim().is_empty() {
        return Err(DhcpError::ValidationFailed(
            "rangeEnd is required when a DHCPv6 scope is configured".to_string(),
        ));
    }
    if !is_valid_ipv6_addr(&scope.pool_end) {
        return Err(DhcpError::ValidationFailed(format!(
            "invalid rangeEnd: {}",
            scope.pool_end
        )));
    }
    if !is_valid_ipv6_range(&scope.pool_start, &scope.pool_end) {
        return Err(DhcpError::ValidationFailed(format!(
            "rangeStart {} must be <= rangeEnd {}",
            scope.pool_start, scope.pool_end
        )));
    }
    if scope.lease_seconds == 0 {
        return Err(DhcpError::ValidationFailed(
            "leaseTime must be greater than 0".to_string(),
        ));
    }
    for dns in &scope.dns_servers {
        if !is_valid_ipv6_addr(dns) {
            return Err(DhcpError::ValidationFailed(format!("invalid DNS server: {dns}")));
        }
    }
    for reservation in &scope.reservations {
        if !is_valid_duid(&reservation.duid) {
            return Err(DhcpError::ValidationFailed(format!(
                "invalid DUID in reservation {}: {}",
                reservation.id, reservation.duid
            )));
        }
        if !is_valid_ipv6_addr(&reservation.ip_address) {
            return Err(DhcpError::ValidationFailed(format!(
                "invalid IPv6 address in reservation {}: {}",
                reservation.id, reservation.ip_address
            )));
        }
        if !ipv6_addr_in_cidr(&reservation.ip_address, &scope.subnet) {
            return Err(DhcpError::ValidationFailed(format!(
                "reservation IPv6 address {} is outside subnet {}",
                reservation.ip_address, scope.subnet
            )));
        }
    }
    Ok(())
}

fn validate_dhcp6_config_for_apply(cfg: &Dhcp6Config) -> Result<(), DhcpError> {
    if cfg.enabled {
        if cfg.interface.trim().is_empty() {
            return Err(DhcpError::ValidationFailed(
                "interface is required when DHCPv6 is enabled".to_string(),
            ));
        }
        if cfg.scopes.is_empty() {
            return Err(DhcpError::ValidationFailed(
                "at least one DHCPv6 scope is required when DHCPv6 is enabled".to_string(),
            ));
        }
    }

    for scope in &cfg.scopes {
        validate_dhcp6_scope(scope)?;
    }

    Ok(())
}

fn dhcp6_request_has_scope_values(req: &UpdateDhcp6FlatRequest) -> bool {
    req.subnet.as_deref().is_some_and(|s| !s.trim().is_empty())
        || req.range_start.as_deref().is_some_and(|s| !s.trim().is_empty())
        || req.range_end.as_deref().is_some_and(|s| !s.trim().is_empty())
        || req
            .dns_servers
            .as_ref()
            .is_some_and(|servers| !servers.is_empty())
        || req
            .domain_name
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty())
}

fn apply_dhcp6_scope_request(cfg: &mut Dhcp6Config, req: UpdateDhcp6FlatRequest) {
    if cfg.scopes.is_empty() {
        if !cfg.enabled && !dhcp6_request_has_scope_values(&req) {
            return;
        }

        let subnet = req
            .subnet
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().to_string())
            .or_else(|| {
                req.range_start
                    .as_deref()
                    .filter(|s| !s.trim().is_empty())
                    .map(derive_subnet_from_ipv6_addr)
            })
            .unwrap_or_else(|| "fd00::/64".to_string());

        cfg.scopes.push(Dhcp6Scope {
            id: Uuid::new_v4(),
            subnet,
            pool_start: String::new(),
            pool_end: String::new(),
            dns_servers: vec![],
            lease_seconds: 86400,
            domain_name: None,
            reservations: vec![],
        });
    }

    let scope = &mut cfg.scopes[0];
    if let Some(v) = req.subnet.filter(|s| !s.trim().is_empty()) {
        scope.subnet = v.trim().to_string();
    }
    if let Some(v) = req.range_start {
        scope.pool_start = v.trim().to_string();
    }
    if let Some(v) = req.range_end {
        scope.pool_end = v.trim().to_string();
    }
    if let Some(v) = req.dns_servers {
        scope.dns_servers = v
            .into_iter()
            .map(|dns| dns.trim().to_string())
            .filter(|dns| !dns.is_empty())
            .collect();
    }
    if let Some(v) = req.lease_time {
        scope.lease_seconds = v;
    }
    if let Some(v) = req.domain_name {
        let domain = v.trim().to_string();
        scope.domain_name = if domain.is_empty() { None } else { Some(domain) };
    }
}

fn ipv6_addr_in_cidr(addr: &str, cidr: &str) -> bool {
    let Some((network, prefix_text)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(addr) = addr.parse::<Ipv6Addr>() else {
        return false;
    };
    let Ok(network) = network.parse::<Ipv6Addr>() else {
        return false;
    };
    let Ok(prefix) = prefix_text.parse::<u32>() else {
        return false;
    };
    if prefix > 128 {
        return false;
    }

    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };

    (u128::from(addr) & mask) == (u128::from(network) & mask)
}

fn dhcp6_static_response(reservation: &Dhcp6Reservation) -> Dhcp6StaticLeaseResponse {
    Dhcp6StaticLeaseResponse {
        id: reservation.id.to_string(),
        duid: reservation.duid.clone(),
        ip_address: reservation.ip_address.clone(),
        hostname: reservation.hostname.clone().unwrap_or_default(),
        description: reservation.description.clone(),
    }
}

fn normalize_dhcp6_reservation_duid(
    req: &CreateDhcp6StaticLeaseRequest,
) -> Result<String, DhcpError> {
    let duid = if let Some(d) = req.duid.as_deref().filter(|s| !s.trim().is_empty()) {
        d.trim().to_ascii_lowercase()
    } else if let Some(mac) = req.mac.as_deref().filter(|s| !s.trim().is_empty()) {
        let mac = mac.trim().to_ascii_lowercase();
        if !is_valid_mac(&mac) {
            return Err(DhcpError::ValidationFailed(format!(
                "invalid MAC address: {mac} (expected aa:bb:cc:dd:ee:ff)"
            )));
        }
        format!("00:03:00:01:{mac}")
    } else {
        return Err(DhcpError::ValidationFailed(
            "either 'duid' or 'mac' must be provided".to_string(),
        ));
    };

    if !is_valid_duid(&duid) {
        return Err(DhcpError::ValidationFailed(format!(
            "invalid DUID: {duid}"
        )));
    }

    Ok(duid)
}

fn add_dhcp6_reservation(
    cfg: &mut Dhcp6Config,
    req: CreateDhcp6StaticLeaseRequest,
    interface_name: Option<&str>,
) -> Result<Dhcp6StaticLeaseResponse, DhcpError> {
    if let Some(interface_name) = interface_name {
        if cfg.interface != interface_name {
            if cfg.interface.is_empty() {
                cfg.interface = interface_name.to_string();
            } else {
                return Err(DhcpError::ValidationFailed(format!(
                    "DHCPv6 config is for interface {}, not {}",
                    cfg.interface, interface_name
                )));
            }
        }
    }

    let duid = normalize_dhcp6_reservation_duid(&req)?;
    let ip_address = req.ip_address.trim().to_string();

    if !is_valid_ipv6_addr(&ip_address) {
        return Err(DhcpError::ValidationFailed(format!(
            "invalid IPv6 address: {}",
            req.ip_address
        )));
    }

    if cfg.scopes.is_empty() {
        return Err(DhcpError::ValidationFailed(
            "configure a DHCPv6 scope before adding static reservations".to_string(),
        ));
    }

    if cfg
        .scopes
        .iter()
        .flat_map(|scope| scope.reservations.iter())
        .any(|reservation| reservation.duid.eq_ignore_ascii_case(&duid))
    {
        return Err(DhcpError::ValidationFailed(format!(
            "DUID {duid} already has a DHCPv6 reservation"
        )));
    }

    if cfg
        .scopes
        .iter()
        .flat_map(|scope| scope.reservations.iter())
        .any(|reservation| reservation.ip_address.eq_ignore_ascii_case(&ip_address))
    {
        return Err(DhcpError::ValidationFailed(format!(
            "IPv6 address {ip_address} already has a DHCPv6 reservation"
        )));
    }

    let Some(scope_index) = cfg
        .scopes
        .iter()
        .position(|scope| ipv6_addr_in_cidr(&ip_address, &scope.subnet))
    else {
        return Err(DhcpError::ValidationFailed(format!(
            "reserved IPv6 address {ip_address} is outside the configured DHCPv6 scopes"
        )));
    };

    let reservation = Dhcp6Reservation {
        id: Uuid::new_v4(),
        duid,
        ip_address,
        hostname: req
            .hostname
            .map(|h| h.trim().to_string())
            .filter(|h| !h.is_empty()),
        description: req.description.unwrap_or_default().trim().to_string(),
    };

    let resp = dhcp6_static_response(&reservation);
    cfg.scopes[scope_index].reservations.push(reservation);
    validate_dhcp6_config_for_apply(cfg)?;

    Ok(resp)
}

/// Return the DHCPv6 configuration in a flat format compatible with the UI.
pub async fn get_config_v6(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, DhcpError> {
    let cfg = state
        .config_store
        .load_dhcp6_config()
        .map_err(DhcpError::StorageError)?
        .unwrap_or_else(default_dhcp6_cfg);

    Ok(Json(serde_json::json!({
        "success": true,
        "data": to_flat_response_v6(&cfg)
    })))
}

/// Update the DHCPv6 configuration from a flat request body.
pub async fn update_config_v6(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpdateDhcp6FlatRequest>,
) -> Result<impl IntoResponse, DhcpError> {
    let mut cfg = state
        .config_store
        .load_dhcp6_config()
        .map_err(DhcpError::StorageError)?
        .unwrap_or_else(default_dhcp6_cfg);

    if let Some(v) = req.enabled { cfg.enabled = v; }
    if let Some(v) = req.interface.as_deref() { cfg.interface = v.trim().to_string(); }

    apply_dhcp6_scope_request(&mut cfg, req);
    validate_dhcp6_config_for_apply(&cfg)?;

    state
        .config_store
        .save_dhcp6_config(cfg.clone())
        .map_err(DhcpError::StorageError)?;

    apply_dhcp6_config(&cfg)
        .await
        .map_err(|e| DhcpError::EngineError(e.to_string()))?;

    Ok(Json(serde_json::json!({
        "success": true,
        "data": to_flat_response_v6(&cfg)
    })))
}

/// Get DHCPv6 configuration for a specific interface.
pub async fn get_interface_dhcp6_config(
    State(state): State<Arc<AppState>>,
    Path(interface_name): Path<String>,
) -> Result<impl IntoResponse, DhcpError> {
    let cfg = state
        .config_store
        .load_dhcp6_config()
        .map_err(DhcpError::StorageError)?
        .unwrap_or_else(default_dhcp6_cfg);

    if cfg.interface != interface_name && !cfg.interface.is_empty() {
        let empty_response = Dhcp6FlatConfigResponse {
            enabled: false,
            interface: interface_name,
            subnet: String::new(),
            range_start: String::new(),
            range_end: String::new(),
            dns_servers: vec![],
            lease_time: 86400,
            domain_name: String::new(),
        };
        return Ok(Json(serde_json::json!({
            "success": true,
            "data": empty_response
        })));
    }

    Ok(Json(serde_json::json!({
        "success": true,
        "data": to_flat_response_v6(&cfg)
    })))
}

/// Update DHCPv6 configuration for a specific interface.
pub async fn update_interface_dhcp6_config(
    State(state): State<Arc<AppState>>,
    Path(interface_name): Path<String>,
    Json(req): Json<UpdateDhcp6FlatRequest>,
) -> Result<impl IntoResponse, DhcpError> {
    let mut cfg = state
        .config_store
        .load_dhcp6_config()
        .map_err(DhcpError::StorageError)?
        .unwrap_or_else(default_dhcp6_cfg);

    cfg.interface = interface_name;
    if let Some(v) = req.enabled { cfg.enabled = v; }

    apply_dhcp6_scope_request(&mut cfg, req);
    validate_dhcp6_config_for_apply(&cfg)?;

    state
        .config_store
        .save_dhcp6_config(cfg.clone())
        .map_err(DhcpError::StorageError)?;

    apply_dhcp6_config(&cfg)
        .await
        .map_err(|e| DhcpError::EngineError(e.to_string()))?;

    Ok(Json(serde_json::json!({
        "success": true,
        "data": to_flat_response_v6(&cfg)
    })))
}

// ---------------------------------------------------------------------------
// GET /dhcp6/static-leases
// ---------------------------------------------------------------------------

/// Return all DUID → IPv6 static reservations across all DHCPv6 scopes.
pub async fn list_dhcp6_static_leases(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, DhcpError> {
    let cfg = state
        .config_store
        .load_dhcp6_config()
        .map_err(DhcpError::StorageError)?
        .unwrap_or_else(default_dhcp6_cfg);

    let leases: Vec<Dhcp6StaticLeaseResponse> = cfg
        .scopes
        .iter()
        .flat_map(|s| s.reservations.iter())
        .map(|r| Dhcp6StaticLeaseResponse {
            id: r.id.to_string(),
            duid: r.duid.clone(),
            ip_address: r.ip_address.clone(),
            hostname: r.hostname.clone().unwrap_or_default(),
            description: r.description.clone(),
        })
        .collect();

    Ok(Json(serde_json::json!({ "success": true, "data": leases })))
}

// ---------------------------------------------------------------------------
// GET /interfaces/{name}/dhcp6/static-leases
// ---------------------------------------------------------------------------

/// Return DUID -> IPv6 reservations for a specific DHCPv6 interface.
pub async fn list_interface_dhcp6_static_leases(
    State(state): State<Arc<AppState>>,
    Path(interface_name): Path<String>,
) -> Result<impl IntoResponse, DhcpError> {
    let cfg = state
        .config_store
        .load_dhcp6_config()
        .map_err(DhcpError::StorageError)?
        .unwrap_or_else(default_dhcp6_cfg);

    let leases: Vec<Dhcp6StaticLeaseResponse> = if cfg.interface == interface_name {
        cfg.scopes
            .iter()
            .flat_map(|s| s.reservations.iter())
            .map(dhcp6_static_response)
            .collect()
    } else {
        vec![]
    };

    Ok(Json(serde_json::json!({ "success": true, "data": leases })))
}

// ---------------------------------------------------------------------------
// POST /dhcp6/static-leases
// ---------------------------------------------------------------------------

/// Add a DUID → IPv6 static reservation to the first DHCPv6 scope.
///
/// Accepts either a raw `duid` or a `mac` address which is automatically
/// converted to a DUID-LL (`00:03:00:01:<mac>`).
pub async fn create_dhcp6_static_lease(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateDhcp6StaticLeaseRequest>,
) -> Result<impl IntoResponse, DhcpError> {
    let mut cfg = state
        .config_store
        .load_dhcp6_config()
        .map_err(DhcpError::StorageError)?
        .unwrap_or_else(default_dhcp6_cfg);

    let resp = add_dhcp6_reservation(&mut cfg, req, None)?;

    state
        .config_store
        .save_dhcp6_config(cfg.clone())
        .map_err(DhcpError::StorageError)?;

    apply_dhcp6_config(&cfg)
        .await
        .map_err(|e| DhcpError::EngineError(e.to_string()))?;

    info!(duid = %resp.duid, ip = %resp.ip_address, "dhcp6: static lease created");

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "success": true, "data": resp })),
    ))
}

// ---------------------------------------------------------------------------
// POST /interfaces/{name}/dhcp6/static-leases
// ---------------------------------------------------------------------------

/// Add a DUID -> IPv6 reservation for a specific DHCPv6 interface.
pub async fn create_interface_dhcp6_static_lease(
    State(state): State<Arc<AppState>>,
    Path(interface_name): Path<String>,
    Json(req): Json<CreateDhcp6StaticLeaseRequest>,
) -> Result<impl IntoResponse, DhcpError> {
    let mut cfg = state
        .config_store
        .load_dhcp6_config()
        .map_err(DhcpError::StorageError)?
        .unwrap_or_else(default_dhcp6_cfg);

    let resp = add_dhcp6_reservation(&mut cfg, req, Some(&interface_name))?;

    state
        .config_store
        .save_dhcp6_config(cfg.clone())
        .map_err(DhcpError::StorageError)?;

    apply_dhcp6_config(&cfg)
        .await
        .map_err(|e| DhcpError::EngineError(e.to_string()))?;

    info!(
        duid = %resp.duid,
        ip = %resp.ip_address,
        interface = %interface_name,
        "dhcp6: static lease created for interface"
    );

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "success": true, "data": resp })),
    ))
}

// ---------------------------------------------------------------------------
// DELETE /dhcp6/static-leases/{id}
// ---------------------------------------------------------------------------

/// Remove a DHCPv6 static reservation by UUID string.
pub async fn delete_dhcp6_static_lease(
    Path(id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, DhcpError> {
    let target = id.parse::<Uuid>().map_err(|_| {
        DhcpError::ValidationFailed(format!("invalid lease ID: {id}"))
    })?;

    let mut cfg = state
        .config_store
        .load_dhcp6_config()
        .map_err(DhcpError::StorageError)?
        .unwrap_or_else(default_dhcp6_cfg);

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
            "DHCPv6 static lease {id} not found"
        )));
    }

    state
        .config_store
        .save_dhcp6_config(cfg.clone())
        .map_err(DhcpError::StorageError)?;

    apply_dhcp6_config(&cfg)
        .await
        .map_err(|e| DhcpError::EngineError(e.to_string()))?;

    info!(%id, "dhcp6: static lease deleted");

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// DELETE /interfaces/{name}/dhcp6/static-leases/{id}
// ---------------------------------------------------------------------------

/// Remove a DHCPv6 static reservation by UUID for a specific interface.
pub async fn delete_interface_dhcp6_static_lease(
    State(state): State<Arc<AppState>>,
    Path((interface_name, id)): Path<(String, String)>,
) -> Result<impl IntoResponse, DhcpError> {
    let target = id.parse::<Uuid>().map_err(|_| {
        DhcpError::ValidationFailed(format!("invalid lease ID: {id}"))
    })?;

    let mut cfg = state
        .config_store
        .load_dhcp6_config()
        .map_err(DhcpError::StorageError)?
        .unwrap_or_else(default_dhcp6_cfg);

    if cfg.interface != interface_name {
        return Err(DhcpError::ValidationFailed(format!(
            "DHCPv6 config is for interface {}, not {}",
            cfg.interface, interface_name
        )));
    }

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
            "DHCPv6 static lease {id} not found in interface {interface_name}"
        )));
    }

    validate_dhcp6_config_for_apply(&cfg)?;

    state
        .config_store
        .save_dhcp6_config(cfg.clone())
        .map_err(DhcpError::StorageError)?;

    apply_dhcp6_config(&cfg)
        .await
        .map_err(|e| DhcpError::EngineError(e.to_string()))?;

    info!(%id, interface = %interface_name, "dhcp6: static lease deleted from interface");

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// GET /dhcp6/leases
// ---------------------------------------------------------------------------

/// Return active DHCPv6 leases parsed from the Kea DHCPv6 memfile lease database.
///
/// Kea DHCPv6 CSV columns:
/// `address,duid,iaid,prefix-len,type,preferred-life,valid-life,expire,subnet-id,
///  fqdn-fwd,fqdn-rev,hostname,hwaddr,state[,user-context,hwtype,hwaddr-source]`
///
/// Returns an empty array when the lease file does not exist.
pub async fn list_active_dhcp6_leases(
    State(_state): State<Arc<AppState>>,
) -> impl IntoResponse {
    use crate::engine::dhcp6::KEA6_LEASES_PATH;

    let content = match tokio::fs::read_to_string(KEA6_LEASES_PATH).await {
        Ok(c) => c,
        Err(_) => {
            return Json(serde_json::json!({ "success": true, "data": serde_json::json!([]) }));
        }
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let leases: Vec<Dhcp6LeaseResponse> = content
        .lines()
        .filter(|l| !l.starts_with("address") && !l.is_empty())
        .filter_map(|line| {
            // Columns: address(0), duid(1), iaid(2), prefix-len(3), type(4),
            // preferred-life(5), valid-life(6), expire(7), subnet-id(8),
            // fqdn-fwd(9), fqdn-rev(10), hostname(11), hwaddr(12), state(13)
            let cols: Vec<&str> = line.splitn(15, ',').collect();
            if cols.len() < 14 {
                return None;
            }
            if cols[4].trim() != "0" {
                return None;
            }
            let address     = cols[0].to_string();
            if !is_valid_ipv6_addr(&address) {
                return None;
            }
            let duid        = cols[1].to_string();
            let expire: u64 = cols[7].parse().ok()?;
            let hostname    = cols[11].to_string();
            let state_col: u8 = cols[13].trim().parse().unwrap_or(0);
            let state_str = match state_col {
                0 if expire > now => "active",
                0                 => "expired",
                1                 => "declined",
                _                 => "reclaimed",
            };
            Some(Dhcp6LeaseResponse {
                ip_address: address,
                duid,
                hostname,
                ends: expire.to_string(),
                state: state_str.to_string(),
            })
        })
        .collect();

    Json(serde_json::json!({ "success": true, "data": leases }))
}
