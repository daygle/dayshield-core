//! Interface endpoints — `GET /interfaces` and `POST /interfaces`.
//!
//! # GET /interfaces
//!
//! Returns a combined view of:
//! - `configured` — the interface list persisted in config storage.
//! - `kernel`     — live interfaces discovered via `ip -j link` / `ip -j addr`.
//!
//! # POST /interfaces
//!
//! Accepts an [`Interface`] JSON body, validates it, atomically persists it,
//! and triggers the engine to apply the changes to the kernel.

use std::sync::Arc;

use axum::{extract::{Path, State}, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::{
    config::models::{is_valid_cidr, is_valid_interface_name, is_valid_mss, is_valid_mtu, Interface},
    engine::gateway::list_kernel_gateways,
    engine::interfaces::{apply_interface, list_kernel_interfaces, InterfaceError, KernelInterface},
    state::AppState,
};

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// Serializable interface for API responses (converts CIDR to separate fields).
#[derive(Serialize)]
#[serde(crate = "serde")]
pub struct InterfaceResponse {
    pub name: String,
    pub description: Option<String>,
    pub r#type: String,  // Inferred from config (e.g. "vlan" if vlan tag present, else "ethernet")
    pub enabled: bool,
    pub dhcp4: bool,
    pub dhcp6: bool,
    pub mtu: Option<u16>,
    pub mss: Option<u16>,
    pub vlan: Option<u16>,
    pub wan_mode: Option<String>,      // "dhcp" or "pppoe"
    pub pppoe_username: Option<String>,
    pub ipv4_address: Option<String>,  // First address from CIDR (e.g. "192.168.1.1")
    pub ipv4_prefix: Option<u8>,       // Prefix from first address (e.g. 24)
    pub gateway: Option<String>,
}

impl InterfaceResponse {
    /// Convert from a backend `Interface` to API response format.
    pub fn from_interface(iface: &Interface) -> Self {
        // Parse first address if available
        let (ipv4_address, ipv4_prefix) = iface
            .addresses
            .first()
            .and_then(|cidr| {
                let parts: Vec<&str> = cidr.split('/').collect();
                match parts.as_slice() {
                    [addr, prefix_str] => {
                        prefix_str.parse::<u8>().ok().map(|p| (addr.to_string(), p))
                    }
                    _ => None,
                }
            })
            .map(|(addr, prefix)| (Some(addr), Some(prefix)))
            .unwrap_or((None, None));

        let wan_mode = iface.wan_mode.as_ref().map(|m| {
            match m {
                crate::config::models::WanMode::Dhcp => "dhcp".to_string(),
                crate::config::models::WanMode::Pppoe => "pppoe".to_string(),
            }
        });

        // Infer type from config (vlan if vlan tag present, else ethernet)
        let r#type = if iface.vlan.is_some() {
            "vlan".to_string()
        } else {
            "ethernet".to_string()
        };

        Self {
            name: iface.name.clone(),
            description: iface.description.clone(),
            r#type,
            enabled: iface.enabled,
            dhcp4: iface.dhcp4,
            dhcp6: iface.dhcp6,
            mtu: iface.mtu,
            mss: iface.mss,
            vlan: iface.vlan,
            wan_mode,
            pppoe_username: iface.pppoe_username.clone(),
            ipv4_address,
            ipv4_prefix,
            gateway: iface.gateway.clone(),
        }
    }
}

/// Response body for `GET /interfaces`.
#[derive(Serialize)]
pub struct ListInterfacesResponse {
    /// Interfaces stored in persistent configuration (converted to API format).
    pub configured: Vec<InterfaceResponse>,
    /// Interfaces currently visible to the kernel.
    pub kernel: Vec<KernelInterface>,
}

/// Request body for creating/updating an interface (from UI).
#[derive(Deserialize)]
pub struct InterfaceRequest {
    pub name: String,
    pub description: Option<String>,
    pub r#type: Option<String>,
    pub enabled: bool,
    pub dhcp4: bool,
    pub dhcp6: Option<bool>,
    pub mtu: Option<u16>,
    pub mss: Option<u16>,
    pub vlan: Option<u16>,
    pub wan_mode: Option<String>,      // "dhcp" or "pppoe"
    pub pppoe_username: Option<String>,
    pub pppoe_password: Option<String>,
    pub ipv4_address: Option<String>,  // UI sends this as separate field
    pub ipv4_prefix: Option<u8>,       // UI sends this as separate field
    pub gateway: Option<String>,
}

impl InterfaceRequest {
    /// Convert from API request format to backend `Interface`.
    pub fn to_interface(self) -> Interface {
        // Build addresses from ipv4_address and ipv4_prefix
        let addresses = if let (Some(addr), Some(prefix)) = (self.ipv4_address, self.ipv4_prefix) {
            vec![format!("{}/{}", addr, prefix)]
        } else {
            vec![]
        };

        let wan_mode = match self.wan_mode.as_deref() {
            Some("pppoe") => Some(crate::config::models::WanMode::Pppoe),
            Some("dhcp") => Some(crate::config::models::WanMode::Dhcp),
            _ => None,
        };

        Interface {
            name: self.name,
            description: self.description,
            addresses,
            mtu: self.mtu,
            mss: self.mss,
            enabled: self.enabled,
            dhcp4: self.dhcp4,
            dhcp6: self.dhcp6.unwrap_or(false),
            vlan: self.vlan,
            wan_mode,
            pppoe_username: self.pppoe_username,
            pppoe_password: self.pppoe_password,
            gateway: self.gateway,
        }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Handler: list configured and kernel-visible network interfaces.
pub async fn list_interfaces(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, InterfaceError> {
    // Load configured interfaces from persistent storage.
    let configured = state
        .config_store
        .load_interfaces()
        .map_err(InterfaceError::StorageError)?;

    info!(count = configured.len(), "interfaces: loaded configured interfaces");

    // Sync the in-memory cache with what is on disk.
    {
        let mut ifaces = state.interfaces.write().await;
        *ifaces = configured.clone();
    }

    // Discover kernel interfaces.
    let kernel = match list_kernel_interfaces().await {
        Ok(k) => k,
        Err(e) => {
            warn!(error = %e, "interfaces: kernel discovery failed; returning empty list");
            vec![]
        }
    };

    info!(count = kernel.len(), "interfaces: discovered kernel interfaces");

    // Convert to response format (this also redacts pppoe_password).
    let configured_response: Vec<InterfaceResponse> = configured
        .iter()
        .map(InterfaceResponse::from_interface)
        .collect();

    // If an interface has no static gateway configured, surface any active
    // default-route gateway currently seen in the kernel for that interface.
    let active_gateways = list_kernel_gateways().await;
    let configured_response = configured_response
        .into_iter()
        .map(|mut iface| {
            if iface.gateway.is_none() {
                iface.gateway = active_gateways
                    .iter()
                    .find(|gw| gw.interface == iface.name)
                    .and_then(|gw| gw.gateway_ip.clone());
            }
            iface
        })
        .collect::<Vec<_>>();

    Ok(Json(ListInterfacesResponse { configured: configured_response, kernel }))
}

/// Handler: create or update a network interface.
///
/// Accepts an [`InterfaceRequest`] from the UI, converts it to backend format,
/// validates it, upserts it in the in-memory cache and persistent storage,
/// then asks the engine to apply the configuration.
pub async fn create_interface(
    State(state): State<Arc<AppState>>,
    Json(req): Json<InterfaceRequest>,
) -> Result<impl IntoResponse, InterfaceError> {
    let iface = req.to_interface();

    // --- Validation --------------------------------------------------------

    if !is_valid_interface_name(&iface.name) {
        return Err(InterfaceError::InvalidName(iface.name.clone()));
    }

    if let Some(mtu) = iface.mtu {
        if !is_valid_mtu(mtu) {
            return Err(InterfaceError::InvalidMtu(mtu));
        }
    }

    if let Some(mss) = iface.mss {
        if !is_valid_mss(mss) {
            return Err(InterfaceError::InvalidMss(mss));
        }
    }

    for cidr in &iface.addresses {
        if !is_valid_cidr(cidr) {
            return Err(InterfaceError::InvalidCIDR(cidr.clone()));
        }
    }

    info!(
        name = %iface.name,
        enabled = iface.enabled,
        "interfaces: received create/update request"
    );

    // --- Persist -----------------------------------------------------------

    // Upsert in the in-memory cache (match by name).
    {
        let mut ifaces = state.interfaces.write().await;
        match ifaces.iter().position(|i| i.name == iface.name) {
            Some(pos) => ifaces[pos] = iface.clone(),
            None => ifaces.push(iface.clone()),
        }
    }

    // Atomically write the updated list to disk.
    {
        let ifaces = state.interfaces.read().await;
        state
            .config_store
            .save_interfaces(ifaces.clone())
            .map_err(InterfaceError::StorageError)?;
    }

    info!(name = %iface.name, "interfaces: configuration persisted");

    // --- Apply -------------------------------------------------------------

    apply_interface(&iface).await?;

    info!(name = %iface.name, "interfaces: engine apply complete");

    Ok((StatusCode::CREATED, Json(InterfaceResponse::from_interface(&iface))))
}

// ---------------------------------------------------------------------------
// DELETE /interfaces/{name}
// ---------------------------------------------------------------------------

/// Remove a configured interface by name.
///
/// Updates the in-memory cache and persistent storage, then attempts to bring
/// the interface down via `ip link set <name> down` (best-effort).
pub async fn delete_interface(
    Path(name): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, InterfaceError> {
    // --- Remove from in-memory cache ---------------------------------------
    {
        let mut ifaces = state.interfaces.write().await;
        let before = ifaces.len();
        ifaces.retain(|i| i.name != name);
        if ifaces.len() == before {
            return Err(InterfaceError::NotFound(name));
        }
    }

    // --- Persist -----------------------------------------------------------
    {
        let ifaces = state.interfaces.read().await;
        state
            .config_store
            .save_interfaces(ifaces.clone())
            .map_err(InterfaceError::StorageError)?;
    }

    // --- Best-effort kernel teardown ---------------------------------------
    let _ = tokio::process::Command::new("ip")
        .args(["link", "set", &name, "down"])
        .output()
        .await;

    info!(%name, "interfaces: deleted interface");

    Ok(StatusCode::NO_CONTENT)
}
