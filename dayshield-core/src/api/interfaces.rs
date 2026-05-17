//! Interface endpoints - `GET /interfaces` and `POST /interfaces`.
//!
//! # GET /interfaces
//!
//! Returns a combined view of:
//! - `configured` - the interface list persisted in config storage.
//! - `kernel`     - live interfaces discovered via `ip -j link` / `ip -j addr`.
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
    config::models::{
        ensure_ipv6_allowed, is_valid_cidr, is_valid_interface_name, is_valid_mss, is_valid_mtu,
        is_valid_vlan_id, Ipv6Mode, RouterAdvertisementMode,
        WanMode,
        Gateway, Interface,
    },
    engine::gateway::list_kernel_gateways_with_ipv6,
    engine::interfaces::{
        apply_interface_with_ipv6, list_kernel_interfaces, refresh_router_advertisements,
        InterfaceError, KernelInterface,
    },
    engine::nftables::apply_rules,
    state::AppState,
};

const AUTO_GATEWAY_DESCRIPTION: &str = "Auto-managed from WAN interface settings";

fn derive_nat_wan_interfaces(interfaces: &[Interface]) -> Vec<String> {
    interfaces
        .iter()
        .filter(|iface| iface.enabled && (iface.wan_mode.is_some() || iface.gateway.is_some()))
        .map(|iface| iface.name.clone())
        .collect()
}

fn sync_nat_wan_interfaces(
    state: &Arc<AppState>,
    interfaces: &[Interface],
) -> Result<bool, InterfaceError> {
    let mut nat_cfg = state
        .config_store
        .load_nat_config()
        .map_err(InterfaceError::StorageError)?
        .unwrap_or_default();

    let next_wan_interfaces = derive_nat_wan_interfaces(interfaces);
    if nat_cfg.wan_interfaces == next_wan_interfaces {
        return Ok(false);
    }

    nat_cfg.wan_interfaces = next_wan_interfaces;
    state
        .config_store
        .save_nat_config(nat_cfg)
        .map_err(InterfaceError::StorageError)?;

    Ok(true)
}

fn derive_auto_gateways(interfaces: &[Interface]) -> Vec<Gateway> {
    interfaces
        .iter()
        .filter(|iface| iface.enabled && (iface.wan_mode.is_some() || iface.gateway.is_some()))
        .map(|iface| Gateway {
            name: format!("{}_AUTO", iface.name),
            description: Some(AUTO_GATEWAY_DESCRIPTION.to_string()),
            interface: iface.name.clone(),
            // Static WAN keeps an explicit gateway; DHCP/PPPoE remains discovered at runtime.
            gateway_ip: iface.gateway.clone(),
            monitor_ip: None,
            weight: 1,
            enabled: true,
        })
        .collect()
}

fn sync_auto_gateways_from_interfaces(
    state: &Arc<AppState>,
    interfaces: &[Interface],
) -> Result<bool, InterfaceError> {
    let desired_gateways = derive_auto_gateways(interfaces);
    let desired_ifaces = desired_gateways
        .iter()
        .map(|g| g.interface.as_str())
        .collect::<std::collections::HashSet<_>>();

    let mut gateways = state
        .config_store
        .load_gateways()
        .map_err(InterfaceError::StorageError)?;
    let mut changed = false;

    // Remove stale auto-managed gateway entries for interfaces that are no longer WAN.
    let original_len = gateways.len();
    gateways.retain(|g| {
        let is_auto_managed = g.description.as_deref() == Some(AUTO_GATEWAY_DESCRIPTION);
        !is_auto_managed || desired_ifaces.contains(g.interface.as_str())
    });
    if gateways.len() != original_len {
        changed = true;
    }

    for desired in desired_gateways {
        if let Some(existing) = gateways
            .iter_mut()
            .find(|g| g.interface == desired.interface && g.description.as_deref() == Some(AUTO_GATEWAY_DESCRIPTION))
        {
            if existing.gateway_ip != desired.gateway_ip {
                existing.gateway_ip = desired.gateway_ip.clone();
                changed = true;
            }
            if !existing.enabled {
                existing.enabled = true;
                changed = true;
            }
            if existing.name != desired.name {
                existing.name = desired.name.clone();
                changed = true;
            }
        } else {
            gateways.push(desired);
            changed = true;
        }
    }

    if !changed {
        return Ok(false);
    }

    state
        .config_store
        .save_gateways(gateways)
        .map_err(InterfaceError::StorageError)?;

    Ok(true)
}

async fn apply_full_nftables_rules(state: &Arc<AppState>) -> Result<(), InterfaceError> {
    let full_cfg = state
        .config_store
        .load()
        .map_err(InterfaceError::StorageError)?;
    let fw_rules = full_cfg.firewall_rules.clone();
    apply_rules(
        &fw_rules,
        full_cfg.nat.as_ref(),
        &full_cfg.firewall_aliases,
        full_cfg.firewall_settings.as_ref(),
        full_cfg
            .system_settings
            .as_ref()
            .map(|settings| settings.ipv6_enabled)
            .unwrap_or(false),
    )
    .await
    .map_err(|e| InterfaceError::ApplyFailed(e.to_string()))
}

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
    pub accept_ra: bool,
    pub ipv6_mode: Option<String>,
    pub track_source_interface: Option<String>,
    pub track_prefix_id: Option<u8>,
    pub delegated_prefix_len: Option<u8>,
    pub ra_mode: Option<String>,
    pub ia_pd_hint_len: Option<u8>,
    /// Runtime-resolved IPv6 prefix (read-only).
    /// For `dhcp6` WAN interfaces with `ia_pd_hint_len` set: the delegated prefix from the ISP.
    /// For `track_interface` LAN interfaces: the computed prefix assigned to this interface.
    pub resolved_ipv6_prefix: Option<String>,
    pub mtu: Option<u16>,
    pub mss: Option<u16>,
    pub vlan: Option<u16>,
    pub parent_interface: Option<String>,
    pub wan_mode: Option<String>,      // "dhcp" or "pppoe"
    pub pppoe_username: Option<String>,
    pub ipv4_address: Option<String>,  // First address from CIDR (e.g. "192.168.1.1")
    pub ipv4_prefix: Option<u8>,       // Prefix from first address (e.g. 24)
    pub ipv6_address: Option<String>,
    pub ipv6_prefix: Option<u8>,
    pub gateway: Option<String>,
}

impl InterfaceResponse {
    /// Convert from a backend `Interface` to API response format.
    pub fn from_interface(iface: &Interface) -> Self {
        // Parse first IPv4 and first IPv6 address if available.
        let (ipv4_address, ipv4_prefix) = iface
            .addresses
            .iter()
            .find(|cidr| !cidr.contains(':'))
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
        let (ipv6_address, ipv6_prefix) = iface
            .addresses
            .iter()
            .find(|cidr| cidr.contains(':'))
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

        let effective_ipv6_mode = iface.effective_ipv6_mode();
        let ipv6_mode = iface.ipv6_mode.as_ref().map(|m| match m {
            Ipv6Mode::Static => "static".to_string(),
            Ipv6Mode::Dhcp6 => "dhcp6".to_string(),
            Ipv6Mode::Slaac => "slaac".to_string(),
            Ipv6Mode::TrackInterface => "track_interface".to_string(),
        });
        let ra_mode = if matches!(effective_ipv6_mode, Ipv6Mode::TrackInterface)
            || iface.ra_mode.is_some()
        {
            Some(iface.effective_ra_mode().as_str().to_string())
        } else {
            None
        };

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
            accept_ra: iface.accept_ra,
            ipv6_mode,
            track_source_interface: iface.track_source_interface.clone(),
            track_prefix_id: iface.track_prefix_id,
            delegated_prefix_len: iface.delegated_prefix_len,
            ra_mode,
            ia_pd_hint_len: iface.ia_pd_hint_len,
            resolved_ipv6_prefix: None, // populated by enrich_with_runtime()
            mtu: iface.mtu,
            mss: iface.mss,
            vlan: iface.vlan,
            parent_interface: iface.parent_interface.clone(),
            wan_mode,
            pppoe_username: iface.pppoe_username.clone(),
            ipv4_address,
            ipv4_prefix,
            ipv6_address,
            ipv6_prefix,
            gateway: iface.gateway.clone(),
        }
    }

    /// Populate runtime-only fields that cannot be derived from stored config.
    ///
    /// * `dhcp6` WAN with `ia_pd_hint_len` â†’ read the delegated prefix from
    ///   the dhclient6-PD state file.
    /// * `track_interface` LAN â†’ compute the assigned /64 from the source
    ///   interface's delegated prefix.
    pub fn enrich_with_runtime(&mut self) {
        use crate::engine::prefix_delegation;

        match self.ipv6_mode.as_deref() {
            Some("dhcp6") if self.ia_pd_hint_len.is_some() => {
                self.resolved_ipv6_prefix = prefix_delegation::read_delegated_prefix(&self.name);
            }
            Some("track_interface") => {
                if let (Some(src), Some(target_len)) = (
                    self.track_source_interface.as_deref(),
                    Some(self.delegated_prefix_len.unwrap_or(64)),
                ) {
                    if let Some(delegated) = prefix_delegation::read_delegated_prefix(src) {
                        self.resolved_ipv6_prefix = prefix_delegation::compute_track_address(
                            &delegated,
                            self.track_prefix_id.unwrap_or(0),
                            target_len,
                            1,
                        );
                    }
                }
            }
            _ => {}
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
    pub accept_ra: Option<bool>,
    pub ipv6_mode: Option<String>,
    pub track_source_interface: Option<String>,
    pub track_prefix_id: Option<u8>,
    pub delegated_prefix_len: Option<u8>,
    pub ra_mode: Option<String>,
    pub ia_pd_hint_len: Option<u8>,
    pub mtu: Option<u16>,
    pub mss: Option<u16>,
    pub vlan: Option<u16>,
    pub parent_interface: Option<String>,
    pub wan_mode: Option<String>,      // "dhcp" or "pppoe"
    pub pppoe_username: Option<String>,
    pub pppoe_password: Option<String>,
    pub ipv4_address: Option<String>,  // UI sends this as separate field
    pub ipv4_prefix: Option<u8>,       // UI sends this as separate field
    pub ipv6_address: Option<String>,
    pub ipv6_prefix: Option<u8>,
    pub gateway: Option<String>,
}

impl InterfaceRequest {
    fn parse_ra_mode(value: &str) -> Option<RouterAdvertisementMode> {
        match value {
            "router_only" => Some(RouterAdvertisementMode::RouterOnly),
            "unmanaged" => Some(RouterAdvertisementMode::Unmanaged),
            "managed" => Some(RouterAdvertisementMode::Managed),
            "assisted" => Some(RouterAdvertisementMode::Assisted),
            "stateless" => Some(RouterAdvertisementMode::Stateless),
            _ => None,
        }
    }

    fn has_valid_ra_mode(&self) -> bool {
        self.ra_mode
            .as_deref()
            .map(Self::parse_ra_mode)
            .map(|mode| mode.is_some())
            .unwrap_or(true)
    }

    /// Convert from API request format to backend `Interface`.
    pub fn to_interface(self) -> Interface {
        // Build addresses from ipv4_address and ipv4_prefix
        let mut addresses = Vec::new();
        if let (Some(addr), Some(prefix)) = (self.ipv4_address, self.ipv4_prefix) {
            addresses.push(format!("{}/{}", addr, prefix));
        }
        if let (Some(addr), Some(prefix)) = (self.ipv6_address, self.ipv6_prefix) {
            addresses.push(format!("{}/{}", addr, prefix));
        }

        let wan_mode = match self.wan_mode.as_deref() {
            Some("pppoe") => Some(crate::config::models::WanMode::Pppoe),
            Some("dhcp") => Some(crate::config::models::WanMode::Dhcp),
            _ => None,
        };

        let ipv6_mode = match self.ipv6_mode.as_deref() {
            Some("dhcp6") => Some(Ipv6Mode::Dhcp6),
            Some("slaac") => Some(Ipv6Mode::Slaac),
            Some("track_interface") => Some(Ipv6Mode::TrackInterface),
            Some("static") => Some(Ipv6Mode::Static),
            _ => None,
        };
        let ra_mode = self
            .ra_mode
            .as_deref()
            .and_then(Self::parse_ra_mode);

        let effective_mode = ipv6_mode.clone().unwrap_or_else(|| {
            if self.dhcp6.unwrap_or(false) {
                Ipv6Mode::Dhcp6
            } else if self.accept_ra.unwrap_or(false) {
                Ipv6Mode::Slaac
            } else {
                Ipv6Mode::Static
            }
        });

        let dhcp6 = matches!(effective_mode, Ipv6Mode::Dhcp6);
        let accept_ra = matches!(effective_mode, Ipv6Mode::Slaac);

        Interface {
            name: self.name,
            description: self.description,
            addresses,
            mtu: self.mtu,
            mss: self.mss,
            enabled: self.enabled,
            dhcp4: self.dhcp4,
            dhcp6,
            accept_ra,
            ipv6_mode,
            track_source_interface: self.track_source_interface,
            track_prefix_id: self.track_prefix_id,
            delegated_prefix_len: self.delegated_prefix_len,
            ra_mode,
            ia_pd_hint_len: self.ia_pd_hint_len,
            vlan: self.vlan,
            parent_interface: self.parent_interface,
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
        .map(|iface| {
            let mut resp = InterfaceResponse::from_interface(iface);
            resp.enrich_with_runtime();
            resp
        })
        .collect();

    // If an interface has no static gateway configured, surface any active
    // default-route gateway currently seen in the kernel for that interface.
    let ipv6_enabled = state
        .config_store
        .load_system_settings()
        .map(|settings| settings.ipv6_enabled)
        .unwrap_or(false);
    let active_gateways = list_kernel_gateways_with_ipv6(ipv6_enabled).await;
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
    if !req.has_valid_ra_mode() {
        return Err(InterfaceError::ApplyFailed(
            "raMode must be one of router_only, unmanaged, managed, assisted, or stateless"
                .to_string(),
        ));
    }

    let iface = req.to_interface();
    let ipv6_enabled = state
        .config_store
        .load_system_settings()
        .map_err(InterfaceError::StorageError)?
        .ipv6_enabled;

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
        if let Err(msg) = ensure_ipv6_allowed(cidr, ipv6_enabled, "interface address") {
            return Err(InterfaceError::ApplyFailed(msg));
        }
    }

    let ipv6_mode = iface.effective_ipv6_mode();

    if !matches!(ipv6_mode, Ipv6Mode::Static) && !ipv6_enabled {
        return Err(InterfaceError::ApplyFailed(
            "Selected IPv6 mode requires system ipv6Enabled".to_string(),
        ));
    }

    if matches!(ipv6_mode, Ipv6Mode::Slaac) {
        let is_wan_designated = iface.wan_mode.is_some() || iface.gateway.is_some();
        if !is_wan_designated {
            return Err(InterfaceError::ApplyFailed(
                "IPv6 RA can only be enabled on WAN-designated interfaces".to_string(),
            ));
        }
        if matches!(iface.wan_mode, Some(WanMode::Pppoe)) {
            return Err(InterfaceError::ApplyFailed(
                "IPv6 RA is not supported on PPPoE interfaces".to_string(),
            ));
        }
    }

    if matches!(ipv6_mode, Ipv6Mode::TrackInterface) {
        if iface.track_source_interface.as_deref().map(str::trim).unwrap_or("").is_empty() {
            return Err(InterfaceError::ApplyFailed(
                "track_interface mode requires trackSourceInterface".to_string(),
            ));
        }
        if iface.track_source_interface.as_deref() == Some(iface.name.as_str()) {
            return Err(InterfaceError::ApplyFailed(
                "trackSourceInterface cannot reference the same interface".to_string(),
            ));
        }
        if let Some(source) = iface.track_source_interface.as_deref() {
            let source_exists = {
                let ifaces = state.interfaces.read().await;
                ifaces.iter().any(|i| i.name == source)
            } || state
                .config_store
                .load_interfaces()
                .map_err(InterfaceError::StorageError)?
                .iter()
                .any(|i| i.name == source);
            if !source_exists {
                return Err(InterfaceError::ApplyFailed(
                    "trackSourceInterface must reference an existing interface".to_string(),
                ));
            }
        }
        if let Some(prefix_len) = iface.delegated_prefix_len {
            if prefix_len > 128 {
                return Err(InterfaceError::ApplyFailed(
                    "delegatedPrefixLen must be between 0 and 128".to_string(),
                ));
            }
        }
    } else if iface.ra_mode.is_some() {
        return Err(InterfaceError::ApplyFailed(
            "raMode requires ipv6Mode = track_interface".to_string(),
        ));
    }

    if let Some(gateway) = &iface.gateway {
        if let Err(msg) = ensure_ipv6_allowed(gateway, ipv6_enabled, "interface gateway") {
            return Err(InterfaceError::ApplyFailed(msg));
        }
    }

    // ia_pd_hint_len is only valid on WAN DHCPv6 interfaces.
    if let Some(hint_len) = iface.ia_pd_hint_len {
        if hint_len < 1 || hint_len > 128 {
            return Err(InterfaceError::ApplyFailed(
                "iaPdHintLen must be between 1 and 128".to_string(),
            ));
        }
        if !matches!(ipv6_mode, Ipv6Mode::Dhcp6) {
            return Err(InterfaceError::ApplyFailed(
                "iaPdHintLen requires ipv6Mode = dhcp6".to_string(),
            ));
        }
        let is_wan = iface.wan_mode.is_some() || iface.gateway.is_some();
        if !is_wan {
            return Err(InterfaceError::ApplyFailed(
                "iaPdHintLen can only be set on WAN-designated interfaces".to_string(),
            ));
        }
    }

    if matches!(iface.wan_mode, Some(WanMode::Pppoe)) {
        let user_ok = iface
            .pppoe_username
            .as_deref()
            .map(|s| !s.trim().is_empty() && !s.chars().any(char::is_control))
            .unwrap_or(false);
        let pass_ok = iface
            .pppoe_password
            .as_deref()
            .map(|s| !s.is_empty() && !s.chars().any(char::is_control))
            .unwrap_or(false);

        if !user_ok || !pass_ok {
            return Err(InterfaceError::ApplyFailed(
                "pppoe mode requires non-empty username/password without control characters"
                    .to_string(),
            ));
        }
    }

    match iface.vlan {
        Some(vlan_id) => {
            if !is_valid_vlan_id(vlan_id) {
                return Err(InterfaceError::InvalidVlanId(vlan_id));
            }
            let parent = iface
                .parent_interface
                .as_deref()
                .ok_or_else(|| InterfaceError::MissingVlanParent(iface.name.clone()))?;
            if !is_valid_interface_name(parent) || parent == iface.name {
                return Err(InterfaceError::InvalidVlanParent(parent.to_string()));
            }
            let parent_exists = {
                let ifaces = state.interfaces.read().await;
                ifaces.iter().any(|i| i.name == parent)
            };
            let parent_exists = parent_exists || state
                    .config_store
                    .load_interfaces()
                    .map_err(InterfaceError::StorageError)?
                    .iter()
                    .any(|i| i.name == parent);
            if !parent_exists {
                return Err(InterfaceError::InvalidVlanParent(parent.to_string()));
            }
        }
        None => {
            if iface.parent_interface.is_some() {
                return Err(InterfaceError::ParentInterfaceWithoutVlan(iface.name.clone()));
            }
        }
    }

    info!(
        name = %iface.name,
        enabled = iface.enabled,
        "interfaces: received create/update request"
    );

    // --- Persist -----------------------------------------------------------

    // Upsert in the in-memory cache (match by name).
    let previous_ifaces = {
        let mut ifaces = state.interfaces.write().await;
        let previous_ifaces = ifaces.clone();
        match ifaces.iter().position(|i| i.name == iface.name) {
            Some(pos) => ifaces[pos] = iface.clone(),
            None => ifaces.push(iface.clone()),
        }
        previous_ifaces
    };

    // Atomically write the updated list to disk.
    let ifaces_to_save = {
        let ifaces = state.interfaces.read().await;
        ifaces.clone()
    };
    if let Err(err) = state
        .config_store
        .save_interfaces(ifaces_to_save.clone())
        .map_err(InterfaceError::StorageError)
    {
        let mut in_memory = state.interfaces.write().await;
        *in_memory = previous_ifaces;
        return Err(err);
    }

    let nat_wan_changed = sync_nat_wan_interfaces(&state, &ifaces_to_save)?;
    let gateways_changed = sync_auto_gateways_from_interfaces(&state, &ifaces_to_save)?;

    info!(name = %iface.name, "interfaces: configuration persisted");

    // --- Apply -------------------------------------------------------------

    apply_interface_with_ipv6(&iface, ipv6_enabled).await?;
    refresh_router_advertisements(&ifaces_to_save, ipv6_enabled).await;

    if nat_wan_changed {
        apply_full_nftables_rules(&state).await?;
        info!(name = %iface.name, "interfaces: synchronized NAT WAN interfaces and reapplied nftables");
    }

    if gateways_changed {
        info!(name = %iface.name, "interfaces: synchronized auto-managed gateways from WAN interfaces");
    }

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
    let (previous_ifaces, deleted_names) = {
        let mut ifaces = state.interfaces.write().await;
        let previous_ifaces = ifaces.clone();
        let before = ifaces.len();
        let mut deleted_names = vec![name.clone()];
        ifaces.retain(|i| {
            if i.name == name || i.parent_interface.as_deref() == Some(name.as_str()) {
                if i.name != name {
                    deleted_names.push(i.name.clone());
                }
                false
            } else {
                true
            }
        });
        if ifaces.len() == before {
            return Err(InterfaceError::NotFound(name));
        }
        (previous_ifaces, deleted_names)
    };

    // --- Persist -----------------------------------------------------------
    let ifaces_to_save = {
        let ifaces = state.interfaces.read().await;
        ifaces.clone()
    };
    if let Err(err) = state
        .config_store
        .save_interfaces(ifaces_to_save.clone())
        .map_err(InterfaceError::StorageError)
    {
        let mut in_memory = state.interfaces.write().await;
        *in_memory = previous_ifaces;
        return Err(err);
    }

    let nat_wan_changed = sync_nat_wan_interfaces(&state, &ifaces_to_save)?;
    let gateways_changed = sync_auto_gateways_from_interfaces(&state, &ifaces_to_save)?;

    // --- Best-effort kernel teardown ---------------------------------------
    for deleted in &deleted_names {
        if is_valid_interface_name(deleted) {
            let _ = tokio::process::Command::new("pkill")
                .args(["-f", &format!("pppd call wan-{deleted}")])
                .output()
                .await;
        }
        let _ = tokio::process::Command::new("ip")
            .args(["link", "set", deleted, "down"])
            .output()
            .await;
        let _ = tokio::process::Command::new("ip")
            .args(["link", "del", "dev", deleted])
            .output()
            .await;
    }

    if nat_wan_changed {
        apply_full_nftables_rules(&state).await?;
        info!(%name, "interfaces: synchronized NAT WAN interfaces and reapplied nftables");
    }

    if gateways_changed {
        info!(%name, "interfaces: synchronized auto-managed gateways from WAN interfaces");
    }

    let ipv6_enabled = state
        .config_store
        .load_system_settings()
        .map_err(InterfaceError::StorageError)?
        .ipv6_enabled;
    refresh_router_advertisements(&ifaces_to_save, ipv6_enabled).await;

    info!(%name, count = deleted_names.len(), "interfaces: deleted interface(s)");

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::{InterfaceRequest, InterfaceResponse};
    use crate::config::models::{Interface, Ipv6Mode};

    #[test]
    fn interface_request_to_interface_preserves_vlan_parent() {
        let req = InterfaceRequest {
            name: "eth0.100".into(),
            description: Some("VLAN 100".into()),
            r#type: Some("vlan".into()),
            enabled: true,
            dhcp4: false,
            dhcp6: Some(false),
            accept_ra: Some(false),
            ipv6_mode: Some("static".into()),
            track_source_interface: None,
            track_prefix_id: None,
            delegated_prefix_len: None,
            ra_mode: None,
            ia_pd_hint_len: None,
            mtu: Some(1500),
            mss: None,
            vlan: Some(100),
            parent_interface: Some("eth0".into()),
            wan_mode: None,
            pppoe_username: None,
            pppoe_password: None,
            ipv4_address: Some("192.168.100.1".into()),
            ipv4_prefix: Some(24),
            ipv6_address: None,
            ipv6_prefix: None,
            gateway: None,
        };

        let iface = req.to_interface();
        assert_eq!(iface.vlan, Some(100));
        assert_eq!(iface.parent_interface.as_deref(), Some("eth0"));
        assert_eq!(iface.addresses, vec!["192.168.100.1/24".to_string()]);
    }

    #[test]
    fn interface_response_from_interface_exposes_vlan_parent() {
        let iface = Interface {
            name: "eth0.100".into(),
            description: Some("VLAN 100".into()),
            addresses: vec!["192.168.100.1/24".into()],
            mtu: Some(1500),
            mss: None,
            enabled: true,
            dhcp4: false,
            dhcp6: false,
            accept_ra: false,
            ipv6_mode: Some(Ipv6Mode::Static),
            track_source_interface: None,
            track_prefix_id: None,
            delegated_prefix_len: None,
            ra_mode: None,
            ia_pd_hint_len: None,
            vlan: Some(100),
            parent_interface: Some("eth0".into()),
            wan_mode: None,
            pppoe_username: None,
            pppoe_password: None,
            gateway: None,
        };

        let resp = InterfaceResponse::from_interface(&iface);
        assert_eq!(resp.r#type, "vlan");
        assert_eq!(resp.vlan, Some(100));
        assert_eq!(resp.parent_interface.as_deref(), Some("eth0"));
    }
}
