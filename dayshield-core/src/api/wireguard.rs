//! WireGuard VPN endpoints.
//!
//! - `GET  /wireguard/interfaces`                     - list all WireGuard interfaces
//! - `POST /wireguard/interfaces`                     - create or update an interface
//! - `DELETE /wireguard/interfaces/{name}`            - remove an interface
//! - `POST /wireguard/interfaces/{name}/generate-keys` - generate a keypair

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
        validate_cidr, validate_endpoint, validate_wg_interface_name, validate_wg_key,
        WireGuardInterface, WireGuardPeer,
    },
    engine::vpn::{apply_interface, generate_keypair, remove_interface},
    state::AppState,
};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by the WireGuard API handlers.
#[derive(Debug, thiserror::Error)]
pub enum WireGuardError {
    /// A field failed validation.
    #[error("validation error: {0}")]
    ValidationFailed(String),

    /// A persistent-storage operation failed.
    #[error("storage error: {0:#}")]
    StorageError(#[from] anyhow::Error),

    /// The VPN engine failed to apply the configuration.
    #[error("engine error: {0}")]
    EngineError(String),

    /// The requested interface was not found.
    #[error("interface not found: {0}")]
    NotFound(String),
}

impl IntoResponse for WireGuardError {
    fn into_response(self) -> axum::response::Response {
        let status = match &self {
            WireGuardError::ValidationFailed(_) => StatusCode::UNPROCESSABLE_ENTITY,
            WireGuardError::NotFound(_) => StatusCode::NOT_FOUND,
            WireGuardError::StorageError(_) | WireGuardError::EngineError(_) => {
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
// Request / response types
// ---------------------------------------------------------------------------

/// Request body for creating or updating a WireGuard peer inside a request.
#[derive(Deserialize)]
pub struct PeerRequest {
    pub name: String,
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<String>,
    pub persistent_keepalive: Option<u16>,
}

/// Request body for `POST /wireguard/interfaces`.
#[derive(Deserialize)]
pub struct CreateWireGuardInterfaceRequest {
    pub name: String,
    pub description: Option<String>,
    pub private_key: String,
    pub public_key: String,
    pub listen_port: u16,
    pub addresses: Vec<String>,
    pub peers: Vec<PeerRequest>,
    pub enabled: bool,
}

/// Response body for `POST /wireguard/interfaces/{name}/generate-keys`.
#[derive(Serialize)]
pub struct GenerateKeysResponse {
    pub private_key: String,
    pub public_key: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Handler: list all persisted WireGuard interfaces.
///
/// The `private_key` of each interface and the `preshared_key` of each peer
/// are redacted in the response.
pub async fn list_interfaces(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, WireGuardError> {
    let ifaces = state
        .config_store
        .load_wireguard_interfaces()
        .map_err(WireGuardError::StorageError)?;

    info!(count = ifaces.len(), "wireguard: loaded interfaces from storage");

    let redacted: Vec<WireGuardInterface> = ifaces.into_iter().map(redact_interface).collect();
    Ok(Json(redacted))
}

/// Handler: create or update a WireGuard interface.
///
/// Validates all fields, upserts the interface in persistent storage, then
/// asks the engine to apply the configuration.  Returns `201 Created` with the
/// saved interface.
pub async fn create_interface(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateWireGuardInterfaceRequest>,
) -> Result<impl IntoResponse, WireGuardError> {
    // --- Validation --------------------------------------------------------

    if !validate_wg_interface_name(&req.name) {
        warn!(name = %req.name, "wireguard: invalid interface name");
        return Err(WireGuardError::ValidationFailed(format!(
            "invalid interface name {:?}: must be 1–15 alphanumeric/[-_.] chars",
            req.name
        )));
    }

    if !validate_wg_key(&req.private_key) {
        return Err(WireGuardError::ValidationFailed(
            "private_key must be a 44-character base64 string".into(),
        ));
    }

    if !validate_wg_key(&req.public_key) {
        return Err(WireGuardError::ValidationFailed(
            "public_key must be a 44-character base64 string".into(),
        ));
    }

    if req.listen_port == 0 {
        return Err(WireGuardError::ValidationFailed(
            "listen_port must be non-zero".into(),
        ));
    }

    for addr in &req.addresses {
        if !validate_cidr(addr) {
            return Err(WireGuardError::ValidationFailed(format!(
                "invalid address CIDR {:?}",
                addr
            )));
        }
    }

    let mut peers: Vec<WireGuardPeer> = Vec::new();
    for p in &req.peers {
        if !validate_wg_key(&p.public_key) {
            return Err(WireGuardError::ValidationFailed(format!(
                "peer {:?}: public_key must be a 44-character base64 string",
                p.name
            )));
        }
        if let Some(psk) = &p.preshared_key {
            if !validate_wg_key(psk) {
                return Err(WireGuardError::ValidationFailed(format!(
                    "peer {:?}: preshared_key must be a 44-character base64 string",
                    p.name
                )));
            }
        }
        for cidr in &p.allowed_ips {
            if !validate_cidr(cidr) {
                return Err(WireGuardError::ValidationFailed(format!(
                    "peer {:?}: invalid allowed_ip CIDR {:?}",
                    p.name, cidr
                )));
            }
        }
        if let Some(ep) = &p.endpoint {
            if !validate_endpoint(ep) {
                return Err(WireGuardError::ValidationFailed(format!(
                    "peer {:?}: invalid endpoint {:?} (expected host:port)",
                    p.name, ep
                )));
            }
        }
        peers.push(WireGuardPeer {
            name: p.name.clone(),
            public_key: p.public_key.clone(),
            preshared_key: p.preshared_key.clone(),
            allowed_ips: p.allowed_ips.clone(),
            endpoint: p.endpoint.clone(),
            persistent_keepalive: p.persistent_keepalive,
        });
    }

    let iface = WireGuardInterface {
        name: req.name,
        description: req.description.filter(|value| !value.trim().is_empty()),
        private_key: req.private_key,
        public_key: req.public_key,
        listen_port: req.listen_port,
        addresses: req.addresses,
        peers,
        enabled: req.enabled,
    };

    info!(
        name = %iface.name,
        enabled = iface.enabled,
        peers = iface.peers.len(),
        "wireguard: received create/update request"
    );

    // --- Persist -----------------------------------------------------------

    let mut ifaces = state
        .config_store
        .load_wireguard_interfaces()
        .map_err(WireGuardError::StorageError)?;

    match ifaces.iter().position(|i| i.name == iface.name) {
        Some(pos) => ifaces[pos] = iface.clone(),
        None => ifaces.push(iface.clone()),
    }

    state
        .config_store
        .save_wireguard_interfaces(ifaces)
        .map_err(WireGuardError::StorageError)?;

    info!(name = %iface.name, "wireguard: configuration persisted");

    // --- Apply -------------------------------------------------------------

    apply_interface(&iface)
        .await
        .map_err(|e| WireGuardError::EngineError(e.to_string()))?;

    info!(name = %iface.name, "wireguard: engine apply complete");

    Ok((StatusCode::CREATED, Json(redact_interface(iface))))
}

/// Handler: remove a WireGuard interface by name.
///
/// Brings the interface down via the engine, removes it from config, and
/// returns `204 No Content`.  Returns `404 Not Found` if unknown.
pub async fn delete_interface(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, WireGuardError> {
    let mut ifaces = state
        .config_store
        .load_wireguard_interfaces()
        .map_err(WireGuardError::StorageError)?;

    let original_len = ifaces.len();
    ifaces.retain(|i| i.name != name);

    if ifaces.len() == original_len {
        return Err(WireGuardError::NotFound(name));
    }

    // Bring the interface down before saving so that the kernel state stays
    // consistent with the config.
    remove_interface(&name)
        .await
        .map_err(|e| WireGuardError::EngineError(e.to_string()))?;

    state
        .config_store
        .save_wireguard_interfaces(ifaces)
        .map_err(WireGuardError::StorageError)?;

    info!(name = %name, "wireguard: interface deleted");

    Ok(StatusCode::NO_CONTENT)
}

/// Handler: generate a WireGuard private/public keypair.
///
/// Calls `wg genkey` + `wg pubkey` and returns the result.  The `{name}` path
/// parameter identifies which interface the caller intends to use the keys for
/// (informational only; the generated keys are returned to the client and not
/// stored automatically).
pub async fn generate_keys(
    Path(name): Path<String>,
) -> Result<impl IntoResponse, WireGuardError> {
    info!(name = %name, "wireguard: generating keypair");

    let (private_key, public_key) = generate_keypair()
        .await
        .map_err(|e| WireGuardError::EngineError(e.to_string()))?;

    Ok(Json(GenerateKeysResponse {
        private_key,
        public_key,
    }))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Return a copy of `iface` with `private_key` cleared and every peer's
/// `preshared_key` cleared so that secrets are never sent over the API.
fn redact_interface(mut iface: WireGuardInterface) -> WireGuardInterface {
    iface.private_key = String::new();
    for peer in &mut iface.peers {
        peer.preshared_key = None;
    }
    iface
}
