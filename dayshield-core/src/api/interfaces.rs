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
use serde::Serialize;
use tracing::{info, warn};

use crate::{
    config::models::{is_valid_cidr, is_valid_interface_name, is_valid_mtu, Interface},
    engine::interfaces::{apply_interface, list_kernel_interfaces, InterfaceError, KernelInterface},
    state::AppState,
};

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// Response body for `GET /interfaces`.
#[derive(Serialize)]
pub struct ListInterfacesResponse {
    /// Interfaces stored in persistent configuration.
    pub configured: Vec<Interface>,
    /// Interfaces currently visible to the kernel.
    pub kernel: Vec<KernelInterface>,
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

    // Redact pppoe_password from all configured interfaces before returning.
    let configured_redacted: Vec<Interface> = configured
        .into_iter()
        .map(|mut i| { i.pppoe_password = None; i })
        .collect();

    Ok(Json(ListInterfacesResponse { configured: configured_redacted, kernel }))
}

/// Handler: create or update a network interface.
///
/// Validates the incoming [`Interface`], upserts it in the in-memory cache and
/// persistent storage, then asks the engine to apply the configuration.
pub async fn create_interface(
    State(state): State<Arc<AppState>>,
    Json(iface): Json<Interface>,
) -> Result<impl IntoResponse, InterfaceError> {
    // --- Validation --------------------------------------------------------

    if !is_valid_interface_name(&iface.name) {
        return Err(InterfaceError::InvalidName(iface.name.clone()));
    }

    if let Some(mtu) = iface.mtu {
        if !is_valid_mtu(mtu) {
            return Err(InterfaceError::InvalidMtu(mtu));
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

    Ok((StatusCode::CREATED, Json(iface)))
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
