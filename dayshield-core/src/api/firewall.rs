//! Firewall rule endpoints - `GET /firewall/rules` and `POST /firewall/rules`.
//!
//! # GET /firewall/rules
//!
//! Returns the persisted [`FirewallRule`] list, syncing the in-memory cache as
//! a side-effect.
//!
//! # POST /firewall/rules
//!
//! Accepts a new firewall rule, validates all fields, appends it to the
//! persisted list, and triggers the nftables engine to regenerate and apply
//! the full ruleset.

use std::sync::Arc;

use axum::{extract::{Path, State}, http::StatusCode, response::IntoResponse, Json};
use tracing::{info, warn};
use uuid::Uuid;

use crate::{
    config::models::{
        is_valid_cidr, is_valid_interface_name, is_valid_port, Action, FirewallRule, Protocol,
    },
    engine::nftables::{apply_rules, NftError},
    state::AppState,
};

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Handler: list all persisted firewall rules.
///
/// Loads the rule list from config storage, syncs the in-memory cache, and
/// returns the list as JSON.
pub async fn list_rules(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, NftError> {
    let rules = state
        .config_store
        .load_firewall_rules()
        .map_err(NftError::StorageError)?;

    info!(count = rules.len(), "firewall: loaded rules from storage");

    // Sync the in-memory cache.
    {
        let mut fw = state.firewall_rules.write().await;
        *fw = rules.clone();
    }

    Ok(Json(rules))
}

/// Request body for `POST /firewall/rules`.
#[derive(serde::Deserialize)]
pub struct CreateRuleRequest {
    pub description: Option<String>,
    pub priority: i32,
    pub source: Option<String>,
    pub destination: Option<String>,
    pub protocol: Option<Protocol>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub action: Action,
    pub interface: Option<String>,
    pub log: bool,
}

/// Handler: create a new firewall rule.
///
/// Validates all fields, appends the rule to persistent storage, and
/// re-applies the full ruleset via the nftables engine.  Returns the
/// newly-created rule with a `201 Created` status on success.
pub async fn create_rule(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateRuleRequest>,
) -> Result<impl IntoResponse, NftError> {
    // --- Validation --------------------------------------------------------

    if let Some(src) = &req.source {
        if !is_valid_cidr(src) {
            warn!(src = %src, "firewall: invalid source CIDR");
            return Err(NftError::ValidationFailed(format!(
                "invalid source CIDR: {src}"
            )));
        }
    }

    if let Some(dst) = &req.destination {
        if !is_valid_cidr(dst) {
            warn!(dst = %dst, "firewall: invalid destination CIDR");
            return Err(NftError::ValidationFailed(format!(
                "invalid destination CIDR: {dst}"
            )));
        }
    }

    if let Some(sport) = req.source_port {
        if !is_valid_port(sport) {
            warn!(port = sport, "firewall: invalid source port");
            return Err(NftError::ValidationFailed(format!(
                "invalid source port: {sport} (must be 1–65535)"
            )));
        }
    }

    if let Some(dport) = req.destination_port {
        if !is_valid_port(dport) {
            warn!(port = dport, "firewall: invalid destination port");
            return Err(NftError::ValidationFailed(format!(
                "invalid destination port: {dport} (must be 1–65535)"
            )));
        }
    }

    if let Some(iface) = &req.interface {
        if !is_valid_interface_name(iface) {
            warn!(iface = %iface, "firewall: invalid interface name");
            return Err(NftError::ValidationFailed(format!(
                "invalid interface name: {iface}"
            )));
        }
    }

    // --- Build rule --------------------------------------------------------

    let rule = FirewallRule {
        id: uuid::Uuid::new_v4(),
        description: req.description,
        priority: req.priority,
        source: req.source,
        destination: req.destination,
        protocol: req.protocol,
        source_port: req.source_port,
        destination_port: req.destination_port,
        action: req.action,
        interface: req.interface,
        log: req.log,
    };

    info!(
        id = %rule.id,
        priority = rule.priority,
        action = ?rule.action,
        "firewall: received create rule request"
    );

    // --- Persist -----------------------------------------------------------

    // Append to in-memory cache and persist atomically.
    // Hold the write lock across the disk write so that no concurrent reader
    // can observe the new rule before it has been durably stored.
    {
        let mut rules = state.firewall_rules.write().await;
        rules.push(rule.clone());

        if let Err(e) = state.config_store.save_firewall_rules(rules.clone()) {
            // Roll back the in-memory change before returning the error.
            rules.pop();
            return Err(NftError::StorageError(e));
        }
    }

    info!(id = %rule.id, "firewall: rule persisted");

    // --- Apply -------------------------------------------------------------

    // Load current NAT rules and aliases so the full ruleset can be regenerated.
    let full_cfg = state
        .config_store
        .load()
        .map_err(NftError::StorageError)?;

    {
        let rules = state.firewall_rules.read().await;
        apply_rules(&rules, full_cfg.nat.as_ref(), &full_cfg.firewall_aliases).await?;
    }

    info!(id = %rule.id, "firewall: nftables engine apply complete");

    Ok((StatusCode::CREATED, Json(rule)))
}

/// Handler: delete a firewall rule by UUID.
///
/// Removes the rule from the in-memory cache, persists the updated list, and
/// re-applies the full ruleset via the nftables engine.  Returns `204 No
/// Content` on success or `404 Not Found` if no rule with that id exists.
pub async fn delete_rule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, NftError> {
    {
        let mut rules = state.firewall_rules.write().await;
        let before = rules.len();
        rules.retain(|r| r.id != id);
        if rules.len() == before {
            return Err(NftError::NotFound(id.to_string()));
        }
        state
            .config_store
            .save_firewall_rules(rules.clone())
            .map_err(NftError::StorageError)?;
    }

    info!(id = %id, "firewall: rule deleted");

    let full_cfg = state
        .config_store
        .load()
        .map_err(NftError::StorageError)?;

    {
        let rules = state.firewall_rules.read().await;
        apply_rules(&rules, full_cfg.nat.as_ref(), &full_cfg.firewall_aliases).await?;
    }

    info!(id = %id, "firewall: nftables engine apply complete after delete");

    Ok(StatusCode::NO_CONTENT)
}
