//! Firewall alias endpoints.
//!
//! - `GET  /firewall/aliases`       - list all aliases
//! - `POST /firewall/aliases`       - create a new alias
//! - `PUT  /firewall/aliases/{name}` - update an existing alias
//! - `DELETE /firewall/aliases/{name}` - remove an alias by name

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use tracing::{info, warn};

use crate::{
    config::models::{
        validate_alias_name, validate_alias_values, AliasType, FirewallAlias,
    },
    state::AppState,
};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by the aliases API handlers.
#[derive(Debug, thiserror::Error)]
pub enum AliasError {
    /// A field failed validation.
    #[error("validation error: {0}")]
    ValidationFailed(String),

    /// A persistent-storage operation failed.
    #[error("storage error: {0:#}")]
    StorageError(#[from] anyhow::Error),

    /// The nftables engine failed to apply the updated ruleset.
    #[error("engine error: {0:#}")]
    EngineError(String),

    /// The requested alias was not found.
    #[error("alias not found: {0}")]
    NotFound(String),
}

impl IntoResponse for AliasError {
    fn into_response(self) -> axum::response::Response {
        let status = match &self {
            AliasError::ValidationFailed(_) => StatusCode::UNPROCESSABLE_ENTITY,
            AliasError::NotFound(_) => StatusCode::NOT_FOUND,
            AliasError::StorageError(_) | AliasError::EngineError(_) => {
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

/// Request body for `POST /firewall/aliases`.
#[derive(serde::Deserialize)]
pub struct CreateAliasRequest {
    pub name: String,
    pub description: Option<String>,
    pub alias_type: AliasType,
    pub values: Vec<String>,
    pub ttl: Option<u64>,
    pub enabled: bool,
}

/// Request body for `PUT /firewall/aliases/{name}`.
#[derive(serde::Deserialize)]
pub struct UpdateAliasRequest {
    /// Optional copy of the path name. Alias renames are intentionally not
    /// supported because firewall rules reference aliases by name.
    pub name: Option<String>,
    pub description: Option<String>,
    pub alias_type: Option<AliasType>,
    pub values: Option<Vec<String>>,
    pub ttl: Option<u64>,
    pub enabled: Option<bool>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Handler: list all persisted firewall aliases.
pub async fn list_aliases(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, AliasError> {
    let aliases = state
        .config_store
        .load_firewall_aliases()
        .map_err(AliasError::StorageError)?;

    info!(count = aliases.len(), "aliases: loaded from storage");
    Ok(Json(aliases))
}

/// Handler: create a new firewall alias.
///
/// Validates the alias name and values, checks name uniqueness, persists, then
/// re-applies the nftables ruleset.  Returns `201 Created` with the new alias.
pub async fn create_alias(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateAliasRequest>,
) -> Result<impl IntoResponse, AliasError> {
    // --- Validation --------------------------------------------------------

    if !validate_alias_name(&req.name) {
        warn!(name = %req.name, "aliases: invalid alias name");
        return Err(AliasError::ValidationFailed(format!(
            "invalid alias name {:?}: must be 1–63 chars, start with a letter or _, \
             contain only [A-Za-z0-9_]",
            req.name
        )));
    }

    let alias = FirewallAlias {
        name: req.name,
        description: req.description,
        alias_type: req.alias_type,
        values: req.values,
        ttl: req.ttl,
        enabled: req.enabled,
    };

    if let Err(msg) = validate_alias_values(&alias) {
        warn!(name = %alias.name, "aliases: invalid alias values");
        return Err(AliasError::ValidationFailed(msg));
    }

    // --- Uniqueness check --------------------------------------------------

    let mut aliases = state
        .config_store
        .load_firewall_aliases()
        .map_err(AliasError::StorageError)?;

    if aliases.iter().any(|a| a.name == alias.name) {
        return Err(AliasError::ValidationFailed(format!(
            "alias name {:?} already exists",
            alias.name
        )));
    }

    info!(name = %alias.name, kind = ?alias.alias_type, "aliases: creating alias");

    // --- Persist -----------------------------------------------------------

    aliases.push(alias.clone());
    state
        .config_store
        .save_firewall_aliases(aliases)
        .map_err(AliasError::StorageError)?;

    info!(name = %alias.name, "aliases: persisted");

    // --- Apply -------------------------------------------------------------

    apply_current_rules(&state).await?;

    info!(name = %alias.name, "aliases: nftables engine apply complete");

    Ok((StatusCode::CREATED, Json(alias)))
}

/// Handler: update an existing firewall alias by name.
///
/// Alias names are immutable so existing firewall rules keep referring to the
/// same set. The editable fields are description, type, values, TTL, and
/// enabled state.
pub async fn update_alias(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(req): Json<UpdateAliasRequest>,
) -> Result<impl IntoResponse, AliasError> {
    if !validate_alias_name(&name) {
        return Err(AliasError::ValidationFailed(format!(
            "invalid alias name {:?}: must be 1-63 chars, start with a letter or _, \
             contain only [A-Za-z0-9_]",
            name
        )));
    }

    if let Some(req_name) = &req.name {
        if req_name != &name {
            return Err(AliasError::ValidationFailed(format!(
                "alias rename is not supported; path name {:?} does not match body name {:?}",
                name, req_name
            )));
        }
    }

    let mut aliases = state
        .config_store
        .load_firewall_aliases()
        .map_err(AliasError::StorageError)?;

    let alias = aliases
        .iter_mut()
        .find(|alias| alias.name == name)
        .ok_or_else(|| AliasError::NotFound(name.clone()))?;

    if let Some(description) = req.description {
        alias.description = if description.trim().is_empty() {
            None
        } else {
            Some(description)
        };
    }
    if let Some(alias_type) = req.alias_type {
        alias.alias_type = alias_type;
    }
    if let Some(values) = req.values {
        alias.values = values;
    }
    if let Some(ttl) = req.ttl {
        alias.ttl = Some(ttl);
    }
    if let Some(enabled) = req.enabled {
        alias.enabled = enabled;
    }

    if let Err(msg) = validate_alias_values(alias) {
        warn!(name = %alias.name, "aliases: invalid updated alias values");
        return Err(AliasError::ValidationFailed(msg));
    }

    let updated = alias.clone();

    state
        .config_store
        .save_firewall_aliases(aliases)
        .map_err(AliasError::StorageError)?;

    info!(name = %updated.name, kind = ?updated.alias_type, "aliases: updated alias");

    apply_current_rules(&state).await?;

    info!(name = %updated.name, "aliases: nftables engine apply complete");

    Ok(Json(updated))
}

/// Handler: delete a firewall alias by name.
///
/// Returns `204 No Content` on success or `404 Not Found` if the alias does
/// not exist.
pub async fn delete_alias(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, AliasError> {
    let mut aliases = state
        .config_store
        .load_firewall_aliases()
        .map_err(AliasError::StorageError)?;

    let original_len = aliases.len();
    aliases.retain(|a| a.name != name);

    if aliases.len() == original_len {
        return Err(AliasError::NotFound(name));
    }

    state
        .config_store
        .save_firewall_aliases(aliases)
        .map_err(AliasError::StorageError)?;

    info!(name = %name, "aliases: deleted alias");

    // Re-apply nftables ruleset without the removed alias.
    apply_current_rules(&state).await?;

    Ok(StatusCode::NO_CONTENT)
}

async fn apply_current_rules(state: &Arc<AppState>) -> Result<(), AliasError> {
    crate::captive_portal::apply_current_ruleset_nft(&state.config_store)
        .await
        .map_err(|e| AliasError::EngineError(e.to_string()))?;

    Ok(())
}
