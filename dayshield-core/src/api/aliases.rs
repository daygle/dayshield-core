//! Firewall alias endpoints.
//!
//! - `GET  /firewall/aliases`       — list all aliases
//! - `POST /firewall/aliases`       — create a new alias
//! - `DELETE /firewall/aliases/{name}` — remove an alias by name

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
    engine::nftables::{apply_rules, NftError},
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

    let full_cfg = state
        .config_store
        .load()
        .map_err(AliasError::StorageError)?;
    let fw_rules = full_cfg.firewall_rules.clone();

    apply_rules(
        &fw_rules,
        full_cfg.nat.as_ref(),
        &full_cfg.firewall_aliases,
        full_cfg.firewall_settings.as_ref(),
    )
        .await
        .map_err(|e| AliasError::EngineError(e.to_string()))?;

    info!(name = %alias.name, "aliases: nftables engine apply complete");

    Ok((StatusCode::CREATED, Json(alias)))
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
    let full_cfg = state
        .config_store
        .load()
        .map_err(AliasError::StorageError)?;
    let fw_rules = full_cfg.firewall_rules.clone();

    apply_rules(
        &fw_rules,
        full_cfg.nat.as_ref(),
        &full_cfg.firewall_aliases,
        full_cfg.firewall_settings.as_ref(),
    )
        .await
        .map_err(|e| AliasError::EngineError(e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}
