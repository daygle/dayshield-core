//! NAT REST API handlers.
//!
//! # Endpoints
//!
//! | Method   | Path                  | Description                               |
//! |----------|-----------------------|-------------------------------------------|
//! | `GET`    | `/nat/config`         | Return the current [`NatConfig`]          |
//! | `PUT`    | `/nat/config`         | Replace the [`NatConfig`]                 |
//! | `GET`    | `/nat/rules`          | Return the user-defined [`NatRule`] list  |
//! | `POST`   | `/nat/rules`          | Append a new [`NatRule`]                  |
//! | `DELETE` | `/nat/rules/{id}`     | Remove a rule by UUID                     |

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
        validate_nat_config_with_ipv6, validate_nat_rule_with_ipv6, AddressFamily, NatConfig,
        NatProtocol, NatRule, NatRuleType, NatTranslation, OutboundMode,
    },
    state::AppState,
};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Structured error returned by NAT handlers.
#[derive(Debug, thiserror::Error)]
pub enum NatError {
    /// A field failed validation.
    #[error("validation error: {0}")]
    ValidationFailed(String),

    /// A persistent-storage operation failed.
    #[error("storage error: {0:#}")]
    StorageError(#[from] anyhow::Error),

    /// The nftables engine failed to apply the updated ruleset.
    #[error("engine error: {0}")]
    EngineError(String),

    /// The requested rule was not found.
    #[error("rule not found: {0}")]
    NotFound(Uuid),
}

/// Machine-readable validation error body.
#[derive(Debug, Serialize)]
pub struct NatErrorBody {
    pub error: String,
    pub field: Option<String>,
}

impl IntoResponse for NatError {
    fn into_response(self) -> axum::response::Response {
        let status = match &self {
            NatError::ValidationFailed(_) => StatusCode::UNPROCESSABLE_ENTITY,
            NatError::NotFound(_) => StatusCode::NOT_FOUND,
            NatError::StorageError(_) | NatError::EngineError(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        (
            status,
            Json(NatErrorBody {
                error: self.to_string(),
                field: None,
            }),
        )
            .into_response()
    }
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

/// Request body for `POST /nat/rules`.
#[derive(Debug, Deserialize)]
pub struct CreateNatRuleRequest {
    pub description: Option<String>,
    pub rule_type: NatRuleType,
    pub interface: Option<String>,
    pub source: Option<String>,
    pub destination: Option<String>,
    #[serde(default)]
    pub protocol: NatProtocol,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub translation: Option<NatTranslation>,
    #[serde(default)]
    pub nat_reflection: bool,
    #[serde(default)]
    pub address_family: AddressFamily,
    #[serde(default)]
    pub priority: Option<i32>,
    #[serde(default)]
    pub log: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub auto_firewall_rule: bool,
}

fn default_true() -> bool {
    true
}

fn next_nat_priority(config: &NatConfig) -> i32 {
    config
        .rules
        .iter()
        .map(|rule| rule.priority)
        .max()
        .map(|priority| priority.saturating_add(10))
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Handler: `GET /nat/config`
///
/// Returns the current [`NatConfig`] (or a default if none has been saved).
pub async fn get_config(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, NatError> {
    let cfg = state
        .config_store
        .load_nat_config()
        .map_err(NatError::StorageError)?
        .unwrap_or_default();

    info!(
        mode = ?cfg.outbound_mode,
        wan_interfaces = cfg.wan_interfaces.len(),
        rules = cfg.rules.len(),
        "nat: loaded config"
    );

    Ok(Json(cfg))
}

/// Handler: `PUT /nat/config`
///
/// Replaces the entire [`NatConfig`].  The request body must be a valid JSON
/// [`NatConfig`].  Validation errors are returned as structured JSON with
/// `422 Unprocessable Entity`.
pub async fn put_config(
    State(state): State<Arc<AppState>>,
    Json(cfg): Json<NatConfig>,
) -> Result<impl IntoResponse, NatError> {
    let ipv6_enabled = state
        .config_store
        .load_system_settings()
        .map_err(NatError::StorageError)?
        .ipv6_enabled;

    // Validate before persisting.
    if let Err(msg) = validate_nat_config_with_ipv6(&cfg, ipv6_enabled) {
        warn!(error = %msg, "nat: config validation failed");
        return Err(NatError::ValidationFailed(msg));
    }

    state
        .config_store
        .save_nat_config(cfg.clone())
        .map_err(NatError::StorageError)?;

    info!(
        mode = ?cfg.outbound_mode,
        wan_interfaces = cfg.wan_interfaces.len(),
        rules = cfg.rules.len(),
        "nat: config saved"
    );

    // Re-apply the full ruleset.
    crate::captive_portal::apply_current_ruleset_nft(&state.config_store)
        .await
        .map_err(|e| NatError::EngineError(e.to_string()))?;

    info!("nat: nftables engine apply complete");
    Ok(Json(cfg))
}

/// Handler: `GET /nat/rules`
///
/// Returns the user-defined [`NatRule`] list from the current [`NatConfig`].
pub async fn list_rules(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, NatError> {
    let cfg = state
        .config_store
        .load_nat_config()
        .map_err(NatError::StorageError)?
        .unwrap_or_default();

    info!(count = cfg.rules.len(), "nat: listed rules");
    Ok(Json(cfg.rules))
}

/// Handler: `POST /nat/rules`
///
/// Appends a new [`NatRule`] to the current [`NatConfig`] and re-applies the
/// nftables ruleset.  Returns `201 Created` with the new rule on success.
pub async fn create_rule(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateNatRuleRequest>,
) -> Result<impl IntoResponse, NatError> {
    let ipv6_enabled = state
        .config_store
        .load_system_settings()
        .map_err(NatError::StorageError)?
        .ipv6_enabled;

    // Load current config before building the rule so hidden UI priority can
    // still produce deterministic ordering.
    let mut cfg = state
        .config_store
        .load_nat_config()
        .map_err(NatError::StorageError)?
        .unwrap_or_default();

    let rule = NatRule {
        id: Uuid::new_v4(),
        enabled: req.enabled,
        description: req.description,
        rule_type: req.rule_type,
        interface: req.interface,
        source: req.source,
        destination: req.destination,
        protocol: req.protocol,
        source_port: req.source_port,
        destination_port: req.destination_port,
        translation: req.translation,
        nat_reflection: req.nat_reflection,
        address_family: req.address_family,
        priority: req.priority.unwrap_or_else(|| next_nat_priority(&cfg)),
        log: req.log,
        auto_firewall_rule: req.auto_firewall_rule,
    };

    // Validate the new rule.
    if let Err(msg) = validate_nat_rule_with_ipv6(&rule, ipv6_enabled) {
        warn!(id = %rule.id, error = %msg, "nat: rule validation failed");
        return Err(NatError::ValidationFailed(msg));
    }

    cfg.rules.push(rule.clone());

    state
        .config_store
        .save_nat_config(cfg)
        .map_err(NatError::StorageError)?;

    info!(id = %rule.id, rule_type = ?rule.rule_type, "nat: rule created");

    // Re-apply the full ruleset.
    crate::captive_portal::apply_current_ruleset_nft(&state.config_store)
        .await
        .map_err(|e| NatError::EngineError(e.to_string()))?;

    info!(id = %rule.id, "nat: nftables engine apply complete");
    Ok((StatusCode::CREATED, Json(rule)))
}

/// Handler: `DELETE /nat/rules/{id}`
///
/// Removes the rule with the given UUID.  Returns `204 No Content` on success
/// or `404 Not Found` if no rule has that ID.
pub async fn delete_rule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, NatError> {
    let mut cfg = state
        .config_store
        .load_nat_config()
        .map_err(NatError::StorageError)?
        .unwrap_or_default();

    let original_len = cfg.rules.len();
    cfg.rules.retain(|r| r.id != id);

    if cfg.rules.len() == original_len {
        warn!(%id, "nat: rule not found for deletion");
        return Err(NatError::NotFound(id));
    }

    state
        .config_store
        .save_nat_config(cfg)
        .map_err(NatError::StorageError)?;

    info!(%id, "nat: rule deleted");

    // Re-apply the full ruleset.
    crate::captive_portal::apply_current_ruleset_nft(&state.config_store)
        .await
        .map_err(|e| NatError::EngineError(e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

/// Handler: `PUT /nat/rules/{id}`
///
/// Replaces the rule with the given UUID and re-applies the nftables ruleset.
/// Returns the updated rule on success or `404 Not Found` if no rule has
/// that ID.
pub async fn update_rule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Json(req): Json<CreateNatRuleRequest>,
) -> Result<impl IntoResponse, NatError> {
    let ipv6_enabled = state
        .config_store
        .load_system_settings()
        .map_err(NatError::StorageError)?
        .ipv6_enabled;

    let mut cfg = state
        .config_store
        .load_nat_config()
        .map_err(NatError::StorageError)?
        .unwrap_or_default();

    let pos = cfg
        .rules
        .iter()
        .position(|r| r.id == id)
        .ok_or(NatError::NotFound(id))?;

    let priority = req.priority.unwrap_or(cfg.rules[pos].priority);

    let rule = NatRule {
        id,
        enabled: req.enabled,
        description: req.description,
        rule_type: req.rule_type,
        interface: req.interface,
        source: req.source,
        destination: req.destination,
        protocol: req.protocol,
        source_port: req.source_port,
        destination_port: req.destination_port,
        translation: req.translation,
        nat_reflection: req.nat_reflection,
        address_family: req.address_family,
        priority,
        log: req.log,
        auto_firewall_rule: req.auto_firewall_rule,
    };

    if let Err(msg) = validate_nat_rule_with_ipv6(&rule, ipv6_enabled) {
        warn!(id = %id, error = %msg, "nat: rule validation failed");
        return Err(NatError::ValidationFailed(msg));
    }

    cfg.rules[pos] = rule.clone();

    state
        .config_store
        .save_nat_config(cfg)
        .map_err(NatError::StorageError)?;

    info!(%id, rule_type = ?rule.rule_type, "nat: rule updated");

    crate::captive_portal::apply_current_ruleset_nft(&state.config_store)
        .await
        .map_err(|e| NatError::EngineError(e.to_string()))?;

    info!(%id, "nat: nftables engine apply complete");
    Ok(Json(rule))
}

// ---------------------------------------------------------------------------
// Handler: PUT /nat/config outbound mode shortcut
// ---------------------------------------------------------------------------

/// Request body for the outbound mode portion of the config.
#[derive(Debug, Deserialize)]
pub struct SetOutboundModeRequest {
    pub outbound_mode: OutboundMode,
    pub wan_interfaces: Vec<String>,
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::{delete, get, post, put},
        Router,
    };
    use tower::ServiceExt;

    use crate::state::AppState;

    fn test_router() -> Router {
        let tmp = std::env::temp_dir().join(format!("dayshield-nat-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        let (state, _rx) = AppState::with_config_dir(tmp);
        let state = std::sync::Arc::new(state);
        Router::new()
            .route("/nat/config", get(get_config).put(put_config))
            .route("/nat/rules", get(list_rules).post(create_rule))
            .route("/nat/rules/{id}", delete(delete_rule).put(update_rule))
            .with_state(state)
    }

    #[tokio::test]
    async fn get_config_returns_ok() {
        let app = test_router();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/nat/config")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn put_config_rejects_invalid_interface_name() {
        let app = test_router();
        let payload = serde_json::json!({
            "outbound_mode": "automatic",
            "wan_interfaces": ["bad interface!"],
            "rules": [],
            "nat_reflection": false
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/nat/config")
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn create_rule_rejects_ipv6_source() {
        let app = test_router();
        let payload = serde_json::json!({
            "rule_type": "masquerade",
            "source": "2001:db8::/32",
            "interface": "eth0"
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/nat/rules")
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn list_rules_returns_ok() {
        let app = test_router();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/nat/rules")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn delete_rule_returns_404_when_not_found() {
        let app = test_router();
        let id = Uuid::new_v4();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/nat/rules/{}", id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn update_rule_returns_404_when_not_found() {
        let app = test_router();
        let id = Uuid::new_v4();
        let payload = serde_json::json!({
            "enabled": true,
            "rule_type": "dnat",
            "interface": "eth0",
            "protocol": "tcp",
            "destination_port": 443,
            "translation": { "address": "10.0.0.2", "port": 443 },
            "address_family": "ipv4",
            "log": false,
            "auto_firewall_rule": false
        });

        let resp = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/nat/rules/{}", id))
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn put_config_rejects_ipv6_destination_in_rule() {
        let app = test_router();
        let payload = serde_json::json!({
            "outbound_mode": "manual",
            "wan_interfaces": [],
            "rules": [{
                "id": Uuid::new_v4().to_string(),
                "enabled": true,
                "rule_type": "dnat",
                "destination": "2001:db8::1/128",
                "translation": { "address": "10.0.0.1", "port": 80 }
            }],
            "nat_reflection": false
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/nat/config")
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }
}
