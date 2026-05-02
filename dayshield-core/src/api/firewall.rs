//! Firewall rule endpoints — `GET /firewall/rules` and `POST /firewall/rules`.

use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;

use crate::{
    config::models::{Action, FirewallRule, Protocol},
    state::AppState,
};

/// Handler: list all firewall rules held in state.
pub async fn list_rules(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let rules = state.firewall_rules.read().await;
    Json(rules.clone())
}

/// Request body for `POST /firewall/rules`.
#[derive(Deserialize)]
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

/// Handler: append a new firewall rule.
pub async fn create_rule(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateRuleRequest>,
) -> impl IntoResponse {
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

    {
        let mut rules = state.firewall_rules.write().await;
        rules.push(rule.clone());
    }

    (StatusCode::CREATED, Json(rule))
}
