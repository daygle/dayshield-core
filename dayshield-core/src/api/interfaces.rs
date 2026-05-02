//! Interface endpoints — `GET /interfaces` and `POST /interfaces`.

use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;

use crate::{
    config::models::{Interface, InterfaceType},
    state::AppState,
};

/// Handler: list all network interfaces currently held in state.
pub async fn list_interfaces(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let ifaces = state.interfaces.read().await;
    Json(ifaces.clone())
}

/// Request body for `POST /interfaces`.
#[derive(Deserialize)]
pub struct CreateInterfaceRequest {
    pub name: String,
    pub description: Option<String>,
    pub if_type: InterfaceType,
    pub enabled: bool,
    pub ipv4_address: Option<String>,
    pub ipv4_prefix_len: Option<u8>,
    pub ipv6_address: Option<String>,
    pub ipv6_prefix_len: Option<u8>,
    pub mtu: Option<u16>,
}

/// Handler: create or replace a network interface entry.
pub async fn create_interface(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateInterfaceRequest>,
) -> impl IntoResponse {
    let iface = Interface {
        id: uuid::Uuid::new_v4(),
        name: req.name,
        description: req.description,
        if_type: req.if_type,
        enabled: req.enabled,
        ipv4_address: req.ipv4_address,
        ipv4_prefix_len: req.ipv4_prefix_len,
        ipv6_address: req.ipv6_address,
        ipv6_prefix_len: req.ipv6_prefix_len,
        mtu: req.mtu,
    };

    {
        let mut ifaces = state.interfaces.write().await;
        ifaces.push(iface.clone());
    }

    (StatusCode::CREATED, Json(iface))
}
