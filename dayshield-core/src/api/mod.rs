//! API module — assembles the Axum router and registers all route handlers.

mod dhcp;
mod dns;
mod firewall;
mod interfaces;
mod system;

use std::sync::Arc;

use axum::{
    routing::{get, post},
    Router,
};

use crate::state::AppState;

/// Build and return the top-level Axum [`Router`] with all registered routes.
///
/// Route overview:
/// - `GET  /system/status`   — overall system health and version information
/// - `GET  /interfaces`      — list all network interfaces
/// - `POST /interfaces`      — create / update a network interface
/// - `GET  /firewall/rules`  — list firewall rules
/// - `POST /firewall/rules`  — add a new firewall rule
/// - `GET  /dns/config`      — get DNS (Unbound) configuration
/// - `POST /dns/config`      — update DNS (Unbound) configuration
/// - `GET  /dhcp/config`     — get DHCP (dnsmasq) configuration
/// - `POST /dhcp/config`     — update DHCP (dnsmasq) configuration
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        // System
        .route("/system/status", get(system::get_status))
        // Interfaces
        .route("/interfaces", get(interfaces::list_interfaces))
        .route("/interfaces", post(interfaces::create_interface))
        // Firewall
        .route("/firewall/rules", get(firewall::list_rules))
        .route("/firewall/rules", post(firewall::create_rule))
        // DNS
        .route("/dns/config", get(dns::get_config))
        .route("/dns/config", post(dns::update_config))
        // DHCP
        .route("/dhcp/config", get(dhcp::get_config))
        .route("/dhcp/config", post(dhcp::update_config))
        .with_state(state)
}
