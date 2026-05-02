//! API module — assembles the Axum router and registers all route handlers.

mod aliases;
mod dhcp;
mod dns;
mod dns_overrides;
mod firewall;
mod interfaces;
mod suricata;
mod system;
mod wireguard;

use std::sync::Arc;

use axum::{
    routing::{delete, get, post},
    Router,
};

use crate::state::AppState;

/// Build and return the top-level Axum [`Router`] with all registered routes.
///
/// Route overview:
/// - `GET  /system/status`                                 — overall system health and version information
/// - `GET  /interfaces`                                    — list all network interfaces
/// - `POST /interfaces`                                    — create / update a network interface
/// - `GET  /firewall/rules`                                — list firewall rules
/// - `POST /firewall/rules`                                — add a new firewall rule
/// - `GET  /firewall/aliases`                              — list firewall aliases
/// - `POST /firewall/aliases`                              — create a firewall alias
/// - `DELETE /firewall/aliases/{name}`                     — delete a firewall alias
/// - `GET  /dns/config`                                    — get DNS (Unbound) configuration
/// - `POST /dns/config`                                    — update DNS (Unbound) configuration
/// - `GET  /dns/overrides`                                 — list DNS host and domain overrides
/// - `POST /dns/overrides`                                 — create a DNS override
/// - `DELETE /dns/overrides/{hostname_or_domain}`          — delete a DNS override
/// - `GET  /dhcp/config`                                   — get DHCP (dnsmasq) configuration
/// - `POST /dhcp/config`                                   — update DHCP (dnsmasq) configuration
/// - `GET  /ips/config`                                    — get Suricata IPS configuration
/// - `POST /ips/config`                                    — update Suricata IPS configuration
/// - `GET  /wireguard/interfaces`                          — list WireGuard interfaces
/// - `POST /wireguard/interfaces`                          — create / update a WireGuard interface
/// - `DELETE /wireguard/interfaces/{name}`                 — remove a WireGuard interface
/// - `POST /wireguard/interfaces/{name}/generate-keys`     — generate a WireGuard keypair
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        // System
        .route("/system/status", get(system::get_status))
        // Interfaces
        .route("/interfaces", get(interfaces::list_interfaces))
        .route("/interfaces", post(interfaces::create_interface))
        // Firewall rules
        .route("/firewall/rules", get(firewall::list_rules))
        .route("/firewall/rules", post(firewall::create_rule))
        // Firewall aliases
        .route("/firewall/aliases", get(aliases::list_aliases))
        .route("/firewall/aliases", post(aliases::create_alias))
        .route("/firewall/aliases/{name}", delete(aliases::delete_alias))
        // DNS config
        .route("/dns/config", get(dns::get_config))
        .route("/dns/config", post(dns::update_config))
        // DNS overrides
        .route("/dns/overrides", get(dns_overrides::list_overrides))
        .route("/dns/overrides", post(dns_overrides::create_override))
        .route(
            "/dns/overrides/{name}",
            delete(dns_overrides::delete_override),
        )
        // DHCP
        .route("/dhcp/config", get(dhcp::get_config))
        .route("/dhcp/config", post(dhcp::update_config))
        // Suricata IPS
        .route("/ips/config", get(suricata::get_config))
        .route("/ips/config", post(suricata::update_config))
        // WireGuard VPN
        .route(
            "/wireguard/interfaces",
            get(wireguard::list_interfaces),
        )
        .route(
            "/wireguard/interfaces",
            post(wireguard::create_interface),
        )
        .route(
            "/wireguard/interfaces/{name}",
            delete(wireguard::delete_interface),
        )
        .route(
            "/wireguard/interfaces/{name}/generate-keys",
            post(wireguard::generate_keys),
        )
        .with_state(state)
}
