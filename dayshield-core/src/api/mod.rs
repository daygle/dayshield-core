//! API module — assembles the Axum router and registers all route handlers.

mod acme;
mod aliases;
mod backup;
mod crowdsec;
mod dhcp;
mod dns;
mod dns_overrides;
mod firewall;
mod interfaces;
mod logs;
mod metrics;
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
/// - `GET  /crowdsec/config`                               — get CrowdSec bouncer configuration
/// - `POST /crowdsec/config`                               — update CrowdSec bouncer configuration
/// - `GET  /crowdsec/decisions`                            — list cached CrowdSec decisions
/// - `GET  /acme/config`                                   — get ACME certificate configuration
/// - `POST /acme/config`                                   — update ACME certificate configuration
/// - `POST /acme/issue`                                    — trigger certificate issuance / renewal
/// - `GET  /acme/status`                                   — get certificate status for primary domain
/// - `GET  /logs/ws`                                       — live log stream (WebSocket upgrade)
/// - `GET  /metrics`                                       — latest metrics snapshot (JSON)
/// - `GET  /metrics/history?seconds=N`                     — last N seconds of metrics history
/// - `GET  /metrics/ws`                                    — live metrics stream (WebSocket upgrade)
/// - `POST /backup/create`                                 — create a new backup archive
/// - `GET  /backup/list`                                   — list backup files on disk
/// - `GET  /backup/download/{filename}`                    — download a specific backup file
/// - `DELETE /backup/{filename}`                           — delete a specific backup file
/// - `POST /backup/restore`                                — restore from an uploaded backup file
/// - `GET  /backup/scheduler`                              — get the scheduler configuration
/// - `POST /backup/scheduler`                              — update the scheduler configuration
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
        // CrowdSec
        .route("/crowdsec/config", get(crowdsec::get_config))
        .route("/crowdsec/config", post(crowdsec::update_config))
        .route("/crowdsec/decisions", get(crowdsec::get_decisions))
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
        // ACME / TLS certificates
        .route("/acme/config", get(acme::get_config))
        .route("/acme/config", post(acme::update_config))
        .route("/acme/issue", post(acme::issue_certificates))
        .route("/acme/status", get(acme::get_certificate_status))
        // Live logs WebSocket
        .route("/logs/ws", get(logs::ws_handler))
        // Metrics REST API
        .route("/metrics", get(metrics::get_latest))
        .route("/metrics/history", get(metrics::get_history))
        // Metrics WebSocket streaming
        .route("/metrics/ws", get(metrics::ws_handler))
        // Backup / restore
        .route("/backup/create", post(backup::create_handler))
        .route("/backup/list", get(backup::list_handler))
        .route("/backup/download/{filename}", get(backup::download_handler))
        .route("/backup/{filename}", delete(backup::delete_handler))
        .route("/backup/restore", post(backup::restore_handler))
        .route("/backup/scheduler", get(backup::get_scheduler_handler))
        .route("/backup/scheduler", post(backup::update_scheduler_handler))
        .with_state(state)
}
