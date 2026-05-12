//! API module - assembles the Axum router and registers all route handlers.

mod acme;
mod admin;
mod aliases;
mod auth;
mod backup;
mod cloudflared;
mod crowdsec;
mod dashboard;
mod dhcp;
mod dns;
mod dns_overrides;
mod firewall;
mod gateways;
mod interfaces;
mod logs;
mod metrics;
mod nat;
mod notify;
mod ntp;
mod suricata;
mod system;
mod wireguard;

use std::sync::Arc;

use axum::{
    extract::DefaultBodyLimit,
    middleware,
    routing::{delete, get, post, put},
    Router,
};

use tower_http::services::{ServeDir, ServeFile};

use crate::auth::middleware::auth_middleware;
use crate::state::AppState;

/// Filesystem path where the compiled Management UI static assets are installed.
const UI_STATIC_DIR: &str = "/usr/local/share/dayshield-ui";

/// Build and return the top-level Axum [`Router`] with all registered routes.
///
/// Route overview:
/// - `POST /auth/login`                                    - authenticate and receive a JWT
/// - `POST /auth/logout`                                   - log out (client-side token drop)
/// - `POST /auth/change-password`                          - change the admin password
/// - `GET  /auth/status`                                   - authentication status
/// - `GET  /system/status`                                 - overall system health and version information
/// - `GET  /system/config`                                 - host-level settings (hostname, timezone, NTP…)
/// - `PUT  /system/config`                                 - update host-level settings
/// - `POST /system/reboot`                                 - trigger immediate system reboot
/// - `POST /system/shutdown`                               - trigger immediate system shutdown
/// - `GET  /system/updates/status`                         - get core/ui update status
/// - `GET  /system/updates/settings`                       - get update settings
/// - `PUT  /system/updates/settings`                       - update check interval / reboot policy / repo config
/// - `POST /system/updates/check`                          - force update check against GitHub
/// - `POST /system/updates/apply`                          - apply updates from GitHub repos
/// - `POST /system/updates/rollback`                       - rollback to prior commit
/// - `POST /system/updates/validate`                       - validate current commit matches applied state
/// - `POST /system/updates/appliance-rebuild-complete`     - clear pending appliance rebuild status
/// - `POST /system/updates/rootfs-live-rollback`           - rollback latest in-place rootfs live update
/// - `GET  /interfaces`                                    - list all network interfaces
/// - `POST /interfaces`                                    - create or update a network interface
/// - `GET  /gateways`                                      - list gateways with live routing and health state
/// - `POST /gateways`                                      - create or update a gateway
/// - `DELETE /gateways/{name}`                             - delete a gateway
/// - `GET  /firewall/rules`                                - list firewall rules
/// - `POST /firewall/rules`                                - add a new firewall rule
/// - `GET  /firewall/aliases`                              - list firewall aliases
/// - `POST /firewall/aliases`                              - create a firewall alias
/// - `DELETE /firewall/aliases/{name}`                     - delete a firewall alias
/// - `GET  /dns/config`                                    - get DNS (Unbound) configuration
/// - `POST /dns/config`                                    - update DNS (Unbound) configuration
/// - `GET  /dns/overrides`                                 - list DNS host and domain overrides
/// - `POST /dns/overrides`                                 - create a DNS override
/// - `DELETE /dns/overrides/{name}`                        - delete a DNS override
/// - `GET  /dhcp/config`                                   - get DHCP (dnsmasq) configuration
/// - `POST /dhcp/config`                                   - update DHCP (dnsmasq) configuration
/// - `GET  /suricata/config`                               - get Suricata configuration
/// - `POST /suricata/config`                               - update Suricata configuration
/// - `GET  /wireguard/interfaces`                          - list WireGuard interfaces
/// - `POST /wireguard/interfaces`                          - create / update a WireGuard interface
/// - `DELETE /wireguard/interfaces/{name}`                 - remove a WireGuard interface
/// - `POST /wireguard/interfaces/{name}/generate-keys`     - generate a WireGuard keypair
/// - `GET  /crowdsec/config`                               - get CrowdSec bouncer configuration
/// - `POST /crowdsec/config`                               - update CrowdSec bouncer configuration
/// - `GET  /crowdsec/decisions`                            - list cached CrowdSec decisions
/// - `GET  /acme/config`                                   - get ACME certificate configuration
/// - `POST /acme/config`                                   - update ACME certificate configuration
/// - `POST /acme/issue`                                    - trigger certificate issuance / renewal
/// - `GET  /acme/status`                                   - get certificate status for primary domain
/// - `GET  /logs/ws`                                       - live log stream (WebSocket upgrade)
/// - `GET  /logs/search?from=...&to=...`                   - historical log search by date/time range
/// - `GET  /metrics`                                       - latest metrics snapshot (JSON)
/// - `GET  /metrics/history?seconds=N`                     - last N seconds of metrics history
/// - `GET  /metrics/ws`                                    - live metrics stream (WebSocket upgrade)
/// - `POST /backup/create`                                 - create a new backup archive
/// - `GET  /backup/list`                                   - list backup files on disk
/// - `GET  /backup/download/{filename}`                    - download a specific backup file
/// - `DELETE /backup/{filename}`                           - delete a specific backup file
/// - `POST /backup/restore`                                - restore from an uploaded backup file
/// - `GET  /backup/scheduler`                              - get the scheduler configuration
/// - `POST /backup/scheduler`                              - update the scheduler configuration
/// - `GET  /notify/config`                                 - get notification configuration
/// - `POST /notify/config`                                 - update notification configuration
/// - `POST /notify/test`                                   - send a test notification email
/// - `GET  /notify/categories`                             - list available notification categories
/// - `GET  /ntp/config`                                    - get NTP configuration
/// - `POST /ntp/config`                                    - update + apply NTP configuration
/// - `GET  /ntp/status`                                    - live NTP synchronisation status
/// - `POST /ntp/resync`                                    - trigger an NTP resynchronization
/// - `GET  /cloudflared/config`                            - get Cloudflared configuration
/// - `POST /cloudflared/config`                            - update Cloudflared configuration
/// - `GET  /cloudflared/status`                            - get Cloudflared service status
/// - `POST /cloudflared/restart`                           - restart the Cloudflared service
/// - `GET  /cloudflared/logs`                              - get Cloudflared logs
/// - `GET  /nat/config`                                    - get NAT configuration
/// - `PUT  /nat/config`                                    - update NAT configuration
/// - `GET  /nat/rules`                                     - list NAT rules
/// - `POST /nat/rules`                                     - create a NAT rule
/// - `PUT  /nat/rules/{id}`                                - update a NAT rule
/// - `DELETE /nat/rules/{id}`                              - delete a NAT rule
/// - `GET  /admin/security`                                - get admin security settings
/// - `PUT  /admin/security`                                - update admin security settings
/// - `GET  /dashboard/system`                              - host resource usage summary
/// - `GET  /dashboard/network`                             - WAN/LAN network overview
/// - `GET  /dashboard/security`                            - firewall, Suricata, CrowdSec summary
/// - `GET  /dashboard/acme`                                - ACME certificate expiry summary
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        // Auth
        .route("/auth/login", post(auth::login))
        .route("/auth/logout", post(auth::logout))
        .route("/auth/change-password", post(auth::change_password))
        .route("/auth/status", get(auth::status))
        // System
        .route("/system/status", get(system::get_status))
        .route("/system/config", get(system::get_config))
        .route("/system/config", put(system::update_config))
        .route("/system/reboot", post(system::reboot))
        .route("/system/shutdown", post(system::shutdown))
        .route("/system/updates/status", get(system::get_updates_status))
        .route("/system/updates/settings", get(system::get_update_settings))
        .route("/system/updates/settings", put(system::update_update_settings))
        .route("/system/updates/check", post(system::check_updates))
        .route("/system/updates/apply", post(system::apply_updates))
        .route("/system/updates/rollback", post(system::rollback_updates))
        .route("/system/updates/validate", post(system::validate_updates))
        .route(
            "/system/updates/rootfs-live-rollback",
            post(system::rollback_rootfs_live_update),
        )
        .route(
            "/system/updates/appliance-rebuild-complete",
            post(system::mark_appliance_rebuild_complete),
        )
        // Dashboard
        .route("/dashboard/system", get(dashboard::get_system_status))
        .route("/dashboard/network", get(dashboard::get_network_status))
        .route("/dashboard/security", get(dashboard::get_security_status))
        .route("/dashboard/acme", get(dashboard::get_acme_status))
        // Interfaces
        .route("/interfaces", get(interfaces::list_interfaces))
        .route("/interfaces", post(interfaces::create_interface))
        .route("/interfaces/{name}", delete(interfaces::delete_interface))
        // Gateways
        .route("/gateways", get(gateways::list_gateways))
        .route("/gateways", post(gateways::upsert_gateway))
        .route("/gateways/{name}", delete(gateways::delete_gateway))
        // Firewall rules
        .route("/firewall/rules", get(firewall::list_rules))
        .route("/firewall/rules", post(firewall::create_rule))
        .route("/firewall/rules/{id}", put(firewall::update_rule))
        .route("/firewall/rules/{id}", delete(firewall::delete_rule))
        .route("/firewall/settings", get(firewall::get_settings))
        .route("/firewall/settings", put(firewall::update_settings))
        .route("/firewall/stats", get(firewall::get_stats))
        // Per-interface firewall rules
        .route("/interfaces/{name}/firewall/rules", get(firewall::list_interface_rules))
        .route("/interfaces/{name}/firewall/rules", post(firewall::create_interface_rule))
        .route("/interfaces/{name}/firewall/rules/{id}", delete(firewall::delete_interface_rule))
        // Firewall aliases
        .route("/firewall/aliases", get(aliases::list_aliases))
        .route("/firewall/aliases", post(aliases::create_alias))
        .route("/firewall/aliases/{name}", delete(aliases::delete_alias))
        // DNS config
        .route("/dns/config", get(dns::get_config))
        .route("/dns/config", post(dns::update_config))
        .route(
            "/interfaces/{name}/dns/blocklists",
            get(dns::list_interface_blocklists),
        )
        .route(
            "/interfaces/{name}/dns/blocklists",
            post(dns::create_interface_blocklist),
        )
        .route(
            "/interfaces/{name}/dns/blocklists/{id}",
            delete(dns::delete_interface_blocklist),
        )
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
        .route("/dhcp/static-leases", get(dhcp::list_static_leases))
        .route("/dhcp/static-leases", post(dhcp::create_static_lease))
        .route("/dhcp/static-leases/{id}", delete(dhcp::delete_static_lease))
        .route("/dhcp/leases", get(dhcp::list_active_leases))
        .route("/dhcp/pools", get(dhcp::list_pools))
        // Per-interface DHCP
        .route("/interfaces/{name}/dhcp/config", get(dhcp::get_interface_dhcp_config))
        .route("/interfaces/{name}/dhcp/config", post(dhcp::update_interface_dhcp_config))
        .route("/interfaces/{name}/dhcp/static-leases", get(dhcp::list_interface_static_leases))
        .route("/interfaces/{name}/dhcp/static-leases", post(dhcp::create_interface_static_lease))
        .route("/interfaces/{name}/dhcp/static-leases/{id}", delete(dhcp::delete_interface_static_lease))
        // Suricata IPS/IDS
        .route("/suricata/config", get(suricata::get_config))
        .route("/suricata/config", post(suricata::update_config))
        .route("/suricata/rulesets", get(suricata::list_rulesets))
        .route("/suricata/rulesets", post(suricata::create_ruleset))
        .route("/suricata/rulesets/{id}", put(suricata::update_ruleset))
        .route("/suricata/alerts", get(suricata::list_alerts))
        .route("/interfaces/{name}/suricata", get(suricata::get_interface_suricata_config))
        .route("/interfaces/{name}/suricata", post(suricata::update_interface_suricata_config))
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
        // Per-WireGuard-interface firewall rules
        .route(
            "/wireguard/interfaces/{name}/firewall/rules",
            get(firewall::list_interface_rules),
        )
        .route(
            "/wireguard/interfaces/{name}/firewall/rules",
            post(firewall::create_interface_rule),
        )
        .route(
            "/wireguard/interfaces/{name}/firewall/rules/{id}",
            delete(firewall::delete_interface_rule),
        )
        // ACME / TLS certificates
        .route("/acme/config", get(acme::get_config))
        .route("/acme/config", post(acme::update_config))
        .route("/acme/issue", post(acme::issue_certificates))
        .route("/acme/status", get(acme::get_certificate_status))
        // Live logs WebSocket
        .route("/logs/ws", get(logs::ws_handler))
        .route("/logs/search", get(logs::search_logs))
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
        .route(
            "/backup/restore",
            post(backup::restore_handler)
                .layer(DefaultBodyLimit::max(backup::MAX_BACKUP_RESTORE_BYTES)),
        )
        .route("/backup/scheduler", get(backup::get_scheduler_handler))
        .route("/backup/scheduler", post(backup::update_scheduler_handler))
        // Notifications
        .route("/notify/config", get(notify::get_config))
        .route("/notify/config", post(notify::update_config))
        .route("/notify/test", post(notify::send_test))
        .route("/notify/categories", get(notify::get_categories))
        // NTP
        .route("/ntp/config", get(ntp::get_config))
        .route("/ntp/config", post(ntp::update_config))
        .route("/ntp/status", get(ntp::get_status))
        .route("/ntp/resync", post(ntp::resync))
        // Cloudflared
        .route("/cloudflared/config", get(cloudflared::get_config))
        .route("/cloudflared/config", post(cloudflared::update_config))
        .route("/cloudflared/status", get(cloudflared::get_status))
        .route("/cloudflared/restart", post(cloudflared::restart_service))
        .route("/cloudflared/logs", get(cloudflared::get_logs))
        // NAT
        .route("/nat/config", get(nat::get_config))
        .route("/nat/config", put(nat::put_config))
        .route("/nat/rules", get(nat::list_rules))
        .route("/nat/rules", post(nat::create_rule))
        .route("/nat/rules/{id}", put(nat::update_rule))
        .route("/nat/rules/{id}", delete(nat::delete_rule))
        // Admin security settings
        .route("/admin/security", get(admin::get_security))
        .route("/admin/security", put(admin::update_security))
        // Serve the compiled Management UI static files.
        // The fallback_service is intentionally placed outside the auth middleware
        // so that the UI assets are publicly accessible; the API routes they call
        // are still JWT-protected via the layer() above.
        // Note: in axum 0.8, fallback_service is NOT covered by layer(), so
        // the auth middleware does not apply to these static assets regardless of ordering.
        .fallback_service(
            ServeDir::new(UI_STATIC_DIR)
                .not_found_service(ServeFile::new(format!("{UI_STATIC_DIR}/index.html"))),
        )
        // Apply authentication middleware to all registered API routes.
        // The static UI fallback service is intentionally left outside this
        // route layer so public UI assets can be loaded without a token.
        .route_layer(middleware::from_fn(auth_middleware))
        .with_state(state)
}
