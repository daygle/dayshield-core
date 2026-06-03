//! DHCP engine - manages the Kea DHCPv4 server.
//!
//! # Overview
//!
//! This module translates a [`DhcpConfig`] into a Kea DHCPv4 JSON configuration
//! and asks the shared Kea runtime helper to validate and restart the server.
//!
//! # Functions
//!
//! | Function            | Purpose                                              |
//! |---------------------|------------------------------------------------------|
//! | [`generate_config`] | Build a complete Kea DHCPv4 JSON config string.      |
//! | [`apply_config`]    | Validate, install, and restart the DHCPv4 server.    |

use anyhow::Result;
use serde_json::json;
use tracing::info;

use crate::config::models::{ipv4_addr_in_cidr, normalize_ipv4_cidr, DhcpConfig, Interface};
use crate::engine::kea::{self, KeaServer};

/// Path to the Kea memfile lease database.
pub const KEA_LEASES_PATH: &str = kea::DHCP4_LEASES_PATH;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Fill DHCP defaults that depend on the configured LAN interface.
///
/// DHCP clients need the router option to point at an address owned by the
/// firewall on the served subnet. Falling back to the first usable subnet
/// address is useful only when interface metadata is unavailable.
pub fn apply_interface_defaults(config: &mut DhcpConfig, interfaces: &[Interface]) -> bool {
    let Some(iface) = interfaces
        .iter()
        .find(|iface| iface.name == config.interface)
    else {
        return false;
    };

    let interface_ipv4_addresses = iface
        .addresses
        .iter()
        .map(|address| {
            address
                .split_once('/')
                .map(|(ip, _)| ip)
                .unwrap_or(address.as_str())
        })
        .filter(|ip| !ip.contains(':') && ip.parse::<std::net::Ipv4Addr>().is_ok())
        .map(str::to_string)
        .collect::<Vec<_>>();

    if interface_ipv4_addresses.is_empty() {
        return false;
    }

    let mut changed = false;
    for scope in &mut config.scopes {
        let Some(router) = interface_ipv4_addresses
            .iter()
            .find(|ip| ipv4_addr_in_cidr(ip, &scope.subnet))
            .cloned()
        else {
            continue;
        };

        let current_gateway = scope
            .gateway
            .as_deref()
            .map(str::trim)
            .filter(|gateway| !gateway.is_empty());
        let gateway_is_interface_address = current_gateway
            .map(|gateway| {
                interface_ipv4_addresses.iter().any(|ip| ip == gateway)
                    && ipv4_addr_in_cidr(gateway, &scope.subnet)
            })
            .unwrap_or(false);

        if !gateway_is_interface_address {
            scope.gateway = Some(router);
            changed = true;
        }
    }

    changed
}

/// Generate a complete Kea DHCPv4 JSON configuration as a `String`.
///
/// Each [`DhcpScope`] becomes a `subnet4` entry.  Static reservations use
/// `hw-address` + `ip-address` entries within the subnet.
pub fn generate_config(config: &DhcpConfig) -> String {
    let mut subnets = Vec::new();

    for (i, scope) in config.scopes.iter().enumerate() {
        let subnet = normalize_ipv4_cidr(&scope.subnet).unwrap_or_else(|| scope.subnet.clone());
        let pool_str = format!("{}-{}", scope.pool_start, scope.pool_end);
        let router = scope
            .gateway
            .as_deref()
            .map(str::trim)
            .filter(|gateway| !gateway.is_empty())
            .map(str::to_string)
            .or_else(|| default_gateway_for_subnet(&subnet));

        let mut option_data = Vec::new();
        if let Some(gw) = &router {
            option_data.push(json!({ "name": "routers", "data": gw }));
        }
        let dns_servers = if scope.dns_servers.is_empty() {
            router.iter().cloned().collect::<Vec<_>>()
        } else {
            scope.dns_servers.clone()
        };
        if !dns_servers.is_empty() {
            option_data.push(json!({
                "name": "domain-name-servers",
                "data": dns_servers.join(", ")
            }));
        }
        if let Some(dn) = &scope.domain_name {
            if !dn.is_empty() {
                option_data.push(json!({ "name": "domain-name", "data": dn }));
                option_data.push(json!({ "name": "domain-search", "data": dn }));
            }
        }

        let reservations: Vec<_> = scope
            .reservations
            .iter()
            .map(|r| {
                let mut reservation_option_data = Vec::new();
                if !r.dns_servers.is_empty() {
                    reservation_option_data.push(json!({
                        "name": "domain-name-servers",
                        "data": r.dns_servers.join(", ")
                    }));
                }
                if !r.ntp_servers.is_empty() {
                    reservation_option_data.push(json!({
                        "name": "ntp-servers",
                        "data": r.ntp_servers.join(", ")
                    }));
                }

                let mut entry = json!({
                    "hw-address": r.mac_address,
                    "ip-address": r.ip_address,
                });
                if let Some(h) = &r.hostname {
                    entry["hostname"] = json!(h);
                }
                if !reservation_option_data.is_empty() {
                    entry["option-data"] = json!(reservation_option_data);
                }
                entry
            })
            .collect();

        subnets.push(json!({
            "id": (i as u32) + 1,
            "subnet": subnet,
            "pools": [{ "pool": pool_str }],
            "valid-lifetime": scope.lease_seconds,
            "option-data": option_data,
            "reservations": reservations,
        }));
    }

    let interfaces = if config.interface.is_empty() {
        vec![]
    } else {
        vec![config.interface.clone()]
    };

    let kea_conf = json!({
        "Dhcp4": {
            "interfaces-config": {
                "interfaces": interfaces,
                "dhcp-socket-type": "raw",
                "service-sockets-require-all": true
            },
            "lease-database": {
                "type": "memfile",
                "persist": true,
                "name": KEA_LEASES_PATH,
                "lfc-interval": 3600
            },
            "expired-leases-processing": {
                "reclaim-timer-wait-time": 10,
                "hold-reclaimed-time": 3600,
                "flush-reclaimed-timer-wait-time": 25
            },
            "renew-timer": 900,
            "rebind-timer": 1800,
            "valid-lifetime": 86400,
            "subnet4": subnets,
            "loggers": [{
                "name": "kea-dhcp4",
                "output-options": [{ "output": "stdout" }],
                "severity": "INFO",
                "debuglevel": 0
            }]
        }
    });

    serde_json::to_string_pretty(&kea_conf).unwrap_or_else(|_| "{}".to_string())
}

fn default_gateway_for_subnet(subnet: &str) -> Option<String> {
    let (addr, prefix) = subnet.split_once('/')?;
    let prefix = prefix.parse::<u32>().ok()?;
    if prefix > 30 {
        return None;
    }

    let octets = addr.parse::<std::net::Ipv4Addr>().ok()?.octets();
    let network = u32::from_be_bytes(octets);
    Some(std::net::Ipv4Addr::from(network.saturating_add(1)).to_string())
}

/// Apply the provided DHCP configuration to the running Kea DHCPv4 instance.
///
/// Steps:
/// 1. Generate `kea-dhcp4.conf` via [`generate_config`].
/// 2. Validate and install it via the shared Kea runtime helper.
/// 3. Restart the resolved Kea DHCPv4 systemd unit.
///
/// # Errors
///
/// Returns an error if the config file cannot be written or if the
/// restart command fails.
pub async fn apply_config(config: &DhcpConfig) -> Result<()> {
    info!(
        enabled = config.enabled,
        scopes = config.scopes.len(),
        "dhcp: applying config"
    );

    if !config.enabled {
        return kea::apply_config(KeaServer::Dhcp4, false, None).await;
    }

    let conf_str = generate_config(config);
    kea::apply_config(KeaServer::Dhcp4, true, Some(&conf_str)).await
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::models::{DhcpReservation, DhcpScope, Interface};
    use uuid::Uuid;

    fn base_scope() -> DhcpScope {
        DhcpScope {
            id: Uuid::new_v4(),
            subnet: "192.168.1.0/24".into(),
            pool_start: "192.168.1.100".into(),
            pool_end: "192.168.1.200".into(),
            gateway: Some("192.168.1.1".into()),
            dns_servers: vec!["1.1.1.1".into(), "8.8.8.8".into()],
            domain_name: None,
            lease_seconds: 86400,
            reservations: vec![],
        }
    }

    fn base_config() -> DhcpConfig {
        DhcpConfig {
            enabled: true,
            interface: "eth1".into(),
            scopes: vec![base_scope()],
        }
    }

    fn lan_interface(addresses: Vec<&str>) -> Interface {
        Interface {
            name: "eth1".into(),
            description: None,
            addresses: addresses.into_iter().map(str::to_string).collect(),
            mtu: None,
            mss: None,
            enabled: true,
            dhcp4: false,
            ipv6_mode: crate::config::models::Ipv6Mode::default(),
            track_source_interface: None,
            track_prefix_id: None,
            delegated_prefix_len: None,
            ra_mode: None,
            ia_pd_hint_len: None,
            vlan: None,
            parent_interface: None,
            wan_mode: None,
            pppoe_username: None,
            pppoe_password: None,
            gateway: None,
            block_private_networks: false,
            block_bogon_networks: false,
        }
    }

    #[test]
    fn generate_config_contains_pool() {
        let cfg = base_config();
        let out = generate_config(&cfg);
        assert!(out.contains("192.168.1.100-192.168.1.200"));
    }

    #[test]
    fn generate_config_contains_subnet() {
        let cfg = base_config();
        let out = generate_config(&cfg);
        assert!(out.contains("192.168.1.0/24"));
    }

    #[test]
    fn generate_config_normalizes_host_cidr_subnet() {
        let mut cfg = base_config();
        cfg.scopes[0].subnet = "192.168.1.1/24".into();
        let out = generate_config(&cfg);
        assert!(out.contains("\"subnet\": \"192.168.1.0/24\""));
        assert!(!out.contains("\"subnet\": \"192.168.1.1/24\""));
    }

    #[test]
    fn generate_config_contains_router_option() {
        let cfg = base_config();
        let out = generate_config(&cfg);
        assert!(out.contains("routers"));
        assert!(out.contains("192.168.1.1"));
    }

    #[test]
    fn generate_config_derives_router_when_gateway_missing() {
        let mut cfg = base_config();
        cfg.scopes[0].subnet = "192.168.50.0/24".into();
        cfg.scopes[0].gateway = None;
        let out = generate_config(&cfg);
        assert!(out.contains("routers"));
        assert!(out.contains("192.168.50.1"));
    }

    #[test]
    fn generate_config_uses_router_as_dns_when_dns_missing() {
        let mut cfg = base_config();
        cfg.scopes[0].dns_servers.clear();
        let out = generate_config(&cfg);
        assert!(out.contains("domain-name-servers"));
        assert!(out.contains("192.168.1.1"));
    }

    #[test]
    fn interface_defaults_use_actual_lan_address_for_router() {
        let mut cfg = base_config();
        cfg.scopes[0].subnet = "192.168.50.0/24".into();
        cfg.scopes[0].gateway = None;
        cfg.scopes[0].dns_servers.clear();

        let changed =
            apply_interface_defaults(&mut cfg, &[lan_interface(vec!["192.168.50.254/24"])]);

        assert!(changed);
        assert_eq!(cfg.scopes[0].gateway.as_deref(), Some("192.168.50.254"));
        let out = generate_config(&cfg);
        assert!(out.contains("192.168.50.254"));
        assert!(!out.contains("192.168.50.1"));
    }

    #[test]
    fn interface_defaults_replace_stale_gateway_not_owned_by_interface() {
        let mut cfg = base_config();
        cfg.scopes[0].subnet = "192.168.50.0/24".into();
        cfg.scopes[0].gateway = Some("192.168.50.1".into());

        let changed =
            apply_interface_defaults(&mut cfg, &[lan_interface(vec!["192.168.50.254/24"])]);

        assert!(changed);
        assert_eq!(cfg.scopes[0].gateway.as_deref(), Some("192.168.50.254"));
    }

    #[test]
    fn interface_defaults_replace_gateway_from_wrong_scope() {
        let mut cfg = base_config();
        cfg.scopes[0].subnet = "192.168.50.0/24".into();
        cfg.scopes[0].gateway = Some("192.168.1.1".into());

        let changed = apply_interface_defaults(
            &mut cfg,
            &[lan_interface(vec!["192.168.1.1/24", "192.168.50.254/24"])],
        );

        assert!(changed);
        assert_eq!(cfg.scopes[0].gateway.as_deref(), Some("192.168.50.254"));
    }

    #[test]
    fn generate_config_contains_dns_option() {
        let cfg = base_config();
        let out = generate_config(&cfg);
        assert!(out.contains("domain-name-servers"));
        assert!(out.contains("1.1.1.1"));
    }

    #[test]
    fn generate_config_static_reservation_with_hostname() {
        let mut cfg = base_config();
        cfg.scopes[0].reservations.push(DhcpReservation {
            id: Uuid::new_v4(),
            hostname: Some("myhost".into()),
            mac_address: "aa:bb:cc:dd:ee:ff".into(),
            ip_address: "192.168.1.50".into(),
            dns_servers: vec![],
            ntp_servers: vec![],
            description: String::new(),
        });
        let out = generate_config(&cfg);
        assert!(out.contains("aa:bb:cc:dd:ee:ff"));
        assert!(out.contains("192.168.1.50"));
        assert!(out.contains("myhost"));
    }

    #[test]
    fn generate_config_static_reservation_no_hostname() {
        let mut cfg = base_config();
        cfg.scopes[0].reservations.push(DhcpReservation {
            id: Uuid::new_v4(),
            hostname: None,
            mac_address: "11:22:33:44:55:66".into(),
            ip_address: "192.168.1.51".into(),
            dns_servers: vec![],
            ntp_servers: vec![],
            description: String::new(),
        });
        let out = generate_config(&cfg);
        assert!(out.contains("11:22:33:44:55:66"));
        assert!(out.contains("192.168.1.51"));
    }

    #[test]
    fn generate_config_static_reservation_with_dns_and_ntp_overrides() {
        let mut cfg = base_config();
        cfg.scopes[0].reservations.push(DhcpReservation {
            id: Uuid::new_v4(),
            hostname: Some("camera".into()),
            mac_address: "22:33:44:55:66:77".into(),
            ip_address: "192.168.1.52".into(),
            dns_servers: vec!["192.168.1.1".into(), "1.1.1.1".into()],
            ntp_servers: vec!["192.168.1.1".into()],
            description: String::new(),
        });
        let out = generate_config(&cfg);
        assert!(out.contains("domain-name-servers"));
        assert!(out.contains("ntp-servers"));
        assert!(out.contains("192.168.1.52"));
    }

    #[test]
    fn generate_config_interface() {
        let cfg = base_config();
        let out = generate_config(&cfg);
        assert!(out.contains("eth1"));
    }

    #[test]
    fn generate_config_requires_configured_sockets() {
        let cfg = base_config();
        let out = generate_config(&cfg);
        assert!(out.contains("service-sockets-require-all"));
    }

    #[test]
    fn generate_config_uses_runtime_leases_and_stdout_logging() {
        let cfg = base_config();
        let out = generate_config(&cfg);
        assert!(out.contains("/var/lib/kea/kea-leases4.csv"));
        assert!(out.contains("\"output\": \"stdout\""));
        assert!(!out.contains("/var/log/kea"));
    }

    #[test]
    fn generate_config_multiple_scopes() {
        let mut cfg = base_config();
        let mut s2 = base_scope();
        s2.subnet = "10.0.0.0/24".into();
        s2.pool_start = "10.0.0.50".into();
        s2.pool_end = "10.0.0.150".into();
        cfg.scopes.push(s2);
        let out = generate_config(&cfg);
        assert!(out.contains("192.168.1.100-192.168.1.200"));
        assert!(out.contains("10.0.0.50-10.0.0.150"));
    }

    #[test]
    fn generate_config_valid_lifetime() {
        let cfg = base_config();
        let out = generate_config(&cfg);
        assert!(out.contains("86400"));
    }
}
