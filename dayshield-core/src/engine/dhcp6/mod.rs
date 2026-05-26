//! DHCPv6 engine - manages the Kea DHCPv6 server.
//!
//! This module translates a [`Dhcp6Config`] into a Kea DHCPv6 JSON
//! configuration and asks the shared Kea runtime helper to validate and restart
//! the server.

use anyhow::Result;
use serde_json::json;
use tracing::info;

use crate::config::models::{normalize_ipv6_cidr, Dhcp6Config};
use crate::engine::kea::{self, KeaServer};

/// Path to the Kea DHCPv6 memfile lease database.
pub const KEA6_LEASES_PATH: &str = kea::DHCP6_LEASES_PATH;

/// Generate a complete Kea DHCPv6 JSON configuration as a `String`.
pub fn generate_config(config: &Dhcp6Config) -> String {
    let mut subnets = Vec::new();

    for (i, scope) in config.scopes.iter().enumerate() {
        let subnet = normalize_ipv6_cidr(&scope.subnet).unwrap_or_else(|| scope.subnet.clone());
        let pool_str = format!("{}-{}", scope.pool_start, scope.pool_end);

        let mut option_data = Vec::new();
        if !scope.dns_servers.is_empty() {
            option_data.push(json!({
                "name": "dns-servers",
                "data": scope.dns_servers.join(", ")
            }));
        }
        if let Some(dn) = &scope.domain_name {
            if !dn.is_empty() {
                option_data.push(json!({ "name": "domain-search", "data": dn }));
            }
        }

        let reservations: Vec<serde_json::Value> = scope
            .reservations
            .iter()
            .map(|r| {
                let mut reservation_option_data = Vec::new();
                if !r.dns_servers.is_empty() {
                    reservation_option_data.push(json!({
                        "name": "dns-servers",
                        "data": r.dns_servers.join(", ")
                    }));
                }
                if !r.ntp_servers.is_empty() {
                    reservation_option_data.push(json!({
                        "name": "sntp-servers",
                        "data": r.ntp_servers.join(", ")
                    }));
                }

                let mut entry = json!({
                    "duid": r.duid,
                    "ip-addresses": [r.ip_address],
                });
                if let Some(hn) = &r.hostname {
                    if !hn.is_empty() {
                        entry["hostname"] = json!(hn);
                    }
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
            "preferred-lifetime": scope.lease_seconds,
            "valid-lifetime": scope.lease_seconds,
            "renew-timer": scope.lease_seconds / 2,
            "rebind-timer": (scope.lease_seconds * 3) / 4,
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
        "Dhcp6": {
            "interfaces-config": {
                "interfaces": interfaces,
                "service-sockets-require-all": true
            },
            "lease-database": {
                "type": "memfile",
                "persist": true,
                "name": KEA6_LEASES_PATH,
                "lfc-interval": 3600
            },
            "expired-leases-processing": {
                "reclaim-timer-wait-time": 10,
                "hold-reclaimed-time": 3600,
                "flush-reclaimed-timer-wait-time": 25
            },
            "subnet6": subnets,
            "loggers": [{
                "name": "kea-dhcp6",
                "output-options": [{ "output": "stdout" }],
                "severity": "INFO",
                "debuglevel": 0
            }]
        }
    });

    serde_json::to_string_pretty(&kea_conf).unwrap_or_else(|_| "{}".to_string())
}

/// Apply the provided DHCPv6 configuration to the running Kea DHCPv6 instance.
pub async fn apply_config(config: &Dhcp6Config) -> Result<()> {
    info!(
        enabled = config.enabled,
        scopes = config.scopes.len(),
        "dhcp6: applying config"
    );

    if !config.enabled {
        return kea::apply_config(KeaServer::Dhcp6, false, None).await;
    }

    let conf_str = generate_config(config);
    kea::apply_config(KeaServer::Dhcp6, true, Some(&conf_str)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::models::{Dhcp6Config, Dhcp6Scope};
    use uuid::Uuid;

    fn base_config() -> Dhcp6Config {
        Dhcp6Config {
            enabled: true,
            interface: "eth1".into(),
            scopes: vec![Dhcp6Scope {
                id: Uuid::new_v4(),
                subnet: "fd00:1::/64".into(),
                pool_start: "fd00:1::100".into(),
                pool_end: "fd00:1::1ff".into(),
                dns_servers: vec!["fd00:1::1".into()],
                lease_seconds: 86400,
                domain_name: None,
                reservations: vec![],
            }],
        }
    }

    #[test]
    fn generate_config_contains_subnet() {
        let cfg = base_config();
        let out = generate_config(&cfg);
        assert!(out.contains("\"subnet\": \"fd00:1::/64\""));
    }

    #[test]
    fn generate_config_normalizes_host_cidr_subnet() {
        let mut cfg = base_config();
        cfg.scopes[0].subnet = "fd00:1::1/64".into();
        let out = generate_config(&cfg);
        assert!(out.contains("\"subnet\": \"fd00:1::/64\""));
        assert!(!out.contains("\"subnet\": \"fd00:1::1/64\""));
    }

    #[test]
    fn generate_config_omits_dhcpv4_socket_type() {
        let cfg = base_config();
        let out = generate_config(&cfg);
        assert!(!out.contains("dhcp-socket-type"));
        assert!(out.contains("service-sockets-require-all"));
    }

    #[test]
    fn generate_config_uses_runtime_leases_and_stdout_logging() {
        let cfg = base_config();
        let out = generate_config(&cfg);
        assert!(out.contains("/var/lib/kea/kea-leases6.csv"));
        assert!(out.contains("\"output\": \"stdout\""));
        assert!(!out.contains("/var/log/kea"));
    }

    #[test]
    fn generate_config_static_reservation_with_dns_and_ntp_overrides() {
        let mut cfg = base_config();
        cfg.scopes[0]
            .reservations
            .push(crate::config::models::Dhcp6Reservation {
                id: Uuid::new_v4(),
                duid: "00:03:00:01:aa:bb:cc:dd:ee:ff".into(),
                ip_address: "fd00:1::50".into(),
                hostname: Some("sensor".into()),
                dns_servers: vec!["fd00:1::1".into()],
                ntp_servers: vec!["fd00:1::2".into()],
                description: String::new(),
            });
        let out = generate_config(&cfg);
        assert!(out.contains("dns-servers"));
        assert!(out.contains("sntp-servers"));
        assert!(out.contains("fd00:1::50"));
    }
}
