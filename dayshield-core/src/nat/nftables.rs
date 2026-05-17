//! NAT nftables generator.
//!
//! This module exposes a small NAT-only wrapper around the engine-level
//! nftables generator. IPv4 output is the default; IPv6 NAT output is included
//! only when the caller passes the global IPv6 setting.

use crate::config::models::LogPosition;
use crate::nat::model::NatConfig;

/// Generate NAT nftables blocks for `config` with IPv6 disabled.
pub fn generate_nat_nft(config: &NatConfig) -> String {
    generate_nat_nft_with_ipv6(config, false)
}

/// Generate NAT nftables blocks for `config`.
///
/// Returns an empty string when the configuration would produce no rules
/// (for example, automatic mode with no WAN interfaces and no user rules).
pub fn generate_nat_nft_with_ipv6(config: &NatConfig, ipv6_enabled: bool) -> String {
    crate::engine::nftables::generate_nat_table(config, &LogPosition::After, ipv6_enabled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat::model::{
        AddressFamily, NatConfig, NatProtocol, NatRule, NatRuleType, NatTranslation, OutboundMode,
    };
    use uuid::Uuid;

    fn masquerade_rule(iface: &str, family: AddressFamily, src: Option<&str>) -> NatRule {
        NatRule {
            id: Uuid::new_v4(),
            enabled: true,
            description: None,
            rule_type: NatRuleType::Masquerade,
            interface: Some(iface.to_string()),
            source: src.map(str::to_string),
            destination: None,
            protocol: NatProtocol::Any,
            source_port: None,
            destination_port: None,
            translation: None,
            nat_reflection: false,
            address_family: family,
            priority: 0,
            log: false,
            auto_firewall_rule: true,
        }
    }

    fn dnat_rule(dst: &str, addr: &str, port: Option<u16>, family: AddressFamily) -> NatRule {
        NatRule {
            id: Uuid::new_v4(),
            enabled: true,
            description: None,
            rule_type: NatRuleType::Dnat,
            interface: None,
            source: None,
            destination: Some(dst.to_string()),
            protocol: NatProtocol::Tcp,
            source_port: None,
            destination_port: port,
            translation: Some(NatTranslation {
                address: Some(addr.to_string()),
                port,
                port_end: None,
            }),
            nat_reflection: false,
            address_family: family,
            priority: 0,
            log: false,
            auto_firewall_rule: true,
        }
    }

    #[test]
    fn empty_config_produces_empty_output() {
        let cfg = NatConfig::default();
        assert_eq!(generate_nat_nft(&cfg), "");
    }

    #[test]
    fn default_output_is_ipv4_only() {
        let cfg = NatConfig {
            outbound_mode: OutboundMode::Automatic,
            wan_interfaces: vec!["eth0".into()],
            rules: vec![],
            nat_reflection: false,
        };
        let out = generate_nat_nft(&cfg);
        assert!(out.contains("table ip nat"));
        assert!(!out.contains("table ip6 nat"));
        assert!(out.contains("oifname \"eth0\" masquerade"));
    }

    #[test]
    fn ipv6_enabled_emits_ip6_nat_table() {
        let cfg = NatConfig {
            outbound_mode: OutboundMode::Manual,
            wan_interfaces: vec![],
            rules: vec![masquerade_rule("eth1", AddressFamily::Ipv6, Some("2001:db8::/64"))],
            nat_reflection: false,
        };
        let out = generate_nat_nft_with_ipv6(&cfg, true);
        assert!(out.contains("table ip6 nat"));
        assert!(out.contains("ip6 saddr 2001:db8::/64"));
    }

    #[test]
    fn ipv6_rules_are_filtered_when_disabled() {
        let cfg = NatConfig {
            outbound_mode: OutboundMode::Manual,
            wan_interfaces: vec![],
            rules: vec![dnat_rule("2001:db8::1", "2001:db8::10", Some(443), AddressFamily::Ipv6)],
            nat_reflection: false,
        };
        assert_eq!(generate_nat_nft(&cfg), "");
    }
}
