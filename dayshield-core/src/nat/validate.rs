//! NAT validation helpers.
//!
//! All rules delegate to [`crate::config::models::validate_nat_config`] and
//! [`crate::config::models::validate_nat_rule`], which are the single source
//! of truth.  This module re-exports them and exposes the lower-level helpers
//! for unit tests.

pub use crate::config::models::{
    is_valid_ipv4_addr, is_valid_ipv4_cidr_or_addr, validate_nat_config, validate_nat_rule,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat::model::{
        AddressFamily, NatConfig, NatProtocol, NatRule, NatRuleType, NatTranslation, OutboundMode,
    };
    use uuid::Uuid;

    // -------------------------------------------------------------------
    // IPv4 helpers
    // -------------------------------------------------------------------

    #[test]
    fn valid_ipv4_address() {
        assert!(is_valid_ipv4_addr("192.168.1.1"));
        assert!(is_valid_ipv4_addr("10.0.0.1"));
        assert!(is_valid_ipv4_addr("0.0.0.0"));
        assert!(is_valid_ipv4_addr("255.255.255.255"));
    }

    #[test]
    fn invalid_ipv4_address() {
        assert!(!is_valid_ipv4_addr("256.0.0.1"));
        assert!(!is_valid_ipv4_addr("::1"));
        assert!(!is_valid_ipv4_addr("2001:db8::1"));
        assert!(!is_valid_ipv4_addr("not-an-ip"));
        assert!(!is_valid_ipv4_addr(""));
    }

    #[test]
    fn valid_ipv4_cidr() {
        assert!(is_valid_ipv4_cidr_or_addr("10.0.0.0/8"));
        assert!(is_valid_ipv4_cidr_or_addr("192.168.1.0/24"));
        assert!(is_valid_ipv4_cidr_or_addr("203.0.113.1/32"));
        assert!(is_valid_ipv4_cidr_or_addr("0.0.0.0/0"));
    }

    #[test]
    fn ipv6_cidr_rejected() {
        assert!(!is_valid_ipv4_cidr_or_addr("2001:db8::/32"));
        assert!(!is_valid_ipv4_cidr_or_addr("::1/128"));
        assert!(!is_valid_ipv4_cidr_or_addr("fe80::/10"));
    }

    // -------------------------------------------------------------------
    // validate_nat_rule
    // -------------------------------------------------------------------

    fn base_masquerade_rule() -> NatRule {
        NatRule {
            id: Uuid::new_v4(),
            enabled: true,
            description: None,
            rule_type: NatRuleType::Masquerade,
            interface: Some("eth0".into()),
            source: Some("192.168.1.0/24".into()),
            destination: None,
            protocol: NatProtocol::Any,
            source_port: None,
            destination_port: None,
            translation: None,
            nat_reflection: false,
            address_family: AddressFamily::Ipv4,
            priority: 0,
            log: false,
        }
    }

    fn base_dnat_rule() -> NatRule {
        NatRule {
            id: Uuid::new_v4(),
            enabled: true,
            description: None,
            rule_type: NatRuleType::Dnat,
            interface: None,
            source: None,
            destination: Some("203.0.113.1/32".into()),
            protocol: NatProtocol::Tcp,
            source_port: None,
            destination_port: Some(80),
            translation: Some(NatTranslation {
                address: Some("192.168.1.10".into()),
                port: Some(80),
                port_end: None,
            }),
            nat_reflection: false,
            address_family: AddressFamily::Ipv4,
            priority: 0,
            log: false,
        }
    }

    #[test]
    fn valid_masquerade_rule() {
        assert!(validate_nat_rule(&base_masquerade_rule()).is_ok());
    }

    #[test]
    fn valid_dnat_rule() {
        assert!(validate_nat_rule(&base_dnat_rule()).is_ok());
    }

    #[test]
    fn valid_snat_rule() {
        let rule = NatRule {
            rule_type: NatRuleType::Snat,
            translation: Some(NatTranslation {
                address: Some("203.0.113.5".into()),
                port: None,
                port_end: None,
            }),
            ..base_masquerade_rule()
        };
        assert!(validate_nat_rule(&rule).is_ok());
    }

    #[test]
    fn ipv6_source_rejected() {
        let rule = NatRule {
            source: Some("2001:db8::/32".into()),
            ..base_masquerade_rule()
        };
        assert!(validate_nat_rule(&rule).is_err());
    }

    #[test]
    fn ipv6_destination_rejected() {
        let rule = NatRule {
            destination: Some("::1/128".into()),
            ..base_dnat_rule()
        };
        assert!(validate_nat_rule(&rule).is_err());
    }

    #[test]
    fn invalid_interface_name_rejected() {
        let rule = NatRule {
            interface: Some("invalid interface name!".into()),
            ..base_masquerade_rule()
        };
        assert!(validate_nat_rule(&rule).is_err());
    }

    #[test]
    fn dnat_without_translation_rejected() {
        let rule = NatRule {
            translation: None,
            ..base_dnat_rule()
        };
        assert!(validate_nat_rule(&rule).is_err());
    }

    #[test]
    fn snat_without_translation_rejected() {
        let rule = NatRule {
            rule_type: NatRuleType::Snat,
            translation: None,
            ..base_masquerade_rule()
        };
        assert!(validate_nat_rule(&rule).is_err());
    }

    #[test]
    fn dnat_with_ipv6_translation_address_rejected() {
        let rule = NatRule {
            translation: Some(NatTranslation {
                address: Some("2001:db8::1".into()),
                port: Some(80),
                port_end: None,
            }),
            ..base_dnat_rule()
        };
        assert!(validate_nat_rule(&rule).is_err());
    }

    #[test]
    fn translation_port_end_less_than_port_rejected() {
        let rule = NatRule {
            translation: Some(NatTranslation {
                address: Some("10.0.0.1".into()),
                port: Some(9000),
                port_end: Some(8000),
            }),
            ..base_dnat_rule()
        };
        assert!(validate_nat_rule(&rule).is_err());
    }

    #[test]
    fn translation_port_zero_rejected() {
        let rule = NatRule {
            translation: Some(NatTranslation {
                address: Some("10.0.0.1".into()),
                port: Some(0),
                port_end: None,
            }),
            ..base_dnat_rule()
        };
        assert!(validate_nat_rule(&rule).is_err());
    }

    // -------------------------------------------------------------------
    // validate_nat_config
    // -------------------------------------------------------------------

    #[test]
    fn empty_config_valid() {
        let cfg = NatConfig::default();
        assert!(validate_nat_config(&cfg).is_ok());
    }

    #[test]
    fn invalid_wan_interface_name_rejected() {
        let cfg = NatConfig {
            wan_interfaces: vec!["bad interface!".into()],
            ..Default::default()
        };
        assert!(validate_nat_config(&cfg).is_err());
    }

    #[test]
    fn invalid_rule_propagates_error() {
        let bad_rule = NatRule {
            source: Some("::1".into()), // IPv6 — invalid
            ..base_masquerade_rule()
        };
        let cfg = NatConfig {
            outbound_mode: OutboundMode::Manual,
            wan_interfaces: vec![],
            rules: vec![bad_rule],
            nat_reflection: false,
        };
        assert!(validate_nat_config(&cfg).is_err());
    }

    #[test]
    fn automatic_mode_with_valid_wan_interfaces_valid() {
        let cfg = NatConfig {
            outbound_mode: OutboundMode::Automatic,
            wan_interfaces: vec!["eth0".into(), "eth1".into()],
            rules: vec![],
            nat_reflection: false,
        };
        assert!(validate_nat_config(&cfg).is_ok());
    }
}
