//! NAT nftables generator.
//!
//! Wraps the engine-level generator and provides helpers specific to the NAT
//! subsystem.  The actual generation logic lives in
//! [`crate::engine::nftables`]; this module provides a convenience function
//! that generates only the `table ip nat { … }` block without the surrounding
//! `inet filter` table.
//!
//! # Usage
//!
//! ```rust,ignore
//! use crate::nat::nftables::generate_nat_nft;
//! use crate::nat::model::{NatConfig, OutboundMode};
//!
//! let cfg = NatConfig {
//!     outbound_mode: OutboundMode::Automatic,
//!     wan_interfaces: vec!["eth0".into()],
//!     ..Default::default()
//! };
//! let nft = generate_nat_nft(&cfg);
//! assert!(nft.contains("oifname \"eth0\" masquerade"));
//! ```

use crate::nat::model::{NatConfig, NatProtocol, NatRuleType, NatTranslation, OutboundMode};

/// Generate the `table ip nat { … }` nftables block for `config`.
///
/// Returns an empty string when the configuration would produce no rules
/// (e.g. `Automatic` mode with no WAN interfaces and no user rules).
///
/// The output is deterministic: rules are sorted by `priority` ascending.
pub fn generate_nat_nft(config: &NatConfig) -> String {
    // Sort enabled user rules by priority.
    let mut sorted: Vec<&crate::nat::model::NatRule> =
        config.rules.iter().filter(|r| r.enabled).collect();
    sorted.sort_by_key(|r| r.priority);

    let has_auto_masquerade = matches!(
        config.outbound_mode,
        OutboundMode::Automatic | OutboundMode::Hybrid
    ) && !config.wan_interfaces.is_empty();

    let user_postrouting: Vec<_> = sorted
        .iter()
        .filter(|r| matches!(r.rule_type, NatRuleType::Masquerade | NatRuleType::Snat))
        .collect();
    let emit_user_postrouting = matches!(
        config.outbound_mode,
        OutboundMode::Hybrid | OutboundMode::Manual
    ) && !user_postrouting.is_empty();

    let prerouting_rules: Vec<_> = sorted
        .iter()
        .filter(|r| matches!(r.rule_type, NatRuleType::Dnat))
        .collect();

    let reflection_rules: Vec<_> = sorted
        .iter()
        .filter(|r| {
            matches!(r.rule_type, NatRuleType::Dnat)
                && (r.nat_reflection || config.nat_reflection)
        })
        .collect();

    let has_postrouting = has_auto_masquerade || emit_user_postrouting;
    let has_prerouting = !prerouting_rules.is_empty();
    let has_reflection = !reflection_rules.is_empty();

    if !has_postrouting && !has_prerouting && !has_reflection {
        return String::new();
    }

    let mut out = String::new();
    out.push_str("table ip nat {\n");

    // postrouting chain
    if has_postrouting {
        out.push_str("    chain postrouting {\n");
        out.push_str(
            "        type nat hook postrouting priority srcnat; policy accept;\n",
        );
        if has_auto_masquerade {
            for iface in &config.wan_interfaces {
                out.push_str(&format!("        oifname \"{}\" masquerade\n", iface));
            }
        }
        if emit_user_postrouting {
            for rule in &user_postrouting {
                if let Some(line) = format_postrouting(rule) {
                    if rule.log {
                        out.push_str(&format!(
                            "        log prefix \"dayshield-nat[{}]: \"\n",
                            rule.id
                        ));
                    }
                    out.push_str(&format!("        {}\n", line));
                }
            }
        }
        out.push_str("    }\n\n");
    }

    // prerouting chain (DNAT / port forwards)
    if has_prerouting {
        out.push_str("    chain prerouting {\n");
        out.push_str(
            "        type nat hook prerouting priority dstnat; policy accept;\n",
        );
        for rule in &prerouting_rules {
            if let Some(line) = format_prerouting(rule) {
                if rule.log {
                    out.push_str(&format!(
                        "        log prefix \"dayshield-nat[{}]: \"\n",
                        rule.id
                    ));
                }
                out.push_str(&format!("        {}\n", line));
            }
        }
        out.push_str("    }\n\n");
    }

    // output chain (hairpin / NAT reflection)
    if has_reflection {
        out.push_str("    chain output {\n");
        out.push_str(
            "        type nat hook output priority -100; policy accept;\n",
        );
        for rule in &reflection_rules {
            if let Some(line) = format_prerouting(rule) {
                out.push_str(&format!("        {}\n", line));
            }
        }
        out.push_str("    }\n");
    }

    out.push_str("}\n");
    out
}

// ---------------------------------------------------------------------------
// Private formatting helpers
// ---------------------------------------------------------------------------

fn format_prerouting(nat: &crate::nat::model::NatRule) -> Option<String> {
    match nat.rule_type {
        NatRuleType::Dnat => {
            let mut parts: Vec<String> = Vec::new();
            if let Some(iface) = &nat.interface {
                parts.push(format!("iifname \"{}\"", iface));
            }
            if let Some(src) = &nat.source {
                parts.push(format!("ip saddr {}", src));
            }
            if let Some(dst) = &nat.destination {
                parts.push(format!("ip daddr {}", dst));
            }
            // Protocol + destination port.
            match nat.protocol {
                NatProtocol::Tcp => {
                    if let Some(dport) = nat.destination_port {
                        parts.push(format!("tcp dport {}", dport));
                    }
                }
                NatProtocol::Udp => {
                    if let Some(dport) = nat.destination_port {
                        parts.push(format!("udp dport {}", dport));
                    }
                }
                NatProtocol::TcpUdp => {
                    if let Some(dport) = nat.destination_port {
                        parts.push(format!("{{ tcp, udp }} dport {}", dport));
                    }
                }
                NatProtocol::Any => {}
            }
            let translation = nat.translation.as_ref()?;
            let addr = translation.address.as_deref()?;
            let target = format_translation_target(addr, translation);
            parts.push(target);
            Some(parts.join(" "))
        }
        _ => None,
    }
}

fn format_postrouting(nat: &crate::nat::model::NatRule) -> Option<String> {
    match nat.rule_type {
        NatRuleType::Masquerade => {
            let mut parts: Vec<String> = Vec::new();
            if let Some(src) = &nat.source {
                parts.push(format!("ip saddr {}", src));
            }
            if let Some(iface) = &nat.interface {
                parts.push(format!("oifname \"{}\"", iface));
            }
            parts.push("masquerade".to_string());
            Some(parts.join(" "))
        }
        NatRuleType::Snat => {
            let mut parts: Vec<String> = Vec::new();
            if let Some(src) = &nat.source {
                parts.push(format!("ip saddr {}", src));
            }
            if let Some(iface) = &nat.interface {
                parts.push(format!("oifname \"{}\"", iface));
            }
            let translation = nat.translation.as_ref()?;
            let addr = translation.address.as_deref()?;
            parts.push(format!("snat to {}", addr));
            Some(parts.join(" "))
        }
        NatRuleType::Dnat => None,
    }
}

fn format_translation_target(addr: &str, t: &NatTranslation) -> String {
    match (t.port, t.port_end) {
        (Some(p), Some(pe)) => format!("dnat to {}:{}-{}", addr, p, pe),
        (Some(p), None) => format!("dnat to {}:{}", addr, p),
        (None, _) => format!("dnat to {}", addr),
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat::model::{
        AddressFamily, NatConfig, NatProtocol, NatRule, NatRuleType, NatTranslation, OutboundMode,
    };
    use uuid::Uuid;

    fn masquerade_rule(iface: &str, src: Option<&str>) -> NatRule {
        NatRule {
            id: Uuid::new_v4(),
            enabled: true,
            description: None,
            rule_type: NatRuleType::Masquerade,
            interface: Some(iface.to_string()),
            source: src.map(|s| s.to_string()),
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

    fn dnat_rule(dst: &str, addr: &str, port: Option<u16>) -> NatRule {
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
            address_family: AddressFamily::Ipv4,
            priority: 0,
            log: false,
        }
    }

    #[test]
    fn empty_config_produces_empty_output() {
        let cfg = NatConfig::default();
        assert_eq!(generate_nat_nft(&cfg), "");
    }

    #[test]
    fn automatic_mode_generates_masquerade_chain() {
        let cfg = NatConfig {
            outbound_mode: OutboundMode::Automatic,
            wan_interfaces: vec!["eth0".into()],
            rules: vec![],
            nat_reflection: false,
        };
        let out = generate_nat_nft(&cfg);
        assert!(out.contains("table ip nat"), "ip nat table header");
        assert!(out.contains("chain postrouting"), "postrouting chain");
        assert!(out.contains("oifname \"eth0\" masquerade"), "auto masquerade rule");
        assert!(!out.contains("chain prerouting"), "no prerouting without dnat");
    }

    #[test]
    fn automatic_mode_multiple_wan_interfaces() {
        let cfg = NatConfig {
            outbound_mode: OutboundMode::Automatic,
            wan_interfaces: vec!["eth0".into(), "ppp0".into()],
            rules: vec![],
            nat_reflection: false,
        };
        let out = generate_nat_nft(&cfg);
        assert!(out.contains("oifname \"eth0\" masquerade"));
        assert!(out.contains("oifname \"ppp0\" masquerade"));
    }

    #[test]
    fn manual_mode_no_auto_masquerade() {
        let cfg = NatConfig {
            outbound_mode: OutboundMode::Manual,
            wan_interfaces: vec!["eth0".into()],
            rules: vec![masquerade_rule("eth0", Some("192.168.0.0/24"))],
            nat_reflection: false,
        };
        let out = generate_nat_nft(&cfg);
        // Auto masquerade "oifname eth0 masquerade" (without src) must not appear.
        assert!(!out.contains("        oifname \"eth0\" masquerade\n"));
        // User masquerade rule with source must appear.
        assert!(out.contains("ip saddr 192.168.0.0/24"));
        assert!(out.contains("masquerade"));
    }

    #[test]
    fn hybrid_mode_both_auto_and_user_rules() {
        let cfg = NatConfig {
            outbound_mode: OutboundMode::Hybrid,
            wan_interfaces: vec!["eth0".into()],
            rules: vec![masquerade_rule("eth1", Some("10.0.0.0/8"))],
            nat_reflection: false,
        };
        let out = generate_nat_nft(&cfg);
        assert!(out.contains("oifname \"eth0\" masquerade"), "auto rule");
        assert!(out.contains("ip saddr 10.0.0.0/8"), "user src");
        assert!(out.contains("oifname \"eth1\" masquerade"), "user iface");
    }

    #[test]
    fn dnat_rule_in_prerouting() {
        let cfg = NatConfig {
            outbound_mode: OutboundMode::Manual,
            wan_interfaces: vec![],
            rules: vec![dnat_rule("203.0.113.1/32", "10.0.0.10", Some(8080))],
            nat_reflection: false,
        };
        let out = generate_nat_nft(&cfg);
        assert!(out.contains("chain prerouting"), "prerouting chain");
        assert!(out.contains("ip daddr 203.0.113.1/32"));
        assert!(out.contains("dnat to 10.0.0.1") || out.contains("dnat to 10.0.0.10"));
    }

    #[test]
    fn port_range_translation() {
        let rule = NatRule {
            id: Uuid::new_v4(),
            enabled: true,
            description: None,
            rule_type: NatRuleType::Dnat,
            interface: None,
            source: None,
            destination: Some("203.0.113.5/32".into()),
            protocol: NatProtocol::Tcp,
            source_port: None,
            destination_port: Some(8000),
            translation: Some(NatTranslation {
                address: Some("10.0.0.1".into()),
                port: Some(8000),
                port_end: Some(8080),
            }),
            nat_reflection: false,
            address_family: AddressFamily::Ipv4,
            priority: 0,
            log: false,
        };
        let cfg = NatConfig {
            outbound_mode: OutboundMode::Manual,
            wan_interfaces: vec![],
            rules: vec![rule],
            nat_reflection: false,
        };
        let out = generate_nat_nft(&cfg);
        assert!(out.contains("dnat to 10.0.0.1:8000-8080"), "port range translation");
    }

    #[test]
    fn reflection_generates_output_chain() {
        let mut rule = dnat_rule("203.0.113.1/32", "10.0.0.1", Some(80));
        rule.nat_reflection = true;
        let cfg = NatConfig {
            outbound_mode: OutboundMode::Manual,
            wan_interfaces: vec![],
            rules: vec![rule],
            nat_reflection: false,
        };
        let out = generate_nat_nft(&cfg);
        assert!(out.contains("hook output"), "output chain for reflection");
    }

    #[test]
    fn global_reflection_applies_to_all_dnat_rules() {
        let cfg = NatConfig {
            outbound_mode: OutboundMode::Manual,
            wan_interfaces: vec![],
            rules: vec![dnat_rule("203.0.113.2/32", "192.168.1.10", Some(443))],
            nat_reflection: true,
        };
        let out = generate_nat_nft(&cfg);
        assert!(out.contains("hook output"), "global reflection");
    }

    #[test]
    fn disabled_rule_not_emitted() {
        let mut rule = masquerade_rule("eth0", None);
        rule.enabled = false;
        let cfg = NatConfig {
            outbound_mode: OutboundMode::Manual,
            wan_interfaces: vec![],
            rules: vec![rule],
            nat_reflection: false,
        };
        let out = generate_nat_nft(&cfg);
        assert_eq!(out, "", "disabled rule must produce no output");
    }

    #[test]
    fn rules_sorted_by_priority() {
        let mut high = dnat_rule("203.0.113.10/32", "10.0.0.10", Some(9090));
        high.priority = 10;
        let mut low = dnat_rule("203.0.113.20/32", "10.0.0.20", Some(8080));
        low.priority = 5;
        let cfg = NatConfig {
            outbound_mode: OutboundMode::Manual,
            wan_interfaces: vec![],
            rules: vec![high, low],
            nat_reflection: false,
        };
        let out = generate_nat_nft(&cfg);
        let pos_low = out.find("203.0.113.20").expect("priority 5 rule not found");
        let pos_high = out.find("203.0.113.10").expect("priority 10 rule not found");
        assert!(pos_low < pos_high, "priority 5 must appear before priority 10");
    }

    #[test]
    fn outbound_auto_rule_generation_test() {
        // Verify auto outbound NAT produces exactly one masquerade line per WAN interface.
        let cfg = NatConfig {
            outbound_mode: OutboundMode::Automatic,
            wan_interfaces: vec!["wan0".into()],
            rules: vec![],
            nat_reflection: false,
        };
        let out = generate_nat_nft(&cfg);
        let masq_count = out.matches("masquerade").count();
        assert_eq!(masq_count, 1, "exactly one masquerade line for one WAN interface");
    }

    #[test]
    fn no_ipv6_output_in_nft() {
        // Any config must not produce IPv6 keywords in nftables output.
        let cfg = NatConfig {
            outbound_mode: OutboundMode::Automatic,
            wan_interfaces: vec!["eth0".into()],
            rules: vec![dnat_rule("203.0.113.1/32", "10.0.0.1", Some(443))],
            nat_reflection: true,
        };
        let out = generate_nat_nft(&cfg);
        assert!(!out.contains("ip6"), "no IPv6 keywords must appear in NAT output");
        assert!(!out.contains("inet nat"), "must use 'ip nat' not 'inet nat'");
    }
}
