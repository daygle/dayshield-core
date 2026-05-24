use std::net::Ipv4Addr;

use crate::{
    ai_firewall::models::{Intent, RuleAudit},
    config::models::{Action, FirewallAddressFamily, FirewallRule, Protocol},
};

pub fn audit_rules(rules: &[FirewallRule], intents: &[Intent], timestamp: &str) -> Vec<RuleAudit> {
    let mut audits = Vec::new();

    for rule in rules {
        if matches!(rule.ip_family, FirewallAddressFamily::Ipv6) {
            audits.push(RuleAudit {
                timestamp: timestamp.to_string(),
                rule_id: Some(rule.id.to_string()),
                finding: "IPv6-only rule detected in IPv4-centric automation path".to_string(),
                recommendation: "Restrict this rule to IPv4 for AI policy automation".to_string(),
            });
        }

        if matches!(rule.action, Action::Accept) && rule.destination_port.is_none() {
            audits.push(RuleAudit {
                timestamp: timestamp.to_string(),
                rule_id: Some(rule.id.to_string()),
                finding: "Broad allow rule without destination port".to_string(),
                recommendation: "Tighten the rule by specifying destination port/protocol"
                    .to_string(),
            });
        }
    }

    for intent in intents {
        if !(intent.lan_only
            || intent
                .condition
                .traffic_scope
                .as_deref()
                .is_some_and(|scope| scope.eq_ignore_ascii_case("lan")))
        {
            continue;
        }
        let protocol = intent
            .condition
            .protocol
            .as_deref()
            .or(intent.protocol.as_deref())
            .unwrap_or("any");
        let port = intent.condition.dst_port.or(intent.port);
        let has_lan_restriction = rules.iter().any(|rule| {
            if !matches!(rule.action, Action::Accept) {
                return false;
            }
            if port.is_some() && rule.destination_port != port {
                return false;
            }
            if !matches!(
                (
                    &rule.protocol,
                    protocol.to_ascii_lowercase().as_str()
                ),
                (Some(Protocol::Tcp), "tcp")
                    | (Some(Protocol::Udp), "udp")
                    | (Some(Protocol::Any), _)
                    | (None, _)
            ) {
                return false;
            }

            rule.source.as_deref().map(is_private_source).unwrap_or(false)
        });

        if !has_lan_restriction {
            audits.push(RuleAudit {
                timestamp: timestamp.to_string(),
                rule_id: None,
                finding: format!(
                    "No explicit LAN-only allow rule found for intent '{}'",
                    intent.name
                ),
                recommendation: "Add a scoped allow rule for private IPv4 CIDRs".to_string(),
            });
        }
    }

    audits
}

fn is_private_source(source: &str) -> bool {
    let ip = source.split('/').next().unwrap_or(source);
    ip.parse::<Ipv4Addr>()
        .map(|parsed| parsed.is_private() || parsed.is_loopback() || parsed.is_link_local())
        .unwrap_or(false)
}
