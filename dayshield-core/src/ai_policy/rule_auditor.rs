use crate::{
    ai_policy::models::{Intent, RuleAudit},
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
        if !intent.lan_only {
            continue;
        }
        let has_lan_restriction = rules.iter().any(|rule| {
            if !matches!(rule.action, Action::Accept) {
                return false;
            }
            if rule.destination_port != Some(intent.port) {
                return false;
            }
            if !matches!(
                (
                    &rule.protocol,
                    intent.protocol.to_ascii_lowercase().as_str()
                ),
                (Some(Protocol::Tcp), "tcp")
                    | (Some(Protocol::Udp), "udp")
                    | (Some(Protocol::Any), _)
                    | (None, _)
            ) {
                return false;
            }

            rule.source
                .as_deref()
                .map(|src| {
                    src.starts_with("10.")
                        || src.starts_with("192.168.")
                        || src.starts_with("172.16.")
                })
                .unwrap_or(false)
        });

        if !has_lan_restriction {
            audits.push(RuleAudit {
                timestamp: timestamp.to_string(),
                rule_id: None,
                finding: format!(
                    "No explicit LAN-only allow rule found for intent '{}' ({}/{})",
                    intent.name, intent.protocol, intent.port
                ),
                recommendation: "Add a scoped allow rule for private IPv4 CIDRs".to_string(),
            });
        }
    }

    audits
}
