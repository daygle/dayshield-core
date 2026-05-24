use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    ai_firewall::models::{DecisionAction, Suggestion},
    config::models::{
        Action, FirewallAddressFamily, FirewallDirection, FirewallRule, FirewallStateLimits,
        Protocol,
    },
};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum AppliedChange {
    AddedRule {
        rule: FirewallRule,
    },
    RemovedRule {
        rule: FirewallRule,
    },
    UpdatedRule {
        before: FirewallRule,
        after: FirewallRule,
    },
}

pub fn apply_suggestion_to_rules(
    rules: &mut Vec<FirewallRule>,
    suggestion: &Suggestion,
) -> Option<AppliedChange> {
    match suggestion.decision.action {
        DecisionAction::Allow | DecisionAction::SuggestAllow => {
            let rule = build_rule_from_suggestion(suggestion, Action::Accept)?;
            rules.push(rule.clone());
            Some(AppliedChange::AddedRule { rule })
        }
        DecisionAction::Deny | DecisionAction::SuggestDeny => {
            let rule = build_rule_from_suggestion(suggestion, Action::Drop)?;
            rules.push(rule.clone());
            Some(AppliedChange::AddedRule { rule })
        }
        DecisionAction::EditRule => {
            let target_id = suggestion.target_rule_id.as_ref()?;
            let idx = rules.iter().position(|r| r.id.to_string() == *target_id)?;
            let before = rules[idx].clone();
            rules[idx].source = Some(format!("{}/32", suggestion.event.src_ip));
            rules[idx].destination_port = suggestion.event.dest_port;
            let after = rules[idx].clone();
            Some(AppliedChange::UpdatedRule { before, after })
        }
        DecisionAction::RemoveRule => {
            let target_id = suggestion.target_rule_id.as_ref()?;
            let idx = rules.iter().position(|r| r.id.to_string() == *target_id)?;
            let removed = rules.remove(idx);
            Some(AppliedChange::RemovedRule { rule: removed })
        }
    }
}

pub fn undo_change(rules: &mut Vec<FirewallRule>, change: &AppliedChange) {
    match change {
        AppliedChange::AddedRule { rule } => {
            rules.retain(|r| r.id != rule.id);
        }
        AppliedChange::RemovedRule { rule } => {
            rules.push(rule.clone());
        }
        AppliedChange::UpdatedRule { before, after } => {
            if let Some(existing) = rules.iter_mut().find(|r| r.id == after.id) {
                *existing = before.clone();
            } else {
                rules.push(before.clone());
            }
        }
    }
}

fn build_rule_from_suggestion(suggestion: &Suggestion, action: Action) -> Option<FirewallRule> {
    let rule_id = stable_rule_uuid(suggestion);
    let protocol = protocol_from_event(&suggestion.event.protocol);
    Some(FirewallRule {
        id: rule_id,
        description: Some(format!("AI policy suggestion {}", suggestion.id)),
        priority: 100,
        source: Some(format!("{}/32", suggestion.event.src_ip)),
        destination: Some(format!("{}/32", suggestion.event.dest_ip)),
        protocol,
        source_port: suggestion.event.src_port,
        destination_port: suggestion.event.dest_port,
        ip_family: FirewallAddressFamily::Ipv4,
        action,
        direction: FirewallDirection::Input,
        interface: Some(suggestion.event.iface.clone()),
        log: true,
        enabled: true,
        schedule: None,
        state_limits: FirewallStateLimits::default(),
    })
}

fn protocol_from_event(proto: &str) -> Option<Protocol> {
    if proto.eq_ignore_ascii_case("tcp") {
        Some(Protocol::Tcp)
    } else if proto.eq_ignore_ascii_case("udp") {
        Some(Protocol::Udp)
    } else if proto.eq_ignore_ascii_case("icmp") {
        Some(Protocol::Icmp)
    } else {
        Some(Protocol::Any)
    }
}

fn stable_rule_uuid(suggestion: &Suggestion) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(suggestion.id.as_bytes());
    hasher.update(suggestion.event.timestamp.as_bytes());
    hasher.update(suggestion.event.src_ip.as_bytes());
    hasher.update(suggestion.event.dest_ip.as_bytes());
    hasher.update(suggestion.event.protocol.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}
