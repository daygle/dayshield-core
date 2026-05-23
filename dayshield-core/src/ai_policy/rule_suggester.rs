use sha2::{Digest, Sha256};

use crate::ai_policy::{
    event_classifier::{is_scoped_allow_event, EventClass},
    models::{Decision, DecisionAction, Event, Suggestion},
};

pub fn build_suggestion(event: Event, classes: &[EventClass]) -> Suggestion {
    let is_blocked = event.action.eq_ignore_ascii_case("drop")
        || event.action.eq_ignore_ascii_case("reject")
        || event.action.eq_ignore_ascii_case("block");

    let scoped_allow_candidate = is_scoped_allow_event(&event);

    let (action, reason, confidence) = if classes.contains(&EventClass::PortScan) {
        (
            DecisionAction::SuggestDeny,
            "Source appears to be scanning multiple ports".to_string(),
            0.95_f32,
        )
    } else if classes.contains(&EventClass::RepeatedAttempts) {
        (
            DecisionAction::SuggestDeny,
            "Repeated blocked attempts detected".to_string(),
            0.85_f32,
        )
    } else if classes.contains(&EventClass::LanDevice) {
        if scoped_allow_candidate && is_blocked {
            (
                DecisionAction::SuggestAllow,
                "Likely LAN-origin traffic blocked unexpectedly".to_string(),
                0.65_f32,
            )
        } else {
            (
                DecisionAction::EditRule,
                "LAN traffic observed but missing enough scope for a safe allow recommendation"
                    .to_string(),
                0.58_f32,
            )
        }
    } else if classes.contains(&EventClass::NewService) {
        if is_blocked {
            (
                DecisionAction::EditRule,
                "Blocked traffic hit a new service; suggest tightening an existing rule"
                    .to_string(),
                0.6_f32,
            )
        } else if scoped_allow_candidate {
            (
                DecisionAction::SuggestAllow,
                "Observed new permitted LAN traffic; suggest creating a scoped allow rule"
                    .to_string(),
                0.62_f32,
            )
        } else {
            (
                DecisionAction::EditRule,
                "Observed new permitted traffic without trusted scope; suggest refining existing rules"
                    .to_string(),
                0.55_f32,
            )
        }
    } else {
        if is_blocked {
            (
                DecisionAction::SuggestDeny,
                "Blocked traffic pattern appears suspicious".to_string(),
                0.5_f32,
            )
        } else {
            (
                DecisionAction::EditRule,
                "Observed permitted traffic without an explicit intent; suggest refining existing rules instead of broad allows"
                    .to_string(),
                0.48_f32,
            )
        }
    };

    let decision = Decision {
        action,
        reason,
        confidence,
        auto_applied: false,
        timestamp: event.timestamp.clone(),
    };

    Suggestion {
        id: stable_suggestion_id(&event, &decision),
        event,
        decision,
        target_rule_id: None,
        applied: false,
        rejected: false,
    }
}

fn stable_suggestion_id(event: &Event, decision: &Decision) -> String {
    let mut hasher = Sha256::new();
    hasher.update(event.timestamp.as_bytes());
    hasher.update(event.src_ip.as_bytes());
    hasher.update(event.dest_ip.as_bytes());
    hasher.update(event.protocol.as_bytes());
    hasher.update(event.action.as_bytes());
    hasher.update(
        format!(
            "{}:{}:{:?}",
            event.src_port.unwrap_or_default(),
            event.dest_port.unwrap_or_default(),
            decision.action
        )
        .as_bytes(),
    );
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_event(action: &str) -> Event {
        Event {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            direction: "inbound".to_string(),
            action: action.to_string(),
            src_ip: "10.0.0.2".to_string(),
            dest_ip: "10.0.0.1".to_string(),
            protocol: "tcp".to_string(),
            src_port: Some(51515),
            dest_port: Some(443),
            iface: "lan0".to_string(),
        }
    }

    #[test]
    fn non_lan_permitted_traffic_prefers_edit_rule() {
        let mut event = base_event("ACCEPT");
        event.src_ip = "203.0.113.5".to_string();

        let suggestion = build_suggestion(event, &[]);

        assert!(matches!(suggestion.decision.action, DecisionAction::EditRule));
    }

    #[test]
    fn lan_blocked_scoped_traffic_can_suggest_allow() {
        let suggestion = build_suggestion(base_event("DROP"), &[EventClass::LanDevice]);

        assert!(matches!(
            suggestion.decision.action,
            DecisionAction::SuggestAllow
        ));
    }

    #[test]
    fn lan_without_port_is_not_allow_candidate() {
        let mut event = base_event("DROP");
        event.dest_port = None;

        let suggestion = build_suggestion(event, &[EventClass::LanDevice]);

        assert!(matches!(suggestion.decision.action, DecisionAction::EditRule));
    }
}
