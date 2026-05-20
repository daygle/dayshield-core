use sha2::{Digest, Sha256};

use crate::ai_policy::{
    event_classifier::EventClass,
    models::{Decision, DecisionAction, Event, Suggestion},
};

pub fn build_suggestion(event: Event, classes: &[EventClass]) -> Suggestion {
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
        (
            DecisionAction::SuggestAllow,
            "Likely LAN-origin traffic blocked unexpectedly".to_string(),
            0.65_f32,
        )
    } else if classes.contains(&EventClass::NewService) {
        (
            DecisionAction::EditRule,
            "Traffic hit a new service; suggest tightening an existing rule".to_string(),
            0.6_f32,
        )
    } else {
        (
            DecisionAction::SuggestDeny,
            "Blocked traffic pattern appears suspicious".to_string(),
            0.5_f32,
        )
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
