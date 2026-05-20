use crate::ai_policy::{
    event_classifier::is_private_ipv4,
    models::{DecisionAction, Event, Intent},
};

pub fn resolve_intent(event: &Event, intents: &[Intent]) -> Option<(DecisionAction, String, f32)> {
    for intent in intents {
        if !matches_protocol(&intent.protocol, &event.protocol) {
            continue;
        }
        if Some(intent.port) != event.dest_port {
            continue;
        }

        if intent.lan_only && !is_private_ipv4(&event.src_ip) {
            return Some((
                DecisionAction::Deny,
                format!(
                    "Intent '{}' enforces LAN-only access for {}:{}",
                    intent.name, intent.protocol, intent.port
                ),
                0.98,
            ));
        }

        if intent.lan_only && is_private_ipv4(&event.src_ip) {
            return Some((
                DecisionAction::SuggestAllow,
                format!(
                    "Intent '{}' allows LAN traffic for {}:{}",
                    intent.name, intent.protocol, intent.port
                ),
                0.75,
            ));
        }
    }

    None
}

fn matches_protocol(intent_protocol: &str, event_protocol: &str) -> bool {
    intent_protocol.eq_ignore_ascii_case("any")
        || intent_protocol.eq_ignore_ascii_case(event_protocol)
}
