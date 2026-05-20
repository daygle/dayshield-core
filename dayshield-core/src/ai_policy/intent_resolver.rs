use crate::ai_policy::{
    event_classifier::is_private_ipv4,
    models::{DecisionAction, Event, Intent},
};

#[derive(Debug, Clone)]
pub struct ResolvedIntent {
    pub action: DecisionAction,
    pub reason: String,
    pub confidence: f32,
    pub intent_id: String,
    pub intent_name: String,
}

pub fn resolve_intent(event: &Event, intents: &[Intent]) -> Option<ResolvedIntent> {
    for intent in intents {
        if !intent.enabled {
            continue;
        }

        let protocol = intent
            .condition
            .protocol
            .as_deref()
            .or(intent.protocol.as_deref());
        let dst_port = intent.condition.dst_port.or(intent.port);

        if let Some(protocol) = protocol {
            if !matches_protocol(protocol, &event.protocol) {
                continue;
            }
        }
        if let Some(dst_port) = dst_port {
            if Some(dst_port) != event.dest_port {
                continue;
            }
        }
        if let Some(src_port) = intent.condition.src_port {
            if Some(src_port) != event.src_port {
                continue;
            }
        }
        if let Some(direction) = intent.condition.direction.as_deref() {
            if !direction.eq_ignore_ascii_case(&event.direction) {
                continue;
            }
        }
        if let Some(iface) = intent.condition.iface.as_deref() {
            if !iface.eq_ignore_ascii_case(&event.iface) {
                continue;
            }
        }
        if let Some(src_ip) = intent.condition.src_ip.as_deref() {
            if !ip_matches(src_ip, &event.src_ip) {
                continue;
            }
        }
        if let Some(dst_ip) = intent.condition.dst_ip.as_deref() {
            if !ip_matches(dst_ip, &event.dest_ip) {
                continue;
            }
        }
        if !intent.allowed_sources.is_empty()
            && !intent
                .allowed_sources
                .iter()
                .any(|source| ip_matches(source, &event.src_ip))
        {
            continue;
        }

        if intent.lan_only
            || intent
                .condition
                .traffic_scope
                .as_deref()
                .is_some_and(|scope| scope.eq_ignore_ascii_case("lan"))
        {
            if !is_private_ipv4(&event.src_ip) {
                return Some(ResolvedIntent {
                    action: DecisionAction::Deny,
                    reason: format!(
                        "Intent '{}' restricts this traffic to private LAN sources",
                        intent.name
                    ),
                    confidence: 0.98,
                    intent_id: intent.id.clone(),
                    intent_name: intent.name.clone(),
                });
            }
        }

        return Some(ResolvedIntent {
            action: intent.desired_action.clone(),
            reason: format!("Intent '{}' matched the observed traffic pattern", intent.name),
            confidence: 0.92,
            intent_id: intent.id.clone(),
            intent_name: intent.name.clone(),
        });
    }

    None
}

fn matches_protocol(intent_protocol: &str, event_protocol: &str) -> bool {
    intent_protocol.eq_ignore_ascii_case("any")
        || intent_protocol.eq_ignore_ascii_case(event_protocol)
}

fn ip_matches(expected: &str, observed: &str) -> bool {
    expected.eq_ignore_ascii_case("any") || expected.eq_ignore_ascii_case(observed)
}
