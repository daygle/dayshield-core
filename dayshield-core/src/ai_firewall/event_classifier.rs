use std::net::Ipv4Addr;

use crate::ai_firewall::models::Event;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventClass {
    LanDevice,
    PortScan,
    NewService,
    RepeatedAttempts,
}

pub fn classify_event(event: &Event, recent: &[Event]) -> Vec<EventClass> {
    let mut classes = Vec::new();

    if is_private_ipv4(&event.src_ip) {
        classes.push(EventClass::LanDevice);
    }

    let same_src_recent: Vec<&Event> = recent.iter().filter(|e| e.src_ip == event.src_ip).collect();

    let repeated_attempts = same_src_recent
        .iter()
        .filter(|e| e.dest_port == event.dest_port && e.dest_ip == event.dest_ip)
        .count();
    if repeated_attempts >= 3 {
        classes.push(EventClass::RepeatedAttempts);
    }

    let mut unique_ports = same_src_recent
        .iter()
        .filter_map(|e| e.dest_port)
        .collect::<Vec<_>>();
    unique_ports.sort_unstable();
    unique_ports.dedup();
    if unique_ports.len() >= 5 {
        classes.push(EventClass::PortScan);
    }

    let seen_service_before = recent
        .iter()
        .any(|e| e.dest_port.is_some() && e.dest_port == event.dest_port);
    if !seen_service_before && event.dest_port.is_some() {
        classes.push(EventClass::NewService);
    }

    classes
}

pub fn is_private_ipv4(ip: &str) -> bool {
    ip.parse::<Ipv4Addr>()
        .map(|parsed| parsed.is_private() || parsed.is_loopback() || parsed.is_link_local())
        .unwrap_or(false)
}

pub fn is_scoped_allow_event(event: &Event) -> bool {
    if !is_private_ipv4(&event.src_ip) {
        return false;
    }
    let protocol = event.protocol.trim();
    if protocol.is_empty() || protocol.eq_ignore_ascii_case("any") {
        return false;
    }
    if (protocol.eq_ignore_ascii_case("tcp") || protocol.eq_ignore_ascii_case("udp"))
        && event.dest_port.is_none()
    {
        return false;
    }
    true
}

pub fn is_block_action(action: &str) -> bool {
    let normalized = action.trim().to_ascii_lowercase();
    matches!(normalized.as_str(), "drop" | "reject" | "block")
        || normalized.starts_with("default-block")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_port_scan_when_many_unique_ports() {
        let base = Event {
            timestamp: "2026-01-01T00:00:00Z".into(),
            direction: "inbound".into(),
            action: "DROP".into(),
            src_ip: "198.51.100.10".into(),
            dest_ip: "10.0.0.1".into(),
            protocol: "TCP".into(),
            src_port: Some(50000),
            dest_port: Some(22),
            iface: "eth0".into(),
        };
        let mut recent = Vec::new();
        for port in [21, 22, 23, 80, 443] {
            let mut e = base.clone();
            e.dest_port = Some(port);
            recent.push(e);
        }
        let classes = classify_event(&base, &recent);
        assert!(classes.contains(&EventClass::PortScan));
    }

    #[test]
    fn scoped_allow_event_requires_private_source_and_service_scope() {
        let mut event = Event {
            timestamp: "2026-01-01T00:00:00Z".into(),
            direction: "inbound".into(),
            action: "ACCEPT".into(),
            src_ip: "10.0.0.10".into(),
            dest_ip: "10.0.0.1".into(),
            protocol: "TCP".into(),
            src_port: Some(50000),
            dest_port: Some(443),
            iface: "lan0".into(),
        };
        assert!(is_scoped_allow_event(&event));

        event.src_ip = "203.0.113.10".into();
        assert!(!is_scoped_allow_event(&event));

        event.src_ip = "10.0.0.10".into();
        event.dest_port = None;
        assert!(!is_scoped_allow_event(&event));
    }

    #[test]
    fn default_block_log_prefix_counts_as_blocked() {
        assert!(is_block_action("DEFAULT-BLOCK INPUT"));
        assert!(is_block_action("drop"));
        assert!(!is_block_action("ACCEPT"));
    }
}
