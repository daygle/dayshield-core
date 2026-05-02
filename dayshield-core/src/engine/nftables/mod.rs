//! nftables engine — compiles [`FirewallRule`] and [`NatRule`] objects into
//! nftables rulesets and applies them via the `nft` CLI.
//!
//! # Functions
//!
//! | Function              | Purpose                                              |
//! |-----------------------|------------------------------------------------------|
//! | [`generate_ruleset`]  | Build a full nftables ruleset string from rules.    |
//! | [`apply_rules`]       | Write ruleset to a temp file and run `nft -f`.      |
//! | [`flush_rules`]       | Flush the entire nftables ruleset.                  |

use tokio::process::Command;
use tracing::{debug, info, warn};

use crate::config::models::{Action, FirewallRule, NatRule, NatType, Protocol};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by the nftables engine.
#[derive(Debug, thiserror::Error)]
pub enum NftError {
    /// Ruleset generation failed (e.g. invalid rule data).
    #[error("ruleset generation failed: {0}")]
    GenerateFailed(String),

    /// `nft -f` failed or could not be spawned.
    #[error("failed to apply nftables ruleset: {0}")]
    ApplyFailed(String),

    /// `nft flush ruleset` failed.
    #[error("failed to flush nftables ruleset: {0}")]
    FlushFailed(String),

    /// A validation error on the incoming rule data.
    #[error("validation error: {0}")]
    ValidationFailed(String),

    /// A persistent-storage operation failed.
    #[error("storage error: {0:#}")]
    StorageError(#[from] anyhow::Error),
}

impl axum::response::IntoResponse for NftError {
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;
        use axum::Json;

        let status = match &self {
            NftError::ValidationFailed(_) => StatusCode::UNPROCESSABLE_ENTITY,
            NftError::GenerateFailed(_)
            | NftError::ApplyFailed(_)
            | NftError::FlushFailed(_)
            | NftError::StorageError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        (status, Json(serde_json::json!({ "error": self.to_string() }))).into_response()
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Generate a complete nftables ruleset from the provided rule lists.
///
/// Returns a `String` that can be written to a file and passed to `nft -f`.
///
/// The ruleset includes:
/// - `flush ruleset` to replace any existing state atomically.
/// - `table inet filter` with `input`, `forward`, and `output` chains.
/// - Rules translated from [`FirewallRule`], sorted by `priority` (ascending).
/// - `table inet nat` with `prerouting` and `postrouting` chains (only when
///   `nat_rules` is non-empty).
pub fn generate_ruleset(rules: &[FirewallRule], nat_rules: &[NatRule]) -> String {
    let mut sorted: Vec<&FirewallRule> = rules.iter().collect();
    sorted.sort_by_key(|r| r.priority);

    debug!(
        fw_rules = sorted.len(),
        nat_rules = nat_rules.len(),
        "nftables: generating ruleset"
    );

    let mut out = String::new();

    out.push_str("flush ruleset\n\n");

    // ------------------------------------------------------------------
    // inet filter table
    // ------------------------------------------------------------------
    out.push_str("table inet filter {\n");

    // input chain
    out.push_str("    chain input {\n");
    out.push_str("        type filter hook input priority 0; policy drop;\n");
    out.push_str("        ct state established,related accept\n");
    out.push_str("        iif lo accept\n");
    for rule in &sorted {
        out.push_str(&format!("        {}\n", format_rule(rule)));
    }
    out.push_str("    }\n\n");

    // forward chain
    out.push_str("    chain forward {\n");
    out.push_str("        type filter hook forward priority 0; policy drop;\n");
    out.push_str("        ct state established,related accept\n");
    for rule in &sorted {
        out.push_str(&format!("        {}\n", format_rule(rule)));
    }
    out.push_str("    }\n\n");

    // output chain
    out.push_str("    chain output {\n");
    out.push_str("        type filter hook output priority 0; policy accept;\n");
    out.push_str("    }\n");

    out.push_str("}\n");

    // ------------------------------------------------------------------
    // inet nat table (only when there are NAT rules)
    // ------------------------------------------------------------------
    if !nat_rules.is_empty() {
        out.push_str("\ntable inet nat {\n");

        out.push_str("    chain prerouting {\n");
        out.push_str("        type nat hook prerouting priority -100;\n");
        for nat in nat_rules {
            if let Some(line) = format_nat_prerouting(nat) {
                out.push_str(&format!("        {}\n", line));
            }
        }
        out.push_str("    }\n\n");

        out.push_str("    chain postrouting {\n");
        out.push_str("        type nat hook postrouting priority 100;\n");
        for nat in nat_rules {
            if let Some(line) = format_nat_postrouting(nat) {
                out.push_str(&format!("        {}\n", line));
            }
        }
        out.push_str("    }\n");

        out.push_str("}\n");
    }

    info!(
        fw_rules = rules.len(),
        nat_rules = nat_rules.len(),
        "nftables: ruleset generated ({} bytes)",
        out.len()
    );

    out
}

/// Write `rules` + `nat_rules` as a complete nftables ruleset to a temp file
/// and apply it with `nft -f <tempfile>`.
///
/// # Errors
///
/// Returns [`NftError::ApplyFailed`] if the temp file cannot be written or
/// `nft` exits non-zero.
pub async fn apply_rules(rules: &[FirewallRule], nat_rules: &[NatRule]) -> Result<(), NftError> {
    let ruleset = generate_ruleset(rules, nat_rules);

    // Unique temp file name based on milliseconds since UNIX epoch.
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let tmp_path = std::env::temp_dir().join(format!("dayshield-nft-{}.conf", ts));

    debug!(path = %tmp_path.display(), "nftables: writing ruleset to temp file");

    std::fs::write(&tmp_path, &ruleset).map_err(|e| {
        NftError::ApplyFailed(format!(
            "failed to write temp ruleset {}: {}",
            tmp_path.display(),
            e
        ))
    })?;

    let tmp_str = tmp_path.to_str().ok_or_else(|| {
        NftError::ApplyFailed(format!(
            "temp file path contains invalid UTF-8: {}",
            tmp_path.display()
        ))
    })?;

    let output = Command::new("nft")
        .args(["-f", tmp_str])
        .output()
        .await
        .map_err(|e| NftError::ApplyFailed(format!("failed to spawn nft: {}", e)))?;

    // Always remove the temp file, regardless of success/failure.
    let _ = std::fs::remove_file(&tmp_path);

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!(
            status = %output.status,
            stderr = %stderr,
            "nftables: apply failed"
        );
        return Err(NftError::ApplyFailed(format!(
            "`nft -f` exited {}: {}",
            output.status, stderr
        )));
    }

    info!("nftables: rules applied successfully");
    Ok(())
}

/// Flush the entire nftables ruleset via `nft flush ruleset`.
///
/// # Errors
///
/// Returns [`NftError::FlushFailed`] if `nft` cannot be spawned or exits
/// non-zero.
pub async fn flush_rules() -> Result<(), NftError> {
    debug!("nftables: flushing ruleset");

    let output = Command::new("nft")
        .args(["flush", "ruleset"])
        .output()
        .await
        .map_err(|e| NftError::FlushFailed(format!("failed to spawn nft: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!(status = %output.status, stderr = %stderr, "nftables: flush failed");
        return Err(NftError::FlushFailed(format!(
            "`nft flush ruleset` exited {}: {}",
            output.status, stderr
        )));
    }

    info!("nftables: ruleset flushed");
    Ok(())
}

// ---------------------------------------------------------------------------
// Private: rule formatting helpers
// ---------------------------------------------------------------------------

/// Translate a single [`FirewallRule`] into an nftables rule statement.
fn format_rule(rule: &FirewallRule) -> String {
    let mut parts: Vec<String> = Vec::new();

    // Interface ingress match.
    if let Some(iif) = &rule.interface {
        parts.push(format!("iif \"{}\"", iif));
    }

    // Resolve the l4 protocol string (None for "any").
    let proto: Option<&str> = rule.protocol.as_ref().and_then(|p| match p {
        Protocol::Tcp => Some("tcp"),
        Protocol::Udp => Some("udp"),
        Protocol::Icmp => Some("icmp"),
        Protocol::Icmpv6 => Some("icmpv6"),
        Protocol::Any => None,
    });

    // Source IP / prefix.
    if let Some(src) = &rule.source {
        if src.contains(':') {
            parts.push(format!("ip6 saddr {}", src));
        } else {
            parts.push(format!("ip saddr {}", src));
        }
    }

    // Destination IP / prefix.
    if let Some(dst) = &rule.destination {
        if dst.contains(':') {
            parts.push(format!("ip6 daddr {}", dst));
        } else {
            parts.push(format!("ip daddr {}", dst));
        }
    }

    // Protocol match: use `meta l4proto` when no port match is needed;
    // the protocol keyword is already implied by the port expressions below.
    let has_ports = rule.source_port.is_some() || rule.destination_port.is_some();
    if !has_ports {
        if let Some(p) = proto {
            parts.push(format!("meta l4proto {}", p));
        }
    }

    // Source port — only valid when a tcp/udp protocol is set.
    if let (Some(sport), Some(p)) = (rule.source_port, proto) {
        parts.push(format!("{} sport {}", p, sport));
    }

    // Destination port — only valid when a tcp/udp protocol is set.
    if let (Some(dport), Some(p)) = (rule.destination_port, proto) {
        parts.push(format!("{} dport {}", p, dport));
    }

    // Optional log statement before the verdict.
    if rule.log {
        parts.push(format!("log prefix \"dayshield[{}]: \"", rule.id));
    }

    // Verdict.
    let action = match rule.action {
        Action::Accept => "accept",
        Action::Drop => "drop",
        Action::Reject => "reject",
        Action::Jump => "jump",
        Action::Log => "log",
    };
    parts.push(action.to_string());

    parts.join(" ")
}

/// Translate a [`NatRule`] into a prerouting statement (DNAT only).
fn format_nat_prerouting(nat: &NatRule) -> Option<String> {
    match nat.nat_type {
        NatType::Dnat => {
            let mut parts: Vec<String> = Vec::new();
            if let Some(dst) = &nat.destination {
                if dst.contains(':') {
                    parts.push(format!("ip6 daddr {}", dst));
                } else {
                    parts.push(format!("ip daddr {}", dst));
                }
            }
            let translated = nat.translated_address.as_deref()?;
            let target = match nat.translated_port {
                Some(port) => format!("dnat to {}:{}", translated, port),
                None => format!("dnat to {}", translated),
            };
            parts.push(target);
            Some(parts.join(" "))
        }
        _ => None,
    }
}

/// Translate a [`NatRule`] into a postrouting statement (masquerade / SNAT).
fn format_nat_postrouting(nat: &NatRule) -> Option<String> {
    match nat.nat_type {
        NatType::Masquerade => {
            let mut parts: Vec<String> = Vec::new();
            if let Some(src) = &nat.source {
                if src.contains(':') {
                    parts.push(format!("ip6 saddr {}", src));
                } else {
                    parts.push(format!("ip saddr {}", src));
                }
            }
            if let Some(oif) = &nat.out_interface {
                parts.push(format!("oif \"{}\"", oif));
            }
            parts.push("masquerade".to_string());
            Some(parts.join(" "))
        }
        NatType::Snat => {
            let mut parts: Vec<String> = Vec::new();
            if let Some(src) = &nat.source {
                if src.contains(':') {
                    parts.push(format!("ip6 saddr {}", src));
                } else {
                    parts.push(format!("ip saddr {}", src));
                }
            }
            let translated = nat.translated_address.as_deref()?;
            parts.push(format!("snat to {}", translated));
            Some(parts.join(" "))
        }
        NatType::Dnat => None,
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::models::{Action, FirewallRule, NatRule, NatType, Protocol};
    use uuid::Uuid;

    /// Minimal valid [`FirewallRule`] with sensible defaults.
    fn base_rule(priority: i32, action: Action) -> FirewallRule {
        FirewallRule {
            id: Uuid::nil(),
            description: None,
            priority,
            source: None,
            destination: None,
            protocol: None,
            source_port: None,
            destination_port: None,
            action,
            interface: None,
            log: false,
        }
    }

    // ------------------------------------------------------------------
    // generate_ruleset — structural checks
    // ------------------------------------------------------------------

    #[test]
    fn empty_ruleset_has_base_structure() {
        let rs = generate_ruleset(&[], &[]);
        assert!(rs.contains("flush ruleset"), "must flush existing rules");
        assert!(rs.contains("table inet filter"), "filter table missing");
        assert!(rs.contains("chain input"), "input chain missing");
        assert!(rs.contains("chain forward"), "forward chain missing");
        assert!(rs.contains("chain output"), "output chain missing");
        assert!(
            rs.contains("ct state established,related accept"),
            "stateful allow missing"
        );
        assert!(
            !rs.contains("table inet nat"),
            "nat table must not appear without nat rules"
        );
    }

    #[test]
    fn accept_rule_with_src_and_dst() {
        let rule = FirewallRule {
            source: Some("192.168.1.0/24".into()),
            destination: Some("10.0.0.1/32".into()),
            ..base_rule(0, Action::Accept)
        };
        let rs = generate_ruleset(&[rule], &[]);
        assert!(rs.contains("ip saddr 192.168.1.0/24"));
        assert!(rs.contains("ip daddr 10.0.0.1/32"));
        assert!(rs.contains("accept"));
    }

    #[test]
    fn tcp_rule_with_destination_port() {
        let rule = FirewallRule {
            protocol: Some(Protocol::Tcp),
            destination_port: Some(443),
            ..base_rule(10, Action::Accept)
        };
        let rs = generate_ruleset(&[rule], &[]);
        assert!(rs.contains("tcp dport 443"), "tcp dport must appear");
        assert!(rs.contains("accept"));
    }

    #[test]
    fn udp_rule_with_source_port() {
        let rule = FirewallRule {
            protocol: Some(Protocol::Udp),
            source_port: Some(53),
            action: Action::Drop,
            ..base_rule(20, Action::Drop)
        };
        let rs = generate_ruleset(&[rule], &[]);
        assert!(rs.contains("udp sport 53"));
        assert!(rs.contains("drop"));
    }

    #[test]
    fn protocol_only_uses_meta_l4proto() {
        let rule = FirewallRule {
            protocol: Some(Protocol::Tcp),
            ..base_rule(0, Action::Accept)
        };
        let rs = generate_ruleset(&[rule], &[]);
        assert!(rs.contains("meta l4proto tcp"));
    }

    #[test]
    fn drop_rule() {
        let rule = base_rule(0, Action::Drop);
        let rs = generate_ruleset(&[rule], &[]);
        assert!(rs.contains("drop"));
    }

    #[test]
    fn reject_rule() {
        let rule = base_rule(0, Action::Reject);
        let rs = generate_ruleset(&[rule], &[]);
        assert!(rs.contains("reject"));
    }

    #[test]
    fn log_flag_adds_log_prefix() {
        let rule = FirewallRule {
            log: true,
            ..base_rule(0, Action::Accept)
        };
        let rs = generate_ruleset(&[rule], &[]);
        assert!(rs.contains("log prefix"), "log prefix must appear");
    }

    #[test]
    fn interface_binding_adds_iif() {
        let rule = FirewallRule {
            interface: Some("eth0".into()),
            ..base_rule(0, Action::Accept)
        };
        let rs = generate_ruleset(&[rule], &[]);
        assert!(rs.contains("iif \"eth0\""));
    }

    #[test]
    fn ipv6_source_uses_ip6_saddr() {
        let rule = FirewallRule {
            source: Some("2001:db8::/32".into()),
            ..base_rule(0, Action::Accept)
        };
        let rs = generate_ruleset(&[rule], &[]);
        assert!(rs.contains("ip6 saddr 2001:db8::/32"));
    }

    #[test]
    fn rules_sorted_by_priority_ascending() {
        let r_high = FirewallRule {
            source: Some("1.1.1.1/32".into()),
            ..base_rule(10, Action::Accept)
        };
        let r_low = FirewallRule {
            source: Some("2.2.2.2/32".into()),
            ..base_rule(5, Action::Drop)
        };
        // Pass higher-priority rule first; expect lower priority (5) to appear earlier.
        let rs = generate_ruleset(&[r_high, r_low], &[]);
        let pos_high_prio = rs.find("2.2.2.2").expect("2.2.2.2 not found");
        let pos_low_prio = rs.find("1.1.1.1").expect("1.1.1.1 not found");
        assert!(
            pos_high_prio < pos_low_prio,
            "priority 5 rule must precede priority 10 rule"
        );
    }

    #[test]
    fn nat_masquerade_appears_in_postrouting() {
        let nat = NatRule {
            id: Uuid::nil(),
            description: None,
            nat_type: NatType::Masquerade,
            source: Some("192.168.0.0/24".into()),
            destination: None,
            translated_address: None,
            translated_port: None,
            out_interface: Some("eth0".into()),
        };
        let rs = generate_ruleset(&[], &[nat]);
        assert!(rs.contains("table inet nat"));
        assert!(rs.contains("chain postrouting"));
        assert!(rs.contains("ip saddr 192.168.0.0/24"));
        assert!(rs.contains("oif \"eth0\""));
        assert!(rs.contains("masquerade"));
    }

    #[test]
    fn nat_snat_appears_in_postrouting() {
        let nat = NatRule {
            id: Uuid::nil(),
            description: None,
            nat_type: NatType::Snat,
            source: Some("10.0.0.0/8".into()),
            destination: None,
            translated_address: Some("203.0.113.5".into()),
            translated_port: None,
            out_interface: None,
        };
        let rs = generate_ruleset(&[], &[nat]);
        assert!(rs.contains("snat to 203.0.113.5"));
    }

    #[test]
    fn nat_dnat_with_port_appears_in_prerouting() {
        let nat = NatRule {
            id: Uuid::nil(),
            description: None,
            nat_type: NatType::Dnat,
            source: None,
            destination: Some("203.0.113.1/32".into()),
            translated_address: Some("10.0.0.1".into()),
            translated_port: Some(8080),
            out_interface: None,
        };
        let rs = generate_ruleset(&[], &[nat]);
        assert!(rs.contains("chain prerouting"));
        assert!(rs.contains("ip daddr 203.0.113.1/32"));
        assert!(rs.contains("dnat to 10.0.0.1:8080"));
    }

    // ------------------------------------------------------------------
    // NftError
    // ------------------------------------------------------------------

    #[test]
    fn nft_error_display() {
        assert!(NftError::ApplyFailed("nft not found".into())
            .to_string()
            .contains("nft not found"));
        assert!(NftError::FlushFailed("flush error".into())
            .to_string()
            .contains("flush error"));
        assert!(NftError::GenerateFailed("bad input".into())
            .to_string()
            .contains("bad input"));
        assert!(NftError::ValidationFailed("invalid port".into())
            .to_string()
            .contains("invalid port"));
    }

    // ------------------------------------------------------------------
    // apply_rules / flush_rules — graceful failure without nft
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn apply_rules_does_not_panic_without_nft() {
        let result = apply_rules(&[], &[]).await;
        match result {
            Ok(()) => {}
            Err(NftError::ApplyFailed(_)) => {}
            Err(e) => panic!("unexpected error variant: {:?}", e),
        }
    }

    #[tokio::test]
    async fn flush_rules_does_not_panic_without_nft() {
        let result = flush_rules().await;
        match result {
            Ok(()) => {}
            Err(NftError::FlushFailed(_)) => {}
            Err(e) => panic!("unexpected error variant: {:?}", e),
        }
    }
}
