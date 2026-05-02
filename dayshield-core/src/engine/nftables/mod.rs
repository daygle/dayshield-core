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

use std::collections::HashMap;

use tokio::process::Command;
use tracing::{debug, info, warn};

use crate::config::models::{Action, AliasType, FirewallAlias, FirewallRule, NatRule, NatType, Protocol};

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
/// - Named `set` declarations inside `table inet filter` for each enabled alias.
/// - `table inet filter` with `input`, `forward`, and `output` chains.
/// - Rules translated from [`FirewallRule`], sorted by `priority` (ascending).
/// - `table inet nat` with `prerouting` and `postrouting` chains (only when
///   `nat_rules` is non-empty).
///
/// `resolved_url_tables` maps alias name → resolved IP/CIDR list for
/// [`AliasType::UrlTable`] aliases (fetched asynchronously by the caller
/// before generating the ruleset).
pub fn generate_ruleset(
    rules: &[FirewallRule],
    nat_rules: &[NatRule],
    aliases: &[FirewallAlias],
    resolved_url_tables: &HashMap<String, Vec<String>>,
) -> String {
    let mut sorted: Vec<&FirewallRule> = rules.iter().collect();
    sorted.sort_by_key(|r| r.priority);

    debug!(
        fw_rules = sorted.len(),
        nat_rules = nat_rules.len(),
        aliases = aliases.len(),
        "nftables: generating ruleset"
    );

    let mut out = String::new();

    out.push_str("flush ruleset\n\n");

    // ------------------------------------------------------------------
    // inet filter table
    // ------------------------------------------------------------------
    out.push_str("table inet filter {\n");

    // Emit named sets for each enabled alias.
    for alias in aliases.iter().filter(|a| a.enabled) {
        let set_body = alias_set_body(alias, resolved_url_tables);
        if let Some(body) = set_body {
            out.push_str(&format!("    set {} {{\n", alias.name));
            out.push_str(&body);
            out.push_str("    }\n\n");
        }
    }

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
        aliases = aliases.len(),
        "nftables: ruleset generated ({} bytes)",
        out.len()
    );

    out
}

/// Write `rules` + `nat_rules` as a complete nftables ruleset to a temp file
/// and apply it with `nft -f <tempfile>`.
///
/// URL-table aliases are fetched via HTTP before the ruleset is generated and
/// their resolved IP/CIDR lists are cached under
/// `/var/lib/dayshield/aliases/<alias_name>.cache`.
///
/// # Errors
///
/// Returns [`NftError::ApplyFailed`] if the temp file cannot be written or
/// `nft` exits non-zero.
pub async fn apply_rules(
    rules: &[FirewallRule],
    nat_rules: &[NatRule],
    aliases: &[FirewallAlias],
) -> Result<(), NftError> {
    // Resolve URL-table aliases (fetch + cache).
    let resolved_url_tables = resolve_url_tables(aliases).await;

    let ruleset = generate_ruleset(rules, nat_rules, aliases, &resolved_url_tables);

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
// Private: alias expansion helpers
// ---------------------------------------------------------------------------

/// Cache directory for URL-table alias contents.
const ALIAS_CACHE_DIR: &str = "/var/lib/dayshield/aliases";

/// Parse a URL-table response body or cached file into a list of IP/CIDR entries.
///
/// Lines starting with `#` (after stripping inline comments) are ignored, as
/// are blank lines.
fn parse_url_table_entries(text: &str) -> Vec<String> {
    text.lines()
        .map(|l| l.split('#').next().unwrap_or("").trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

/// Fetch and cache all URL-table aliases, returning a map of alias name →
/// resolved IP/CIDR list.
///
/// Each URL is fetched via HTTP GET.  The response body is split on whitespace
/// and blank lines; lines starting with `#` are treated as comments and
/// ignored.  The resolved list is written to a cache file so that subsequent
/// calls can fall back to stale data when the remote is unreachable.
async fn resolve_url_tables(aliases: &[FirewallAlias]) -> HashMap<String, Vec<String>> {
    let mut result = HashMap::new();

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("nftables: failed to build HTTP client for URL-table fetch: {e}");
            return result;
        }
    };

    let cache_dir = std::path::Path::new(ALIAS_CACHE_DIR);
    let _ = std::fs::create_dir_all(cache_dir);

    for alias in aliases.iter().filter(|a| a.enabled && a.alias_type == AliasType::UrlTable) {
        let mut entries: Vec<String> = Vec::new();

        for url in &alias.values {
            match client.get(url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    match resp.text().await {
                        Ok(body) => {
                            let fetched = parse_url_table_entries(&body);
                            // Write cleaned entries to the cache file.
                            let cache_path = cache_dir.join(format!("{}.cache", alias.name));
                            let cache_content = fetched.join("\n");
                            if let Err(e) = std::fs::write(&cache_path, cache_content.as_bytes()) {
                                warn!(
                                    alias = %alias.name,
                                    path = %cache_path.display(),
                                    "nftables: failed to write URL-table cache: {e}"
                                );
                            }
                            entries.extend(fetched);
                        }
                        Err(e) => {
                            warn!(alias = %alias.name, url = %url,
                                  "nftables: failed to decode URL-table response: {e}");
                        }
                    }
                }
                Ok(resp) => {
                    warn!(alias = %alias.name, url = %url,
                          status = %resp.status(),
                          "nftables: URL-table fetch returned non-success status");
                }
                Err(e) => {
                    warn!(alias = %alias.name, url = %url,
                          "nftables: URL-table fetch failed: {e}");
                    // Try to use cached data as fallback.
                    let cache_path = cache_dir.join(format!("{}.cache", alias.name));
                    if let Ok(cached) = std::fs::read_to_string(&cache_path) {
                        let fallback = parse_url_table_entries(&cached);
                        warn!(alias = %alias.name, count = fallback.len(),
                              "nftables: using cached URL-table data as fallback");
                        entries.extend(fallback);
                    }
                }
            }
        }

        if !entries.is_empty() {
            result.insert(alias.name.clone(), entries);
        }
    }

    result
}

/// Build the nftables `set` body for a single alias, or return `None` if the
/// alias has no values to emit.
///
/// For URL-table aliases the `resolved_url_tables` map is consulted.
fn alias_set_body(
    alias: &FirewallAlias,
    resolved_url_tables: &HashMap<String, Vec<String>>,
) -> Option<String> {
    let values: Vec<String> = match alias.alias_type {
        AliasType::Host | AliasType::Network => alias.values.clone(),
        AliasType::Port => alias.values.clone(),
        AliasType::UrlTable => resolved_url_tables
            .get(&alias.name)
            .cloned()
            .unwrap_or_default(),
    };

    if values.is_empty() {
        return None;
    }

    let mut body = String::new();

    match alias.alias_type {
        AliasType::Host => {
            // Determine address family from the first entry.
            let af = if values.first().map_or(false, |v| v.contains(':')) {
                "ipv6_addr"
            } else {
                "ipv4_addr"
            };
            body.push_str(&format!("        type {af}\n"));
        }
        AliasType::Network | AliasType::UrlTable => {
            let af = if values.first().map_or(false, |v| v.contains(':')) {
                "ipv6_addr"
            } else {
                "ipv4_addr"
            };
            body.push_str(&format!("        type {af}\n"));
            body.push_str("        flags interval\n");
        }
        AliasType::Port => {
            body.push_str("        type inet_service\n");
        }
    }

    let elements = values.join(", ");
    body.push_str(&format!("        elements = {{ {elements} }}\n"));

    Some(body)
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
        let rs = generate_ruleset(&[], &[], &[], &HashMap::new());
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
        let rs = generate_ruleset(&[rule], &[], &[], &HashMap::new());
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
        let rs = generate_ruleset(&[rule], &[], &[], &HashMap::new());
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
        let rs = generate_ruleset(&[rule], &[], &[], &HashMap::new());
        assert!(rs.contains("udp sport 53"));
        assert!(rs.contains("drop"));
    }

    #[test]
    fn protocol_only_uses_meta_l4proto() {
        let rule = FirewallRule {
            protocol: Some(Protocol::Tcp),
            ..base_rule(0, Action::Accept)
        };
        let rs = generate_ruleset(&[rule], &[], &[], &HashMap::new());
        assert!(rs.contains("meta l4proto tcp"));
    }

    #[test]
    fn drop_rule() {
        let rule = base_rule(0, Action::Drop);
        let rs = generate_ruleset(&[rule], &[], &[], &HashMap::new());
        assert!(rs.contains("drop"));
    }

    #[test]
    fn reject_rule() {
        let rule = base_rule(0, Action::Reject);
        let rs = generate_ruleset(&[rule], &[], &[], &HashMap::new());
        assert!(rs.contains("reject"));
    }

    #[test]
    fn log_flag_adds_log_prefix() {
        let rule = FirewallRule {
            log: true,
            ..base_rule(0, Action::Accept)
        };
        let rs = generate_ruleset(&[rule], &[], &[], &HashMap::new());
        assert!(rs.contains("log prefix"), "log prefix must appear");
    }

    #[test]
    fn interface_binding_adds_iif() {
        let rule = FirewallRule {
            interface: Some("eth0".into()),
            ..base_rule(0, Action::Accept)
        };
        let rs = generate_ruleset(&[rule], &[], &[], &HashMap::new());
        assert!(rs.contains("iif \"eth0\""));
    }

    #[test]
    fn ipv6_source_uses_ip6_saddr() {
        let rule = FirewallRule {
            source: Some("2001:db8::/32".into()),
            ..base_rule(0, Action::Accept)
        };
        let rs = generate_ruleset(&[rule], &[], &[], &HashMap::new());
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
        let rs = generate_ruleset(&[r_high, r_low], &[], &[], &HashMap::new());
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
        let rs = generate_ruleset(&[], &[nat], &[], &HashMap::new());
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
        let rs = generate_ruleset(&[], &[nat], &[], &HashMap::new());
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
        let rs = generate_ruleset(&[], &[nat], &[], &HashMap::new());
        assert!(rs.contains("chain prerouting"));
        assert!(rs.contains("ip daddr 203.0.113.1/32"));
        assert!(rs.contains("dnat to 10.0.0.1:8080"));
    }

    // ------------------------------------------------------------------
    // Alias set generation
    // ------------------------------------------------------------------

    #[test]
    fn host_alias_emits_named_set() {
        use crate::config::models::{AliasType, FirewallAlias};
        let alias = FirewallAlias {
            name: "web_servers".into(),
            description: None,
            alias_type: AliasType::Host,
            values: vec!["192.168.1.10".into(), "192.168.1.11".into()],
            ttl: None,
            enabled: true,
        };
        let rs = generate_ruleset(&[], &[], &[alias], &HashMap::new());
        assert!(rs.contains("set web_servers"), "named set must appear");
        assert!(rs.contains("192.168.1.10"), "IP must appear in set");
        assert!(rs.contains("ipv4_addr"), "type must be ipv4_addr for IPv4 hosts");
    }

    #[test]
    fn network_alias_emits_interval_flag() {
        use crate::config::models::{AliasType, FirewallAlias};
        let alias = FirewallAlias {
            name: "private_nets".into(),
            description: None,
            alias_type: AliasType::Network,
            values: vec!["10.0.0.0/8".into()],
            ttl: None,
            enabled: true,
        };
        let rs = generate_ruleset(&[], &[], &[alias], &HashMap::new());
        assert!(rs.contains("set private_nets"));
        assert!(rs.contains("flags interval"), "network aliases need interval flag");
    }

    #[test]
    fn port_alias_emits_inet_service_type() {
        use crate::config::models::{AliasType, FirewallAlias};
        let alias = FirewallAlias {
            name: "web_ports".into(),
            description: None,
            alias_type: AliasType::Port,
            values: vec!["80".into(), "443".into()],
            ttl: None,
            enabled: true,
        };
        let rs = generate_ruleset(&[], &[], &[alias], &HashMap::new());
        assert!(rs.contains("set web_ports"));
        assert!(rs.contains("inet_service"), "port aliases must use inet_service type");
    }

    #[test]
    fn disabled_alias_not_emitted() {
        use crate::config::models::{AliasType, FirewallAlias};
        let alias = FirewallAlias {
            name: "disabled_alias".into(),
            description: None,
            alias_type: AliasType::Host,
            values: vec!["1.2.3.4".into()],
            ttl: None,
            enabled: false,
        };
        let rs = generate_ruleset(&[], &[], &[alias], &HashMap::new());
        assert!(!rs.contains("disabled_alias"), "disabled alias must not appear in ruleset");
    }

    #[test]
    fn url_table_alias_uses_resolved_values() {
        use crate::config::models::{AliasType, FirewallAlias};
        let alias = FirewallAlias {
            name: "blocklist".into(),
            description: None,
            alias_type: AliasType::UrlTable,
            values: vec!["https://example.com/blocklist.txt".into()],
            ttl: None,
            enabled: true,
        };
        let mut resolved = HashMap::new();
        resolved.insert("blocklist".into(), vec!["198.51.100.1".into(), "198.51.100.2".into()]);
        let rs = generate_ruleset(&[], &[], &[alias], &resolved);
        assert!(rs.contains("set blocklist"));
        assert!(rs.contains("198.51.100.1"));
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
        let result = apply_rules(&[], &[], &[]).await;
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
