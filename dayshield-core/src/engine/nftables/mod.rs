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

use crate::config::models::{Action, AliasType, FirewallAlias, FirewallRule, NatConfig, NatProtocol, NatRuleType, OutboundMode, Protocol};

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
/// - `table ip nat` with `postrouting`, `prerouting`, and (when reflection is
///   enabled) `output` chains (only when `nat_config` is `Some`).
///
/// `resolved_url_tables` maps alias name → resolved IP/CIDR list for
/// [`AliasType::UrlTable`] aliases (fetched asynchronously by the caller
/// before generating the ruleset).
pub fn generate_ruleset(
    rules: &[FirewallRule],
    nat_config: Option<&NatConfig>,
    aliases: &[FirewallAlias],
    resolved_url_tables: &HashMap<String, Vec<String>>,
) -> String {
    let mut sorted: Vec<&FirewallRule> = rules.iter().collect();
    sorted.sort_by_key(|r| r.priority);

    debug!(
        fw_rules = sorted.len(),
        nat_rules = nat_config.map(|c| c.rules.len()).unwrap_or(0),
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
    // ip nat table (IPv4 only; only emitted when NAT is configured)
    // ------------------------------------------------------------------
    if let Some(nat) = nat_config {
        out.push_str(&generate_nat_table(nat));
    }

    info!(
        fw_rules = rules.len(),
        nat_rules = nat_config.map(|c| c.rules.len()).unwrap_or(0),
        aliases = aliases.len(),
        "nftables: ruleset generated ({} bytes)",
        out.len()
    );

    out
}

/// Write `rules` and `nat_config` as a complete nftables ruleset to a temp file
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
    nat_config: Option<&NatConfig>,
    aliases: &[FirewallAlias],
) -> Result<(), NftError> {
    // Resolve URL-table aliases (fetch + cache).
    let resolved_url_tables = resolve_url_tables(aliases).await;

    let ruleset = generate_ruleset(rules, nat_config, aliases, &resolved_url_tables);

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
fn format_nat_prerouting(nat: &crate::config::models::NatRule) -> Option<String> {
    match nat.rule_type {
        NatRuleType::Dnat => {
            let mut parts: Vec<String> = Vec::new();
            // Inbound interface match.
            if let Some(iface) = &nat.interface {
                parts.push(format!("iifname \"{}\"", iface));
            }
            // Source address (IPv4 only).
            if let Some(src) = &nat.source {
                parts.push(format!("ip saddr {}", src));
            }
            // Destination address (IPv4 only).
            if let Some(dst) = &nat.destination {
                parts.push(format!("ip daddr {}", dst));
            }
            // Protocol + destination port.
            match nat.protocol {
                NatProtocol::Tcp => {
                    if let Some(dport) = nat.destination_port {
                        parts.push(format!("tcp dport {}", dport));
                    }
                }
                NatProtocol::Udp => {
                    if let Some(dport) = nat.destination_port {
                        parts.push(format!("udp dport {}", dport));
                    }
                }
                NatProtocol::TcpUdp => {
                    if let Some(dport) = nat.destination_port {
                        parts.push(format!("{{ tcp, udp }} dport {}", dport));
                    }
                }
                NatProtocol::Any => {}
            }
            // Translation target.
            let translation = nat.translation.as_ref()?;
            let addr = translation.address.as_deref()?;
            let target = match (translation.port, translation.port_end) {
                (Some(p), Some(pe)) => format!("dnat to {}:{}-{}", addr, p, pe),
                (Some(p), None) => format!("dnat to {}:{}", addr, p),
                (None, _) => format!("dnat to {}", addr),
            };
            parts.push(target);
            Some(parts.join(" "))
        }
        _ => None,
    }
}

/// Translate a [`NatRule`] into a postrouting statement (masquerade / SNAT).
fn format_nat_postrouting(nat: &crate::config::models::NatRule) -> Option<String> {
    match nat.rule_type {
        NatRuleType::Masquerade => {
            let mut parts: Vec<String> = Vec::new();
            if let Some(src) = &nat.source {
                parts.push(format!("ip saddr {}", src));
            }
            if let Some(iface) = &nat.interface {
                parts.push(format!("oifname \"{}\"", iface));
            }
            parts.push("masquerade".to_string());
            Some(parts.join(" "))
        }
        NatRuleType::Snat => {
            let mut parts: Vec<String> = Vec::new();
            if let Some(src) = &nat.source {
                parts.push(format!("ip saddr {}", src));
            }
            if let Some(iface) = &nat.interface {
                parts.push(format!("oifname \"{}\"", iface));
            }
            let translation = nat.translation.as_ref()?;
            let addr = translation.address.as_deref()?;
            parts.push(format!("snat to {}", addr));
            Some(parts.join(" "))
        }
        NatRuleType::Dnat => None,
    }
}

/// Generate the `table ip nat { … }` block from a [`NatConfig`].
///
/// Produces:
/// - `postrouting` — auto masquerade (automatic/hybrid) + user masquerade/SNAT rules.
/// - `prerouting`  — user DNAT rules.
/// - `output`      — reflection DNAT rules (hairpin NAT) when enabled.
///
/// Returns an empty string when no rules would be emitted.
fn generate_nat_table(config: &NatConfig) -> String {
    // Sort user rules deterministically by priority.
    let mut sorted: Vec<&crate::config::models::NatRule> =
        config.rules.iter().filter(|r| r.enabled).collect();
    sorted.sort_by_key(|r| r.priority);

    let has_auto_masquerade = matches!(
        config.outbound_mode,
        OutboundMode::Automatic | OutboundMode::Hybrid
    ) && !config.wan_interfaces.is_empty();

    let user_postrouting: Vec<_> = sorted
        .iter()
        .filter(|r| matches!(r.rule_type, NatRuleType::Masquerade | NatRuleType::Snat))
        .collect();

    let emit_user_postrouting = matches!(
        config.outbound_mode,
        OutboundMode::Hybrid | OutboundMode::Manual
    ) && !user_postrouting.is_empty();

    let prerouting_rules: Vec<_> = sorted
        .iter()
        .filter(|r| matches!(r.rule_type, NatRuleType::Dnat))
        .collect();

    let reflection_rules: Vec<_> = sorted
        .iter()
        .filter(|r| {
            matches!(r.rule_type, NatRuleType::Dnat)
                && (r.nat_reflection || config.nat_reflection)
        })
        .collect();

    let has_postrouting = has_auto_masquerade || emit_user_postrouting;
    let has_prerouting = !prerouting_rules.is_empty();
    let has_reflection = !reflection_rules.is_empty();

    if !has_postrouting && !has_prerouting && !has_reflection {
        return String::new();
    }

    let mut out = String::new();
    out.push_str("\ntable ip nat {\n");

    // postrouting chain
    if has_postrouting {
        out.push_str("    chain postrouting {\n");
        out.push_str(
            "        type nat hook postrouting priority srcnat; policy accept;\n",
        );
        // Automatic masquerade rules for each WAN interface.
        if has_auto_masquerade {
            for iface in &config.wan_interfaces {
                out.push_str(&format!("        oifname \"{}\" masquerade\n", iface));
            }
        }
        // User masquerade / SNAT rules (hybrid or manual mode).
        if emit_user_postrouting {
            for rule in &user_postrouting {
                if rule.log {
                    out.push_str(&format!(
                        "        log prefix \"dayshield-nat[{}]: \"\n",
                        rule.id
                    ));
                }
                if let Some(line) = format_nat_postrouting(rule) {
                    out.push_str(&format!("        {}\n", line));
                }
            }
        }
        out.push_str("    }\n\n");
    }

    // prerouting chain (DNAT / port forwards)
    if has_prerouting {
        out.push_str("    chain prerouting {\n");
        out.push_str(
            "        type nat hook prerouting priority dstnat; policy accept;\n",
        );
        for rule in &prerouting_rules {
            if rule.log {
                out.push_str(&format!(
                    "        log prefix \"dayshield-nat[{}]: \"\n",
                    rule.id
                ));
            }
            if let Some(line) = format_nat_prerouting(rule) {
                out.push_str(&format!("        {}\n", line));
            }
        }
        out.push_str("    }\n\n");
    }

    // output chain (hairpin / NAT reflection)
    if has_reflection {
        out.push_str("    chain output {\n");
        out.push_str(
            "        type nat hook output priority -100; policy accept;\n",
        );
        for rule in &reflection_rules {
            if let Some(line) = format_nat_prerouting(rule) {
                out.push_str(&format!("        {}\n", line));
            }
        }
        out.push_str("    }\n");
    }

    out.push_str("}\n");
    out
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::models::{
        Action, AddressFamily, FirewallRule, NatConfig, NatProtocol, NatRule, NatRuleType,
        NatTranslation, OutboundMode, Protocol,
    };
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

    /// Minimal enabled [`NatRule`] for masquerade.
    fn masquerade_rule(iface: &str, src: Option<&str>) -> NatRule {
        NatRule {
            id: Uuid::new_v4(),
            enabled: true,
            description: None,
            rule_type: NatRuleType::Masquerade,
            interface: Some(iface.to_string()),
            source: src.map(|s| s.to_string()),
            destination: None,
            protocol: NatProtocol::Any,
            source_port: None,
            destination_port: None,
            translation: None,
            nat_reflection: false,
            address_family: AddressFamily::Ipv4,
            priority: 0,
            log: false,
        }
    }

    /// Minimal enabled DNAT [`NatRule`].
    fn dnat_rule(dst: &str, translated_addr: &str, translated_port: Option<u16>) -> NatRule {
        NatRule {
            id: Uuid::new_v4(),
            enabled: true,
            description: None,
            rule_type: NatRuleType::Dnat,
            interface: None,
            source: None,
            destination: Some(dst.to_string()),
            protocol: NatProtocol::Tcp,
            source_port: None,
            destination_port: translated_port,
            translation: Some(NatTranslation {
                address: Some(translated_addr.to_string()),
                port: translated_port,
                port_end: None,
            }),
            nat_reflection: false,
            address_family: AddressFamily::Ipv4,
            priority: 0,
            log: false,
        }
    }

    // ------------------------------------------------------------------
    // generate_ruleset — structural checks
    // ------------------------------------------------------------------

    #[test]
    fn empty_ruleset_has_base_structure() {
        let rs = generate_ruleset(&[], None, &[], &HashMap::new());
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
            !rs.contains("table ip nat"),
            "nat table must not appear without nat config"
        );
    }

    #[test]
    fn accept_rule_with_src_and_dst() {
        let rule = FirewallRule {
            source: Some("192.168.1.0/24".into()),
            destination: Some("10.0.0.1/32".into()),
            ..base_rule(0, Action::Accept)
        };
        let rs = generate_ruleset(&[rule], None, &[], &HashMap::new());
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
        let rs = generate_ruleset(&[rule], None, &[], &HashMap::new());
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
        let rs = generate_ruleset(&[rule], None, &[], &HashMap::new());
        assert!(rs.contains("udp sport 53"));
        assert!(rs.contains("drop"));
    }

    #[test]
    fn protocol_only_uses_meta_l4proto() {
        let rule = FirewallRule {
            protocol: Some(Protocol::Tcp),
            ..base_rule(0, Action::Accept)
        };
        let rs = generate_ruleset(&[rule], None, &[], &HashMap::new());
        assert!(rs.contains("meta l4proto tcp"));
    }

    #[test]
    fn drop_rule() {
        let rule = base_rule(0, Action::Drop);
        let rs = generate_ruleset(&[rule], None, &[], &HashMap::new());
        assert!(rs.contains("drop"));
    }

    #[test]
    fn reject_rule() {
        let rule = base_rule(0, Action::Reject);
        let rs = generate_ruleset(&[rule], None, &[], &HashMap::new());
        assert!(rs.contains("reject"));
    }

    #[test]
    fn log_flag_adds_log_prefix() {
        let rule = FirewallRule {
            log: true,
            ..base_rule(0, Action::Accept)
        };
        let rs = generate_ruleset(&[rule], None, &[], &HashMap::new());
        assert!(rs.contains("log prefix"), "log prefix must appear");
    }

    #[test]
    fn interface_binding_adds_iif() {
        let rule = FirewallRule {
            interface: Some("eth0".into()),
            ..base_rule(0, Action::Accept)
        };
        let rs = generate_ruleset(&[rule], None, &[], &HashMap::new());
        assert!(rs.contains("iif \"eth0\""));
    }

    #[test]
    fn ipv6_source_uses_ip6_saddr() {
        let rule = FirewallRule {
            source: Some("2001:db8::/32".into()),
            ..base_rule(0, Action::Accept)
        };
        let rs = generate_ruleset(&[rule], None, &[], &HashMap::new());
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
        let rs = generate_ruleset(&[r_high, r_low], None, &[], &HashMap::new());
        let pos_high_prio = rs.find("2.2.2.2").expect("2.2.2.2 not found");
        let pos_low_prio = rs.find("1.1.1.1").expect("1.1.1.1 not found");
        assert!(
            pos_high_prio < pos_low_prio,
            "priority 5 rule must precede priority 10 rule"
        );
    }

    // ------------------------------------------------------------------
    // NAT table generation
    // ------------------------------------------------------------------

    #[test]
    fn no_nat_config_omits_nat_table() {
        let rs = generate_ruleset(&[], None, &[], &HashMap::new());
        assert!(!rs.contains("table ip nat"), "nat table must not appear without config");
    }

    #[test]
    fn automatic_mode_generates_postrouting_masquerade() {
        let nat = NatConfig {
            outbound_mode: OutboundMode::Automatic,
            wan_interfaces: vec!["eth0".into()],
            rules: vec![],
            nat_reflection: false,
        };
        let rs = generate_ruleset(&[], Some(&nat), &[], &HashMap::new());
        assert!(rs.contains("table ip nat"), "nat table must appear");
        assert!(rs.contains("chain postrouting"), "postrouting chain missing");
        assert!(rs.contains("oifname \"eth0\" masquerade"), "auto masquerade missing");
    }

    #[test]
    fn automatic_mode_no_wan_interfaces_omits_nat_table() {
        let nat = NatConfig {
            outbound_mode: OutboundMode::Automatic,
            wan_interfaces: vec![],
            rules: vec![],
            nat_reflection: false,
        };
        let rs = generate_ruleset(&[], Some(&nat), &[], &HashMap::new());
        assert!(!rs.contains("table ip nat"), "nat table must not appear without WAN interfaces");
    }

    #[test]
    fn manual_mode_with_masquerade_user_rule() {
        let nat = NatConfig {
            outbound_mode: OutboundMode::Manual,
            wan_interfaces: vec!["eth0".into()],
            rules: vec![masquerade_rule("eth0", Some("192.168.0.0/24"))],
            nat_reflection: false,
        };
        let rs = generate_ruleset(&[], Some(&nat), &[], &HashMap::new());
        assert!(rs.contains("table ip nat"), "nat table must appear");
        assert!(rs.contains("chain postrouting"), "postrouting chain missing");
        assert!(rs.contains("ip saddr 192.168.0.0/24"), "source address missing");
        assert!(rs.contains("masquerade"), "masquerade missing");
        // Auto rule must NOT appear in manual mode.
        let postrouting_start = rs.find("chain postrouting").unwrap();
        let postrouting_body = &rs[postrouting_start..];
        // The oifname from the user rule must be present but auto-masquerade line
        // should not appear as a standalone "oifname eth0 masquerade" without src.
        let auto_line = "oifname \"eth0\" masquerade";
        // Manual mode: no bare auto masquerade line.
        assert!(!postrouting_body.contains(auto_line), "auto masquerade must not appear in manual mode");
    }

    #[test]
    fn hybrid_mode_generates_both_auto_and_user_rules() {
        let nat = NatConfig {
            outbound_mode: OutboundMode::Hybrid,
            wan_interfaces: vec!["eth0".into()],
            rules: vec![masquerade_rule("eth1", Some("10.0.0.0/8"))],
            nat_reflection: false,
        };
        let rs = generate_ruleset(&[], Some(&nat), &[], &HashMap::new());
        assert!(rs.contains("oifname \"eth0\" masquerade"), "auto masquerade missing");
        assert!(rs.contains("ip saddr 10.0.0.0/8"), "user rule src missing");
        assert!(rs.contains("oifname \"eth1\" masquerade"), "user rule iface missing");
    }

    #[test]
    fn dnat_rule_appears_in_prerouting() {
        let nat = NatConfig {
            outbound_mode: OutboundMode::Manual,
            wan_interfaces: vec![],
            rules: vec![dnat_rule("203.0.113.1/32", "10.0.0.1", Some(8080))],
            nat_reflection: false,
        };
        let rs = generate_ruleset(&[], Some(&nat), &[], &HashMap::new());
        assert!(rs.contains("chain prerouting"), "prerouting chain missing");
        assert!(rs.contains("ip daddr 203.0.113.1/32"), "dst addr missing");
        assert!(rs.contains("dnat to 10.0.0.1:8080"), "dnat target missing");
    }

    #[test]
    fn snat_rule_appears_in_postrouting() {
        let snat = NatRule {
            id: Uuid::new_v4(),
            enabled: true,
            description: None,
            rule_type: NatRuleType::Snat,
            interface: None,
            source: Some("10.0.0.0/8".into()),
            destination: None,
            protocol: NatProtocol::Any,
            source_port: None,
            destination_port: None,
            translation: Some(NatTranslation {
                address: Some("203.0.113.5".into()),
                port: None,
                port_end: None,
            }),
            nat_reflection: false,
            address_family: AddressFamily::Ipv4,
            priority: 0,
            log: false,
        };
        let nat = NatConfig {
            outbound_mode: OutboundMode::Manual,
            wan_interfaces: vec![],
            rules: vec![snat],
            nat_reflection: false,
        };
        let rs = generate_ruleset(&[], Some(&nat), &[], &HashMap::new());
        assert!(rs.contains("chain postrouting"), "postrouting missing");
        assert!(rs.contains("snat to 203.0.113.5"), "snat target missing");
    }

    #[test]
    fn nat_reflection_generates_output_chain() {
        let mut rule = dnat_rule("203.0.113.1/32", "10.0.0.1", Some(80));
        rule.nat_reflection = true;
        let nat = NatConfig {
            outbound_mode: OutboundMode::Manual,
            wan_interfaces: vec![],
            rules: vec![rule],
            nat_reflection: false,
        };
        let rs = generate_ruleset(&[], Some(&nat), &[], &HashMap::new());
        // Count occurrences of "chain output" — only the nat output chain should appear.
        assert!(rs.contains("hook output"), "reflection output chain missing");
    }

    #[test]
    fn global_nat_reflection_applies_to_all_dnat_rules() {
        let nat = NatConfig {
            outbound_mode: OutboundMode::Manual,
            wan_interfaces: vec![],
            rules: vec![dnat_rule("203.0.113.2/32", "192.168.1.10", Some(443))],
            nat_reflection: true,
        };
        let rs = generate_ruleset(&[], Some(&nat), &[], &HashMap::new());
        assert!(rs.contains("hook output"), "global reflection must generate output chain");
    }

    #[test]
    fn nat_rules_sorted_by_priority() {
        let mut rule_high = dnat_rule("203.0.113.10/32", "10.0.0.10", Some(9090));
        rule_high.priority = 10;
        let mut rule_low = dnat_rule("203.0.113.20/32", "10.0.0.20", Some(8080));
        rule_low.priority = 5;
        let nat = NatConfig {
            outbound_mode: OutboundMode::Manual,
            wan_interfaces: vec![],
            rules: vec![rule_high, rule_low],
            nat_reflection: false,
        };
        let rs = generate_ruleset(&[], Some(&nat), &[], &HashMap::new());
        let pos_low = rs.find("203.0.113.20").expect("low priority rule not found");
        let pos_high = rs.find("203.0.113.10").expect("high priority rule not found");
        assert!(pos_low < pos_high, "priority 5 rule must appear before priority 10 rule");
    }

    #[test]
    fn disabled_nat_rule_not_emitted() {
        let mut rule = masquerade_rule("eth0", None);
        rule.enabled = false;
        let nat = NatConfig {
            outbound_mode: OutboundMode::Manual,
            wan_interfaces: vec![],
            rules: vec![rule],
            nat_reflection: false,
        };
        let rs = generate_ruleset(&[], Some(&nat), &[], &HashMap::new());
        assert!(!rs.contains("table ip nat"), "disabled rule must not emit nat table");
    }

    #[test]
    fn nat_uses_ip_not_inet_table() {
        let nat = NatConfig {
            outbound_mode: OutboundMode::Automatic,
            wan_interfaces: vec!["eth0".into()],
            rules: vec![],
            nat_reflection: false,
        };
        let rs = generate_ruleset(&[], Some(&nat), &[], &HashMap::new());
        assert!(rs.contains("table ip nat"), "must use 'table ip nat' (IPv4 only)");
        assert!(!rs.contains("table inet nat"), "must not use 'table inet nat'");
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
        let rs = generate_ruleset(&[], None, &[alias], &HashMap::new());
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
        let rs = generate_ruleset(&[], None, &[alias], &HashMap::new());
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
        let rs = generate_ruleset(&[], None, &[alias], &HashMap::new());
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
        let rs = generate_ruleset(&[], None, &[alias], &HashMap::new());
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
        let rs = generate_ruleset(&[], None, &[alias], &resolved);
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
        let result = apply_rules(&[], None, &[]).await;
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
