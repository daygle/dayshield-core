//! Firewall metrics collector: nftables state count and per-rule hit counters.
//!
//! Runs `nft list` commands via `tokio::process::Command` and parses the
//! output.  All errors are logged and result in zero-valued metrics so the
//! rest of the subsystem keeps working on systems without nftables.

use tokio::process::Command;
use tracing::warn;

use crate::metrics::{FirewallMetrics, RuleHitCount};

// ---------------------------------------------------------------------------
// nft state count
// ---------------------------------------------------------------------------

/// Run `nft list ct table ip filter` and count the number of output lines
/// that look like conntrack state entries.
///
/// Returns 0 on any error.
pub async fn collect_state_count() -> u64 {
    // `conntrack -C` is the canonical way to count states, but nftables
    // environments may not have it.  Fall back to /proc/net/nf_conntrack.
    match tokio::fs::read_to_string("/proc/net/nf_conntrack").await {
        Ok(content) => content.lines().filter(|l| !l.is_empty()).count() as u64,
        Err(_) => {
            // Try the older /proc/net/ip_conntrack path.
            match tokio::fs::read_to_string("/proc/net/ip_conntrack").await {
                Ok(content) => content.lines().filter(|l| !l.is_empty()).count() as u64,
                Err(e) => {
                    warn!(error = %e, "metrics/firewall: cannot read conntrack state file");
                    0
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// nft rule hit counters
// ---------------------------------------------------------------------------

/// Run `nft -j list ruleset` (JSON output) and extract per-rule packet
/// counters.
///
/// Returns an empty `Vec` when nftables is unavailable or the output cannot
/// be parsed.
pub async fn collect_rule_hits() -> Vec<RuleHitCount> {
    let output = match Command::new("nft")
        .args(["-j", "list", "ruleset"])
        .output()
        .await
    {
        Ok(o) => o,
        Err(e) => {
            warn!(error = %e, "metrics/firewall: failed to spawn nft");
            return vec![];
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!(stderr = %stderr, "metrics/firewall: nft exited with error");
        return vec![];
    }

    let text = String::from_utf8_lossy(&output.stdout);
    parse_nft_json_hits(&text)
}

/// Parse the JSON output of `nft -j list ruleset` and extract
/// `(handle, packet_count)` pairs.
///
/// The relevant JSON path is:
/// `nftables[].rule.handle` and `nftables[].rule.expr[].counter.packets`.
pub fn parse_nft_json_hits(json_text: &str) -> Vec<RuleHitCount> {
    let root: serde_json::Value = match serde_json::from_str(json_text) {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "metrics/firewall: failed to parse nft JSON output");
            return vec![];
        }
    };

    let entries = match root.get("nftables").and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return vec![],
    };

    let mut result = Vec::new();

    for entry in entries {
        let rule = match entry.get("rule") {
            Some(r) => r,
            None => continue,
        };

        let handle = match rule.get("handle").and_then(|h| h.as_u64()) {
            Some(h) => h,
            None => continue,
        };

        // Sum packets across all counter expressions in this rule.
        let mut packets: u64 = 0;
        if let Some(exprs) = rule.get("expr").and_then(|e| e.as_array()) {
            for expr in exprs {
                if let Some(counter) = expr.get("counter") {
                    if let Some(p) = counter.get("packets").and_then(|p| p.as_u64()) {
                        packets = packets.saturating_add(p);
                    }
                }
            }
        }

        let comment = rule
            .get("comment")
            .and_then(|c| c.as_str())
            .map(|s| s.to_string());
        result.push(RuleHitCount { handle, packets, comment });
    }

    result
}

// ---------------------------------------------------------------------------
// Top-level collector
// ---------------------------------------------------------------------------

/// Collect a fresh [`FirewallMetrics`] reading.
pub async fn collect_firewall() -> FirewallMetrics {
    let (state_count, rule_hit_counts) =
        tokio::join!(collect_state_count(), collect_rule_hits());
    FirewallMetrics { state_count, rule_hit_counts }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const NFT_JSON: &str = r#"{
  "nftables": [
    { "metainfo": { "version": "1.0" } },
    {
      "rule": {
        "family": "ip",
        "table": "filter",
        "chain": "INPUT",
        "handle": 10,
        "expr": [
          { "counter": { "packets": 1234, "bytes": 56789 } },
          { "accept": null }
        ]
      }
    },
    {
      "rule": {
        "family": "ip",
        "table": "filter",
        "chain": "INPUT",
        "handle": 11,
        "expr": [
          { "counter": { "packets": 0, "bytes": 0 } },
          { "drop": null }
        ]
      }
    },
    {
      "rule": {
        "family": "ip",
        "table": "filter",
        "chain": "FORWARD",
        "handle": 20,
        "expr": [
          { "counter": { "packets": 42, "bytes": 100 } }
        ]
      }
    }
  ]
}"#;

    #[test]
    fn test_parse_nft_json_hits_basic() {
        let hits = parse_nft_json_hits(NFT_JSON);
        assert_eq!(hits.len(), 3);

        let h10 = hits.iter().find(|h| h.handle == 10).expect("handle 10");
        assert_eq!(h10.packets, 1234);

        let h11 = hits.iter().find(|h| h.handle == 11).expect("handle 11");
        assert_eq!(h11.packets, 0);

        let h20 = hits.iter().find(|h| h.handle == 20).expect("handle 20");
        assert_eq!(h20.packets, 42);
    }

    #[test]
    fn test_parse_nft_json_hits_invalid_json() {
        let hits = parse_nft_json_hits("not valid json");
        assert!(hits.is_empty());
    }

    #[test]
    fn test_parse_nft_json_hits_empty_ruleset() {
        let json = r#"{"nftables":[]}"#;
        assert!(parse_nft_json_hits(json).is_empty());
    }

    #[test]
    fn test_parse_nft_json_hits_no_counter_expr() {
        let json = r#"{
  "nftables": [
    { "rule": { "handle": 5, "expr": [ { "accept": null } ] } }
  ]
}"#;
        let hits = parse_nft_json_hits(json);
        // Rule exists but has no counter - still emitted with packets=0.
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].packets, 0);
    }
}
