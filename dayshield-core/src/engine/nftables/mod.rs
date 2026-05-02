//! nftables engine — compiles [`FirewallRule`] and [`NatRule`] objects into
//! nftables rulesets and applies them via the `nft` CLI.
//!
//! TODO: implement ruleset generation from `FirewallRule` and `NatRule` lists.
//! TODO: implement atomic ruleset application using `nft -f <file>`.
//! TODO: implement ruleset flush and reload on config change.
//! TODO: implement zone-based policy model (LAN, WAN, DMZ).
//! TODO: add support for named sets and maps for efficient matching.
//! TODO: add ip6tables / nftables IPv6 dual-stack support.

use anyhow::Result;
use tracing::{info, warn};

use crate::config::models::{FirewallRule, NatRule};

/// Apply the given firewall rules and NAT rules to the running kernel.
///
/// This is a placeholder — the actual implementation will call `nft -f` with
/// a generated ruleset file.
pub async fn apply_rules(rules: &[FirewallRule], nat_rules: &[NatRule]) -> Result<()> {
    // TODO: generate nftables ruleset text from `rules` and `nat_rules`.
    // TODO: write ruleset to a temp file and invoke `nft -f <path>`.
    info!(
        fw_rules = rules.len(),
        nat_rules = nat_rules.len(),
        "nftables: apply_rules called (stub)"
    );
    Ok(())
}

/// Flush all DayShield-managed chains from the kernel.
///
/// TODO: implement selective flush that only removes DayShield chains.
pub async fn flush_rules() -> Result<()> {
    warn!("nftables: flush_rules called (stub — no-op)");
    Ok(())
}

/// Generate a plain-text nftables ruleset from the provided rule lists.
///
/// Returns the ruleset as a `String` that can be passed to `nft -f`.
///
/// TODO: implement full ruleset generation.
pub fn generate_ruleset(rules: &[FirewallRule], nat_rules: &[NatRule]) -> String {
    // TODO: build nftables syntax from rule structs.
    format!(
        "# DayShield nftables ruleset (stub)\n\
         # {} firewall rule(s), {} NAT rule(s)\n",
        rules.len(),
        nat_rules.len()
    )
}
