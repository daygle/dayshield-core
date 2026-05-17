//! DHCPv6 Prefix Delegation (IA-PD) utilities.
//!
//! # Overview
//!
//! This module provides:
//! - Reading the current delegated prefix granted by an ISP via the dhclient6
//!   exit-hook state file (`/run/dayshield-pd-<iface>.prefix`).
//! - Computing per-LAN-interface /64 (or custom) addresses by inserting a
//!   `track_prefix_id` into the bits between the delegated prefix length and
//!   the target prefix length.
//! - Installing the dhclient exit-hook script that writes the state file.
//!
//! # Prefix Mathematics
//!
//! Given a delegated prefix `2001:db8::/56` (56-bit ISP network), and a LAN
//! interface with `track_prefix_id = 3` and `target_prefix_len = 64`:
//!
//! 1. `available_bits = 64 - 56 = 8`   (fits u8, 0-255 subnets)
//! 2. `shift = 128 - 64 = 64`
//! 3. `prefix_part = 3 << 64`
//! 4. `addr = base_network | prefix_part | host_bits`
//! 5. Result: `2001:db8:0:3::1/64`

use std::net::Ipv6Addr;

use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// State file paths
// ---------------------------------------------------------------------------

/// Path to the dhclient PD exit-hook state file for an interface.
pub fn pd_prefix_path(iface_name: &str) -> String {
    format!("/run/dayshield-pd-{iface_name}.prefix")
}

/// Path where the dhclient6-PD config file is written for a given interface.
pub fn pd_conf_path(iface_name: &str) -> String {
    format!("/etc/dhcp/dhclient6-pd-{iface_name}.conf")
}

// ---------------------------------------------------------------------------
// Read delegated prefix
// ---------------------------------------------------------------------------

/// Read the current delegated prefix for a WAN interface from its state file.
///
/// Returns `None` if no prefix has been granted yet (the dhclient PD client
/// may still be negotiating with the ISP).
///
/// File format: a single line `<address>/<prefix_len>`, e.g. `2001:db8::/56`.
pub fn read_delegated_prefix(iface_name: &str) -> Option<String> {
    let path = pd_prefix_path(iface_name);
    std::fs::read_to_string(&path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s.contains('/'))
}

// ---------------------------------------------------------------------------
// Prefix computation
// ---------------------------------------------------------------------------

/// Compute the IPv6 address to assign to a LAN interface, given a delegated
/// prefix from the WAN, a subnet ID, and the desired target prefix length.
///
/// # Parameters
///
/// * `delegated_prefix` — e.g. `"2001:db8::/56"`
/// * `prefix_id`        — subnet selector (0-255), inserted into available bits
/// * `target_prefix_len`— final network prefix length, typically 64
/// * `host_part`        — host bits to OR into the final address (e.g. `1` → `::1`)
///
/// # Returns
///
/// The full interface address in CIDR notation, e.g. `"2001:db8:0:3::1/64"`,
/// or `None` if the delegated prefix is malformed or the `prefix_id` overflows.
pub fn compute_track_address(
    delegated_prefix: &str,
    prefix_id: u8,
    target_prefix_len: u8,
    host_part: u64,
) -> Option<String> {
    let (base_addr, del_len) = parse_prefix(delegated_prefix)?;

    if target_prefix_len < del_len {
        warn!(
            delegated = %delegated_prefix,
            target_len = target_prefix_len,
            "prefix_delegation: target prefix len shorter than delegated len"
        );
        return None;
    }
    if target_prefix_len > 128 {
        return None;
    }

    let available_bits = target_prefix_len - del_len;

    // Check that prefix_id fits within the available bits.
    // u8 is max 8 bits; if available_bits < 8 we need the stricter check.
    if available_bits < 8 && (prefix_id as u32) >= (1u32 << available_bits) {
        warn!(
            prefix_id,
            available_bits,
            "prefix_delegation: prefix_id does not fit in available bits"
        );
        return None;
    }

    let base_u128 = u128::from(base_addr);

    // Mask off any host bits below del_len.
    let prefix_mask: u128 = if del_len == 0 {
        0
    } else {
        !0u128 << (128 - del_len as u32)
    };
    let base_network = base_u128 & prefix_mask;

    // Insert prefix_id into bits [del_len .. target_prefix_len].
    // shift = position of bit 0 of the prefix_id slot from the right.
    let shift = 128u32 - target_prefix_len as u32;
    let prefix_part = (prefix_id as u128) << shift;

    // Compose: fixed ISP network | our subnet ID | host part.
    let addr_u128 = base_network | prefix_part | (host_part as u128);
    let addr = Ipv6Addr::from(addr_u128);

    debug!(
        delegated = %delegated_prefix,
        prefix_id,
        target_len = target_prefix_len,
        host_part,
        assigned = %addr,
        "prefix_delegation: computed track address"
    );

    Some(format!("{addr}/{target_prefix_len}"))
}

/// Parse `"<addr>/<len>"` into an `(Ipv6Addr, u8)` pair.
fn parse_prefix(prefix: &str) -> Option<(Ipv6Addr, u8)> {
    let mut parts = prefix.splitn(2, '/');
    let addr: Ipv6Addr = parts.next()?.trim().parse().ok()?;
    let len: u8 = parts.next()?.trim().parse().ok()?;
    if len > 128 {
        return None;
    }
    Some((addr, len))
}

// ---------------------------------------------------------------------------
// dhclient exit-hook
// ---------------------------------------------------------------------------

/// Content of the dhclient exit-hook script that writes the delegated prefix
/// to the DayShield state file after each lease event.
///
/// Install at: `/etc/dhcp/dhclient-exit-hooks.d/dayshield-pd`
pub fn pd_exit_hook_content() -> &'static str {
    r#"#!/bin/sh
# DayShield DHCPv6-PD exit hook - managed by dayshield-core, do not edit.
# Persists the delegated prefix to /run/dayshield-pd-<iface>.prefix so the
# dayshield-core engine can distribute it to downstream LAN interfaces.

case "$reason" in
    BOUND6|RENEW6|REBIND6)
        if [ -n "$new_ip6_prefix" ] && [ -n "$new_ip6_prefixlen" ] && [ -n "$interface" ]; then
            printf '%s/%s\n' "$new_ip6_prefix" "$new_ip6_prefixlen" \
                > "/run/dayshield-pd-${interface}.prefix"
        fi
        ;;
    STOP6|EXPIRE6|FAIL)
        rm -f "/run/dayshield-pd-${interface}.prefix"
        ;;
esac
"#
}

/// Ensure the dhclient exit-hook is installed and executable.
pub async fn ensure_pd_hook_installed() -> anyhow::Result<()> {
    use tokio::fs;

    let hook_dir = "/etc/dhcp/dhclient-exit-hooks.d";
    let hook_path = format!("{hook_dir}/dayshield-pd");

    fs::create_dir_all(hook_dir)
        .await
        .map_err(|e| anyhow::anyhow!("create dhclient hook dir: {e}"))?;

    fs::write(&hook_path, pd_exit_hook_content())
        .await
        .map_err(|e| anyhow::anyhow!("write dhclient hook: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook_path, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| anyhow::anyhow!("chmod dhclient hook: {e}"))?;
    }

    debug!("prefix_delegation: hook installed at {hook_path}");
    Ok(())
}

/// Generate a dhclient6 configuration file that requests a prefix of the
/// given length hint.  Returns the path of the written file.
///
/// When `hint_len` is `None`, no hint file is written and the caller should
/// invoke dhclient with `-P` alone (ISP decides prefix size).
pub async fn write_dhcp6_pd_conf(iface_name: &str, hint_len: u8) -> anyhow::Result<String> {
    use tokio::fs;

    let conf_path = pd_conf_path(iface_name);

    // Ensure /etc/dhcp exists.
    fs::create_dir_all("/etc/dhcp")
        .await
        .map_err(|e| anyhow::anyhow!("create /etc/dhcp: {e}"))?;

    let content = format!(
        r#"# DayShield DHCPv6-PD config for {iface_name} - managed by dayshield-core
interface "{iface_name}" {{
  send dhcp6.rapid-commit;
  request dhcp6.name-servers, dhcp6.domain-search;
  ia-pd 1 {{
    prefix-hint {{
      prefix-address ::/{hint_len};
    }}
  }}
}}
"#
    );

    fs::write(&conf_path, content)
        .await
        .map_err(|e| anyhow::anyhow!("write dhclient6-pd conf: {e}"))?;

    debug!(iface = %iface_name, hint_len, conf = %conf_path, "prefix_delegation: wrote dhclient6-pd config");
    Ok(conf_path)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_56_to_64_prefix_id_3() {
        // /56 delegated, prefix_id=3, target /64, host ::1
        let result = compute_track_address("2001:db8::/56", 3, 64, 1);
        assert_eq!(result, Some("2001:db8:0:3::1/64".to_string()));
    }

    #[test]
    fn compute_48_to_64_prefix_id_5() {
        // /48 delegated, prefix_id=5, target /64, host ::1
        let result = compute_track_address("2001:db8:cafe::/48", 5, 64, 1);
        assert_eq!(result, Some("2001:db8:cafe:5::1/64".to_string()));
    }

    #[test]
    fn compute_56_to_64_zero_host() {
        // Network address only (host_part=0)
        let result = compute_track_address("2001:db8::/56", 0, 64, 0);
        assert_eq!(result, Some("2001:db8::/64".to_string()));
    }

    #[test]
    fn compute_60_to_64_prefix_id_overflow() {
        // /60 delegated → /64: only 4 bits available, prefix_id=16 overflows
        let result = compute_track_address("2001:db8::/60", 16, 64, 1);
        assert_eq!(result, None);
    }

    #[test]
    fn compute_60_to_64_max_valid() {
        // /60 → /64: 4 bits available, max valid prefix_id = 15
        let result = compute_track_address("2001:db8::/60", 15, 64, 1);
        assert!(result.is_some());
    }

    #[test]
    fn compute_target_shorter_than_delegated() {
        let result = compute_track_address("2001:db8::/56", 3, 48, 1);
        assert_eq!(result, None);
    }

    #[test]
    fn compute_48_to_64_all_subnets_unique() {
        // Prefix IDs 0-9 should produce distinct /64 networks
        let prefixes: Vec<String> = (0u8..10)
            .filter_map(|id| compute_track_address("2001:db8::/48", id, 64, 0))
            .collect();
        let unique: std::collections::HashSet<&str> = prefixes.iter().map(|s| s.as_str()).collect();
        assert_eq!(prefixes.len(), unique.len());
    }

    #[test]
    fn parse_delegated_prefix_round_trip() {
        let cidr = "2001:db8::/56";
        let (addr, len) = parse_prefix(cidr).unwrap();
        assert_eq!(len, 56);
        assert_eq!(addr.to_string(), "2001:db8::");
    }
}
