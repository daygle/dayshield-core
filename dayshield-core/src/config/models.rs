//! Configuration models.
//!
//! All structs are serialisable / deserialisable with serde so they can be
//! written to JSON files on disk and exchanged over the REST API.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Network interface
// ---------------------------------------------------------------------------

/// The kind of network interface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum InterfaceType {
    /// Physical Ethernet adapter.
    Ethernet,
    /// VLAN sub-interface.
    Vlan,
    /// WireGuard tunnel interface.
    Wireguard,
    /// Generic loopback.
    Loopback,
    /// Bridge device.
    Bridge,
    /// Bonding / LAG.
    Bond,
    /// Software dummy interface.
    Dummy,
}

/// WAN connection mode, used when this interface is designated as the upstream.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum WanMode {
    /// Obtain an IPv4 address via DHCP (default).
    #[default]
    Dhcp,
    /// PPPoE (DSL / fibre) - requires `pppoe_username` and `pppoe_password`.
    Pppoe,
}

/// Represents a managed network interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Interface {
    /// OS-level interface name, e.g. `eth0` or `wg0`.
    pub name: String,
    /// Optional human-readable description.
    pub description: Option<String>,
    /// IP addresses in CIDR notation, e.g. `["192.168.1.1/24", "10.0.0.1/8"]`.
    #[serde(default)]
    pub addresses: Vec<String>,
    /// MTU in bytes (defaults to 1500 when `None`).
    pub mtu: Option<u16>,
    /// Optional TCP MSS value for this interface.
    ///
    /// Used for environments that require MSS tuning (for example PPPoE links).
    /// The value is persisted and exposed via the API.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mss: Option<u16>,
    /// Whether the interface should be brought up.
    pub enabled: bool,
    /// Obtain an IPv4 address via DHCP.
    pub dhcp4: bool,
    /// Obtain an IPv6 address via DHCP (reserved for future use).
    pub dhcp6: bool,
    /// VLAN tag ID (802.1Q), if this is a VLAN sub-interface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vlan: Option<u16>,
    /// Parent/base interface name for VLAN sub-interfaces (for example `eth0`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_interface: Option<String>,
    /// WAN connection mode.  `None` means this interface is not a WAN uplink.
    /// When `Some(WanMode::Pppoe)` the `pppoe_username` / `pppoe_password`
    /// fields must also be present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wan_mode: Option<WanMode>,
    /// PPPoE username (only used when `wan_mode == Some(WanMode::Pppoe)`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pppoe_username: Option<String>,
    /// PPPoE password (only used when `wan_mode == Some(WanMode::Pppoe)`).
    /// Stored in the local config file; never returned in API list responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pppoe_password: Option<String>,
    /// Static WAN gateway IP address.
    ///
    /// Only used when `dhcp4` is `false` and `wan_mode` is not PPPoE.
    /// When set, the engine applies `ip route replace default via <gateway> dev <name>`
    /// after configuring the interface addresses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
}

// ---------------------------------------------------------------------------
// Gateway
// ---------------------------------------------------------------------------

/// A named upstream gateway.
///
/// Gateways are associated with a network interface and represent the
/// next-hop IP address used to route traffic out of that interface.
/// For DHCP and PPPoE uplinks the gateway IP is discovered automatically;
/// for static uplinks it must be specified explicitly in [`Interface::gateway`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gateway {
    /// Unique gateway name, e.g. `"WAN_GW"` or `"WAN_DHCP"`.
    pub name: String,
    /// Optional human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The network interface this gateway is reachable via.
    pub interface: String,
    /// Static next-hop IP address.
    ///
    /// `None` for DHCP / PPPoE interfaces where the gateway is negotiated
    /// automatically; `Some` for static WAN.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_ip: Option<String>,
    /// IP address to use for health monitoring (ICMP ping).
    ///
    /// Defaults to `gateway_ip` at probe time when `None`.  For DHCP / PPPoE
    /// gateways without a static `gateway_ip`, set this to a reliable public
    /// address (e.g. `"8.8.8.8"`) to enable health checking.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monitor_ip: Option<String>,
    /// Routing priority weight (1–100, lower = higher priority).
    /// Used for multi-WAN and gateway groups.
    #[serde(default = "gateway_default_weight")]
    pub weight: u8,
    /// Whether this gateway is active.
    pub enabled: bool,
}

fn gateway_default_weight() -> u8 {
    1
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Return `true` if `name` is a valid Linux network interface name.
///
/// Rules:
/// - Non-empty.
/// - At most 15 bytes (Linux `IFNAMSIZ - 1`).
/// - Only alphanumeric characters, hyphens (`-`), underscores (`_`), dots (`.`).
pub fn is_valid_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

/// Return `true` if `addr` is a valid IPv4 or IPv6 address (without prefix).
///
/// Accepts any string parseable as [`std::net::IpAddr`].
pub fn is_valid_ip(addr: &str) -> bool {
    addr.parse::<std::net::IpAddr>().is_ok()
}

/// Return `true` if `start` and `end` are valid IPv4 addresses and
/// `start` ≤ `end` in numeric order.
pub fn is_valid_ipv4_range(start: &str, end: &str) -> bool {
    match (
        start.parse::<std::net::Ipv4Addr>(),
        end.parse::<std::net::Ipv4Addr>(),
    ) {
        (Ok(s), Ok(e)) => u32::from(s) <= u32::from(e),
        _ => false,
    }
}

/// Return `true` if `mac` is a valid IEEE 802 MAC address.
///
/// Accepts colon-separated (`aa:bb:cc:dd:ee:ff`) or hyphen-separated
/// (`aa-bb-cc-dd-ee-ff`) hex pairs (case-insensitive).
pub fn is_valid_mac(mac: &str) -> bool {
    let sep = if mac.contains(':') {
        ':'
    } else if mac.contains('-') {
        '-'
    } else {
        return false;
    };
    let parts: Vec<&str> = mac.split(sep).collect();
    parts.len() == 6 && parts.iter().all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Return `true` if `domain` is a syntactically valid domain name.
///
/// Rules (per RFC 1035 / 952):
/// - Non-empty.
/// - Each label is 1–63 ASCII alphanumeric characters or hyphens, and must
///   not start or end with a hyphen.
/// - Total length ≤ 253 characters (excluding any trailing dot).
pub fn is_valid_domain(domain: &str) -> bool {
    let domain = domain.strip_suffix('.').unwrap_or(domain);
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }
    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

/// Return `true` if `cidr` is a valid IPv4 or IPv6 CIDR string.
///
/// Accepts `"<addr>/<prefix-len>"` where `addr` is parseable as either
/// [`std::net::Ipv4Addr`] or [`std::net::Ipv6Addr`] and the prefix length is
/// in the valid range for the address family.
pub fn is_valid_cidr(cidr: &str) -> bool {
    let mut parts = cidr.splitn(2, '/');
    let addr_str = match parts.next() {
        Some(s) => s,
        None => return false,
    };
    let prefix_str = match parts.next() {
        Some(s) => s,
        None => return false,
    };
    let prefix_len: u8 = match prefix_str.parse() {
        Ok(p) => p,
        Err(_) => return false,
    };

    if addr_str.parse::<std::net::Ipv4Addr>().is_ok() {
        return prefix_len <= 32;
    }
    if addr_str.parse::<std::net::Ipv6Addr>().is_ok() {
        return prefix_len <= 128;
    }
    false
}

/// Return `true` if `mtu` is within the acceptable range (68–65 535 bytes).
pub fn is_valid_mtu(mtu: u16) -> bool {
    mtu >= 68
}

/// Return `true` if `mss` is within an acceptable TCP MSS range (536–65 535).
pub fn is_valid_mss(mss: u16) -> bool {
    mss >= 536
}

/// Return `true` if `vlan_id` is a valid IEEE 802.1Q VLAN ID (1–4094).
pub fn is_valid_vlan_id(vlan_id: u16) -> bool {
    (1..=4094).contains(&vlan_id)
}

/// Return `true` for any [`Action`] value.
///
/// All variants of the typed enum are valid; this helper exists so callers
/// have a uniform `is_valid_*` surface alongside the other validators.
pub fn is_valid_action(_action: &Action) -> bool {
    true
}

/// Return `true` for any [`Protocol`] value.
///
/// All variants of the typed enum are valid; this helper exists so callers
/// have a uniform `is_valid_*` surface alongside the other validators.
pub fn is_valid_protocol(_protocol: &Protocol) -> bool {
    true
}

/// Return `true` if `port` is a non-zero port number (1–65 535).
///
/// Port 0 is reserved and not meaningful as an explicit filter criterion.
pub fn is_valid_port(port: u16) -> bool {
    port > 0
}

// ---------------------------------------------------------------------------
// Firewall
// ---------------------------------------------------------------------------

/// IP protocol selector for firewall rules.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    /// Match any protocol.
    Any,
}

/// What a firewall rule does when its conditions match.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Accept,
    Drop,
    Reject,
    /// Jump to another chain (nftables-style).
    Jump,
    /// Log without affecting packet flow.
    Log,
}

/// Global chain policy for nftables filter chains.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum FirewallChainPolicy {
    #[default]
    Drop,
    Accept,
}

/// Whether per-rule/default block firewall logs should be emitted before or
/// after the rule action.
///
/// `After` suppresses logs for terminal drop/reject tails, which reduces noise.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogPosition {
    Before,
    After,
}

fn default_log_position() -> LogPosition {
    LogPosition::After
}

/// Global firewall behavior that is not tied to individual allow/deny rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FirewallSettings {
    /// Default policy for the input chain.
    pub input_policy: FirewallChainPolicy,
    /// Default policy for the forward chain.
    pub forward_policy: FirewallChainPolicy,
    /// Default policy for the output chain.
    pub output_policy: FirewallChainPolicy,
    /// Drop packets with invalid conntrack state.
    pub drop_invalid_state: bool,
    /// Enable global SYN flood protection on inbound traffic.
    pub syn_flood_protection: bool,
    /// SYN packets per second allowed before dropping excess.
    pub syn_flood_rate: u32,
    /// Burst allowance for SYN flood limiter.
    pub syn_flood_burst: u32,
    /// Emit a built-in rule that keeps management ports reachable.
    pub management_anti_lockout: bool,
    /// Optional management interface restriction.
    pub management_interface: Option<String>,
    /// Optional list of source CIDRs allowed for management.
    pub management_allowed_sources: Vec<String>,
    /// TCP ports covered by the management anti-lockout rule.
    pub management_ports: Vec<u16>,
    /// ACME domain whose certificate should be used by the firewall appliance.
    pub management_tls_acme_domain: Option<String>,
    /// Whether to log before or after the rule action.
    #[serde(default = "default_log_position")]
    pub log_position: LogPosition,
}

impl Default for FirewallSettings {
    fn default() -> Self {
        Self {
            input_policy: FirewallChainPolicy::Drop,
            forward_policy: FirewallChainPolicy::Drop,
            output_policy: FirewallChainPolicy::Accept,
            drop_invalid_state: true,
            syn_flood_protection: true,
            syn_flood_rate: 120,
            syn_flood_burst: 240,
            management_anti_lockout: true,
            management_interface: None,
            management_allowed_sources: vec![],
            management_ports: vec![22, 443, 8443],
            management_tls_acme_domain: None,
            log_position: default_log_position(),
        }
    }
}

/// Time-based schedule that gates when a firewall rule is active.
///
/// All fields are optional - omitting them means "no restriction on that dimension".
/// Days use JavaScript / cron convention: 0 = Sunday, 1 = Monday, …, 6 = Saturday.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallSchedule {
    /// Days of the week on which the rule is active (0=Sun … 6=Sat).
    /// An empty vec means "all days".
    #[serde(default)]
    pub days: Vec<u8>,
    /// Start of the active time window, e.g. `"08:00"`.  `None` = midnight.
    pub time_start: Option<String>,
    /// End of the active time window, e.g. `"17:00"`.  `None` = midnight (next day).
    pub time_end: Option<String>,
    /// First date the rule is active, formatted `"YYYY-MM-DD"`.  `None` = no lower bound.
    pub date_start: Option<String>,
    /// Last date the rule is active, formatted `"YYYY-MM-DD"`.  `None` = no upper bound.
    pub date_end: Option<String>,
}

/// Which nftables filter chain a firewall rule should target.

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FirewallDirection {
    Input,
    Forward,
    Output,
    Both,
}

fn default_firewall_direction() -> FirewallDirection {
    FirewallDirection::Forward
}

/// A single stateless firewall rule that will be compiled into nftables.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    /// Unique identifier.
    pub id: Uuid,
    /// Optional human-readable comment.
    pub description: Option<String>,
    /// Evaluation priority (lower wins).
    pub priority: i32,
    /// Source CIDR or IP address; `None` means any.
    pub source: Option<String>,
    /// Destination CIDR or IP address; `None` means any.
    pub destination: Option<String>,
    /// Protocol filter; `None` means any.
    pub protocol: Option<Protocol>,
    /// Source port; `None` means any.
    pub source_port: Option<u16>,
    /// Destination port; `None` means any.
    pub destination_port: Option<u16>,
    /// Action to take when the rule matches.
    pub action: Action,
    /// Which chain the rule is emitted into.
    #[serde(default = "default_firewall_direction")]
    pub direction: FirewallDirection,
    /// Optional interface filter. Input/forward rules match ingress; output rules match egress.
    pub interface: Option<String>,
    /// Whether to emit a log statement before applying the action.
    pub log: bool,
    /// When `false` the rule is stored but not compiled into the nftables ruleset.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Optional time-based schedule; `None` means always active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<FirewallSchedule>,
}

// ---------------------------------------------------------------------------
// NAT
// ---------------------------------------------------------------------------

/// Outbound NAT mode - controls whether automatic masquerade rules are emitted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum OutboundMode {
    /// Automatically masquerade all traffic leaving every WAN interface.
    #[default]
    Automatic,
    /// Automatic masquerade for WAN interfaces **plus** any user-defined rules.
    Hybrid,
    /// Only user-defined rules; no automatic masquerade is generated.
    Manual,
}

/// NAT rule type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum NatRuleType {
    /// Dynamic source NAT - rewrites the source IP to the outbound interface address.
    Masquerade,
    /// Static source NAT - rewrites the source IP to a fixed address.
    Snat,
    /// Destination NAT / port forward - rewrites the destination IP and/or port.
    Dnat,
}

/// Protocol selector for NAT rules.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum NatProtocol {
    Tcp,
    Udp,
    /// Matches both TCP and UDP.
    #[serde(rename = "tcp_udp")]
    TcpUdp,
    /// Match any protocol.
    #[default]
    Any,
}

/// Address family.  IPv4 only; IPv6 is explicitly unsupported.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum AddressFamily {
    #[default]
    Ipv4,
}

/// Translated address and/or port for SNAT / DNAT rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatTranslation {
    /// IPv4 address to translate to.
    pub address: Option<String>,
    /// Single port to translate to (or lower bound of a port range).
    pub port: Option<u16>,
    /// Upper bound of a translated port range.  Must be ≥ `port` when set.
    pub port_end: Option<u16>,
}

/// A WAN / LAN interface descriptor returned by the NAT interface listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatInterface {
    /// OS-level interface name, e.g. `"eth0"`.
    pub name: String,
    /// `true` when this interface is the WAN uplink.
    pub is_wan: bool,
}

fn default_true() -> bool {
    true
}

/// A single NAT rule compiled into the nftables `nat` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatRule {
    /// Unique identifier.
    pub id: Uuid,
    /// Whether this rule is active.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Optional human-readable comment.
    pub description: Option<String>,
    /// Type of NAT to perform.
    pub rule_type: NatRuleType,
    /// WAN or LAN interface to match (outbound for masquerade/SNAT; inbound for DNAT).
    pub interface: Option<String>,
    /// Source IPv4 address or CIDR filter (`None` = any).
    pub source: Option<String>,
    /// Destination IPv4 address or CIDR filter (`None` = any).
    pub destination: Option<String>,
    /// Protocol filter.
    #[serde(default)]
    pub protocol: NatProtocol,
    /// Source port filter.
    pub source_port: Option<u16>,
    /// Destination port filter.
    pub destination_port: Option<u16>,
    /// Translation target (required for SNAT / DNAT; absent for masquerade).
    pub translation: Option<NatTranslation>,
    /// Enable NAT reflection (hairpin NAT) for this rule.
    #[serde(default)]
    pub nat_reflection: bool,
    /// Address family - IPv4 only; IPv6 values are rejected by the validator.
    #[serde(default)]
    pub address_family: AddressFamily,
    /// Rule priority - lower values are evaluated first.
    #[serde(default)]
    pub priority: i32,
    /// Emit a log statement before applying the NAT action.
    #[serde(default)]
    pub log: bool,
    /// When `true` (the default), a companion `accept` rule is automatically
    /// injected into the nftables `forward` chain for DNAT rules so that
    /// forwarded packets are not dropped by the default-drop forward policy.
    #[serde(default = "default_true")]
    pub auto_firewall_rule: bool,
}

/// Top-level NAT configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatConfig {
    /// Outbound NAT mode.
    #[serde(default)]
    pub outbound_mode: OutboundMode,
    /// WAN interface names used when generating automatic masquerade rules.
    #[serde(default)]
    pub wan_interfaces: Vec<String>,
    /// User-defined NAT rules, sorted deterministically by `priority`.
    #[serde(default)]
    pub rules: Vec<NatRule>,
    /// Enable NAT reflection (hairpin NAT) globally for all DNAT rules.
    #[serde(default)]
    pub nat_reflection: bool,
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            outbound_mode: OutboundMode::Automatic,
            wan_interfaces: vec![],
            rules: vec![],
            nat_reflection: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Validation helpers - NAT
// ---------------------------------------------------------------------------

/// Return `true` if `addr` is a valid IPv4 address (without prefix length).
pub fn is_valid_ipv4_addr(addr: &str) -> bool {
    addr.parse::<std::net::Ipv4Addr>().is_ok()
}

/// Return `true` if `value` is a valid IPv4 address or an IPv4 CIDR prefix.
///
/// Rejects IPv6 addresses and IPv6 CIDRs.
pub fn is_valid_ipv4_cidr_or_addr(value: &str) -> bool {
    if value.parse::<std::net::Ipv4Addr>().is_ok() {
        return true;
    }
    if let Some((ip_str, prefix_str)) = value.split_once('/') {
        if let (Ok(_), Ok(prefix)) = (
            ip_str.parse::<std::net::Ipv4Addr>(),
            prefix_str.parse::<u8>(),
        ) {
            return prefix <= 32;
        }
    }
    false
}

/// Validate a single [`NatRule`].
///
/// Returns `Ok(())` on success or `Err` with a descriptive message.
pub fn validate_nat_rule(rule: &NatRule) -> Result<(), String> {
    // IPv4 boundary: reject IPv6 in source / destination.
    if let Some(src) = &rule.source {
        if !is_valid_ipv4_cidr_or_addr(src) {
            return Err(format!(
                "source {:?} is not a valid IPv4 address/CIDR (IPv6 not supported)",
                src
            ));
        }
    }
    if let Some(dst) = &rule.destination {
        if !is_valid_ipv4_cidr_or_addr(dst) {
            return Err(format!(
                "destination {:?} is not a valid IPv4 address/CIDR (IPv6 not supported)",
                dst
            ));
        }
    }
    // Interface name validation.
    if let Some(iface) = &rule.interface {
        if !is_valid_interface_name(iface) {
            return Err(format!(
                "interface {:?} is not a valid interface name",
                iface
            ));
        }
    }
    // Translation validation.
    match rule.rule_type {
        NatRuleType::Snat | NatRuleType::Dnat => {
            let translation = rule.translation.as_ref().ok_or_else(|| {
                format!(
                    "{:?} rule must specify a translation",
                    rule.rule_type
                )
            })?;
            let addr = translation.address.as_deref().ok_or_else(|| {
                format!("{:?} rule translation must specify an address", rule.rule_type)
            })?;
            if !is_valid_ipv4_addr(addr) {
                return Err(format!(
                    "translation address {:?} is not a valid IPv4 address",
                    addr
                ));
            }
            if let Some(port) = translation.port {
                if port == 0 {
                    return Err("translation port must be non-zero".into());
                }
            }
            if let Some(port_end) = translation.port_end {
                if port_end == 0 {
                    return Err("translation port_end must be non-zero".into());
                }
                if let Some(port) = translation.port {
                    if port_end < port {
                        return Err(format!(
                            "translation port_end {} must be ≥ port {}",
                            port_end, port
                        ));
                    }
                }
            }
        }
        NatRuleType::Masquerade => {
            // Masquerade rules do not use a translation target.
        }
    }
    Ok(())
}

/// Return `Ok(())` if `config` is a valid [`NatConfig`], or `Err` with a
/// descriptive message.
pub fn validate_nat_config(config: &NatConfig) -> Result<(), String> {
    for iface in &config.wan_interfaces {
        if !is_valid_interface_name(iface) {
            return Err(format!(
                "NAT wan_interfaces contains invalid interface name {:?}",
                iface
            ));
        }
    }
    for rule in &config.rules {
        if let Err(msg) = validate_nat_rule(rule) {
            return Err(format!("NAT rule {}: {}", rule.id, msg));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// DNS (Unbound)
// ---------------------------------------------------------------------------

/// Configuration for the Unbound recursive resolver.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// Whether the DNS service should be running.
    pub enabled: bool,
    /// Address(es) Unbound should listen on.
    pub listen_addresses: Vec<String>,
    /// UDP/TCP port (default 53).
    pub port: u16,
    /// Upstream forwarders; empty means full recursion.
    pub forwarders: Vec<String>,
    /// Enable DNSSEC validation.
    pub dnssec: bool,
    /// Local DNS overrides: hostname → IP address.
    pub local_records: Vec<DnsLocalRecord>,
    /// Per-interface DNS blocklist sources.
    #[serde(default)]
    pub interface_blocklists: Vec<DnsInterfaceBlocklists>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen_addresses: vec![],
            port: 53,
            forwarders: vec![],
            dnssec: true,
            local_records: vec![],
            interface_blocklists: vec![],
        }
    }
}

/// A set of DNS blocklist URLs scoped to one interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsInterfaceBlocklists {
    pub interface: String,
    #[serde(default)]
    pub blocklists: Vec<DnsBlocklistEntry>,
}

/// A DNS blocklist source URL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsBlocklistEntry {
    pub id: Uuid,
    pub name: Option<String>,
    pub url: String,
    pub enabled: bool,
}

/// A static DNS mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsLocalRecord {
    pub name: String,
    pub record_type: String,
    pub value: String,
}

// ---------------------------------------------------------------------------
// DNS-over-TLS (DoT)
// ---------------------------------------------------------------------------

fn default_dot_port() -> u16 {
    853
}

/// Configuration for the DNS-over-TLS (DoT) listener.
///
/// When enabled, Unbound listens on [`DotConfig::port`] (default 853) using
/// the provided TLS certificate and private key, accepting connections from
/// any client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DotConfig {
    /// Whether the DoT listener should be active.
    pub enabled: bool,
    /// TCP port to listen on.  Defaults to 853 (the IANA-assigned DoT port).
    #[serde(default = "default_dot_port")]
    pub port: u16,
    /// If true, restrict DoT access to LAN clients only.
    ///
    /// This is enforced at the firewall layer; Unbound still binds the DoT
    /// port on all interfaces so the listener remains reachable from local
    /// and external networks as needed.
    #[serde(default = "default_dot_lan_only")]
    pub lan_only: bool,
    /// PEM-encoded TLS certificate chain presented to connecting clients.
    #[serde(default)]
    pub cert_pem: Option<String>,
    /// PEM-encoded private key matching the certificate.
    #[serde(default)]
    pub key_pem: Option<String>,
    /// ACME domain to use for DoT TLS material, if any.
    #[serde(default)]
    pub acme_domain: Option<String>,
    /// Certificate storage path for the selected ACME domain.
    #[serde(default)]
    pub acme_cert_storage_path: Option<String>,
}

fn default_dot_lan_only() -> bool {
    true
}

impl Default for DotConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: 853,
            lan_only: true,
            cert_pem: None,
            key_pem: None,
            acme_domain: None,
            acme_cert_storage_path: None,
        }
    }
}

/// Return `Ok(())` if `config` is a valid [`DotConfig`], or `Err` with a
/// descriptive message.
pub fn validate_dot_config(config: &DotConfig) -> Result<(), String> {
    if config.port == 0 {
        return Err("DoT port must be non-zero".into());
    }
    if config.enabled {
        let use_acme = config.acme_domain.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false);
        let has_raw_cert = config.cert_pem.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false);
        let has_raw_key = config.key_pem.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false);

        if !use_acme {
            if !has_raw_cert {
                return Err("DoT cert_pem must not be empty when enabled".into());
            }
            if !has_raw_key {
                return Err("DoT key_pem must not be empty when enabled".into());
            }
            // Basic PEM structure checks – a full crypto parse would require
            // additional heavy dependencies; this guards against obvious mistakes.
            let cert_pem = config.cert_pem.as_ref().unwrap();
            let key_pem = config.key_pem.as_ref().unwrap();
            if !cert_pem.contains("-----BEGIN CERTIFICATE-----") {
                return Err(
                    "DoT cert_pem does not appear to be a valid PEM certificate \
                     (expected '-----BEGIN CERTIFICATE-----' header)"
                        .into(),
                );
            }
            if !key_pem.contains("-----BEGIN") {
                return Err(
                    "DoT key_pem does not appear to be a valid PEM private key \
                     (expected '-----BEGIN' header)"
                        .into(),
                );
            }
        } else if config.acme_cert_storage_path.as_ref().map(|s| s.trim().is_empty()).unwrap_or(true) {
            return Err("DoT acme_cert_storage_path must be set when using an ACME domain".into());
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// DHCP (Kea / dnsmasq)
// ---------------------------------------------------------------------------

/// Configuration for the DHCP server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpConfig {
    /// Whether the DHCP service should be running.
    pub enabled: bool,
    /// Interface the DHCP server listens on (e.g. `"eth1"`).
    #[serde(default)]
    pub interface: String,
    /// DHCP scopes (one per subnet).
    pub scopes: Vec<DhcpScope>,
}

/// A DHCP address pool for a single subnet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpScope {
    pub id: Uuid,
    /// Subnet in CIDR notation.
    pub subnet: String,
    /// First address in the dynamic pool.
    pub pool_start: String,
    /// Last address in the dynamic pool.
    pub pool_end: String,
    /// Default gateway to advertise.
    pub gateway: Option<String>,
    /// DNS servers to advertise.
    pub dns_servers: Vec<String>,
    /// Lease duration in seconds.
    pub lease_seconds: u32,
    /// DNS search domain to advertise (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_name: Option<String>,
    /// Static host reservations within this scope.
    pub reservations: Vec<DhcpReservation>,
}

/// A static DHCP binding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpReservation {
    pub id: Uuid,
    pub hostname: Option<String>,
    pub mac_address: String,
    pub ip_address: String,
    /// Optional human-readable label for this reservation.
    #[serde(default)]
    pub description: String,
}

// ---------------------------------------------------------------------------
// VPN (WireGuard)
// ---------------------------------------------------------------------------

/// A WireGuard tunnel definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnTunnel {
    pub id: Uuid,
    /// Interface name, e.g. `wg0`.
    pub name: String,
    /// Whether the tunnel should be active.
    pub enabled: bool,
    /// Server listen port.
    pub listen_port: u16,
    /// Server private key (base64).
    pub private_key: String,
    /// Server public key (base64) - derived from the private key at runtime.
    pub public_key: Option<String>,
    /// Tunnel address (CIDR).
    pub address: String,
    /// DNS server(s) pushed to peers.
    pub dns: Vec<String>,
    /// Connected peers.
    pub peers: Vec<VpnPeer>,
}

/// A WireGuard peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnPeer {
    pub id: Uuid,
    pub name: Option<String>,
    pub public_key: String,
    pub preshared_key: Option<String>,
    /// Allowed IP ranges for this peer.
    pub allowed_ips: Vec<String>,
    /// Optional endpoint `host:port` for client peers.
    pub endpoint: Option<String>,
    /// Keep-alive interval in seconds (0 = disabled).
    pub persistent_keepalive: u16,
}

// ---------------------------------------------------------------------------
// ACME / TLS certificates
// ---------------------------------------------------------------------------

fn default_acme_directory_url() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".to_string()
}

fn default_acme_renew_interval_hours() -> u64 {
    24
}

fn default_acme_cert_storage_path() -> String {
    "/etc/dayshield/certs".to_string()
}

/// ACME provider to use for certificate issuance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum AcmeProvider {
    #[default]
    LetsEncrypt,
    ZeroSSL,
    Buypass,
    Custom,
}

/// Challenge type used for ACME domain validation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AcmeChallengeType {
    /// HTTP-01: serve a token at `http://<domain>/.well-known/acme-challenge/<token>`.
    /// Requires port 80 to be reachable from the ACME server.
    #[default]
    Http01,
    /// DNS-01: create a TXT record `_acme-challenge.<domain>` with the key-authorization digest.
    Dns01,
}

/// Configuration for automatic TLS certificate management via ACME.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeConfig {
    /// Whether ACME certificate automation is enabled.
    pub enabled: bool,
    /// ACME directory URL.  Defaults to the Let's Encrypt production endpoint.
    #[serde(default = "default_acme_directory_url")]
    pub directory_url: String,
    /// ACME account e-mail address.
    pub email: String,
    /// Domains for which certificates should be issued.
    pub domains: Vec<String>,
    /// Challenge type used to prove domain ownership.
    #[serde(default)]
    pub challenge_type: AcmeChallengeType,
    /// How often (in hours) the renewal scheduler checks for expiring certificates.
    #[serde(default = "default_acme_renew_interval_hours")]
    pub renew_interval_hours: u64,
    /// ACME provider hint (retained for backward compatibility).
    #[serde(default)]
    pub provider: AcmeProvider,
    /// Path where issued certificates and account credentials will be stored.
    #[serde(default = "default_acme_cert_storage_path")]
    pub cert_storage_path: String,
}

// ---------------------------------------------------------------------------
// Validation helpers - ACME
// ---------------------------------------------------------------------------

/// Return `true` if `email` is a syntactically valid e-mail address.
///
/// Accepts any string of the form `<local>@<domain>` where `<local>` is
/// non-empty and `<domain>` passes [`is_valid_domain`].
pub fn validate_email(email: &str) -> bool {
    let mut parts = email.splitn(2, '@');
    let local = parts.next().unwrap_or("");
    let domain = match parts.next() {
        Some(d) => d,
        None => return false,
    };
    !local.is_empty() && is_valid_domain(domain)
}

/// Return `true` if `url` is a syntactically valid ACME directory URL.
///
/// Delegates to [`validate_url`]: accepts any `http://` or `https://` URL
/// with a non-empty host component.
pub fn validate_directory_url(url: &str) -> bool {
    validate_url(url)
}

/// Return `true` for any [`AcmeChallengeType`] value.
///
/// All variants are valid; this helper provides a uniform `validate_*`
/// surface alongside the other ACME validators.
pub fn validate_challenge_type(_t: &AcmeChallengeType) -> bool {
    true
}

/// Return `Ok(())` if `config` is a valid [`AcmeConfig`], or `Err` with a
/// descriptive message describing the first validation failure.
pub fn validate_acme_config(config: &AcmeConfig) -> Result<(), String> {
    if !validate_email(&config.email) {
        return Err(format!(
            "acme email {:?} is not a valid e-mail address",
            config.email
        ));
    }
    if config.domains.is_empty() {
        return Err("acme domains must not be empty".into());
    }
    for domain in &config.domains {
        if !is_valid_domain(domain) {
            return Err(format!(
                "acme domain {:?} is not a valid domain name",
                domain
            ));
        }
    }
    if !validate_directory_url(&config.directory_url) {
        return Err(format!(
            "acme directory_url {:?} is not a valid HTTP/HTTPS URL",
            config.directory_url
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// CrowdSec
// ---------------------------------------------------------------------------

/// Remediation action CrowdSec should trigger.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CrowdsecRemediation {
    Ban,
    Captcha,
    Throttle,
}

/// Policy applied to IPs that CrowdSec has flagged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrowdsecPolicy {
    pub id: Uuid,
    pub description: Option<String>,
    pub remediation: CrowdsecRemediation,
    /// Ban duration in seconds (0 = permanent).
    pub duration_seconds: u64,
    /// Automatically add the IP to the nftables blocklist.
    pub sync_to_nftables: bool,
}

/// Configuration for the CrowdSec bouncer integration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrowdSecConfig {
    /// Whether the CrowdSec integration is active.
    pub enabled: bool,
    /// URL of the CrowdSec Local API, e.g. `http://127.0.0.1:8080`.
    pub lapi_url: String,
    /// Bouncer API key issued by the CrowdSec agent.
    pub api_key: String,
    /// How often (in seconds) to poll the LAPI for new decisions.
    pub update_interval: u64,
    /// Name of the nftables set that receives banned IPs/CIDRs.
    pub ban_alias_name: String,
}

/// A CrowdSec remediation decision received from the Local API.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrowdSecDecision {
    /// Numeric decision ID assigned by the LAPI.
    pub id: i64,
    /// The IP address or CIDR range to act on.
    pub value: String,
    /// Remediation type - `"ban"`, `"captcha"`, etc.
    #[serde(rename = "type")]
    pub type_: String,
    /// Scope of the decision - `"Ip"`, `"Range"`, etc.
    pub scope: String,
    /// Human-readable duration string, e.g. `"4h"`, `"1d"`.
    pub duration: String,
}

// ---------------------------------------------------------------------------
// Validation helpers - CrowdSec
// ---------------------------------------------------------------------------

/// Return `true` if `api_key` is a non-empty string.
///
/// CrowdSec API keys are opaque strings; the only hard requirement is that
/// they must not be empty.
pub fn validate_api_key(api_key: &str) -> bool {
    !api_key.trim().is_empty()
}

/// Return `true` if `value` is either a valid IP address or a valid CIDR.
///
/// Accepts:
/// - Any bare IP parseable as [`std::net::IpAddr`].
/// - Any CIDR string accepted by [`is_valid_cidr`].
pub fn validate_ip_or_cidr(value: &str) -> bool {
    value.parse::<std::net::IpAddr>().is_ok() || is_valid_cidr(value)
}

// ---------------------------------------------------------------------------
// Suricata IPS
// ---------------------------------------------------------------------------

fn default_suricata_mode() -> String {
    "ids".to_string()
}

/// Configuration for the Suricata intrusion-prevention / detection system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuricataConfig {
    /// Whether the Suricata service should be running.
    pub enabled: bool,
    /// Network interfaces Suricata listens on (e.g. `["eth0", "eth1"]`).
    /// Multiple interfaces are supported for monitoring multiple network segments.
    #[serde(default)]
    pub interfaces: Vec<String>,
    /// Operating mode: `"ids"` (alert-only) or `"ips"` (inline drop).
    #[serde(default = "default_suricata_mode")]
    pub mode: String,
    /// CIDRs that define the HOME_NET variable in suricata.yaml.
    pub home_nets: Vec<String>,
    /// CIDRs for EXTERNAL_NET; when empty, Suricata uses `"any"`.
    pub external_nets: Vec<String>,
    /// Rule sources (ET/Open, local files, etc.).
    pub rule_sources: Vec<RuleSource>,
    /// Whether to write EVE JSON alert/flow logs.
    pub eve_log_enabled: bool,
    /// Path for the EVE JSON log file, e.g. `/var/log/suricata/eve.json`.
    pub eve_log_path: String,
    /// Whether to write periodic stats logs.
    pub stats_log_enabled: bool,
    /// Path for the stats log file, e.g. `/var/log/suricata/stats.log`.
    pub stats_log_path: String,
    /// How often (in seconds) Suricata flushes stats to disk.
    /// Defaults to 8 seconds (Suricata upstream default).
    pub stats_interval_seconds: u32,
}

/// A Suricata rule source - either a remote URL (fetched via suricata-update)
/// or a local rule file path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSource {
    /// Human-readable name, e.g. `"emerging-threats"` or `"local"`.
    pub name: String,
    /// Whether this rule source is active.
    pub enabled: bool,
    /// Remote URL for rule sets fetched via suricata-update.
    pub url: Option<String>,
    /// Absolute path to a local `.rules` file.
    pub path: Option<String>,
}

/// Return `Ok(())` if the [`SuricataConfig`] is valid, or `Err` with a
/// descriptive message.
///
/// Rules:
/// - All `home_nets` / `external_nets` entries must be valid CIDRs.
/// - `eve_log_path` must be non-empty when `eve_log_enabled` is `true`.
/// - `stats_log_path` must be non-empty when `stats_log_enabled` is `true`.
pub fn validate_suricata_config(config: &SuricataConfig) -> Result<(), String> {
    for cidr in config.home_nets.iter().chain(config.external_nets.iter()) {
        if !is_valid_cidr(cidr) {
            return Err(format!("invalid CIDR in home_nets/external_nets: {cidr}"));
        }
    }
    if config.eve_log_enabled && config.eve_log_path.is_empty() {
        return Err("eve_log_path must not be empty when eve_log_enabled is true".into());
    }
    if config.stats_log_enabled && config.stats_log_path.is_empty() {
        return Err("stats_log_path must not be empty when stats_log_enabled is true".into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Firewall Aliases
// ---------------------------------------------------------------------------

/// The kind of value stored in a [`FirewallAlias`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AliasType {
    /// One or more individual IP addresses.
    Host,
    /// One or more CIDR network prefixes.
    Network,
    /// One or more port numbers or port ranges (e.g. `"80"`, `"8000:8080"`).
    Port,
    /// Remote list of IPs/CIDRs fetched via HTTP.
    UrlTable,
}

/// A named alias that can be referenced in firewall rules.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FirewallAlias {
    /// Unique alias name (alphanumeric + underscore, 1–63 chars).
    pub name: String,
    /// Optional human-readable description.
    pub description: Option<String>,
    /// What kind of values are stored in this alias.
    pub alias_type: AliasType,
    /// The alias values: IPs, CIDRs, port strings, or URLs, depending on `alias_type`.
    pub values: Vec<String>,
    /// Time-to-live in seconds for URL-table cache refresh.  Only used when
    /// `alias_type` is [`AliasType::UrlTable`].
    pub ttl: Option<u64>,
    /// Whether this alias is currently active.
    pub enabled: bool,
}

// ---------------------------------------------------------------------------
// DNS Overrides
// ---------------------------------------------------------------------------

/// A host-level DNS override: maps a fully-qualified hostname to an A or AAAA
/// record address.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnsHostOverride {
    /// Fully-qualified hostname, e.g. `"myhost.example.com"`.
    pub hostname: String,
    /// IPv4 or IPv6 address to return for this hostname.
    pub address: String,
}

/// A domain-level DNS override: forwards all queries for `domain` to a
/// specific resolver.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnsDomainOverride {
    /// Domain to forward, e.g. `"internal.corp"`.
    pub domain: String,
    /// IP address of the DNS server to forward queries to.
    pub forward_to: String,
}

// ---------------------------------------------------------------------------
// Validation helpers - aliases
// ---------------------------------------------------------------------------

/// Return `true` if `name` is a valid firewall alias name.
///
/// Rules: non-empty, at most 63 characters, only ASCII letters, digits, and
/// underscores, must start with a letter or underscore.
pub fn validate_alias_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 63 {
        return false;
    }
    let mut chars = name.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_alphabetic() && first != '_' {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Return `true` if `url` looks like a syntactically valid HTTP or HTTPS URL.
///
/// Accepts any string that starts with `http://` or `https://` and has a
/// non-empty host component.
pub fn validate_url(url: &str) -> bool {
    let rest = if let Some(r) = url.strip_prefix("https://") {
        r
    } else if let Some(r) = url.strip_prefix("http://") {
        r
    } else {
        return false;
    };
    // The host part is everything before the first `/` or `?` or end of string.
    let host = rest.split(&['/', '?']).next().unwrap_or("");
    !host.is_empty()
}

/// Return `true` if `port_or_range` is a valid port number or port range.
///
/// Accepts:
/// - A single port number `"80"` (1–65535).
/// - A range `"8000:8080"` where both ends are valid ports and start ≤ end.
pub fn validate_port_or_range(port_or_range: &str) -> bool {
    if let Some((start_str, end_str)) = port_or_range.split_once(':') {
        match (start_str.parse::<u16>(), end_str.parse::<u16>()) {
            (Ok(s), Ok(e)) => s > 0 && e > 0 && s <= e,
            _ => false,
        }
    } else {
        match port_or_range.parse::<u16>() {
            Ok(p) => p > 0,
            Err(_) => false,
        }
    }
}

/// Validate all values in a [`FirewallAlias`] against its declared type.
///
/// Returns `Ok(())` when every value is consistent with `alias_type`, or an
/// `Err` describing the first invalid value.
pub fn validate_alias_values(alias: &FirewallAlias) -> Result<(), String> {
    if alias.values.is_empty() {
        return Err(format!("alias {:?} has no values", alias.name));
    }
    for v in &alias.values {
        let ok = match alias.alias_type {
            AliasType::Host => is_valid_ip(v),
            AliasType::Network => is_valid_cidr(v),
            AliasType::Port => validate_port_or_range(v),
            AliasType::UrlTable => validate_url(v),
        };
        if !ok {
            return Err(format!(
                "alias {:?}: value {:?} is not valid for type {:?}",
                alias.name, v, alias.alias_type
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Validation helpers - DNS overrides
// ---------------------------------------------------------------------------

/// Return `true` if `hostname` is a syntactically valid fully-qualified or
/// relative DNS hostname.
///
/// Applies the same rules as [`is_valid_domain`].
pub fn validate_dns_hostname(hostname: &str) -> bool {
    is_valid_domain(hostname)
}

/// Return `true` if `domain` is a syntactically valid DNS domain name.
///
/// Applies the same rules as [`is_valid_domain`].
pub fn validate_dns_domain(domain: &str) -> bool {
    is_valid_domain(domain)
}

// ---------------------------------------------------------------------------
// WireGuard VPN
// ---------------------------------------------------------------------------

/// A WireGuard VPN interface (server-side).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireGuardInterface {
    /// OS-level interface name, e.g. `wg0`.
    pub name: String,
    /// Optional friendly name for this VPN interface shown in the UI.
    pub description: Option<String>,
    /// Interface private key (base64-encoded).
    pub private_key: String,
    /// Interface public key (base64-encoded, derived from private key).
    pub public_key: String,
    /// UDP port the interface listens on.
    pub listen_port: u16,
    /// Tunnel address(es) in CIDR notation, e.g. `["10.0.0.1/24"]`.
    pub addresses: Vec<String>,
    /// Configured peers for this interface.
    pub peers: Vec<WireGuardPeer>,
    /// Whether this interface should be active.
    pub enabled: bool,
}

/// A WireGuard peer connected to a [`WireGuardInterface`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireGuardPeer {
    /// Human-readable name for this peer.
    pub name: String,
    /// Peer public key (base64-encoded).
    pub public_key: String,
    /// Optional pre-shared key for additional symmetric encryption.
    pub preshared_key: Option<String>,
    /// IP ranges that will be routed through this peer tunnel.
    pub allowed_ips: Vec<String>,
    /// Optional remote endpoint in `host:port` format.
    pub endpoint: Option<String>,
    /// Keep-alive interval in seconds; `None` disables persistent keep-alive.
    pub persistent_keepalive: Option<u16>,
}

// ---------------------------------------------------------------------------
// Validation helpers - WireGuard
// ---------------------------------------------------------------------------

/// Return `true` if `name` is a valid WireGuard interface name.
///
/// WireGuard interface names follow the same rules as Linux interface names
/// (see [`is_valid_interface_name`]) and conventionally start with `wg`.
pub fn validate_wg_interface_name(name: &str) -> bool {
    is_valid_interface_name(name)
}

/// Return `true` if `key` is a syntactically valid WireGuard base64 key.
///
/// A WireGuard key is a 32-byte value encoded as base64, producing exactly
/// 44 characters (including the trailing `=` padding).
pub fn validate_wg_key(key: &str) -> bool {
    if key.len() != 44 {
        return false;
    }
    // Standard base64 alphabet plus '=' padding only at the end.
    let body = &key[..43];
    let last = &key[43..44];
    body.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/')
        && last == "="
}

/// Return `true` if `port` is a valid non-zero port number (1–65535).
pub fn validate_port(port: u16) -> bool {
    port > 0
}

/// Return `true` if `cidr` is a valid IPv4 or IPv6 CIDR string.
///
/// Delegates to [`is_valid_cidr`].
pub fn validate_cidr(cidr: &str) -> bool {
    is_valid_cidr(cidr)
}

/// Return `true` if `endpoint` is a syntactically valid `host:port` pair.
///
/// Accepts:
/// - IPv4 address with port: `"1.2.3.4:51820"`
/// - Hostname with port: `"vpn.example.com:51820"`
/// - IPv6 address with port (bracketed): `"[::1]:51820"`
pub fn validate_endpoint(endpoint: &str) -> bool {
    // IPv6 bracketed form: "[addr]:port"
    if endpoint.starts_with('[') {
        if let Some(bracket_end) = endpoint.find(']') {
            let addr = &endpoint[1..bracket_end];
            let rest = &endpoint[bracket_end + 1..];
            if let Some(port_str) = rest.strip_prefix(':') {
                if let Ok(port) = port_str.parse::<u16>() {
                    return port > 0 && addr.parse::<std::net::Ipv6Addr>().is_ok();
                }
            }
        }
        return false;
    }

    // host:port - split on the LAST colon to allow IPv4 addresses.
    if let Some(colon) = endpoint.rfind(':') {
        let host = &endpoint[..colon];
        let port_str = &endpoint[colon + 1..];
        if let Ok(port) = port_str.parse::<u16>() {
            if port == 0 || host.is_empty() {
                return false;
            }
            // Accept bare IP addresses or valid hostnames.
            return host.parse::<std::net::IpAddr>().is_ok() || is_valid_domain(host);
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Notifications
// ---------------------------------------------------------------------------

/// Category of a notification event; used to filter which alerts are sent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum NotifyCategory {
    Suricata,
    CrowdSec,
    Acme,
    System,
}

fn default_notify_rate_limit() -> u32 {
    10
}

fn default_notify_categories() -> Vec<NotifyCategory> {
    vec![
        NotifyCategory::Suricata,
        NotifyCategory::CrowdSec,
        NotifyCategory::Acme,
        NotifyCategory::System,
    ]
}

/// Configuration for the email notification subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotifyConfig {
    /// Whether email notifications are enabled.
    pub enabled: bool,
    /// SMTP server hostname or IP address.
    pub smtp_server: String,
    /// SMTP server port (typically 587 for STARTTLS or 465 for SMTPS).
    pub smtp_port: u16,
    /// SMTP authentication username.
    pub smtp_username: String,
    /// SMTP authentication password.
    pub smtp_password: String,
    /// Envelope / header `From` address.
    pub from_address: String,
    /// List of recipient e-mail addresses.
    pub to_addresses: Vec<String>,
    /// Which alert categories should trigger notifications.
    #[serde(default = "default_notify_categories")]
    pub categories: Vec<NotifyCategory>,
    /// Maximum number of emails sent per minute (token-bucket rate limit).
    #[serde(default = "default_notify_rate_limit")]
    pub rate_limit_per_minute: u32,
    /// When true, buffer events for 5 minutes and send one combined digest.
    #[serde(default)]
    pub digest_mode: bool,
}

impl Default for NotifyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            smtp_server: String::new(),
            smtp_port: 587,
            smtp_username: String::new(),
            smtp_password: String::new(),
            from_address: String::new(),
            to_addresses: vec![],
            categories: default_notify_categories(),
            rate_limit_per_minute: default_notify_rate_limit(),
            digest_mode: false,
        }
    }
}

/// Validate a [`NotifyConfig`].
///
/// Returns `Ok(())` when all fields are consistent, or `Err` with the first
/// problem found.
pub fn validate_notify_config(cfg: &NotifyConfig) -> Result<(), String> {
    if !cfg.enabled {
        return Ok(());
    }
    if cfg.smtp_server.trim().is_empty() {
        return Err("notify smtp_server must not be empty".into());
    }
    if cfg.smtp_port == 0 {
        return Err("notify smtp_port must be non-zero".into());
    }
    if cfg.from_address.trim().is_empty() {
        return Err("notify from_address must not be empty".into());
    }
    if !validate_email(&cfg.from_address) {
        return Err(format!(
            "notify from_address {:?} is not a valid e-mail address",
            cfg.from_address
        ));
    }
    if cfg.to_addresses.is_empty() {
        return Err("notify to_addresses must contain at least one address".into());
    }
    for addr in &cfg.to_addresses {
        if !validate_email(addr) {
            return Err(format!(
                "notify to_addresses contains invalid address {:?}",
                addr
            ));
        }
    }
    if cfg.rate_limit_per_minute == 0 {
        return Err("notify rate_limit_per_minute must be greater than 0".into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Top-level system config
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// System settings
// ---------------------------------------------------------------------------

/// Host-level system settings (hostname, timezone, NTP, SSH, web UI port).
///
/// Stored as a separate `system_settings` key inside the root JSON file so
/// they can be read/written independently without touching the rest of the
/// config.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemSettings {
    /// Machine hostname (e.g. `"dayshield-fw"`).
    pub hostname: String,
    /// IANA timezone identifier (e.g. `"Europe/London"`).
    pub timezone: String,
    /// NTP server addresses.
    #[serde(default = "default_ntp_servers")]
    pub ntp_servers: Vec<String>,
    /// Additional DNS resolver addresses for the host itself (not for client devices).
    #[serde(default)]
    pub dns_servers: Vec<String>,
    /// Whether the SSH daemon is enabled.
    #[serde(default = "default_ssh_enabled")]
    pub ssh_enabled: bool,
    /// TCP port for the SSH daemon.
    #[serde(default = "default_ssh_port")]
    pub ssh_port: u16,
    /// TCP port for the DayShield web UI / REST API.
    #[serde(default = "default_web_port")]
    pub web_port: u16,
    /// ACME domain whose certificate should be used for the management UI.
    pub management_tls_acme_domain: Option<String>,
}

fn default_ntp_servers() -> Vec<String> {
    vec!["0.pool.ntp.org".into(), "1.pool.ntp.org".into()]
}
fn default_ssh_enabled() -> bool { true }
fn default_ssh_port()    -> u16  { 22 }
fn default_web_port()    -> u16  { 443 }

impl Default for SystemSettings {
    fn default() -> Self {
        Self {
            hostname:    "dayshield".into(),
            timezone:    "UTC".into(),
            ntp_servers: default_ntp_servers(),
            dns_servers: vec![],
            ssh_enabled: default_ssh_enabled(),
            ssh_port:    default_ssh_port(),
            web_port:    default_web_port(),
            management_tls_acme_domain: None,
        }
    }
}

// ---------------------------------------------------------------------------
// NTP
// ---------------------------------------------------------------------------

/// Configuration for the NTP client/server subsystem.
///
/// When `serve_clients` is `false`, DayShield configures `systemd-timesyncd`
/// to synchronise the host clock against `upstream_servers` only.
///
/// When `serve_clients` is `true`, DayShield installs and configures `chrony`
/// which both synchronises the host clock and serves NTP to LAN clients via
/// the interfaces listed in `listen_interfaces`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NtpConfig {
    /// Whether the NTP subsystem is enabled.
    pub enabled: bool,
    /// IPv4 addresses or hostnames of upstream NTP servers.
    ///
    /// At least one entry is required when `enabled` is `true`.
    /// IPv6 addresses are rejected by the validator.
    pub upstream_servers: Vec<String>,
    /// Whether to also serve NTP time to LAN clients.
    pub serve_clients: bool,
    /// Network interface names on which chrony should listen when
    /// `serve_clients` is `true`.
    pub listen_interfaces: Vec<String>,
}

impl Default for NtpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            upstream_servers: vec!["0.pool.ntp.org".into(), "1.pool.ntp.org".into()],
            serve_clients: false,
            listen_interfaces: vec![],
        }
    }
}

// ---------------------------------------------------------------------------
// Validation helpers - NTP
// ---------------------------------------------------------------------------

/// Return `true` if `server` is a valid IPv4 address or a valid hostname.
///
/// Rejects bare IPv6 addresses (square-bracket notation and plain `::` form).
pub fn validate_ntp_server(server: &str) -> bool {
    // Reject explicit IPv6 (bracket form used in URIs).
    if server.starts_with('[') {
        return false;
    }
    // Reject bare IPv6 addresses.
    if server.parse::<std::net::Ipv6Addr>().is_ok() {
        return false;
    }
    // Accept valid IPv4 addresses.
    if server.parse::<std::net::Ipv4Addr>().is_ok() {
        return true;
    }
    // Accept valid hostnames / FQDNs.
    is_valid_domain(server)
}

/// Return `Ok(())` if `config` is a valid [`NtpConfig`], or `Err` with a
/// descriptive message describing the first validation failure found.
pub fn validate_ntp_config(config: &NtpConfig) -> Result<(), String> {
    if !config.enabled {
        return Ok(());
    }
    if config.upstream_servers.is_empty() {
        return Err("ntp upstream_servers must contain at least one entry when enabled".into());
    }
    for server in &config.upstream_servers {
        if !validate_ntp_server(server) {
            return Err(format!(
                "ntp upstream_servers contains invalid entry {:?} \
                 (must be an IPv4 address or hostname, not IPv6)",
                server
            ));
        }
    }
    if config.serve_clients && config.listen_interfaces.is_empty() {
        return Err(
            "ntp listen_interfaces must contain at least one interface when serve_clients is true"
                .into(),
        );
    }
    for iface in &config.listen_interfaces {
        if !is_valid_interface_name(iface) {
            return Err(format!(
                "ntp listen_interfaces contains invalid interface name {:?}",
                iface
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Cloudflared
// ---------------------------------------------------------------------------

fn default_cloudflared_metrics_address() -> String {
    "127.0.0.1:60123".to_string()
}

fn default_cloudflared_log_level() -> String {
    "info".to_string()
}

/// Single Cloudflare Tunnel ingress mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudflaredIngressRule {
    pub hostname: String,
    pub service: String,
}

/// Configuration for the cloudflared outbound tunnel integration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudflaredConfig {
    pub enabled: bool,
    pub tunnel_name: String,
    pub tunnel_token: String,
    #[serde(default = "default_cloudflared_metrics_address")]
    pub metrics_address: String,
    #[serde(default = "default_cloudflared_log_level")]
    pub log_level: String,
    #[serde(default)]
    pub ingress: Vec<CloudflaredIngressRule>,
}

impl Default for CloudflaredConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            tunnel_name: String::new(),
            tunnel_token: String::new(),
            metrics_address: default_cloudflared_metrics_address(),
            log_level: default_cloudflared_log_level(),
            ingress: vec![],
        }
    }
}

pub fn validate_cloudflared_config(config: &CloudflaredConfig) -> Result<(), String> {
    if !config.enabled {
        return Ok(());
    }

    if config.tunnel_name.trim().is_empty() {
        return Err("cloudflared tunnel_name must not be empty".into());
    }

    if config.tunnel_token.trim().is_empty() {
        return Err("cloudflared tunnel_token must not be empty when enabled".into());
    }

    if config.ingress.is_empty() {
        return Err("cloudflared ingress must contain at least one route when enabled".into());
    }

    for rule in &config.ingress {
        if !is_valid_domain(&rule.hostname) {
            return Err(format!(
                "cloudflared ingress hostname {:?} is not a valid domain",
                rule.hostname
            ));
        }
        if !validate_url(&rule.service) {
            return Err(format!(
                "cloudflared ingress service {:?} is not a valid HTTP/HTTPS URL",
                rule.service
            ));
        }
    }

    Ok(())
}

/// AI threat-engine policy and blocking controls.
///
/// The engine runs entirely in-process using a self-reliant local logistic
/// regression model that is continually retrained from operator feedback.
/// No third-party or remote inference services are used.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AiEngineConfig {
    /// Enables AI threat handling.
    pub enabled: bool,
    /// Allows AI-triggered automatic blocking.
    pub automatic_blocking: bool,
    /// Risk score threshold that triggers threat events and blocking.
    pub risk_score_block_threshold: f64,
    /// Window used for escalation decisions.
    pub escalation_window_seconds: u64,
    /// Base temporary block duration in seconds (`0` = permanent).
    pub block_duration_seconds: u64,
    /// If true, feedback-driven training updates are applied to the local model.
    pub training_enabled: bool,
    /// Learning rate for the local model update algorithm.
    pub model_learning_rate: f64,
}

impl Default for AiEngineConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            automatic_blocking: false,
            risk_score_block_threshold: 0.9,
            escalation_window_seconds: 300,
            block_duration_seconds: 300,
            training_enabled: true,
            model_learning_rate: 0.25,
        }
    }
}

pub fn validate_ai_engine_config(config: &AiEngineConfig) -> Result<(), String> {
    if config.automatic_blocking && !config.enabled {
        return Err("automatic_blocking cannot be enabled when ai_engine is disabled".to_string());
    }
    if !(0.0..=1.0).contains(&config.risk_score_block_threshold) {
        return Err("risk_score_block_threshold must be between 0.0 and 1.0".to_string());
    }
    if config.escalation_window_seconds == 0 {
        return Err("escalation_window_seconds must be greater than 0".to_string());
    }
    if config.model_learning_rate <= 0.0 {
        return Err("model_learning_rate must be greater than 0".to_string());
    }
    Ok(())
}

/// Administrator account security policy.
///
/// Controls session lifetime, login lockout behaviour, and password complexity
/// requirements.  All fields have sensible defaults; an omitted field in the
/// stored JSON falls back to the `Default` implementation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AdminSecuritySettings {
    /// How long an issued JWT remains valid, in minutes.  Default: 480 (8 h).
    pub session_timeout_minutes: u32,
    /// Maximum consecutive failed login attempts before the account is
    /// temporarily locked.  Set to `0` to disable lockout.  Default: 5.
    pub max_login_attempts: u32,
    /// How long the account stays locked after exceeding
    /// `max_login_attempts`, in minutes.  Default: 15.
    pub lockout_duration_minutes: u32,
    /// Minimum number of characters required for a new password.  Default: 8.
    pub min_password_length: u8,
    /// Require at least one uppercase letter in new passwords.  Default: false.
    pub require_uppercase: bool,
    /// Require at least one numeric digit in new passwords.  Default: false.
    pub require_number: bool,
    /// Require at least one special character in new passwords.  Default: false.
    pub require_special: bool,
}

impl Default for AdminSecuritySettings {
    fn default() -> Self {
        Self {
            session_timeout_minutes: 480,
            max_login_attempts: 5,
            lockout_duration_minutes: 15,
            min_password_length: 8,
            require_uppercase: false,
            require_number: false,
            require_special: false,
        }
    }
}

/// Root configuration object that is persisted to disk and loaded on startup.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SystemConfig {
    pub hostname: String,
    pub domain: Option<String>,
    pub interfaces: Vec<Interface>,
    pub firewall_rules: Vec<FirewallRule>,
    /// Global firewall defaults and management/stateful protections.
    #[serde(default)]
    pub firewall_settings: Option<FirewallSettings>,
    /// NAT configuration (outbound mode, WAN interfaces, and user rules).
    #[serde(default)]
    pub nat: Option<NatConfig>,
    pub dns: Option<DnsConfig>,
    pub dhcp: Option<DhcpConfig>,
    pub vpn_tunnels: Vec<VpnTunnel>,
    /// WireGuard VPN interfaces managed by DayShield.
    #[serde(default)]
    pub wireguard_interfaces: Vec<WireGuardInterface>,
    pub acme: Option<AcmeConfig>,
    pub crowdsec_policies: Vec<CrowdsecPolicy>,
    pub suricata: Option<SuricataConfig>,
    /// Named firewall aliases (IP sets, network sets, port sets, URL tables).
    #[serde(default)]
    pub firewall_aliases: Vec<FirewallAlias>,
    /// Per-hostname DNS overrides (A / AAAA records).
    #[serde(default)]
    pub dns_host_overrides: Vec<DnsHostOverride>,
    /// Per-domain DNS forwarding overrides.
    #[serde(default)]
    pub dns_domain_overrides: Vec<DnsDomainOverride>,
    /// CrowdSec bouncer integration configuration.
    #[serde(default)]
    pub crowdsec: Option<CrowdSecConfig>,
    /// Email notification configuration.
    #[serde(default)]
    pub notify: Option<NotifyConfig>,
    /// Host-level system settings (hostname, timezone, NTP, SSH).
    #[serde(default)]
    pub system_settings: Option<SystemSettings>,
    /// NTP client/server configuration.
    #[serde(default)]
    pub ntp: Option<NtpConfig>,
    /// Cloudflare Tunnel configuration.
    #[serde(default)]
    pub cloudflared: Option<CloudflaredConfig>,
    /// AI threat-engine policy and automatic blocking settings.
    #[serde(default)]
    pub ai_engine: Option<AiEngineConfig>,
    /// Named upstream gateways.
    #[serde(default)]
    pub gateways: Vec<Gateway>,
    /// Logging configuration (format, level, per-module overrides, syslog).
    #[serde(default)]
    pub logging: Option<crate::logging::LoggingConfig>,
    /// Administrator account security policy.
    #[serde(default)]
    pub admin_security: Option<AdminSecuritySettings>,
    /// DNS-over-TLS (DoT) listener configuration.
    #[serde(default)]
    pub dot: Option<DotConfig>,
}
