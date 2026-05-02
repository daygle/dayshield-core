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
    /// Whether the interface should be brought up.
    pub enabled: bool,
    /// Obtain an IPv4 address via DHCP.
    pub dhcp4: bool,
    /// Obtain an IPv6 address via DHCP (reserved for future use).
    pub dhcp6: bool,
    /// VLAN tag ID (802.1Q), if this is a VLAN sub-interface.
    pub vlan: Option<u16>,
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
    /// Optional interface filter (ingress).
    pub interface: Option<String>,
    /// Whether to emit a log statement before applying the action.
    pub log: bool,
}

// ---------------------------------------------------------------------------
// NAT
// ---------------------------------------------------------------------------

/// Type of NAT translation to perform.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NatType {
    Masquerade,
    Snat,
    Dnat,
}

/// A NAT rule to be compiled into the nftables `nat` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatRule {
    pub id: Uuid,
    pub description: Option<String>,
    pub nat_type: NatType,
    /// Source CIDR that should be translated.
    pub source: Option<String>,
    /// Destination CIDR that should be translated.
    pub destination: Option<String>,
    /// Translated-to address (for SNAT/DNAT).
    pub translated_address: Option<String>,
    /// Translated-to port (for DNAT).
    pub translated_port: Option<u16>,
    /// Outbound interface for masquerade rules.
    pub out_interface: Option<String>,
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
}

/// A static DNS mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsLocalRecord {
    pub name: String,
    pub record_type: String,
    pub value: String,
}

// ---------------------------------------------------------------------------
// DHCP (Kea / dnsmasq)
// ---------------------------------------------------------------------------

/// Configuration for the DHCP server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpConfig {
    /// Whether the DHCP service should be running.
    pub enabled: bool,
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
    /// Server public key (base64) — derived from the private key at runtime.
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

/// ACME provider to use for certificate issuance.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AcmeProvider {
    LetsEncrypt,
    ZeroSSL,
    Buypass,
    Custom,
}

/// Configuration for automatic TLS certificate management via ACME.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeConfig {
    pub enabled: bool,
    pub provider: AcmeProvider,
    /// ACME account e-mail address.
    pub email: String,
    /// Directory URL override (used when provider is `Custom`).
    pub directory_url: Option<String>,
    /// Domains for which certificates should be issued.
    pub domains: Vec<String>,
    /// Path where issued certificates will be stored.
    pub cert_storage_path: String,
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

// ---------------------------------------------------------------------------
// Suricata IPS
// ---------------------------------------------------------------------------

/// Configuration for the Suricata intrusion-prevention / detection system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuricataConfig {
    /// Whether the Suricata service should be running.
    pub enabled: bool,
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

/// A Suricata rule source — either a remote URL (fetched via suricata-update)
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
// Top-level system config
// ---------------------------------------------------------------------------

/// Root configuration object that is persisted to disk and loaded on startup.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SystemConfig {
    pub hostname: String,
    pub domain: Option<String>,
    pub interfaces: Vec<Interface>,
    pub firewall_rules: Vec<FirewallRule>,
    pub nat_rules: Vec<NatRule>,
    pub dns: Option<DnsConfig>,
    pub dhcp: Option<DhcpConfig>,
    pub vpn_tunnels: Vec<VpnTunnel>,
    pub acme: Option<AcmeConfig>,
    pub crowdsec_policies: Vec<CrowdsecPolicy>,
    pub suricata: Option<SuricataConfig>,
}
