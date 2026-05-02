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
    /// Unique identifier.
    pub id: Uuid,
    /// OS-level interface name, e.g. `eth0` or `wg0`.
    pub name: String,
    /// Optional human-readable description.
    pub description: Option<String>,
    /// Interface type.
    pub if_type: InterfaceType,
    /// Whether the interface should be brought up.
    pub enabled: bool,
    /// IPv4 address in dotted-decimal notation.
    pub ipv4_address: Option<String>,
    /// IPv4 prefix length (CIDR).
    pub ipv4_prefix_len: Option<u8>,
    /// IPv6 address.
    pub ipv6_address: Option<String>,
    /// IPv6 prefix length (CIDR).
    pub ipv6_prefix_len: Option<u8>,
    /// MTU in bytes (defaults to 1500 when `None`).
    pub mtu: Option<u16>,
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
}
