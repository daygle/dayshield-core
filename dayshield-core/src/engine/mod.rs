//! Engine module — sub-modules that generate and apply system configurations.
//!
//! Each sub-module corresponds to one external system or service managed by
//! DayShield Core:
//!
//! | Module        | Service                |
//! |---------------|------------------------|
//! | `nftables`    | Kernel packet filter   |
//! | `suricata`    | IPS / IDS              |
//! | `dns`         | Unbound resolver       |
//! | `dhcp`        | Kea / dnsmasq server   |
//! | `vpn`         | WireGuard tunnels      |
//! | `acme`        | ACME / TLS cert mgmt   |
//! | `crowdsec`    | Threat intelligence    |
//! | `interfaces`  | Kernel network ifaces  |

pub mod acme;
pub mod crowdsec;
pub mod dhcp;
pub mod dns;
pub mod gateway;
pub mod interfaces;
pub mod nftables;
pub mod suricata;
pub mod vpn;
