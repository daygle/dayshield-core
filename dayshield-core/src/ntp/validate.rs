//! NTP validation helpers.
//!
//! All rules are delegated to [`crate::config::models::validate_ntp_config`]
//! which is the single source of truth.  This module re-exports it and
//! exposes the lower-level [`validate_ntp_server`] helper for unit tests.

pub use crate::config::models::{validate_ntp_config, validate_ntp_server};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntp::model::NtpConfig;

    #[test]
    fn valid_ipv4_server() {
        assert!(validate_ntp_server("192.168.1.1"));
        assert!(validate_ntp_server("8.8.8.8"));
    }

    #[test]
    fn valid_hostname_server() {
        assert!(validate_ntp_server("pool.ntp.org"));
        assert!(validate_ntp_server("0.pool.ntp.org"));
        assert!(validate_ntp_server("time.cloudflare.com"));
    }

    #[test]
    fn ipv6_server_rejected() {
        assert!(!validate_ntp_server("2001:db8::1"));
        assert!(!validate_ntp_server("::1"));
        assert!(!validate_ntp_server("[2001:db8::1]"));
    }

    #[test]
    fn disabled_config_always_valid() {
        let cfg = NtpConfig {
            enabled: false,
            upstream_servers: vec![],
            serve_clients: false,
            listen_interfaces: vec![],
        };
        assert!(validate_ntp_config(&cfg).is_ok());
    }

    #[test]
    fn enabled_with_no_servers_invalid() {
        let cfg = NtpConfig {
            enabled: true,
            upstream_servers: vec![],
            serve_clients: false,
            listen_interfaces: vec![],
        };
        assert!(validate_ntp_config(&cfg).is_err());
    }

    #[test]
    fn serve_clients_without_interfaces_invalid() {
        let cfg = NtpConfig {
            enabled: true,
            upstream_servers: vec!["0.pool.ntp.org".into()],
            serve_clients: true,
            listen_interfaces: vec![],
        };
        assert!(validate_ntp_config(&cfg).is_err());
    }

    #[test]
    fn valid_enabled_serve_clients() {
        let cfg = NtpConfig {
            enabled: true,
            upstream_servers: vec!["0.pool.ntp.org".into()],
            serve_clients: true,
            listen_interfaces: vec!["eth0".into()],
        };
        assert!(validate_ntp_config(&cfg).is_ok());
    }

    #[test]
    fn ipv6_server_in_config_invalid() {
        let cfg = NtpConfig {
            enabled: true,
            upstream_servers: vec!["::1".into()],
            serve_clients: false,
            listen_interfaces: vec![],
        };
        assert!(validate_ntp_config(&cfg).is_err());
    }
}
