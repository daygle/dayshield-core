//! Utility helpers shared across the crate.
//!
//! TODO: add CIDR / IP address parsing and validation helpers.
//! TODO: add process management helpers (spawn, signal, wait).
//! TODO: add file-system helpers (atomic write, backup, checksum).
//! TODO: add shell-quoting utilities for safe argument construction.

/// Validate that a string is a syntactically valid IPv4 CIDR block.
///
/// Returns `true` if the string is in the form `a.b.c.d/n` where
/// `a`–`d` are valid octets and `n` is in `0..=32`.
///
/// TODO: replace with a proper CIDR library that also validates IPv6.
pub fn is_valid_ipv4_cidr(s: &str) -> bool {
    let parts: Vec<&str> = s.splitn(2, '/').collect();
    if parts.len() != 2 {
        return false;
    }
    let ip_parts: Vec<&str> = parts[0].split('.').collect();
    if ip_parts.len() != 4 {
        return false;
    }
    let octets_valid = ip_parts
        .iter()
        .all(|p| p.parse::<u8>().is_ok());
    let prefix_valid = parts[1]
        .parse::<u8>()
        .map(|n| n <= 32)
        .unwrap_or(false);
    octets_valid && prefix_valid
}

/// Validate that a string is a syntactically valid MAC address.
///
/// Accepts the colon-separated form `aa:bb:cc:dd:ee:ff` (case-insensitive).
///
/// TODO: also accept hyphen-separated and Cisco dot-separated forms.
pub fn is_valid_mac(s: &str) -> bool {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return false;
    }
    parts.iter().all(|p| p.len() == 2 && u8::from_str_radix(p, 16).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_cidr() {
        assert!(is_valid_ipv4_cidr("192.168.1.0/24"));
        assert!(is_valid_ipv4_cidr("10.0.0.0/8"));
        assert!(is_valid_ipv4_cidr("0.0.0.0/0"));
    }

    #[test]
    fn test_invalid_cidr() {
        assert!(!is_valid_ipv4_cidr("192.168.1.0"));
        assert!(!is_valid_ipv4_cidr("192.168.1.0/33"));
        assert!(!is_valid_ipv4_cidr("not-an-ip/24"));
    }

    #[test]
    fn test_valid_mac() {
        assert!(is_valid_mac("aa:bb:cc:dd:ee:ff"));
        assert!(is_valid_mac("00:1A:2B:3C:4D:5E"));
    }

    #[test]
    fn test_invalid_mac() {
        assert!(!is_valid_mac("aa:bb:cc:dd:ee"));
        assert!(!is_valid_mac("aa:bb:cc:dd:ee:zz"));
        assert!(!is_valid_mac("aabbccddeeff"));
    }
}
