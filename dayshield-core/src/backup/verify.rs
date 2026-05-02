//! Backup integrity verification via SHA-256.
//!
//! The SHA-256 digest stored in [`BackupMetadata::sha256`] covers the
//! concatenation of all config-entry bytes written to the archive in the
//! canonical subsystem order.  This design lets the digest be computed and
//! embedded in `metadata.json` without a second pass over the archive.

use sha2::{Digest, Sha256};

/// Compute the SHA-256 hex digest of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

/// Return `true` if `sha256_hex(data)` equals `expected` (case-insensitive).
pub fn verify_sha256(data: &[u8], expected: &str) -> bool {
    sha256_hex(data).eq_ignore_ascii_case(expected)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_bytes_known_hash() {
        // SHA-256("") is a well-known constant.
        let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(sha256_hex(b""), expected);
    }

    #[test]
    fn verify_sha256_accepts_correct() {
        let data = b"hello world";
        let hex = sha256_hex(data);
        assert!(verify_sha256(data, &hex));
    }

    #[test]
    fn verify_sha256_rejects_wrong() {
        assert!(!verify_sha256(b"hello world", "deadbeef"));
    }

    #[test]
    fn verify_sha256_case_insensitive() {
        let data = b"test";
        let lower = sha256_hex(data);
        let upper = lower.to_uppercase();
        assert!(verify_sha256(data, &upper));
    }
}
