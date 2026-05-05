//! Utility helpers shared across the crate.
//!
//! Covers four areas:
//!
//! - **CIDR / IP address** – parsing and validation helpers for IPv4, IPv6,
//!   and MAC addresses (see the top-level functions and [`cidr`] module).
//! - **Process management** – spawn, signal, and wait helpers (see [`process`]).
//! - **File-system helpers** – atomic write, backup, and checksum (see [`fs`]).
//! - **Shell-quoting** – safe argument construction (see [`shell`]).

// ── CIDR / IP address helpers ────────────────────────────────────────────────

/// Validate that a string is a syntactically valid IPv4 CIDR block.
///
/// Returns `true` if the string is in the form `a.b.c.d/n` where
/// `a`–`d` are valid octets (parseable by [`std::net::Ipv4Addr`]) and
/// `n` is in `0..=32`.
pub fn is_valid_ipv4_cidr(s: &str) -> bool {
    let mut parts = s.splitn(2, '/');
    let addr_str = match parts.next() {
        Some(a) => a,
        None => return false,
    };
    let prefix_str = match parts.next() {
        Some(p) => p,
        None => return false,
    };
    addr_str.parse::<std::net::Ipv4Addr>().is_ok()
        && prefix_str.parse::<u8>().map(|n| n <= 32).unwrap_or(false)
}

/// Validate that a string is a syntactically valid IPv6 CIDR block.
///
/// Returns `true` if the string is in the form `addr/n` where `addr` is a
/// valid IPv6 address (parseable by [`std::net::Ipv6Addr`]) and `n` is in
/// `0..=128`.
pub fn is_valid_ipv6_cidr(s: &str) -> bool {
    let mut parts = s.splitn(2, '/');
    let addr_str = match parts.next() {
        Some(a) => a,
        None => return false,
    };
    let prefix_str = match parts.next() {
        Some(p) => p,
        None => return false,
    };
    addr_str.parse::<std::net::Ipv6Addr>().is_ok()
        && prefix_str.parse::<u8>().map(|n| n <= 128).unwrap_or(false)
}

/// Validate an IPv4 **or** IPv6 CIDR block.
///
/// Returns `true` for any string accepted by [`is_valid_ipv4_cidr`] or
/// [`is_valid_ipv6_cidr`].
pub fn is_valid_cidr(s: &str) -> bool {
    is_valid_ipv4_cidr(s) || is_valid_ipv6_cidr(s)
}

/// Return `true` if `addr` is a valid IPv4 or IPv6 address (no prefix length).
///
/// Delegates to [`std::net::IpAddr`]'s `FromStr` implementation.
pub fn is_valid_ip(addr: &str) -> bool {
    addr.parse::<std::net::IpAddr>().is_ok()
}

/// Validate that a string is a syntactically valid MAC address.
///
/// Accepted formats (all case-insensitive):
/// - Colon-separated: `aa:bb:cc:dd:ee:ff`
/// - Hyphen-separated: `aa-bb-cc-dd-ee-ff`
/// - Cisco dot-separated groups of four: `aabb.ccdd.eeff`
pub fn is_valid_mac(s: &str) -> bool {
    if s.contains('.') {
        // Cisco dot notation: three groups of four hex chars separated by dots.
        let groups: Vec<&str> = s.split('.').collect();
        return groups.len() == 3
            && groups.iter().all(|g| {
                g.len() == 4 && g.chars().all(|c| c.is_ascii_hexdigit())
            });
    }
    let sep = if s.contains(':') {
        ':'
    } else if s.contains('-') {
        '-'
    } else {
        return false;
    };
    let parts: Vec<&str> = s.split(sep).collect();
    parts.len() == 6
        && parts.iter().all(|p| {
            p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit())
        })
}

// ── Shell-quoting utilities ──────────────────────────────────────────────────

/// Utilities for constructing shell command arguments safely.
///
/// These functions produce strings that are safe to pass to a POSIX shell
/// without risk of word-splitting, glob expansion, or injection.
pub mod shell {
    /// Quote a single argument for safe use in a POSIX shell command.
    ///
    /// The argument is wrapped in single quotes; any embedded single-quote
    /// characters are replaced with the sequence `'\''` (end quote, literal
    /// single-quote, re-open quote), which is the standard POSIX idiom.
    ///
    /// # Examples
    ///
    /// ```
    /// use dayshield_core::utils::shell::quote;
    /// assert_eq!(quote("hello world"), "'hello world'");
    /// assert_eq!(quote("it's"), "'it'\\''s'");
    /// assert_eq!(quote(""), "''");
    /// ```
    pub fn quote(arg: &str) -> String {
        // Fast path: if the argument contains no characters that need quoting,
        // wrap it in single quotes as a single pass.
        let escaped = arg.replace('\'', "'\\''");
        format!("'{}'", escaped)
    }

    /// Quote each argument in `args` and return the results as a `Vec<String>`.
    ///
    /// Equivalent to calling [`quote`] on every element.
    pub fn quote_args(args: &[&str]) -> Vec<String> {
        args.iter().map(|a| quote(a)).collect()
    }

    /// Join quoted arguments into a single space-separated string suitable
    /// for passing to a shell.
    ///
    /// # Examples
    ///
    /// ```
    /// use dayshield_core::utils::shell::join_quoted;
    /// assert_eq!(join_quoted(&["echo", "hello world"]), "'echo' 'hello world'");
    /// ```
    pub fn join_quoted(args: &[&str]) -> String {
        quote_args(args).join(" ")
    }
}

// ── File-system helpers ──────────────────────────────────────────────────────

/// File-system utility helpers.
///
/// These helpers complement the storage layer's own atomic-write logic and
/// provide convenient, reusable building blocks for other subsystems.
pub mod fs {
    use std::path::{Path, PathBuf};

    use anyhow::{Context, Result};
    use sha2::{Digest, Sha256};

    /// Write `contents` to `path` atomically.
    ///
    /// The data is first written to a sibling temp file (`<path>.tmp`) and
    /// then renamed into place.  On POSIX systems the rename is atomic, so
    /// concurrent readers never see a partially-written file.
    ///
    /// The parent directory is created if it does not exist.
    pub fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory {}", parent.display()))?;
        }
        let tmp = path.with_extension(format!(
            "{}.tmp",
            path.extension().and_then(|e| e.to_str()).unwrap_or("")
        ));
        std::fs::write(&tmp, contents)
            .with_context(|| format!("Failed to write temp file {}", tmp.display()))?;
        std::fs::rename(&tmp, path).with_context(|| {
            format!("Failed to rename {} to {}", tmp.display(), path.display())
        })?;
        Ok(())
    }

    /// Create a backup copy of `path` at `<path>.bak`.
    ///
    /// Returns the path of the backup file on success.  If `path` does not
    /// exist the function returns `Ok(<path>.bak)` without creating any file.
    pub fn backup_file(path: &Path) -> Result<PathBuf> {
        let bak = PathBuf::from(format!("{}.bak", path.display()));
        if path.exists() {
            std::fs::copy(path, &bak)
                .with_context(|| format!("Failed to back up {} to {}", path.display(), bak.display()))?;
        }
        Ok(bak)
    }

    /// Compute the SHA-256 digest of the file at `path` and return it as a
    /// lowercase hexadecimal string.
    pub fn checksum_file(path: &Path) -> Result<String> {
        let data = std::fs::read(path)
            .with_context(|| format!("Failed to read {} for checksum", path.display()))?;
        let digest = Sha256::digest(&data);
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        Ok(hex)
    }
}

// ── Process management helpers ───────────────────────────────────────────────

/// Helpers for spawning, signalling, and waiting on child processes.
///
/// All functions are `async` and built on [`tokio::process::Command`].
pub mod process {
    use anyhow::{Context, Result};
    use std::process::Output;
    use tokio::process::Command;

    /// Spawn `program` with `args`, wait for it to finish, and return its
    /// combined output.
    ///
    /// Returns an error if the command cannot be spawned or exits with a
    /// non-zero status code.
    pub async fn spawn_and_wait(program: &str, args: &[&str]) -> Result<Output> {
        let output = Command::new(program)
            .args(args)
            .output()
            .await
            .with_context(|| format!("Failed to spawn `{program}`"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "`{}` exited with status {}: {}",
                program,
                output.status,
                stderr.trim()
            );
        }
        Ok(output)
    }

    /// Send UNIX signal `signal_name` (e.g. `"TERM"`, `"HUP"`, `"KILL"`) to
    /// the process identified by `pid`.
    ///
    /// Internally invokes the system `kill` command so no unsafe code or extra
    /// crate dependencies are required.
    pub async fn signal(pid: u32, signal_name: &str) -> Result<()> {
        let sig_arg = format!("-{}", signal_name);
        let pid_str = pid.to_string();
        Command::new("kill")
            .args([sig_arg.as_str(), pid_str.as_str()])
            .output()
            .await
            .with_context(|| format!("Failed to send SIG{signal_name} to PID {pid}"))?;
        Ok(())
    }

    /// Return `true` if a process with the given `pid` is currently running.
    ///
    /// Uses `/proc/<pid>` on Linux; always returns `false` on non-Linux
    /// platforms where `/proc` is not available.
    pub fn is_running(pid: u32) -> bool {
        std::path::Path::new(&format!("/proc/{pid}")).exists()
    }

    /// Wait for the process identified by `pid` to exit, polling every
    /// `interval_ms` milliseconds until either the process is gone or
    /// `timeout_ms` has elapsed.
    ///
    /// Returns `Ok(())` when the process has exited, or an error if the
    /// timeout is reached before the process terminates.
    pub async fn wait_for_exit(pid: u32, timeout_ms: u64, interval_ms: u64) -> Result<()> {
        let mut elapsed = 0u64;
        while is_running(pid) {
            if elapsed >= timeout_ms {
                anyhow::bail!(
                    "Timed out waiting for PID {pid} to exit after {timeout_ms} ms"
                );
            }
            tokio::time::sleep(std::time::Duration::from_millis(interval_ms)).await;
            elapsed = elapsed.saturating_add(interval_ms);
        }
        Ok(())
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── CIDR helpers ─────────────────────────────────────────────────────────

    #[test]
    fn test_valid_ipv4_cidr() {
        assert!(is_valid_ipv4_cidr("192.168.1.0/24"));
        assert!(is_valid_ipv4_cidr("10.0.0.0/8"));
        assert!(is_valid_ipv4_cidr("0.0.0.0/0"));
        assert!(is_valid_ipv4_cidr("255.255.255.255/32"));
    }

    #[test]
    fn test_invalid_ipv4_cidr() {
        assert!(!is_valid_ipv4_cidr("192.168.1.0"));
        assert!(!is_valid_ipv4_cidr("192.168.1.0/33"));
        assert!(!is_valid_ipv4_cidr("not-an-ip/24"));
        assert!(!is_valid_ipv4_cidr("256.0.0.0/8"));
    }

    #[test]
    fn test_valid_ipv6_cidr() {
        assert!(is_valid_ipv6_cidr("::1/128"));
        assert!(is_valid_ipv6_cidr("2001:db8::/32"));
        assert!(is_valid_ipv6_cidr("fe80::/10"));
        assert!(is_valid_ipv6_cidr("::/0"));
    }

    #[test]
    fn test_invalid_ipv6_cidr() {
        assert!(!is_valid_ipv6_cidr("::1"));
        assert!(!is_valid_ipv6_cidr("::1/129"));
        assert!(!is_valid_ipv6_cidr("not-ipv6/64"));
    }

    #[test]
    fn test_is_valid_cidr_both_families() {
        assert!(is_valid_cidr("10.0.0.0/8"));
        assert!(is_valid_cidr("2001:db8::/32"));
        assert!(!is_valid_cidr("not-a-cidr"));
    }

    #[test]
    fn test_is_valid_ip() {
        assert!(is_valid_ip("192.168.1.1"));
        assert!(is_valid_ip("::1"));
        assert!(is_valid_ip("2001:db8::1"));
        assert!(!is_valid_ip("not-an-ip"));
        assert!(!is_valid_ip("192.168.1.0/24"));
    }

    // ── MAC address ──────────────────────────────────────────────────────────

    #[test]
    fn test_valid_mac_colon() {
        assert!(is_valid_mac("aa:bb:cc:dd:ee:ff"));
        assert!(is_valid_mac("00:1A:2B:3C:4D:5E"));
    }

    #[test]
    fn test_valid_mac_hyphen() {
        assert!(is_valid_mac("aa-bb-cc-dd-ee-ff"));
        assert!(is_valid_mac("00-1A-2B-3C-4D-5E"));
    }

    #[test]
    fn test_valid_mac_cisco_dot() {
        assert!(is_valid_mac("aabb.ccdd.eeff"));
        assert!(is_valid_mac("001A.2B3C.4D5E"));
    }

    #[test]
    fn test_invalid_mac() {
        assert!(!is_valid_mac("aa:bb:cc:dd:ee"));
        assert!(!is_valid_mac("aa:bb:cc:dd:ee:zz"));
        assert!(!is_valid_mac("aabbccddeeff"));
        assert!(!is_valid_mac("aa:bb:cc:dd:ee:ff:00"));
    }

    // ── Shell quoting ─────────────────────────────────────────────────────────

    #[test]
    fn test_shell_quote_simple() {
        assert_eq!(shell::quote("hello"), "'hello'");
        assert_eq!(shell::quote("hello world"), "'hello world'");
    }

    #[test]
    fn test_shell_quote_empty() {
        assert_eq!(shell::quote(""), "''");
    }

    #[test]
    fn test_shell_quote_single_quote() {
        assert_eq!(shell::quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn test_shell_join_quoted() {
        assert_eq!(
            shell::join_quoted(&["echo", "hello world"]),
            "'echo' 'hello world'"
        );
    }

    // ── File-system helpers ───────────────────────────────────────────────────

    #[test]
    fn test_atomic_write_and_checksum() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.txt");
        fs::atomic_write(&path, b"hello").unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "hello");
        let checksum = fs::checksum_file(&path).unwrap();
        // SHA-256 of "hello"
        assert_eq!(
            checksum,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_backup_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cfg.json");
        std::fs::write(&path, b"original").unwrap();
        let bak = fs::backup_file(&path).unwrap();
        assert!(bak.exists());
        assert_eq!(std::fs::read(&bak).unwrap(), b"original");
    }
}
