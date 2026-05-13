//! VPN engine - manages WireGuard tunnels.
//!
//! # Overview
//!
//! This module translates a [`WireGuardInterface`] into a WireGuard
//! configuration file (`/etc/wireguard/<name>.conf`) and manages the interface
//! lifecycle via `wg-quick`.
//!
//! # Functions
//!
//! | Function              | Purpose                                               |
//! |-----------------------|-------------------------------------------------------|
//! | [`generate_config`]   | Build a `wg.conf`-format string for an interface.   |
//! | [`apply_interface`]   | Write config to disk and bring the interface up.    |
//! | [`remove_interface`]  | Bring the interface down and remove the config.     |
//! | [`generate_keypair`]  | Generate a WireGuard private/public keypair.        |

use std::path::Path;

use anyhow::{Context, Result};
use tokio::process::Command;
use tracing::{info, warn};

use crate::config::models::{VpnTunnel, WireGuardInterface};

/// Directory where WireGuard configuration files are stored.
const WG_CONFIG_DIR: &str = "/etc/wireguard";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Generate a WireGuard configuration file (`wg.conf` format) for `iface`.
///
/// The generated file includes:
/// - An `[Interface]` section with the private key, listen port, and
///   addresses.
/// - One `[Peer]` section per configured peer, with public key, allowed IPs,
///   optional pre-shared key, optional endpoint, and optional persistent
///   keep-alive.
pub fn generate_config(iface: &WireGuardInterface) -> String {
    let mut out = String::new();

    out.push_str("# DayShield - WireGuard configuration (auto-generated; do not edit by hand)\n");
    out.push_str("[Interface]\n");
    out.push_str(&format!("PrivateKey = {}\n", iface.private_key));
    out.push_str(&format!("ListenPort = {}\n", iface.listen_port));

    if !iface.addresses.is_empty() {
        out.push_str(&format!("Address = {}\n", iface.addresses.join(", ")));
    }

    for peer in &iface.peers {
        out.push('\n');
        if !peer.name.is_empty() {
            out.push_str(&format!("# Peer: {}\n", peer.name));
        }
        out.push_str("[Peer]\n");
        out.push_str(&format!("PublicKey = {}\n", peer.public_key));

        if let Some(psk) = &peer.preshared_key {
            out.push_str(&format!("PresharedKey = {psk}\n"));
        }

        if !peer.allowed_ips.is_empty() {
            out.push_str(&format!("AllowedIPs = {}\n", peer.allowed_ips.join(", ")));
        }

        if let Some(ep) = &peer.endpoint {
            out.push_str(&format!("Endpoint = {ep}\n"));
        }

        if let Some(ka) = peer.persistent_keepalive {
            if ka > 0 {
                out.push_str(&format!("PersistentKeepalive = {ka}\n"));
            }
        }
    }

    out
}

/// Apply the WireGuard configuration for `iface`.
///
/// Steps:
/// 1. Generate the config file via [`generate_config`].
/// 2. Write it atomically to `/etc/wireguard/<name>.conf`.
/// 3. If the interface already exists (`wg show <name>` succeeds), run
///    `wg syncconf` to apply changes without dropping existing sessions.
///    Otherwise, bring the interface up with `wg-quick up`.
pub async fn apply_interface(iface: &WireGuardInterface) -> Result<()> {
    use crate::config::models::validate_wg_interface_name;

    if !validate_wg_interface_name(&iface.name) {
        anyhow::bail!("invalid WireGuard interface name: {:?}", iface.name);
    }
    info!(
        name = %iface.name,
        enabled = iface.enabled,
        peers = iface.peers.len(),
        "vpn: applying WireGuard interface config"
    );

    let conf_path = format!("{}/{}.conf", WG_CONFIG_DIR, iface.name);

    if !iface.enabled {
        info!(name = %iface.name, "vpn: interface disabled - bringing down");
        bring_down(&iface.name).await?;
        return Ok(());
    }

    let conf_str = generate_config(iface);
    write_config_atomic(&conf_path, &conf_str)
        .context("failed to write WireGuard config file")?;

    info!(path = %conf_path, "vpn: config file written");

    // Check whether the interface already exists.
    let exists = Command::new("wg")
        .args(["show", &iface.name])
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false);

    if exists {
        // Sync without disrupting existing sessions.
        let out = Command::new("wg")
            .args(["syncconf", &iface.name, &conf_path])
            .output()
            .await
            .context("failed to run wg syncconf")?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            anyhow::bail!("wg syncconf failed for {}: {stderr}", iface.name);
        }
        info!(name = %iface.name, "vpn: interface synced via wg syncconf");
    } else {
        bring_up(&iface.name).await?;
    }

    Ok(())
}

/// Bring down and remove the WireGuard interface named `name`.
///
/// Calls `wg-quick down <name>` and removes the config file if it exists.
pub async fn remove_interface(name: &str) -> Result<()> {
    use crate::config::models::validate_wg_interface_name;

    if !validate_wg_interface_name(name) {
        anyhow::bail!("invalid WireGuard interface name: {:?}", name);
    }

    info!(name = %name, "vpn: removing WireGuard interface");

    bring_down(name).await?;

    let conf_path = format!("{}/{}.conf", WG_CONFIG_DIR, name);
    if Path::new(&conf_path).exists() {
        std::fs::remove_file(&conf_path)
            .with_context(|| format!("failed to remove config file {conf_path}"))?;
        info!(path = %conf_path, "vpn: config file removed");
    }

    Ok(())
}

/// Generate a WireGuard private/public keypair.
///
/// Shells out to `wg genkey` to produce a private key, then pipes it to
/// `wg pubkey` to derive the corresponding public key.
///
/// Returns `(private_key, public_key)` as base64 strings.
pub async fn generate_keypair() -> Result<(String, String)> {
    // Generate private key.
    let privkey_out = Command::new("wg")
        .arg("genkey")
        .output()
        .await
        .context("failed to run wg genkey")?;

    if !privkey_out.status.success() {
        let stderr = String::from_utf8_lossy(&privkey_out.stderr);
        anyhow::bail!("wg genkey failed: {stderr}");
    }

    let private_key = String::from_utf8(privkey_out.stdout)
        .context("wg genkey produced non-UTF-8 output")?
        .trim()
        .to_string();

    // Derive public key from private key.
    let mut pubkey_cmd = Command::new("wg");
    pubkey_cmd.arg("pubkey");

    use std::process::Stdio;
    pubkey_cmd.stdin(Stdio::piped());
    pubkey_cmd.stdout(Stdio::piped());
    pubkey_cmd.stderr(Stdio::piped());

    let mut child = pubkey_cmd
        .spawn()
        .context("failed to spawn wg pubkey")?;

    if let Some(stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        let mut stdin = stdin;
        // `wg pubkey` expects the private key followed by a newline.
        let key_with_newline = format!("{private_key}\n");
        stdin
            .write_all(key_with_newline.as_bytes())
            .await
            .context("failed to write private key to wg pubkey stdin")?;
    }

    let pubkey_out = child
        .wait_with_output()
        .await
        .context("failed to wait for wg pubkey")?;

    if !pubkey_out.status.success() {
        let stderr = String::from_utf8_lossy(&pubkey_out.stderr);
        anyhow::bail!("wg pubkey failed: {stderr}");
    }

    let public_key = String::from_utf8(pubkey_out.stdout)
        .context("wg pubkey produced non-UTF-8 output")?
        .trim()
        .to_string();

    info!("vpn: WireGuard keypair generated");

    Ok((private_key, public_key))
}

// ---------------------------------------------------------------------------
// Legacy stub - kept for backward compatibility
// ---------------------------------------------------------------------------

/// Apply the provided VPN tunnel configuration (legacy stub).
pub async fn apply_tunnel(tunnel: &VpnTunnel) -> Result<()> {
    info!(
        name = %tunnel.name,
        enabled = tunnel.enabled,
        peers = tunnel.peers.len(),
        "vpn: apply_tunnel called (legacy stub)"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Bring up a WireGuard interface via `wg-quick up <name>`.
async fn bring_up(name: &str) -> Result<()> {
    let out = Command::new("wg-quick")
        .args(["up", name])
        .output()
        .await
        .context("failed to spawn wg-quick up")?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("wg-quick up {} failed: {stderr}", name);
    }

    info!(name = %name, "vpn: interface brought up via wg-quick");
    Ok(())
}

/// Bring down a WireGuard interface via `wg-quick down <name>`.
///
/// Logs a warning (but does not fail) if the interface is not currently up.
async fn bring_down(name: &str) -> Result<()> {
    let out = Command::new("wg-quick")
        .args(["down", name])
        .output()
        .await
        .context("failed to spawn wg-quick down")?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        warn!(name = %name, stderr = %stderr, "vpn: wg-quick down returned non-zero (interface may already be down)");
    } else {
        info!(name = %name, "vpn: interface brought down via wg-quick");
    }

    Ok(())
}

/// Write `content` to `path` using an atomic rename with mode 0o600.
fn write_config_atomic(path: &str, content: &str) -> Result<()> {
    let tmp = format!("{path}.tmp");

    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("failed to open temporary file {tmp}"))?;
        f.write_all(content.as_bytes())
            .with_context(|| format!("failed to write temporary file {tmp}"))?;
    }

    #[cfg(not(unix))]
    std::fs::write(&tmp, content)
        .with_context(|| format!("failed to write temporary file {tmp}"))?;

    std::fs::rename(&tmp, path)
        .with_context(|| format!("failed to rename {tmp} to {path}"))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::models::WireGuardPeer;

    fn dummy_key(n: u8) -> String {
        // Produce a syntactically valid 44-char base64 string.
        // 43 base64 chars + '='
        let body: String = (0..43).map(|i| if (i + n) % 3 == 0 { 'A' } else if (i + n) % 3 == 1 { 'B' } else { 'C' }).collect();
        format!("{body}=")
    }

    fn make_iface() -> WireGuardInterface {
        WireGuardInterface {
            name: "wg0".into(),
            description: Some("Remote Access".into()),
            private_key: dummy_key(0),
            public_key: dummy_key(1),
            listen_port: 51820,
            addresses: vec!["10.0.0.1/24".into()],
            peers: vec![],
            enabled: true,
        }
    }

    #[test]
    fn generate_config_interface_section() {
        let iface = make_iface();
        let out = generate_config(&iface);
        assert!(out.contains("[Interface]"));
        assert!(out.contains(&format!("PrivateKey = {}", iface.private_key)));
        assert!(out.contains("ListenPort = 51820"));
        assert!(out.contains("Address = 10.0.0.1/24"));
    }

    #[test]
    fn generate_config_no_peers() {
        let iface = make_iface();
        let out = generate_config(&iface);
        assert!(!out.contains("[Peer]"));
    }

    #[test]
    fn generate_config_with_peer() {
        let mut iface = make_iface();
        iface.peers.push(WireGuardPeer {
            name: "laptop".into(),
            public_key: dummy_key(2),
            preshared_key: None,
            allowed_ips: vec!["10.0.0.2/32".into()],
            endpoint: Some("203.0.113.1:51820".into()),
            persistent_keepalive: Some(25),
        });
        let out = generate_config(&iface);
        assert!(out.contains("[Peer]"));
        assert!(out.contains("# Peer: laptop"));
        assert!(out.contains("AllowedIPs = 10.0.0.2/32"));
        assert!(out.contains("Endpoint = 203.0.113.1:51820"));
        assert!(out.contains("PersistentKeepalive = 25"));
    }

    #[test]
    fn generate_config_peer_with_preshared_key() {
        let mut iface = make_iface();
        iface.peers.push(WireGuardPeer {
            name: "phone".into(),
            public_key: dummy_key(3),
            preshared_key: Some(dummy_key(4)),
            allowed_ips: vec!["10.0.0.3/32".into()],
            endpoint: None,
            persistent_keepalive: None,
        });
        let out = generate_config(&iface);
        assert!(out.contains("PresharedKey ="));
    }

    #[test]
    fn generate_config_peer_keepalive_zero_omitted() {
        let mut iface = make_iface();
        iface.peers.push(WireGuardPeer {
            name: "server".into(),
            public_key: dummy_key(5),
            preshared_key: None,
            allowed_ips: vec!["0.0.0.0/0".into()],
            endpoint: Some("10.1.2.3:51820".into()),
            persistent_keepalive: Some(0),
        });
        let out = generate_config(&iface);
        assert!(!out.contains("PersistentKeepalive"));
    }

    #[test]
    fn generate_config_multiple_addresses() {
        let mut iface = make_iface();
        iface.addresses.push("fd00::1/64".into());
        let out = generate_config(&iface);
        assert!(out.contains("Address = 10.0.0.1/24, fd00::1/64"));
    }
}
