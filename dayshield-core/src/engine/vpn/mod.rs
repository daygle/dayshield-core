//! VPN engine — manages WireGuard tunnels.
//!
//! TODO: generate `wg<N>.conf` from [`VpnTunnel`].
//! TODO: implement `wg-quick up / down / reload` lifecycle management.
//! TODO: derive public key from private key at startup using the `x25519`
//!       crate and store it back in the config.
//! TODO: implement peer handshake monitoring and report status to state layer.
//! TODO: support split-tunnel and full-tunnel routing policies.
//! TODO: implement pre-shared key rotation.

use anyhow::Result;
use tracing::info;

use crate::config::models::VpnTunnel;

/// Apply the provided VPN tunnel configuration.
///
/// TODO: generate the WireGuard config file and call `wg-quick`.
pub async fn apply_tunnel(tunnel: &VpnTunnel) -> Result<()> {
    info!(
        name = %tunnel.name,
        enabled = tunnel.enabled,
        peers = tunnel.peers.len(),
        "vpn: apply_tunnel called (stub)"
    );
    Ok(())
}

/// Generate the `wg<N>.conf` file contents for the given tunnel.
///
/// TODO: implement full WireGuard config generation including peer sections.
pub fn generate_config(tunnel: &VpnTunnel) -> String {
    // TODO: build complete wg.conf from `tunnel`.
    format!(
        "# DayShield WireGuard config (stub)\n\
         # interface={}, peers={}\n",
        tunnel.name,
        tunnel.peers.len()
    )
}
