//! IPv6 runtime switch.
//!
//! DayShield keeps IPv6 disabled by default, but the kernel must not be booted
//! with `ipv6.disable=1` if the administrator wants to enable it later.  This
//! module applies the persisted global setting through sysctl at service start
//! and when the setting is changed through the API.

use anyhow::{Context, Result};
use tokio::process::Command;
use tracing::{debug, info};

/// Apply the global IPv6 setting to Linux runtime sysctls.
pub async fn apply_ipv6_setting(enabled: bool) -> Result<()> {
    let disable_value = if enabled { "0" } else { "1" };
    set_sysctl("net.ipv6.conf.all.disable_ipv6", disable_value).await?;
    set_sysctl("net.ipv6.conf.default.disable_ipv6", disable_value).await?;
    set_sysctl("net.ipv6.conf.lo.disable_ipv6", disable_value).await?;

    let forwarding_value = if enabled { "1" } else { "0" };
    set_sysctl("net.ipv6.conf.all.forwarding", forwarding_value).await?;
    set_sysctl("net.ipv6.conf.default.forwarding", forwarding_value).await?;

    info!(enabled, "ipv6: runtime setting applied");
    Ok(())
}

async fn set_sysctl(key: &str, value: &str) -> Result<()> {
    debug!(key, value, "ipv6: applying sysctl");
    let assignment = format!("{key}={value}");
    let output = Command::new("sysctl")
        .args(["-w", &assignment])
        .output()
        .await
        .with_context(|| format!("failed to spawn sysctl for {key}"))?;

    if !output.status.success() {
        anyhow::bail!(
            "sysctl -w {assignment} exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(())
}
