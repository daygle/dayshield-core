//! Shared Kea runtime helpers.
//!
//! DHCPv4 and DHCPv6 have different JSON schemas, but they share the same
//! runtime chores: preparing Kea directories, validating generated config,
//! mirroring it to the distro path, and controlling the systemd unit.

use std::{
    io::ErrorKind,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use anyhow::{Context, Result};
use tokio::process::Command;
use tracing::{info, warn};

pub const CONFIG_DIR: &str = "/etc/kea";
pub const DAYSHIELD_CONFIG_DIR: &str = "/etc/dayshield";
pub const DATA_DIR: &str = "/var/lib/kea";

pub const DHCP4_DAYSHIELD_CONF_PATH: &str = "/etc/dayshield/kea-dhcp4.conf";
pub const DHCP4_SYSTEM_CONF_PATH: &str = "/etc/kea/kea-dhcp4.conf";
pub const DHCP4_LEASES_PATH: &str = "/var/lib/kea/kea-leases4.csv";

pub const DHCP6_DAYSHIELD_CONF_PATH: &str = "/etc/dayshield/kea-dhcp6.conf";
pub const DHCP6_SYSTEM_CONF_PATH: &str = "/etc/kea/kea-dhcp6.conf";
pub const DHCP6_LEASES_PATH: &str = "/var/lib/kea/kea-leases6.csv";

static KEA_DIR_CHMOD_WARNED: AtomicBool = AtomicBool::new(false);
static KEA_FILE_CHMOD_WARNED: AtomicBool = AtomicBool::new(false);

const DHCP4_SERVICE_CANDIDATES: &[&str] = &[
    "isc-kea-dhcp4-server.service",
    "kea-dhcp4-server.service",
    "kea-dhcp4.service",
];
const DHCP6_SERVICE_CANDIDATES: &[&str] = &[
    "isc-kea-dhcp6-server.service",
    "kea-dhcp6-server.service",
    "kea-dhcp6.service",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeaServer {
    Dhcp4,
    Dhcp6,
}

impl KeaServer {
    pub fn label(self) -> &'static str {
        match self {
            Self::Dhcp4 => "dhcp",
            Self::Dhcp6 => "dhcp6",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Dhcp4 => "Kea DHCPv4",
            Self::Dhcp6 => "Kea DHCPv6",
        }
    }

    fn binary(self) -> &'static str {
        match self {
            Self::Dhcp4 => "kea-dhcp4",
            Self::Dhcp6 => "kea-dhcp6",
        }
    }

    pub fn day_shield_config_path(self) -> &'static str {
        match self {
            Self::Dhcp4 => DHCP4_DAYSHIELD_CONF_PATH,
            Self::Dhcp6 => DHCP6_DAYSHIELD_CONF_PATH,
        }
    }

    pub fn system_config_path(self) -> &'static str {
        match self {
            Self::Dhcp4 => DHCP4_SYSTEM_CONF_PATH,
            Self::Dhcp6 => DHCP6_SYSTEM_CONF_PATH,
        }
    }

    fn candidate_config_path(self) -> String {
        format!("{}.candidate", self.day_shield_config_path())
    }

    fn lease_path(self) -> &'static str {
        match self {
            Self::Dhcp4 => DHCP4_LEASES_PATH,
            Self::Dhcp6 => DHCP6_LEASES_PATH,
        }
    }

    pub fn service_candidates(self) -> &'static [&'static str] {
        match self {
            Self::Dhcp4 => DHCP4_SERVICE_CANDIDATES,
            Self::Dhcp6 => DHCP6_SERVICE_CANDIDATES,
        }
    }
}

pub fn dhcp4_service_candidates() -> &'static [&'static str] {
    DHCP4_SERVICE_CANDIDATES
}

pub fn dhcp6_service_candidates() -> &'static [&'static str] {
    DHCP6_SERVICE_CANDIDATES
}

pub async fn apply_config(server: KeaServer, enabled: bool, config: Option<&str>) -> Result<()> {
    if !enabled {
        disable_server(server).await?;
        return Ok(());
    }

    let config = config.with_context(|| format!("{} config was not generated", server.name()))?;
    prepare_runtime(server).await?;

    let candidate_path = server.candidate_config_path();
    write_config_atomic(&candidate_path, config)
        .with_context(|| format!("failed to write candidate config {candidate_path}"))?;

    if let Err(err) = test_config(server, &candidate_path).await {
        remove_config_if_exists(&candidate_path)?;
        return Err(err);
    }

    write_config_atomic(server.day_shield_config_path(), config)
        .with_context(|| format!("failed to write {}", server.day_shield_config_path()))?;
    set_file_permissions_best_effort(server.day_shield_config_path());

    write_config_atomic(server.system_config_path(), config).with_context(|| {
        format!(
            "failed to mirror {} to {} (check dayshield.service sandbox: ReadWritePaths should include /etc/kea)",
            server.day_shield_config_path(),
            server.system_config_path()
        )
    })?;
    set_file_permissions_best_effort(server.system_config_path());
    remove_config_if_exists(&candidate_path)?;

    info!(
        service = server.label(),
        path = server.day_shield_config_path(),
        system_path = server.system_config_path(),
        "{} config written",
        server.name()
    );

    enable_and_restart(server).await
}

async fn disable_server(server: KeaServer) -> Result<()> {
    info!(
        service = server.label(),
        "{} disabled - stopping service",
        server.name()
    );

    for unit in server.service_candidates() {
        let _ = Command::new("systemctl")
            .args(["disable", "--now", unit])
            .output()
            .await;
    }

    remove_config_if_exists(server.day_shield_config_path())?;
    remove_config_if_exists(server.system_config_path())?;
    Ok(())
}

async fn prepare_runtime(_server: KeaServer) -> Result<()> {
    std::fs::create_dir_all(CONFIG_DIR).context("failed to create /etc/kea")?;
    std::fs::create_dir_all(DAYSHIELD_CONFIG_DIR).context("failed to create /etc/dayshield")?;
    std::fs::create_dir_all(DATA_DIR).context("failed to create /var/lib/kea")?;

    set_directory_permissions_best_effort(CONFIG_DIR);
    set_directory_permissions_best_effort(DAYSHIELD_CONFIG_DIR);

    Ok(())
}

async fn test_config(server: KeaServer, path: &str) -> Result<()> {
    let output = Command::new(server.binary())
        .args(["-t", path])
        .output()
        .await
        .with_context(|| format!("failed to spawn {} for config validation", server.binary()))?;

    if output.status.success() {
        info!(
            service = server.label(),
            path,
            "{} config-test passed",
            server.name()
        );
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if stderr.is_empty() { stdout } else { stderr };
    anyhow::bail!("{} config-test failed: {detail}", server.name());
}

async fn enable_and_restart(server: KeaServer) -> Result<()> {
    let unit = resolve_service_unit(server).await?;

    if let Err(error) = run_systemctl(&["enable", unit]).await {
        warn!(
            service = server.label(),
            unit,
            error = %error,
            "kea: systemctl enable failed; continuing with runtime start"
        );
    }

    if let Err(error) = run_systemctl(&["restart", unit]).await {
        warn!(
            service = server.label(),
            unit,
            error = %error,
            "kea: systemctl restart failed; trying start"
        );
        run_systemctl(&["start", unit]).await?;
    }

    info!(
        service = server.label(),
        unit,
        "{} service restarted",
        server.name()
    );
    Ok(())
}

pub async fn resolve_service_unit(server: KeaServer) -> Result<&'static str> {
    for unit in server.service_candidates() {
        if systemd_unit_exists(unit).await {
            return Ok(unit);
        }
    }

    anyhow::bail!(
        "{} systemd unit not found; tried {}",
        server.name(),
        server.service_candidates().join(", ")
    );
}

async fn systemd_unit_exists(unit: &str) -> bool {
    let Ok(output) = Command::new("systemctl")
        .args([
            "show",
            unit,
            "--property=LoadState",
            "--value",
            "--no-pager",
        ])
        .output()
        .await
    else {
        return false;
    };

    if !output.status.success() {
        return false;
    }

    let state = String::from_utf8_lossy(&output.stdout).trim().to_string();
    !state.is_empty() && state != "not-found"
}

async fn run_systemctl(args: &[&str]) -> Result<()> {
    let output = Command::new("systemctl")
        .args(args)
        .output()
        .await
        .context("failed to spawn systemctl")?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if stderr.is_empty() { stdout } else { stderr };
    anyhow::bail!("systemctl {} failed: {detail}", args.join(" "));
}

fn write_config_atomic(path: &str, content: &str) -> Result<()> {
    let tmp = format!("{path}.tmp");

    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }

    std::fs::write(&tmp, content)
        .with_context(|| format!("failed to write temporary file {tmp}"))?;
    std::fs::rename(&tmp, path).with_context(|| format!("failed to rename {tmp} to {path}"))?;

    Ok(())
}

fn remove_config_if_exists(path: &str) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {
            info!(path, "kea: removed stale config file");
            Ok(())
        }
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("failed to remove stale config {path}")),
    }
}

#[cfg(unix)]
fn set_directory_permissions_best_effort(path: &str) {
    set_permissions_best_effort(path, 0o755, true);
}

#[cfg(not(unix))]
fn set_directory_permissions_best_effort(_path: &str) {}

#[cfg(unix)]
fn set_file_permissions_best_effort(path: &str) {
    set_permissions_best_effort(path, 0o644, false);
}

#[cfg(not(unix))]
fn set_file_permissions_best_effort(_path: &str) {}

#[cfg(unix)]
fn set_permissions_best_effort(path: &str, mode: u32, directory: bool) {
    if permission_mode_matches(path, mode) {
        return;
    }

    if let Err(error) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)) {
        let warned = if directory {
            &KEA_DIR_CHMOD_WARNED
        } else {
            &KEA_FILE_CHMOD_WARNED
        };
        if warned.swap(true, Ordering::Relaxed) {
            return;
        }

        let kind = if directory { "directory" } else { "file" };
        if error.kind() == ErrorKind::PermissionDenied {
            info!(
                path,
                mode = %format!("{mode:o}"),
                error = %error,
                "kea: {kind} chmod not permitted; continuing"
            );
        } else {
            warn!(
                path,
                mode = %format!("{mode:o}"),
                error = %error,
                "kea: continuing after {kind} chmod failed"
            );
        }
    }
}

#[cfg(unix)]
fn permission_mode_matches(path: &str, mode: u32) -> bool {
    std::fs::metadata(path)
        .map(|metadata| metadata.permissions().mode() & 0o777 == mode)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debian_real_units_are_preferred_before_aliases() {
        assert_eq!(
            KeaServer::Dhcp4.service_candidates()[0],
            "isc-kea-dhcp4-server.service"
        );
        assert_eq!(
            KeaServer::Dhcp6.service_candidates()[0],
            "isc-kea-dhcp6-server.service"
        );
    }

    #[test]
    fn server_paths_are_protocol_specific() {
        assert_eq!(
            KeaServer::Dhcp4.system_config_path(),
            "/etc/kea/kea-dhcp4.conf"
        );
        assert_eq!(
            KeaServer::Dhcp6.system_config_path(),
            "/etc/kea/kea-dhcp6.conf"
        );
    }

    #[test]
    fn lease_paths_use_runtime_storage() {
        assert_eq!(
            KeaServer::Dhcp4.lease_path(),
            "/var/lib/kea/kea-leases4.csv"
        );
        assert_eq!(
            KeaServer::Dhcp6.lease_path(),
            "/var/lib/kea/kea-leases6.csv"
        );
    }
}
