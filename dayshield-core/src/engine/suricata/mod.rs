//! Suricata engine - manages the Suricata IPS/IDS process and rule sets.
//!
//! # Overview
//!
//! This module translates a [`SuricataConfig`] into a complete `suricata.yaml`
//! file and manages the Suricata process lifecycle (start/stop/reload).
//!
//! # Functions
//!
//! | Function            | Purpose                                              |
//! |---------------------|------------------------------------------------------|
//! | [`generate_config`] | Build a complete `suricata.yaml` string.            |
//! | [`apply_config`]    | Write `suricata.yaml` to disk and reload Suricata.  |
//! | [`update_rules`]    | Run `suricata-update` to refresh rule sets.         |
//! | [`reload`]          | Send `SIGUSR2` to reload rules without packet loss. |

use std::path::Path;

use anyhow::{Context, Result};
use tokio::process::Command;
use tracing::{info, warn};

use crate::config::models::SuricataConfig;
use crate::rules::storage::RulesetStore;

/// Path where the Suricata configuration file is written.
const SURICATA_YAML_PATH: &str = "/etc/suricata/suricata.yaml";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Generate a complete `suricata.yaml` configuration file as a `String`.
///
/// The generated file covers:
/// - `vars:` block with `HOME_NET` / `EXTERNAL_NET` address groups.
/// - `outputs:` block with EVE JSON and stats log settings.
/// - `rule-files:` block listing all enabled local rule paths.
pub fn generate_config(config: &SuricataConfig) -> String {
    let mut out = String::new();

    out.push_str("%YAML 1.1\n");
    out.push_str("---\n");
    out.push_str("# DayShield - Suricata configuration (auto-generated; do not edit by hand)\n\n");

    // ---------------------------------------------------------------------------
    // vars
    // ---------------------------------------------------------------------------
    out.push_str("vars:\n");
    out.push_str("  address-groups:\n");

    let home_net = if config.home_nets.is_empty() {
        "\"[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]\"".to_string()
    } else {
        format!("\"[{}]\"", config.home_nets.join(","))
    };
    out.push_str(&format!("    HOME_NET: {home_net}\n"));

    let external_net = if config.external_nets.is_empty() {
        "\"any\"".to_string()
    } else {
        format!("\"[{}]\"", config.external_nets.join(","))
    };
    out.push_str(&format!("    EXTERNAL_NET: {external_net}\n"));

    out.push_str("  port-groups:\n");
    out.push_str("    HTTP_PORTS: \"80\"\n");
    out.push_str("    SHELLCODE_PORTS: \"!80\"\n");
    out.push_str("    ORACLE_PORTS: 1521\n");
    out.push_str("    SSH_PORTS: 22\n");
    out.push_str("    DNP3_PORTS: 20000\n");
    out.push_str("    MODBUS_PORTS: 502\n");
    out.push_str("    FILE_DATA_PORTS: \"[$HTTP_PORTS,110,143]\"\n");
    out.push_str("    FTP_PORTS: 21\n");
    out.push_str("    VXLAN_PORTS: 4789\n");
    out.push_str("    TEREDO_PORTS: 3544\n\n");

    // ---------------------------------------------------------------------------
    // default-rule-path
    // ---------------------------------------------------------------------------
    out.push_str("default-rule-path: /var/lib/suricata/rules\n\n");

    // ---------------------------------------------------------------------------
    // rule-files
    // ---------------------------------------------------------------------------
    out.push_str("rule-files:\n");
    let has_local_rules = config
        .rule_sources
        .iter()
        .any(|s| s.enabled && s.path.is_some());
    if has_local_rules {
        for src in &config.rule_sources {
            if src.enabled {
                if let Some(path) = &src.path {
                    out.push_str(&format!("  - {path}\n"));
                }
            }
        }
    } else {
        out.push_str("  - suricata.rules\n");
    }
    out.push('\n');

    // ---------------------------------------------------------------------------
    // inputs (af-packet capture interfaces)
    // ---------------------------------------------------------------------------
    out.push_str("inputs:\n");
    if config.interfaces.is_empty() {
        // Default: monitor eth0 if no interfaces specified
        out.push_str("  - interface: eth0\n");
        out.push_str("    af-packet:\n");
        out.push_str("      use-mmap: yes\n");
        out.push_str("      tpacket-v3: yes\n");
    } else {
        // Generate af-packet entries for each configured interface
        for iface in &config.interfaces {
            out.push_str("  - interface: ");
            out.push_str(iface);
            out.push('\n');
            out.push_str("    af-packet:\n");
            out.push_str("      use-mmap: yes\n");
            out.push_str("      tpacket-v3: yes\n");
        }
    }
    out.push('\n');

    // ---------------------------------------------------------------------------
    // outputs
    // ---------------------------------------------------------------------------
    out.push_str("outputs:\n");

    // EVE JSON
    if config.eve_log_enabled {
        out.push_str("  - eve-log:\n");
        out.push_str("      enabled: yes\n");
        out.push_str(&format!("      filename: {}\n", config.eve_log_path));
        out.push_str("      types:\n");
        out.push_str("        - alert:\n");
        out.push_str("            payload: yes\n");
        out.push_str("            payload-printable: yes\n");
        out.push_str("            packet: yes\n");
        out.push_str("            metadata: yes\n");
        out.push_str("        - drop:\n");
        out.push_str("            alerts: yes\n");
        out.push_str("        - tls:\n");
        out.push_str("            extended: yes\n");
        out.push_str("        - files:\n");
        out.push_str("            force-magic: no\n");
        out.push_str("        - http:\n");
        out.push_str("            extended: yes\n");
        out.push_str("        - dns:\n");
        out.push_str("            query: yes\n");
        out.push_str("            answer: yes\n");
        out.push_str("        - flow\n");
        out.push_str("        - netflow\n");
    } else {
        out.push_str("  - eve-log:\n");
        out.push_str("      enabled: no\n");
        out.push_str(&format!("      filename: {}\n", config.eve_log_path));
    }
    out.push('\n');

    // Stats log
    if config.stats_log_enabled {
        out.push_str("  - stats:\n");
        out.push_str("      enabled: yes\n");
        out.push_str(&format!("      filename: {}\n", config.stats_log_path));
        // stats_interval_seconds: 0 means use Suricata's built-in default (8s).
        let interval = if config.stats_interval_seconds == 0 {
            8
        } else {
            config.stats_interval_seconds
        };
        out.push_str(&format!("      interval: {interval}\n"));
    } else {
        out.push_str("  - stats:\n");
        out.push_str("      enabled: no\n");
        out.push_str(&format!("      filename: {}\n", config.stats_log_path));
    }
    out.push('\n');

    // Fast log (alerts, always on as a lightweight fallback).
    out.push_str("  - fast:\n");
    out.push_str("      enabled: yes\n");
    out.push_str("      filename: /var/log/suricata/fast.log\n");
    out.push_str("      append: yes\n\n");

    // ---------------------------------------------------------------------------
    // app-layer
    // ---------------------------------------------------------------------------
    out.push_str("app-layer:\n");
    out.push_str("  protocols:\n");
    out.push_str("    tls:\n");
    out.push_str("      enabled: yes\n");
    out.push_str("      detection-ports:\n");
    out.push_str("        dp: 443\n");
    out.push_str("    http:\n");
    out.push_str("      enabled: yes\n");
    out.push_str("    dns:\n");
    out.push_str("      enabled: yes\n");
    out.push_str("    smtp:\n");
    out.push_str("      enabled: yes\n");
    out.push_str("    ssh:\n");
    out.push_str("      enabled: yes\n\n");

    // ---------------------------------------------------------------------------
    // threading / detection
    // ---------------------------------------------------------------------------
    out.push_str("threading:\n");
    out.push_str("  set-cpu-affinity: no\n\n");

    out.push_str("detect:\n");
    out.push_str("  profile: medium\n");
    out.push_str("  custom-values:\n");
    out.push_str("    toclient-groups: 3\n");
    out.push_str("    toserver-groups: 25\n");
    out.push_str("  sgh-mpm-context: auto\n");
    out.push_str("  inspection-recursion-limit: 3000\n\n");

    out
}

/// Apply the provided Suricata configuration to the running Suricata instance.
///
/// Steps:
/// 1. Collect paths of all enabled *managed* rulesets from the ruleset store.
/// 2. Generate `suricata.yaml` via [`generate_config`], merging managed paths
///    with any user-defined rule sources.
/// 3. Write the file atomically to [`SURICATA_YAML_PATH`].
/// 4. If Suricata is running, send it `SIGUSR2` (live rule reload); otherwise
///    attempt to start it with `systemctl start suricata`.
///
/// # Errors
///
/// Returns an error if the configuration file cannot be written or if the
/// reload / start command fails.
pub async fn apply_config(config: &SuricataConfig) -> Result<()> {
    info!(
        enabled = config.enabled,
        home_nets = config.home_nets.len(),
        rule_sources = config.rule_sources.len(),
        "suricata: applying config"
    );

    if !config.enabled {
        info!("suricata: service disabled - stopping Suricata");
        let _ = Command::new("systemctl")
            .args(["stop", "suricata"])
            .output()
            .await;
        return Ok(());
    }

    // Merge enabled managed rulesets into a working copy of the config so
    // that the generator sees them alongside any user-defined sources.
    let mut effective_config = config.clone();
    match RulesetStore::new().load() {
        Ok(managed) => {
            for rs in managed.iter().filter(|r| r.enabled) {
                if let Some(path) = &rs.local_path {
                    effective_config.rule_sources.push(crate::config::models::RuleSource {
                        name: rs.id.clone(),
                        enabled: true,
                        url: None,
                        path: Some(path.clone()),
                    });
                }
            }
        }
        Err(e) => {
            warn!(error = %e, "suricata: failed to load managed rulesets; continuing without them");
        }
    }

    let conf_str = generate_config(&effective_config);
    write_config_atomic(SURICATA_YAML_PATH, &conf_str)
        .with_context(|| {
            format!(
                "failed to write {} (check dayshield.service sandbox: ReadWritePaths should include /etc/suricata)",
                SURICATA_YAML_PATH
            )
        })?;

    info!(path = SURICATA_YAML_PATH, "suricata: suricata.yaml written");

    // Try a live reload via SIGUSR2; fall back to a full service start.
    let reload_result = reload().await;
    match reload_result {
        Ok(_) => {
            info!("suricata: reload succeeded");
        }
        Err(e) => {
            warn!(error = %e, "suricata: reload failed; attempting systemctl start suricata");
            start_suricata().await?;
        }
    }

    Ok(())
}

/// Download and install the latest Suricata rule sets.
///
/// Shells out to `suricata-update` and then reloads the rule engine via
/// [`reload`].
pub async fn update_rules() -> Result<()> {
    info!("suricata: running suricata-update");

    let out = Command::new("suricata-update")
        .output()
        .await
        .context("failed to spawn suricata-update")?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("suricata-update failed: {stderr}");
    }

    info!("suricata: suricata-update completed; reloading rules");
    reload().await
}

/// Reload the Suricata rule engine without dropping network packets.
///
/// Sends `SIGUSR2` to the Suricata process via `kill -USR2` (looked up
/// through `suricatasc` if available, otherwise via `systemctl kill`).
pub async fn reload() -> Result<()> {
    // Try suricatasc first (cleanest method).
    let sc = Command::new("suricatasc")
        .args(["-c", "reload-rules"])
        .output()
        .await;

    match sc {
        Ok(out) if out.status.success() => {
            info!("suricata: rules reloaded via suricatasc");
            return Ok(());
        }
        Ok(out) => {
            warn!(
                stderr = %String::from_utf8_lossy(&out.stderr),
                "suricata: suricatasc reload-rules failed; falling back to systemctl kill"
            );
        }
        Err(e) => {
            warn!(error = %e, "suricata: suricatasc not available; falling back to systemctl kill");
        }
    }

    // Fall back: send SIGUSR2 via systemctl kill.
    let kill = Command::new("systemctl")
        .args(["kill", "-s", "SIGUSR2", "suricata"])
        .output()
        .await
        .context("failed to spawn systemctl kill")?;

    if !kill.status.success() {
        let stderr = String::from_utf8_lossy(&kill.stderr);
        anyhow::bail!("systemctl kill -s SIGUSR2 suricata failed: {stderr}");
    }

    info!("suricata: SIGUSR2 sent via systemctl kill");
    Ok(())
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Write `content` to `path` using an atomic rename.
fn write_config_atomic(path: &str, content: &str) -> Result<()> {
    let tmp = format!("{path}.tmp");

    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }

    std::fs::write(&tmp, content)
        .with_context(|| format!("failed to write temporary file {tmp}"))?;

    std::fs::rename(&tmp, path)
        .with_context(|| format!("failed to rename {tmp} to {path}"))?;

    Ok(())
}

/// Start the Suricata service via systemctl.
async fn start_suricata() -> Result<()> {
    let out = Command::new("systemctl")
        .args(["start", "suricata"])
        .output()
        .await
        .context("failed to spawn systemctl")?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("systemctl start suricata failed: {stderr}");
    }

    info!("suricata: started via systemctl");
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::models::RuleSource;

    fn base_config() -> SuricataConfig {
        SuricataConfig {
            enabled: true,
            home_nets: vec!["192.168.1.0/24".into()],
            external_nets: vec![],
            rule_sources: vec![],
            eve_log_enabled: true,
            eve_log_path: "/var/log/suricata/eve.json".into(),
            stats_log_enabled: true,
            stats_log_path: "/var/log/suricata/stats.log".into(),
            stats_interval_seconds: 0,
        }
    }

    #[test]
    fn generate_config_contains_home_net() {
        let cfg = base_config();
        let out = generate_config(&cfg);
        assert!(out.contains("HOME_NET: \"[192.168.1.0/24]\""), "should contain HOME_NET");
    }

    #[test]
    fn generate_config_external_net_defaults_to_any() {
        let cfg = base_config();
        let out = generate_config(&cfg);
        assert!(out.contains("EXTERNAL_NET: \"any\""));
    }

    #[test]
    fn generate_config_external_net_explicit() {
        let mut cfg = base_config();
        cfg.external_nets = vec!["0.0.0.0/0".into()];
        let out = generate_config(&cfg);
        assert!(out.contains("EXTERNAL_NET: \"[0.0.0.0/0]\""));
    }

    #[test]
    fn generate_config_eve_log_enabled() {
        let cfg = base_config();
        let out = generate_config(&cfg);
        assert!(out.contains("eve-log:"));
        assert!(out.contains("enabled: yes"));
        assert!(out.contains("filename: /var/log/suricata/eve.json"));
    }

    #[test]
    fn generate_config_eve_log_disabled() {
        let mut cfg = base_config();
        cfg.eve_log_enabled = false;
        let out = generate_config(&cfg);
        // The eve-log block should still be present but disabled.
        assert!(out.contains("eve-log:"));
        assert!(out.contains("enabled: no"));
    }

    #[test]
    fn generate_config_stats_log_enabled() {
        let cfg = base_config();
        let out = generate_config(&cfg);
        assert!(out.contains("stats:"));
        assert!(out.contains("filename: /var/log/suricata/stats.log"));
    }

    #[test]
    fn generate_config_stats_log_disabled() {
        let mut cfg = base_config();
        cfg.stats_log_enabled = false;
        let out = generate_config(&cfg);
        assert!(out.contains("stats:"));
        // Disabled stats block.
        let stats_pos = out.find("  - stats:").unwrap();
        let stats_block = &out[stats_pos..];
        assert!(stats_block.contains("enabled: no"));
    }

    #[test]
    fn generate_config_default_rule_file_when_no_local() {
        let cfg = base_config();
        let out = generate_config(&cfg);
        assert!(out.contains("  - suricata.rules"));
    }

    #[test]
    fn generate_config_local_rule_source() {
        let mut cfg = base_config();
        cfg.rule_sources.push(RuleSource {
            name: "local".into(),
            enabled: true,
            url: None,
            path: Some("/etc/suricata/rules/local.rules".into()),
        });
        let out = generate_config(&cfg);
        assert!(out.contains("  - /etc/suricata/rules/local.rules"));
        assert!(!out.contains("  - suricata.rules"), "should not include default when local rules are set");
    }

    #[test]
    fn generate_config_disabled_rule_source_not_included() {
        let mut cfg = base_config();
        cfg.rule_sources.push(RuleSource {
            name: "disabled-src".into(),
            enabled: false,
            url: None,
            path: Some("/etc/suricata/rules/disabled.rules".into()),
        });
        let out = generate_config(&cfg);
        assert!(!out.contains("disabled.rules"));
    }

    #[test]
    fn generate_config_multiple_home_nets() {
        let mut cfg = base_config();
        cfg.home_nets = vec!["192.168.1.0/24".into(), "10.0.0.0/8".into()];
        let out = generate_config(&cfg);
        assert!(out.contains("HOME_NET: \"[192.168.1.0/24,10.0.0.0/8]\""));
    }

    #[test]
    fn generate_config_yaml_header() {
        let cfg = base_config();
        let out = generate_config(&cfg);
        assert!(out.starts_with("%YAML 1.1\n"));
        assert!(out.contains("---\n"));
    }
}
