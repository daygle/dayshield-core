//! Linux traffic-control backend for QoS / Smart Queue Management.
//!
//! DayShield installs a root queue discipline per configured interface. CAKE is
//! the default because it combines shaping, fair queueing, and diffserv-aware
//! priority handling behind a compact operational surface.

use std::collections::BTreeSet;

use serde::Serialize;
use tokio::process::Command;
use tracing::{debug, info, warn};

use crate::qos::model::{QosConfig, QosDiffservMode, QosInterface, QosQueueDiscipline};

#[derive(Debug, thiserror::Error)]
pub enum QosEngineError {
    #[error("failed to apply QoS: {0}")]
    ApplyFailed(String),
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QosInterfaceStatus {
    pub name: String,
    pub configured: bool,
    pub enabled: bool,
    pub qdisc: Option<String>,
    pub applied: bool,
    pub details: String,
    pub last_error: Option<String>,
}

/// Apply a QoS config without knowledge of a previous config.
pub async fn apply_config(config: &QosConfig) -> Result<(), QosEngineError> {
    apply_config_replacing(None, config).await
}

/// Apply `current` while cleaning up interfaces that were only present in
/// `previous`, so removing or disabling an interface also removes its qdisc.
pub async fn apply_config_replacing(
    previous: Option<&QosConfig>,
    current: &QosConfig,
) -> Result<(), QosEngineError> {
    let previous_names = previous
        .into_iter()
        .flat_map(|config| config.interfaces.iter().map(|iface| iface.name.clone()))
        .collect::<BTreeSet<_>>();

    let active_current = active_interfaces(current).collect::<Vec<_>>();
    let active_current_names = active_current
        .iter()
        .map(|iface| iface.name.as_str())
        .collect::<BTreeSet<_>>();

    let current_names = current
        .interfaces
        .iter()
        .map(|iface| iface.name.as_str())
        .collect::<BTreeSet<_>>();

    for iface in current
        .interfaces
        .iter()
        .filter(|iface| !current.enabled || !iface.enabled)
    {
        delete_root_qdisc_best_effort(&iface.name).await;
    }

    for name in previous_names {
        if !current_names.contains(name.as_str()) || !active_current_names.contains(name.as_str()) {
            delete_root_qdisc_best_effort(&name).await;
        }
    }

    if !current.enabled {
        info!("qos: disabled; removed managed qdiscs from configured interfaces");
        return Ok(());
    }

    for iface in active_current {
        apply_interface(iface).await?;
    }

    Ok(())
}

/// Read `tc -s qdisc` status for every configured interface.
pub async fn read_status(config: &QosConfig) -> Vec<QosInterfaceStatus> {
    let mut statuses = Vec::with_capacity(config.interfaces.len());

    for iface in &config.interfaces {
        let output = Command::new("tc")
            .args(["-s", "qdisc", "show", "dev", &iface.name])
            .output()
            .await;

        match output {
            Ok(output) if output.status.success() => {
                let details = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let qdisc = detected_qdisc(&details).map(str::to_string);
                statuses.push(QosInterfaceStatus {
                    name: iface.name.clone(),
                    configured: true,
                    enabled: config.enabled && iface.enabled,
                    qdisc,
                    applied: config.enabled && iface.enabled && qdisc_matches(iface, &details),
                    details,
                    last_error: None,
                });
            }
            Ok(output) => {
                statuses.push(QosInterfaceStatus {
                    name: iface.name.clone(),
                    configured: true,
                    enabled: config.enabled && iface.enabled,
                    qdisc: None,
                    applied: false,
                    details: String::new(),
                    last_error: Some(command_error("tc -s qdisc show", &output)),
                });
            }
            Err(err) => {
                statuses.push(QosInterfaceStatus {
                    name: iface.name.clone(),
                    configured: true,
                    enabled: config.enabled && iface.enabled,
                    qdisc: None,
                    applied: false,
                    details: String::new(),
                    last_error: Some(format!("failed to spawn tc: {err}")),
                });
            }
        }
    }

    statuses
}

async fn apply_interface(iface: &QosInterface) -> Result<(), QosEngineError> {
    delete_root_qdisc_best_effort(&iface.name).await;

    let args = qdisc_replace_args(iface);
    let output = Command::new("tc")
        .args(&args)
        .output()
        .await
        .map_err(|err| {
            QosEngineError::ApplyFailed(format!(
                "failed to spawn tc for interface {}: {}",
                iface.name, err
            ))
        })?;

    if !output.status.success() {
        return Err(QosEngineError::ApplyFailed(command_error(
            &format!("tc {}", args.join(" ")),
            &output,
        )));
    }

    info!(
        interface = %iface.name,
        qdisc = iface.qdisc.as_str(),
        bandwidth_kbps = ?iface.bandwidth_kbps,
        "qos: applied interface policy"
    );
    Ok(())
}

async fn delete_root_qdisc_best_effort(name: &str) {
    let output = Command::new("tc")
        .args(["qdisc", "del", "dev", name, "root"])
        .output()
        .await;

    match output {
        Ok(output) if output.status.success() => {
            debug!(interface = %name, "qos: removed existing root qdisc");
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
            if !(stderr.contains("no such file")
                || stderr.contains("cannot delete")
                || stderr.contains("not found"))
            {
                debug!(
                    interface = %name,
                    status = %output.status,
                    stderr = %String::from_utf8_lossy(&output.stderr),
                    "qos: root qdisc cleanup did not succeed"
                );
            }
        }
        Err(err) => {
            warn!(interface = %name, error = %err, "qos: failed to spawn tc for qdisc cleanup");
        }
    }
}

fn active_interfaces(config: &QosConfig) -> impl Iterator<Item = &QosInterface> {
    config
        .interfaces
        .iter()
        .filter(|iface| config.enabled && iface.enabled)
}

pub(crate) fn qdisc_replace_args(iface: &QosInterface) -> Vec<String> {
    let mut args = vec![
        "qdisc".to_string(),
        "replace".to_string(),
        "dev".to_string(),
        iface.name.clone(),
        "root".to_string(),
    ];

    match iface.qdisc {
        QosQueueDiscipline::Cake => {
            args.push("cake".to_string());
            if let Some(kbps) = iface.bandwidth_kbps {
                args.push("bandwidth".to_string());
                args.push(format!("{kbps}kbit"));
            }
            args.push(iface.diffserv.as_tc_arg().to_string());
            if iface.nat_aware {
                args.push("nat".to_string());
            }
            if iface.wash {
                args.push("wash".to_string());
            }
        }
        QosQueueDiscipline::FqCodel => {
            args.push("fq_codel".to_string());
        }
    }

    args
}

fn detected_qdisc(details: &str) -> Option<&'static str> {
    if details.contains("qdisc cake ") {
        Some("cake")
    } else if details.contains("qdisc fq_codel ") {
        Some("fq_codel")
    } else {
        None
    }
}

fn qdisc_matches(iface: &QosInterface, details: &str) -> bool {
    match iface.qdisc {
        QosQueueDiscipline::Cake => details.contains("qdisc cake "),
        QosQueueDiscipline::FqCodel => details.contains("qdisc fq_codel "),
    }
}

fn command_error(command: &str, output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let message = if !stderr.is_empty() { stderr } else { stdout };
    if message.is_empty() {
        format!("{command} exited {}", output.status)
    } else {
        format!("{command} exited {}: {message}", output.status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cake_iface() -> QosInterface {
        QosInterface {
            name: "wan0".to_string(),
            enabled: true,
            bandwidth_kbps: Some(100_000),
            qdisc: QosQueueDiscipline::Cake,
            diffserv: QosDiffservMode::Diffserv4,
            nat_aware: true,
            wash: true,
        }
    }

    #[test]
    fn cake_args_include_bandwidth_diffserv_and_nat() {
        assert_eq!(
            qdisc_replace_args(&cake_iface()),
            vec![
                "qdisc",
                "replace",
                "dev",
                "wan0",
                "root",
                "cake",
                "bandwidth",
                "100000kbit",
                "diffserv4",
                "nat",
                "wash",
            ]
        );
    }

    #[test]
    fn fq_codel_args_ignore_cake_options() {
        let mut iface = cake_iface();
        iface.qdisc = QosQueueDiscipline::FqCodel;

        assert_eq!(
            qdisc_replace_args(&iface),
            vec!["qdisc", "replace", "dev", "wan0", "root", "fq_codel"]
        );
    }
}
