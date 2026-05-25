use anyhow::{bail, Context, Result};
use chrono::Utc;
use serde::Serialize;
use serde_json::Value;
use tokio::process::Command;

const MAX_COMMAND_OUTPUT_LINES: usize = 20;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OstreeDeployment {
    pub id: Option<String>,
    pub os_name: Option<String>,
    pub version: Option<String>,
    pub checksum: Option<String>,
    pub origin: Option<String>,
    pub booted: bool,
    pub staged: bool,
    pub pinned: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OstreeStatus {
    pub supported: bool,
    pub checked_at: String,
    pub current_deployment: Option<OstreeDeployment>,
    pub staged_deployment: Option<OstreeDeployment>,
    pub available_update: Option<OstreeDeployment>,
    pub update_available: bool,
    pub reboot_required: bool,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OstreeActionResult {
    pub operation: &'static str,
    pub success: bool,
    pub message: String,
    pub details: Vec<String>,
    pub status: OstreeStatus,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OstreeRebootState {
    pub supported: bool,
    pub reboot_required: bool,
    pub update_available: bool,
    pub current_version: Option<String>,
    pub target_version: Option<String>,
    pub checked_at: String,
    pub last_error: Option<String>,
}

pub async fn status() -> OstreeStatus {
    match run_status_command().await {
        Ok(stdout) => match parse_status_payload(&stdout) {
            Ok(status) => status,
            Err(err) => OstreeStatus {
                supported: true,
                checked_at: Utc::now().to_rfc3339(),
                current_deployment: None,
                staged_deployment: None,
                available_update: None,
                update_available: false,
                reboot_required: false,
                last_error: Some(format!("failed to parse rpm-ostree status JSON: {err:#}")),
            },
        },
        Err(err) if is_command_not_found(&err) => unsupported_status(err),
        Err(err) => OstreeStatus {
            supported: true,
            checked_at: Utc::now().to_rfc3339(),
            current_deployment: None,
            staged_deployment: None,
            available_update: None,
            update_available: false,
            reboot_required: false,
            last_error: Some(format!("failed to query rpm-ostree status: {err:#}")),
        },
    }
}

pub async fn reboot_state() -> OstreeRebootState {
    let status = status().await;
    OstreeRebootState {
        supported: status.supported,
        reboot_required: status.reboot_required,
        update_available: status.update_available,
        current_version: status
            .current_deployment
            .as_ref()
            .and_then(|d| d.version.as_deref().map(str::to_string)),
        target_version: status
            .available_update
            .as_ref()
            .and_then(|d| d.version.as_deref().map(str::to_string)),
        checked_at: status.checked_at,
        last_error: status.last_error,
    }
}

pub async fn check_for_updates() -> Result<OstreeActionResult> {
    let command = run_rpm_ostree(&["upgrade", "--check"]).await?;
    let status = status().await;
    Ok(OstreeActionResult {
        operation: "check",
        success: command.success && status.supported && status.last_error.is_none(),
        message: if status.supported {
            if status.update_available {
                "OSTree updates checked: update available".to_string()
            } else {
                "OSTree updates checked: system is up to date".to_string()
            }
        } else {
            "rpm-ostree is not available on this appliance image".to_string()
        },
        details: command.details,
        status,
    })
}

pub async fn stage_update() -> Result<OstreeActionResult> {
    let command = run_rpm_ostree(&["upgrade", "--download-only"]).await?;
    let status = status().await;
    Ok(OstreeActionResult {
        operation: "stage",
        success: command.success && status.supported && status.last_error.is_none(),
        message: if command.success {
            "OSTree update assets downloaded".to_string()
        } else {
            "OSTree update staging failed".to_string()
        },
        details: command.details,
        status,
    })
}

pub async fn apply_update() -> Result<OstreeActionResult> {
    let command = run_rpm_ostree(&["upgrade"]).await?;
    let status = status().await;
    let message = if status.reboot_required {
        "OSTree update applied and staged for reboot".to_string()
    } else {
        "OSTree update apply completed".to_string()
    };
    Ok(OstreeActionResult {
        operation: "apply",
        success: command.success && status.supported && status.last_error.is_none(),
        message,
        details: command.details,
        status,
    })
}

struct CommandOutcome {
    success: bool,
    details: Vec<String>,
}

async fn run_status_command() -> Result<String> {
    let output = Command::new("rpm-ostree")
        .arg("status")
        .arg("--json")
        .output()
        .await
        .context("failed to execute `rpm-ostree status --json`")?;

    if !output.status.success() {
        bail!(
            "`rpm-ostree status --json` failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    String::from_utf8(output.stdout).context("rpm-ostree status output is not valid UTF-8")
}

async fn run_rpm_ostree(args: &[&str]) -> Result<CommandOutcome> {
    let output = Command::new("rpm-ostree")
        .args(args)
        .output()
        .await
        .with_context(|| format!("failed to execute `rpm-ostree {}`", args.join(" ")))?;

    if !output.status.success() {
        bail!(
            "`rpm-ostree {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(CommandOutcome {
        success: true,
        details: summarize_output(&output.stdout, &output.stderr),
    })
}

fn summarize_output(stdout: &[u8], stderr: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(stdout)
        .lines()
        .chain(String::from_utf8_lossy(stderr).lines())
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .take(MAX_COMMAND_OUTPUT_LINES)
        .map(str::to_string)
        .collect()
}

fn unsupported_status(err: anyhow::Error) -> OstreeStatus {
    OstreeStatus {
        supported: false,
        checked_at: Utc::now().to_rfc3339(),
        current_deployment: None,
        staged_deployment: None,
        available_update: None,
        update_available: false,
        reboot_required: false,
        last_error: Some(format!("rpm-ostree command unavailable: {err:#}")),
    }
}

fn is_command_not_found(err: &anyhow::Error) -> bool {
    err.to_string().contains("No such file or directory")
}

fn parse_status_payload(payload: &str) -> Result<OstreeStatus> {
    let value: Value = serde_json::from_str(payload).context("invalid JSON")?;
    let deployments = value
        .get("deployments")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let parsed: Vec<OstreeDeployment> = deployments
        .iter()
        .map(parse_deployment)
        .collect::<Result<Vec<_>>>()?;

    let current = parsed.iter().find(|deployment| deployment.booted).cloned();
    let staged = parsed.iter().find(|deployment| deployment.staged).cloned();
    let fallback_candidate = parsed
        .iter()
        .find(|deployment| !deployment.booted)
        .cloned();
    let staged_deployment = staged.or(fallback_candidate);

    let cached_update = value
        .get("cached-update")
        .or_else(|| value.get("cached_update"))
        .map(parse_deployment)
        .transpose()?;

    let current_version = current.as_ref().and_then(|deployed| deployed.version.as_ref());
    let first_non_booted = parsed.into_iter().find(|deployment| !deployment.booted);
    let candidate_update = staged_deployment
        .clone()
        .or(first_non_booted)
        .or(cached_update);
    let available_update = candidate_update.filter(|candidate| {
        current_version.map(|version| version.as_str()) != candidate.version.as_deref()
    });

    Ok(OstreeStatus {
        supported: true,
        checked_at: Utc::now().to_rfc3339(),
        current_deployment: current,
        staged_deployment: staged_deployment.clone(),
        update_available: available_update.is_some(),
        reboot_required: staged_deployment.is_some(),
        available_update,
        last_error: None,
    })
}

fn parse_deployment(value: &Value) -> Result<OstreeDeployment> {
    let object = value
        .as_object()
        .context("deployment entry is not an object")?;
    let string_field = |key: &str| object.get(key).and_then(Value::as_str).map(str::to_string);
    let bool_field = |key: &str| object.get(key).and_then(Value::as_bool).unwrap_or(false);

    Ok(OstreeDeployment {
        id: string_field("id"),
        // rpm-ostree has used `osname` in JSON output; tolerate `os_name` for
        // compatibility with tooling/fixtures that normalize snake_case.
        os_name: string_field("osname").or_else(|| string_field("os_name")),
        version: string_field("version"),
        checksum: string_field("checksum"),
        origin: string_field("origin"),
        booted: bool_field("booted"),
        staged: bool_field("staged"),
        pinned: bool_field("pinned"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_status_finds_booted_and_staged_deployments() {
        let payload = r#"
        {
          "deployments": [
            {
              "id": "deployed",
              "osname": "dayshield",
              "version": "1.0.0",
              "checksum": "abc",
              "origin": "prod",
              "booted": true
            },
            {
              "id": "staged",
              "osname": "dayshield",
              "version": "1.1.0",
              "checksum": "def",
              "origin": "prod",
              "staged": true
            }
          ]
        }
        "#;

        let status = parse_status_payload(payload).expect("status should parse");
        assert!(status.supported);
        assert_eq!(
            status.current_deployment.and_then(|deployment| deployment.version),
            Some("1.0.0".to_string())
        );
        assert_eq!(
            status.available_update.and_then(|deployment| deployment.version),
            Some("1.1.0".to_string())
        );
        assert!(status.reboot_required);
        assert!(status.update_available);
    }

    #[test]
    fn parse_status_uses_cached_update_when_no_staged_deployment_exists() {
        let payload = r#"
        {
          "deployments": [
            {
              "id": "deployed",
              "version": "1.0.0",
              "checksum": "abc",
              "booted": true
            }
          ],
          "cached-update": {
            "id": "cached",
            "version": "1.2.0",
            "checksum": "ghi"
          }
        }
        "#;

        let status = parse_status_payload(payload).expect("status should parse");
        assert_eq!(
            status.available_update.and_then(|deployment| deployment.version),
            Some("1.2.0".to_string())
        );
        assert!(status.update_available);
    }

    #[test]
    fn parse_status_does_not_report_cached_update_when_version_matches_current() {
        let payload = r#"
        {
          "deployments": [
            {
              "id": "deployed",
              "version": "1.0.0",
              "checksum": "abc",
              "booted": true
            }
          ],
          "cached-update": {
            "id": "cached",
            "version": "1.0.0",
            "checksum": "ghi"
          }
        }
        "#;

        let status = parse_status_payload(payload).expect("status should parse");
        assert!(status.available_update.is_none());
        assert!(!status.update_available);
        assert!(!status.reboot_required);
    }
}
