use std::{
    env,
    future::Future,
    io::ErrorKind,
    path::Path,
    pin::Pin,
    sync::{Mutex as StdMutex, OnceLock},
};

use anyhow::{bail, Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
    sync::Mutex as AsyncMutex,
};

const MAX_COMMAND_OUTPUT_LINES: usize = 20;
const DAYSHIELD_OSTREE_HELPER: &str = "/usr/local/lib/dayshield/ostree-update.sh";
const DEFAULT_OSTREE_OS: &str = "dayshield";
const DEFAULT_OSTREE_REMOTE: &str = "dayshield";

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OstreeTransactionState {
    pub active: bool,
    pub state: String,
    pub operation: Option<String>,
    pub source: Option<String>,
    pub started_at: Option<String>,
    pub message: Option<String>,
}

impl OstreeTransactionState {
    fn idle() -> Self {
        Self {
            active: false,
            state: "idle".to_string(),
            operation: None,
            source: None,
            started_at: None,
            message: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OstreeStatus {
    pub supported: bool,
    pub checked_at: String,
    pub current_deployment: Option<OstreeDeployment>,
    pub staged_deployment: Option<OstreeDeployment>,
    pub available_update: Option<OstreeDeployment>,
    pub update_available: bool,
    pub reboot_required: bool,
    pub transaction_state: OstreeTransactionState,
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
    pub transaction_state: OstreeTransactionState,
    pub checked_at: String,
    pub last_error: Option<String>,
}

#[derive(Debug)]
struct ProcessOutput {
    label: String,
    success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

type CommandFuture<'a> = Pin<Box<dyn Future<Output = Result<ProcessOutput>> + Send + 'a>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OstreeCommand {
    Status,
    Check,
    Stage,
    Apply,
}

impl OstreeCommand {
    fn operation_name(self) -> Option<&'static str> {
        match self {
            OstreeCommand::Status => None,
            OstreeCommand::Check => Some("check"),
            OstreeCommand::Stage => Some("stage"),
            OstreeCommand::Apply => Some("apply"),
        }
    }
}

trait OstreeRunner: Send + Sync {
    fn run(&self, command: OstreeCommand) -> CommandFuture<'_>;
}

struct SystemOstreeRunner;

impl OstreeRunner for SystemOstreeRunner {
    fn run(&self, command: OstreeCommand) -> CommandFuture<'_> {
        Box::pin(async move {
            let invocation = system_ostree_invocation(command);
            match command.operation_name() {
                Some(operation) => run_command_with_live_update_logs(invocation, operation).await,
                None => {
                    let output = Command::new(&invocation.program)
                        .args(&invocation.args)
                        .output()
                        .await
                        .with_context(|| format!("failed to execute `{}`", invocation.label))?;

                    Ok(ProcessOutput {
                        label: invocation.label,
                        success: output.status.success(),
                        stdout: output.stdout,
                        stderr: output.stderr,
                    })
                }
            }
        })
    }
}

struct CommandInvocation {
    program: String,
    args: Vec<String>,
    label: String,
}

fn system_ostree_invocation(command: OstreeCommand) -> CommandInvocation {
    if is_executable_file(Path::new(DAYSHIELD_OSTREE_HELPER)) {
        return helper_ostree_invocation(command);
    }

    if let Some(ostree) = known_binary_path("ostree", &["/usr/bin/ostree", "/bin/ostree"]) {
        return native_ostree_invocation(&ostree, command);
    }

    rpm_ostree_invocation(command)
}

fn known_binary_path(command: &str, candidates: &[&str]) -> Option<String> {
    candidates
        .iter()
        .find(|candidate| is_executable_file(Path::new(candidate)))
        .map(|candidate| (*candidate).to_string())
        .or_else(|| {
            env::var_os("PATH").and_then(|path| {
                env::split_paths(&path)
                    .map(|dir| dir.join(command))
                    .find(|candidate| is_executable_file(candidate))
                    .map(|candidate| candidate.to_string_lossy().into_owned())
            })
        })
}

fn is_executable_file(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }

    has_execute_permission(path)
}

#[cfg(unix)]
fn has_execute_permission(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    path.metadata()
        .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn has_execute_permission(_path: &Path) -> bool {
    true
}

fn helper_ostree_invocation(command: OstreeCommand) -> CommandInvocation {
    let action = match command {
        OstreeCommand::Status => "status",
        OstreeCommand::Check => "check",
        OstreeCommand::Stage | OstreeCommand::Apply => "stage",
    };
    CommandInvocation {
        program: DAYSHIELD_OSTREE_HELPER.to_string(),
        args: vec![action.to_string()],
        label: format!("{DAYSHIELD_OSTREE_HELPER} {action}"),
    }
}

fn native_ostree_invocation(program: &str, command: OstreeCommand) -> CommandInvocation {
    let args = match command {
        OstreeCommand::Status => vec!["admin".to_string(), "status".to_string()],
        OstreeCommand::Check => vec!["remote".to_string(), "refs".to_string(), ostree_remote()],
        OstreeCommand::Stage | OstreeCommand::Apply => vec![
            "admin".to_string(),
            "upgrade".to_string(),
            "--os".to_string(),
            ostree_os(),
            "--stage".to_string(),
        ],
    };

    CommandInvocation {
        program: program.to_string(),
        label: command_label(program, &args),
        args,
    }
}

fn rpm_ostree_invocation(command: OstreeCommand) -> CommandInvocation {
    let args = match command {
        OstreeCommand::Status => vec!["status", "--json"],
        OstreeCommand::Check => vec!["upgrade", "--check"],
        OstreeCommand::Stage => vec!["upgrade", "--download-only"],
        OstreeCommand::Apply => vec!["upgrade"],
    }
    .into_iter()
    .map(str::to_string)
    .collect::<Vec<_>>();

    CommandInvocation {
        program: "rpm-ostree".to_string(),
        label: command_label("rpm-ostree", &args),
        args,
    }
}

fn ostree_remote() -> String {
    env::var("DAYSHIELD_OSTREE_REMOTE").unwrap_or_else(|_| DEFAULT_OSTREE_REMOTE.to_string())
}

fn ostree_os() -> String {
    env::var("DAYSHIELD_OSTREE_OS").unwrap_or_else(|_| DEFAULT_OSTREE_OS.to_string())
}

fn command_label(program: &str, args: &[String]) -> String {
    if args.is_empty() {
        program.to_string()
    } else {
        format!("{} {}", program, args.join(" "))
    }
}

async fn run_command_with_live_update_logs(
    invocation: CommandInvocation,
    operation: &'static str,
) -> Result<ProcessOutput> {
    let mut child = Command::new(&invocation.program)
        .args(&invocation.args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to execute `{}`", invocation.label))?;

    let stdout_task = child.stdout.take().map(|stdout| {
        tokio::spawn(async move { collect_and_publish_update_output(stdout, operation).await })
    });
    let stderr_task = child.stderr.take().map(|stderr| {
        tokio::spawn(async move { collect_and_publish_update_output(stderr, operation).await })
    });

    let status = child
        .wait()
        .await
        .with_context(|| format!("failed to wait for `{}`", invocation.label))?;
    let stdout = join_output(stdout_task).await;
    let stderr = join_output(stderr_task).await;

    Ok(ProcessOutput {
        label: invocation.label,
        success: status.success(),
        stdout,
        stderr,
    })
}

async fn join_output(task: Option<tokio::task::JoinHandle<Vec<u8>>>) -> Vec<u8> {
    match task {
        Some(task) => task.await.unwrap_or_default(),
        None => Vec::new(),
    }
}

async fn collect_and_publish_update_output<R>(mut reader: R, operation: &'static str) -> Vec<u8>
where
    R: AsyncRead + Unpin,
{
    let mut collected = Vec::new();
    let mut pending_line = Vec::new();
    let mut buf = [0_u8; 4096];
    let mut last_published: Option<String> = None;

    loop {
        let read = reader.read(&mut buf).await.unwrap_or(0);
        if read == 0 {
            break;
        }

        collected.extend_from_slice(&buf[..read]);
        for byte in &buf[..read] {
            match *byte {
                b'\n' | b'\r' => {
                    publish_update_output_line(operation, &mut pending_line, &mut last_published);
                }
                _ => pending_line.push(*byte),
            }
        }
    }

    publish_update_output_line(operation, &mut pending_line, &mut last_published);
    collected
}

fn publish_update_output_line(
    operation: &'static str,
    pending_line: &mut Vec<u8>,
    last_published: &mut Option<String>,
) {
    let line = String::from_utf8_lossy(pending_line).trim().to_string();
    pending_line.clear();
    if line.is_empty() || last_published.as_deref() == Some(line.as_str()) {
        return;
    }

    *last_published = Some(line.clone());
    crate::live_logs::ui::publish(crate::live_logs::LogEvent::UpdateEvent {
        timestamp: Utc::now().to_rfc3339(),
        operation: operation.to_string(),
        level: classify_command_output_level(&line).to_string(),
        message: line,
        component: Some("rootfs".to_string()),
    });
}

fn classify_command_output_level(line: &str) -> &'static str {
    let lower = line.to_ascii_lowercase();
    if lower.contains("error")
        || lower.contains("failed")
        || lower.contains("failure")
        || lower.contains("mismatch")
    {
        "error"
    } else if lower.contains("warning") || lower.contains("warn") {
        "warning"
    } else {
        "info"
    }
}

#[derive(Debug, Clone)]
struct ActiveOperation {
    operation: &'static str,
    started_at: String,
}

struct ActiveOperationGuard;

impl ActiveOperationGuard {
    fn start(operation: &'static str) -> Self {
        *active_operation_guard() = Some(ActiveOperation {
            operation,
            started_at: Utc::now().to_rfc3339(),
        });
        Self
    }
}

impl Drop for ActiveOperationGuard {
    fn drop(&mut self) {
        *active_operation_guard() = None;
    }
}

static SYSTEM_OSTREE_RUNNER: SystemOstreeRunner = SystemOstreeRunner;

pub async fn status() -> OstreeStatus {
    status_with(&SYSTEM_OSTREE_RUNNER).await
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
        transaction_state: status.transaction_state,
        checked_at: status.checked_at,
        last_error: status.last_error,
    }
}

pub async fn check_for_updates() -> Result<OstreeActionResult> {
    check_for_updates_with(&SYSTEM_OSTREE_RUNNER).await
}

pub async fn stage_update() -> Result<OstreeActionResult> {
    stage_update_with(&SYSTEM_OSTREE_RUNNER).await
}

pub async fn apply_update() -> Result<OstreeActionResult> {
    apply_update_with(&SYSTEM_OSTREE_RUNNER).await
}

async fn status_with(runner: &dyn OstreeRunner) -> OstreeStatus {
    match run_status_command_with(runner).await {
        Ok(stdout) => match parse_status_payload(&stdout) {
            Ok(status) => with_local_transaction_state(status),
            Err(err) => OstreeStatus {
                supported: true,
                checked_at: Utc::now().to_rfc3339(),
                current_deployment: None,
                staged_deployment: None,
                available_update: None,
                update_available: false,
                reboot_required: false,
                transaction_state: local_transaction_state()
                    .unwrap_or_else(OstreeTransactionState::idle),
                last_error: Some(format!("failed to parse OSTree status output: {err:#}")),
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
            transaction_state: local_transaction_state()
                .unwrap_or_else(OstreeTransactionState::idle),
            last_error: Some(format!("failed to query OSTree status: {err:#}")),
        },
    }
}

async fn check_for_updates_with(runner: &dyn OstreeRunner) -> Result<OstreeActionResult> {
    let command = run_ostree_operation_with(runner, "check", OstreeCommand::Check).await?;
    let status = status_with(runner).await;
    Ok(OstreeActionResult {
        operation: "check",
        success: command.success && status.supported && status.last_error.is_none(),
        message: if status.supported {
            if status.update_available {
                "OSTree updates checked: update available".to_string()
            } else {
                "OSTree remote checked: no staged deployment detected".to_string()
            }
        } else {
            "OSTree update tooling is not available on this appliance image".to_string()
        },
        details: command.details,
        status,
    })
}

async fn stage_update_with(runner: &dyn OstreeRunner) -> Result<OstreeActionResult> {
    let command = run_ostree_operation_with(runner, "stage", OstreeCommand::Stage).await?;
    let status = status_with(runner).await;
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

async fn apply_update_with(runner: &dyn OstreeRunner) -> Result<OstreeActionResult> {
    let command = run_ostree_operation_with(runner, "apply", OstreeCommand::Apply).await?;
    let status = status_with(runner).await;
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

async fn run_status_command_with(runner: &dyn OstreeRunner) -> Result<String> {
    let output = runner.run(OstreeCommand::Status).await?;

    if !output.success {
        let detail = command_error_detail(&output);
        if status_error_indicates_uninitialized_sysroot(&detail) {
            return Ok("No deployments.\n".to_string());
        }

        bail!("`{}` failed: {}", output.label, detail);
    }

    String::from_utf8(output.stdout)
        .with_context(|| format!("{} output is not valid UTF-8", output.label))
}

async fn run_ostree_operation_with(
    runner: &dyn OstreeRunner,
    operation: &'static str,
    command: OstreeCommand,
) -> Result<CommandOutcome> {
    let _queue_guard = operation_lock().lock().await;
    let _active_guard = ActiveOperationGuard::start(operation);
    let output = runner.run(command).await?;

    if !output.success {
        bail!(
            "`{}` failed: {}",
            output.label,
            command_error_detail(&output)
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

fn command_error_detail(output: &ProcessOutput) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !stderr.is_empty() {
        return stderr;
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() {
        "command exited unsuccessfully without output".to_string()
    } else {
        stdout
    }
}

fn status_error_indicates_uninitialized_sysroot(detail: &str) -> bool {
    detail.contains("fstatat(ostree/deploy)") || detail.contains("opendir(objects)")
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
        transaction_state: local_transaction_state().unwrap_or_else(OstreeTransactionState::idle),
        last_error: Some(format!("OSTree update command unavailable: {err:#}")),
    }
}

fn is_command_not_found(err: &anyhow::Error) -> bool {
    // Only match on IO-level NotFound errors (spawn failure), not on command output
    // that happens to contain "No such file or directory" (e.g. broken OSTree repo).
    err.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .map(|io_err| io_err.kind() == ErrorKind::NotFound)
            .unwrap_or(false)
    })
}

fn operation_lock() -> &'static AsyncMutex<()> {
    static LOCK: OnceLock<AsyncMutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| AsyncMutex::new(()))
}

fn active_operation_slot() -> &'static StdMutex<Option<ActiveOperation>> {
    static ACTIVE_OPERATION: OnceLock<StdMutex<Option<ActiveOperation>>> = OnceLock::new();
    ACTIVE_OPERATION.get_or_init(|| StdMutex::new(None))
}

fn active_operation_guard() -> std::sync::MutexGuard<'static, Option<ActiveOperation>> {
    active_operation_slot()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn local_transaction_state() -> Option<OstreeTransactionState> {
    active_operation_guard()
        .clone()
        .map(|operation| OstreeTransactionState {
            active: true,
            state: "running".to_string(),
            operation: Some(operation.operation.to_string()),
            source: Some("dayshield".to_string()),
            started_at: Some(operation.started_at),
            message: Some("DayShield OSTree operation is running".to_string()),
        })
}

fn parse_status_payload(payload: &str) -> Result<OstreeStatus> {
    let trimmed = payload.trim();
    if trimmed.is_empty() {
        // Valid repo with no deployments yet (e.g. fresh install before first OSTree deploy).
        return Ok(OstreeStatus {
            supported: true,
            checked_at: Utc::now().to_rfc3339(),
            current_deployment: None,
            staged_deployment: None,
            available_update: None,
            update_available: false,
            reboot_required: false,
            transaction_state: OstreeTransactionState::idle(),
            last_error: None,
        });
    }

    match serde_json::from_str::<Value>(trimmed) {
        Ok(value) => parse_json_status_payload(&value),
        Err(json_err) => parse_admin_status_payload(trimmed).with_context(|| {
            format!("invalid JSON and invalid ostree admin status text: {json_err}")
        }),
    }
}

fn parse_json_status_payload(value: &Value) -> Result<OstreeStatus> {
    let deployments = value
        .get("deployments")
        .or_else(|| value.get("deploymentList"))
        .or_else(|| value.get("deployment_list"))
        .map(parse_deployments)
        .transpose()?
        .unwrap_or_default();

    let current = deployments
        .iter()
        .find(|deployment| deployment.booted)
        .cloned()
        .or_else(|| deployments.first().cloned());
    let staged_from_deployments = deployments
        .iter()
        .find(|deployment| deployment.staged)
        .cloned();
    let staged_from_status = first_named_deployment(
        &value,
        &[
            "staged-deployment",
            "staged_deployment",
            "stagedDeployment",
            "pending-deployment",
            "pending_deployment",
            "pendingDeployment",
        ],
        true,
    )?;
    let staged_deployment = staged_from_deployments.or(staged_from_status);

    let mut update_candidates = Vec::new();
    if let Some(deployment) = staged_deployment.clone() {
        update_candidates.push(deployment);
    }
    update_candidates.extend(named_deployments(
        &value,
        &[
            "cached-update",
            "cached_update",
            "cachedUpdate",
            "available-update",
            "available_update",
            "availableUpdate",
            "update-candidate",
            "update_candidate",
            "updateCandidate",
            "new-deployment",
            "new_deployment",
            "newDeployment",
        ],
        false,
    )?);

    let available_update = update_candidates.into_iter().find(|candidate| {
        deployment_has_identity(candidate)
            && deployment_differs_from_current(candidate, current.as_ref())
    });
    let transaction_state = parse_transaction_state(&value);

    Ok(OstreeStatus {
        supported: true,
        checked_at: Utc::now().to_rfc3339(),
        current_deployment: current,
        staged_deployment: staged_deployment.clone(),
        update_available: available_update.is_some(),
        reboot_required: staged_deployment.is_some(),
        available_update,
        transaction_state,
        last_error: None,
    })
}

fn parse_admin_status_payload(payload: &str) -> Result<OstreeStatus> {
    let mut deployments = Vec::new();

    for line in payload
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        if let Some(deployment) = parse_admin_status_deployment_line(line) {
            deployments.push(deployment);
            continue;
        }

        if let Some(deployment) = deployments.last_mut() {
            apply_admin_status_detail_line(deployment, line);
        }
    }

    if deployments.is_empty() {
        return Ok(OstreeStatus {
            supported: true,
            checked_at: Utc::now().to_rfc3339(),
            current_deployment: None,
            staged_deployment: None,
            available_update: None,
            update_available: false,
            reboot_required: false,
            transaction_state: OstreeTransactionState::idle(),
            last_error: None,
        });
    }

    let booted_index = deployments
        .iter()
        .position(|deployment| deployment.booted)
        .unwrap_or(0);
    if !deployments.iter().any(|deployment| deployment.booted) {
        deployments[0].booted = true;
    }
    if booted_index > 0 {
        deployments[0].staged = true;
    }

    let current = deployments
        .iter()
        .find(|deployment| deployment.booted)
        .cloned()
        .or_else(|| deployments.first().cloned());
    let staged_deployment = deployments
        .iter()
        .find(|deployment| deployment.staged)
        .cloned();
    let available_update = staged_deployment
        .clone()
        .filter(|deployment| deployment_differs_from_current(deployment, current.as_ref()));

    Ok(OstreeStatus {
        supported: true,
        checked_at: Utc::now().to_rfc3339(),
        current_deployment: current,
        staged_deployment: staged_deployment.clone(),
        update_available: available_update.is_some(),
        reboot_required: staged_deployment.is_some(),
        available_update,
        transaction_state: OstreeTransactionState::idle(),
        last_error: None,
    })
}

fn parse_admin_status_deployment_line(line: &str) -> Option<OstreeDeployment> {
    let booted = line.starts_with('*');
    let text = if booted { line[1..].trim() } else { line };
    let lower = text.to_ascii_lowercase();
    if lower.starts_with("version:")
        || lower.starts_with("origin")
        || lower.starts_with("gpg")
        || lower.starts_with("signatures")
    {
        return None;
    }

    let mut parts = text.split_whitespace();
    let os_name = parts.next()?;
    let checksum_raw = parts.next()?;
    if !looks_like_ostree_checksum(checksum_raw) {
        return None;
    }

    Some(OstreeDeployment {
        id: None,
        os_name: Some(os_name.to_string()),
        version: None,
        checksum: Some(normalize_admin_status_checksum(checksum_raw)),
        origin: None,
        booted,
        staged: lower.contains("(staged)")
            || lower.contains("[staged]")
            || lower.contains("pending"),
        pinned: lower.contains("pinned"),
    })
}

fn apply_admin_status_detail_line(deployment: &mut OstreeDeployment, line: &str) {
    let lower = line.to_ascii_lowercase();
    if let Some(value) = line
        .strip_prefix("Version:")
        .or_else(|| line.strip_prefix("version:"))
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        deployment.version = Some(value.to_string());
        return;
    }

    if let Some(value) = line
        .strip_prefix("origin refspec:")
        .or_else(|| line.strip_prefix("Origin refspec:"))
        .or_else(|| line.strip_prefix("origin:"))
        .or_else(|| line.strip_prefix("Origin:"))
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        deployment.origin = Some(value.to_string());
    }

    if lower.contains("pinned") {
        deployment.pinned = true;
    }
}

fn looks_like_ostree_checksum(value: &str) -> bool {
    let checksum = normalize_admin_status_checksum(value);
    checksum.len() >= 8 && checksum.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn normalize_admin_status_checksum(value: &str) -> String {
    value
        .trim_matches(|ch: char| !ch.is_ascii_hexdigit() && ch != '.')
        .split('.')
        .next()
        .unwrap_or(value)
        .to_string()
}

fn with_local_transaction_state(mut status: OstreeStatus) -> OstreeStatus {
    if let Some(transaction_state) = local_transaction_state() {
        status.transaction_state = transaction_state;
    }
    status
}

fn parse_deployments(value: &Value) -> Result<Vec<OstreeDeployment>> {
    match value {
        Value::Array(items) => items.iter().map(parse_deployment).collect(),
        Value::Object(map) => map
            .values()
            .filter(|entry| entry.is_object())
            .map(parse_deployment)
            .collect(),
        Value::Null => Ok(vec![]),
        _ => bail!("deployments entry is not an array or object"),
    }
}

fn named_deployments(
    value: &Value,
    keys: &[&str],
    force_staged: bool,
) -> Result<Vec<OstreeDeployment>> {
    let mut deployments = Vec::new();
    let Some(object) = value.as_object() else {
        return Ok(deployments);
    };

    for key in keys {
        if let Some(candidate) = object.get(*key) {
            deployments.extend(parse_deployment_candidates(candidate, force_staged)?);
        }
    }

    Ok(deployments)
}

fn first_named_deployment(
    value: &Value,
    keys: &[&str],
    force_staged: bool,
) -> Result<Option<OstreeDeployment>> {
    Ok(named_deployments(value, keys, force_staged)?
        .into_iter()
        .next())
}

fn parse_deployment_candidates(value: &Value, force_staged: bool) -> Result<Vec<OstreeDeployment>> {
    match value {
        Value::Null => Ok(vec![]),
        Value::Array(items) => {
            let mut deployments = Vec::new();
            for item in items {
                deployments.extend(parse_deployment_candidates(item, force_staged)?);
            }
            Ok(deployments)
        }
        Value::Object(object) => {
            for key in [
                "deployment",
                "deployments",
                "cached",
                "update",
                "candidate",
                "pending",
            ] {
                if let Some(nested) = object.get(key) {
                    let deployments = parse_deployment_candidates(nested, force_staged)?;
                    if !deployments.is_empty() {
                        return Ok(deployments);
                    }
                }
            }

            let mut deployment = parse_deployment(value)?;
            if force_staged {
                deployment.staged = true;
            }
            Ok(vec![deployment])
        }
        _ => Ok(vec![]),
    }
}

fn parse_deployment(value: &Value) -> Result<OstreeDeployment> {
    let object = value
        .as_object()
        .context("deployment entry is not an object")?;
    let state = string_field_any(object, &["state", "status", "deploymentState"]);

    Ok(OstreeDeployment {
        id: string_field_any(object, &["id", "name", "deployment"]),
        os_name: string_field_any(object, &["osname", "os_name", "os-name", "osName"]),
        version: string_field_any(object, &["version", "base-version", "baseVersion"])
            .or_else(|| nested_string_field_any(object, &["base-commit-meta"], &["version"]))
            .or_else(|| nested_string_field_any(object, &["metadata", "meta"], &["version"])),
        checksum: string_field_any(
            object,
            &[
                "checksum",
                "base-checksum",
                "baseChecksum",
                "commit",
                "ostree-commit",
                "ostreeCommit",
            ],
        ),
        origin: string_field_any(
            object,
            &["origin", "origin-refspec", "originRefspec", "refspec"],
        )
        .or_else(|| nested_string_field_any(object, &["origin"], &["refspec", "branch", "remote"])),
        booted: bool_field_any(object, &["booted", "isBooted"])
            .unwrap_or_else(|| state_matches(state.as_deref(), &["booted", "current"])),
        staged: bool_field_any(object, &["staged", "pending", "isStaged"])
            .unwrap_or_else(|| state_matches(state.as_deref(), &["staged", "pending"])),
        pinned: bool_field_any(object, &["pinned", "isPinned"]).unwrap_or(false),
    })
}

fn deployment_has_identity(deployment: &OstreeDeployment) -> bool {
    deployment.id.is_some()
        || deployment.os_name.is_some()
        || deployment.version.is_some()
        || deployment.checksum.is_some()
        || deployment.origin.is_some()
}

fn deployment_differs_from_current(
    candidate: &OstreeDeployment,
    current: Option<&OstreeDeployment>,
) -> bool {
    let Some(current) = current else {
        return true;
    };

    if let (Some(candidate_checksum), Some(current_checksum)) =
        (&candidate.checksum, &current.checksum)
    {
        return candidate_checksum != current_checksum;
    }
    if let (Some(candidate_version), Some(current_version)) = (&candidate.version, &current.version)
    {
        return candidate_version != current_version;
    }
    if let (Some(candidate_id), Some(current_id)) = (&candidate.id, &current.id) {
        return candidate_id != current_id;
    }

    true
}

fn parse_transaction_state(value: &Value) -> OstreeTransactionState {
    let Some(transaction) = value
        .get("transaction")
        .or_else(|| value.get("transaction-state"))
        .or_else(|| value.get("transaction_state"))
        .or_else(|| value.get("transactionState"))
    else {
        return OstreeTransactionState::idle();
    };

    transaction_state_from_value(transaction)
}

fn transaction_state_from_value(value: &Value) -> OstreeTransactionState {
    match value {
        Value::Null => OstreeTransactionState::idle(),
        Value::Bool(false) => OstreeTransactionState::idle(),
        Value::Bool(true) => active_transaction_state("running", None, None),
        Value::Number(number) => {
            if number.as_i64() == Some(0) || number.as_u64() == Some(0) {
                OstreeTransactionState::idle()
            } else {
                active_transaction_state("running", Some(number.to_string()), None)
            }
        }
        Value::String(label) => {
            if transaction_label_is_idle(label) {
                OstreeTransactionState::idle()
            } else {
                active_transaction_state("running", Some(label.trim().to_string()), None)
            }
        }
        Value::Array(items) => items
            .iter()
            .find_map(|item| {
                let state = transaction_state_from_value(item);
                state.active.then_some(state)
            })
            .unwrap_or_else(OstreeTransactionState::idle),
        Value::Object(object) => {
            let state = string_field_any(object, &["state", "status", "phase"])
                .unwrap_or_else(|| "running".to_string());
            let operation = string_field_any(
                object,
                &[
                    "operation",
                    "kind",
                    "method",
                    "name",
                    "title",
                    "transaction",
                ],
            );
            let message = string_field_any(object, &["message", "description", "details", "error"]);
            let active =
                bool_field_any(object, &["active", "running", "inProgress", "in_progress"])
                    .unwrap_or_else(|| {
                        !transaction_label_is_idle(&state)
                            || operation.is_some()
                            || message.is_some()
                    });

            if !active {
                return OstreeTransactionState::idle();
            }

            OstreeTransactionState {
                active: true,
                state,
                operation,
                source: Some("ostree".to_string()),
                started_at: string_field_any(object, &["startedAt", "started_at", "startTime"]),
                message,
            }
        }
    }
}

fn active_transaction_state(
    state: &str,
    operation: Option<String>,
    message: Option<String>,
) -> OstreeTransactionState {
    OstreeTransactionState {
        active: true,
        state: state.to_string(),
        operation,
        source: Some("ostree".to_string()),
        started_at: None,
        message,
    }
}

fn transaction_label_is_idle(label: &str) -> bool {
    matches!(
        label.trim().to_ascii_lowercase().as_str(),
        "" | "none" | "null" | "idle" | "inactive" | "no transaction" | "complete" | "completed"
    )
}

fn string_field_any(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(json_value_to_string))
}

fn nested_string_field_any(
    object: &Map<String, Value>,
    object_keys: &[&str],
    field_keys: &[&str],
) -> Option<String> {
    object_keys.iter().find_map(|object_key| {
        object
            .get(*object_key)
            .and_then(Value::as_object)
            .and_then(|nested| string_field_any(nested, field_keys))
    })
}

fn bool_field_any(object: &Map<String, Value>, keys: &[&str]) -> Option<bool> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(json_value_to_bool))
}

fn json_value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => non_empty_string(value),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Object(object) => string_field_any(
            object,
            &[
                "value", "refspec", "branch", "remote", "checksum", "version", "id", "name",
            ],
        )
        .or_else(|| Some(Value::Object(object.clone()).to_string())),
        Value::Array(items) => {
            let values = items
                .iter()
                .filter_map(json_value_to_string)
                .collect::<Vec<_>>();
            (!values.is_empty()).then(|| values.join(","))
        }
        Value::Null => None,
    }
}

fn non_empty_string(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn json_value_to_bool(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(value) => Some(*value),
        Value::Number(value) => value
            .as_i64()
            .map(|number| number != 0)
            .or_else(|| value.as_u64().map(|number| number != 0)),
        Value::String(value) => match value.trim().to_ascii_lowercase().as_str() {
            "true" | "yes" | "y" | "1" | "on" | "booted" | "staged" | "pending" => Some(true),
            "false" | "no" | "n" | "0" | "off" | "none" | "idle" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

fn state_matches(state: Option<&str>, expected: &[&str]) -> bool {
    let Some(state) = state else {
        return false;
    };
    let normalized = state.trim().to_ascii_lowercase();
    expected
        .iter()
        .any(|candidate| normalized == *candidate || normalized.contains(candidate))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::VecDeque,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };
    use tokio::time::{sleep, Duration};

    enum MockStep {
        Output(ProcessOutput),
        MissingCommand,
    }

    struct MockRunner {
        steps: StdMutex<VecDeque<MockStep>>,
    }

    impl MockRunner {
        fn new(steps: Vec<MockStep>) -> Self {
            Self {
                steps: StdMutex::new(VecDeque::from(steps)),
            }
        }
    }

    impl OstreeRunner for MockRunner {
        fn run(&self, _command: OstreeCommand) -> CommandFuture<'_> {
            let step = self
                .steps
                .lock()
                .unwrap()
                .pop_front()
                .expect("mock OSTree response missing");
            Box::pin(async move {
                match step {
                    MockStep::Output(output) => Ok(output),
                    MockStep::MissingCommand => Err(std::io::Error::new(
                        ErrorKind::NotFound,
                        "mock OSTree command missing",
                    )
                    .into()),
                }
            })
        }
    }

    struct CountingRunner {
        active_upgrades: AtomicUsize,
        max_active_upgrades: AtomicUsize,
    }

    impl OstreeRunner for CountingRunner {
        fn run(&self, command: OstreeCommand) -> CommandFuture<'_> {
            let is_upgrade = matches!(command, OstreeCommand::Stage | OstreeCommand::Apply);
            let active_upgrades = &self.active_upgrades;
            let max_active_upgrades = &self.max_active_upgrades;
            Box::pin(async move {
                if is_upgrade {
                    let current = active_upgrades.fetch_add(1, Ordering::SeqCst) + 1;
                    loop {
                        let observed = max_active_upgrades.load(Ordering::SeqCst);
                        if current <= observed
                            || max_active_upgrades
                                .compare_exchange(
                                    observed,
                                    current,
                                    Ordering::SeqCst,
                                    Ordering::SeqCst,
                                )
                                .is_ok()
                        {
                            break;
                        }
                    }
                    sleep(Duration::from_millis(10)).await;
                    active_upgrades.fetch_sub(1, Ordering::SeqCst);
                }

                Ok(output(true, status_payload_current_only(), ""))
            })
        }
    }

    fn output(
        success: bool,
        stdout: impl Into<Vec<u8>>,
        stderr: impl Into<Vec<u8>>,
    ) -> ProcessOutput {
        ProcessOutput {
            label: "mock ostree".to_string(),
            success,
            stdout: stdout.into(),
            stderr: stderr.into(),
        }
    }

    fn status_payload_current_only() -> &'static str {
        r#"
        {
          "deployments": [
            {
              "id": "deployed",
              "osname": "dayshield",
              "version": "1.0.0",
              "checksum": "abc",
              "origin": "prod",
              "booted": true
            }
          ],
          "transaction": null
        }
        "#
    }

    #[cfg(unix)]
    #[test]
    fn executable_detection_requires_execute_bit() {
        use std::{fs, os::unix::fs::PermissionsExt};

        let file = tempfile::NamedTempFile::new().expect("temp file");
        fs::set_permissions(file.path(), fs::Permissions::from_mode(0o644))
            .expect("set non-executable permissions");
        assert!(!is_executable_file(file.path()));

        fs::set_permissions(file.path(), fs::Permissions::from_mode(0o755))
            .expect("set executable permissions");
        assert!(is_executable_file(file.path()));
    }

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
            status
                .current_deployment
                .and_then(|deployment| deployment.version),
            Some("1.0.0".to_string())
        );
        assert_eq!(
            status
                .available_update
                .and_then(|deployment| deployment.version),
            Some("1.1.0".to_string())
        );
        assert!(status.reboot_required);
        assert!(status.update_available);
        assert!(!status.transaction_state.active);
    }

    #[test]
    fn parse_status_accepts_ostree_admin_status_text() {
        let payload = r#"
  dayshield def4567890abcdef.0
      Version: 1.1.0
      origin refspec: dayshield:dayshield/amd64
* dayshield abc1234567890def.0
      Version: 1.0.0
      origin refspec: dayshield:dayshield/amd64
        "#;

        let status = parse_status_payload(payload).expect("status should parse");

        assert_eq!(
            status
                .current_deployment
                .as_ref()
                .and_then(|deployment| deployment.version.as_deref()),
            Some("1.0.0")
        );
        assert_eq!(
            status
                .available_update
                .as_ref()
                .and_then(|deployment| deployment.version.as_deref()),
            Some("1.1.0")
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
            status
                .available_update
                .and_then(|deployment| deployment.version),
            Some("1.2.0".to_string())
        );
        assert!(status.update_available);
        assert!(!status.reboot_required);
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
            "checksum": "abc"
          }
        }
        "#;

        let status = parse_status_payload(payload).expect("status should parse");
        assert!(status.available_update.is_none());
        assert!(!status.update_available);
        assert!(!status.reboot_required);
    }

    #[test]
    fn parse_status_ignores_non_staged_rollback_deployment_for_reboot_required() {
        let payload = r#"
        {
          "deployments": [
            {
              "id": "current",
              "version": "1.1.0",
              "checksum": "def",
              "booted": true
            },
            {
              "id": "rollback",
              "version": "1.0.0",
              "checksum": "abc",
              "booted": false
            }
          ]
        }
        "#;

        let status = parse_status_payload(payload).expect("status should parse");
        assert!(!status.reboot_required);
        assert!(!status.update_available);
    }

    #[test]
    fn parse_status_accepts_nested_update_and_transaction_variants() {
        let payload = r#"
        {
          "deployments": {
            "0": {
              "id": "current",
              "os-name": "dayshield",
              "base-commit-meta": { "version": "1.0.0" },
              "base-checksum": "abc",
              "booted": "yes"
            }
          },
          "availableUpdate": {
            "deployment": {
              "id": "candidate",
              "baseVersion": "1.1.0",
              "baseChecksum": "def",
              "origin": { "refspec": "dayshield:stable" }
            }
          },
          "transactionState": {
            "state": "downloading",
            "kind": "upgrade",
            "description": "Downloading objects"
          }
        }
        "#;

        let status = parse_status_payload(payload).expect("status should parse");
        assert_eq!(
            status
                .current_deployment
                .and_then(|deployment| deployment.version),
            Some("1.0.0".to_string())
        );
        assert_eq!(
            status
                .available_update
                .and_then(|deployment| deployment.version),
            Some("1.1.0".to_string())
        );
        assert!(status.transaction_state.active);
        assert_eq!(
            status.transaction_state.operation.as_deref(),
            Some("upgrade")
        );
        assert_eq!(status.transaction_state.state, "downloading");
    }

    #[tokio::test]
    async fn mocked_check_success_no_update() {
        let runner = MockRunner::new(vec![
            MockStep::Output(output(true, "No upgrade available.\n", "")),
            MockStep::Output(output(true, status_payload_current_only(), "")),
        ]);

        let result = check_for_updates_with(&runner)
            .await
            .expect("check should succeed");

        assert!(result.success);
        assert!(!result.status.update_available);
        assert_eq!(result.details, vec!["No upgrade available."]);
    }

    #[tokio::test]
    async fn mocked_stage_success_reports_staged_update() {
        let status_payload = r#"
        {
          "deployments": [
            { "id": "current", "version": "1.0.0", "checksum": "abc", "booted": true },
            { "id": "staged", "version": "1.1.0", "checksum": "def", "staged": true }
          ]
        }
        "#;
        let runner = MockRunner::new(vec![
            MockStep::Output(output(true, "Receiving objects: done\n", "")),
            MockStep::Output(output(true, status_payload, "")),
        ]);

        let result = stage_update_with(&runner)
            .await
            .expect("stage should succeed");

        assert!(result.success);
        assert!(result.status.reboot_required);
        assert_eq!(
            result
                .status
                .available_update
                .and_then(|deployment| deployment.version),
            Some("1.1.0".to_string())
        );
    }

    #[tokio::test]
    async fn mocked_apply_failure_returns_error() {
        let runner = MockRunner::new(vec![MockStep::Output(output(
            false,
            "",
            "error: transaction already in progress",
        ))]);

        let err = apply_update_with(&runner)
            .await
            .expect_err("apply failure should be returned");

        assert!(err.to_string().contains("transaction already in progress"));
    }

    #[tokio::test]
    async fn mocked_command_missing_reports_unsupported_status() {
        let runner = MockRunner::new(vec![MockStep::MissingCommand]);

        let status = status_with(&runner).await;

        assert!(!status.supported);
        assert!(status
            .last_error
            .as_deref()
            .unwrap_or_default()
            .contains("command unavailable"));
    }

    #[tokio::test]
    async fn mocked_uninitialized_sysroot_status_reports_no_deployments() {
        let runner = MockRunner::new(vec![MockStep::Output(output(
            false,
            "",
            "error: loading sysroot: fstatat(ostree/deploy): No such file or directory",
        ))]);

        let status = status_with(&runner).await;

        assert!(status.supported);
        assert!(status.last_error.is_none());
        assert!(status.current_deployment.is_none());
        assert!(!status.update_available);
        assert!(!status.reboot_required);
    }

    #[tokio::test]
    async fn mocked_ostree_transactions_are_serialized() {
        let runner = Arc::new(CountingRunner {
            active_upgrades: AtomicUsize::new(0),
            max_active_upgrades: AtomicUsize::new(0),
        });

        let first = stage_update_with(runner.as_ref());
        let second = stage_update_with(runner.as_ref());
        let (first, second) = tokio::join!(first, second);

        first.expect("first stage should succeed");
        second.expect("second stage should succeed");
        assert_eq!(runner.max_active_upgrades.load(Ordering::SeqCst), 1);
    }
}
