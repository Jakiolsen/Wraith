use anyhow::{Context, Result};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use chrono::Utc;
use clap::Parser;
use reqwest::Client as HttpClient;
use shared::{
    sha256_hex_bytes, AgentCommandKind, AgentCommandSpec, AgentHealth, AgentHeartbeatRequest,
    AgentHeartbeatResponse, AgentRegistrationRequest, AgentRegistrationResponse,
    AgentRuntimeConfig, AgentRuntimeState, HealthPayload, JobAcceptance, JobRecord, JobStatus,
    JobSubmission, LogSource, MaintenanceAction, MetricsPayload,
};
use std::collections::HashMap;
use std::fs;
use std::path::{Component, Path as StdPath, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use sysinfo::System;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "examples/agent.json")]
    config: PathBuf,
}

#[derive(Clone)]
struct AppState {
    config: AgentRuntimeConfig,
    runtime_state: Arc<RwLock<Option<AgentRuntimeState>>>,
    jobs: Arc<RwLock<HashMap<Uuid, JobRecord>>>,
    active_command_counts: Arc<RwLock<HashMap<String, usize>>>,
    http: HttpClient,
    state_path: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let args = Args::parse();
    let config = load_config(&args.config)?;
    validate_config(&config)?;
    let state_path = state_path_for_config(&args.config, &config);
    let runtime_state = load_runtime_state(&state_path)?;

    let state = AppState {
        config: config.clone(),
        runtime_state: Arc::new(RwLock::new(runtime_state)),
        jobs: Arc::new(RwLock::new(HashMap::new())),
        active_command_counts: Arc::new(RwLock::new(HashMap::new())),
        http: HttpClient::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .context("failed to build HTTP client")?,
        state_path,
    };

    bootstrap_agent(&state).await?;

    let heartbeat_state = state.clone();
    tokio::spawn(async move {
        heartbeat_loop(heartbeat_state).await;
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/jobs", post(submit_job))
        .route("/jobs/:id", get(get_job))
        .with_state(state.clone());

    let listener = TcpListener::bind(&config.listen_addr)
        .await
        .with_context(|| format!("failed to bind {}", config.listen_addr))?;

    info!(
        "agent {} listening on {}",
        current_agent_id(&state),
        config.listen_addr
    );
    axum::serve(listener, app).await?;
    Ok(())
}

fn load_config(path: &PathBuf) -> Result<AgentRuntimeConfig> {
    let content =
        fs::read_to_string(path).with_context(|| format!("failed reading {}", path.display()))?;
    serde_json::from_str(&content).context("invalid agent config")
}

fn validate_config(config: &AgentRuntimeConfig) -> Result<()> {
    let mut seen = HashMap::new();
    for command in &config.commands {
        if seen.insert(command.id.clone(), true).is_some() {
            anyhow::bail!("duplicate command id `{}`", command.id);
        }
        validate_command_spec(command)?;
    }
    Ok(())
}

fn validate_command_spec(command: &AgentCommandSpec) -> Result<()> {
    if command.id.trim().is_empty() {
        anyhow::bail!("command id is required");
    }
    if command.description.trim().is_empty() {
        anyhow::bail!("description is required for command `{}`", command.id);
    }
    if command.concurrency_limit == 0 {
        anyhow::bail!("command `{}` concurrency_limit must be at least 1", command.id);
    }

    match command.kind {
        AgentCommandKind::ShellCommand => {
            if command.program.trim().is_empty() {
                anyhow::bail!("command `{}` is missing program", command.id);
            }
        }
        AgentCommandKind::FileCollection => {
            if command.base_directory.as_deref().unwrap_or("").trim().is_empty() {
                anyhow::bail!("file collection command `{}` needs base_directory", command.id);
            }
            if !command.allow_args && command.source_path.as_deref().unwrap_or("").trim().is_empty() {
                anyhow::bail!(
                    "file collection command `{}` needs source_path when allow_args is false",
                    command.id
                );
            }
        }
    }

    Ok(())
}

fn state_path_for_config(config_path: &StdPath, config: &AgentRuntimeConfig) -> PathBuf {
    if let Some(path) = &config.state_path {
        return PathBuf::from(path);
    }
    config_path.with_extension("state.json")
}

fn load_runtime_state(path: &StdPath) -> Result<Option<AgentRuntimeState>> {
    if !path.exists() {
        return Ok(None);
    }
    let content =
        fs::read_to_string(path).with_context(|| format!("failed reading {}", path.display()))?;
    serde_json::from_str(&content)
        .map(Some)
        .context("invalid agent runtime state")
}

fn persist_runtime_state(path: &StdPath, state: &AgentRuntimeState) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed creating {}", parent.display()))?;
    }
    fs::write(path, serde_json::to_vec_pretty(state)?)
        .with_context(|| format!("failed writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

async fn bootstrap_agent(state: &AppState) -> Result<()> {
    if state.runtime_state.read().unwrap().is_some() {
        sync_heartbeat(state).await?;
        return Ok(());
    }

    let control_plane_url = state
        .config
        .control_plane_url
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("control_plane_url is required for registration"))?;
    let bootstrap_token = state
        .config
        .bootstrap_token
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("bootstrap_token is required for first registration"))?;

    let request = AgentRegistrationRequest {
        bootstrap_token: bootstrap_token.to_owned(),
        name: advertised_name(&state.config),
        environment: advertised_environment(&state.config),
        location: advertised_location(&state.config),
        endpoint: advertised_endpoint(&state.config),
        capabilities: advertised_capabilities(&state.config),
        commands: advertised_commands(&state.config),
    };

    let response = state
        .http
        .post(format!("{control_plane_url}/api/v1/agents/register"))
        .json(&request)
        .send()
        .await
        .context("failed calling agent registration endpoint")?
        .error_for_status()
        .context("agent registration rejected by control plane")?
        .json::<AgentRegistrationResponse>()
        .await
        .context("failed decoding agent registration response")?;

    let runtime_state = AgentRuntimeState {
        agent_id: response.agent_id,
        management_token: response.management_token,
        inbound_auth_token: response.inbound_auth_token,
    };
    persist_runtime_state(&state.state_path, &runtime_state)?;
    *state.runtime_state.write().unwrap() = Some(runtime_state);
    sync_heartbeat(state).await?;
    Ok(())
}

async fn heartbeat_loop(state: AppState) {
    loop {
        if let Err(err) = sync_heartbeat(&state).await {
            warn!("agent heartbeat failed: {err}");
        }
        sleep(Duration::from_secs(10)).await;
    }
}

async fn sync_heartbeat(state: &AppState) -> Result<()> {
    let control_plane_url = state
        .config
        .control_plane_url
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("control_plane_url is required"))?;
    let runtime_state = state
        .runtime_state
        .read()
        .unwrap()
        .clone()
        .ok_or_else(|| anyhow::anyhow!("agent is not registered"))?;

    let request = AgentHeartbeatRequest {
        agent_id: runtime_state.agent_id.clone(),
        management_token: runtime_state.management_token.clone(),
        endpoint: advertised_endpoint(&state.config),
        capabilities: advertised_capabilities(&state.config),
        commands: advertised_commands(&state.config),
    };

    let response = state
        .http
        .post(format!("{control_plane_url}/api/v1/agents/heartbeat"))
        .json(&request)
        .send()
        .await
        .context("failed calling heartbeat endpoint")?
        .error_for_status()
        .context("control plane rejected agent heartbeat")?
        .json::<AgentHeartbeatResponse>()
        .await
        .context("failed decoding heartbeat response")?;

    if !response.accepted {
        anyhow::bail!("control plane did not accept heartbeat");
    }

    let mut updated_state = runtime_state;
    updated_state.inbound_auth_token = response.inbound_auth_token;
    persist_runtime_state(&state.state_path, &updated_state)?;
    *state.runtime_state.write().unwrap() = Some(updated_state);

    if !response.enabled {
        warn!("agent is registered but currently disabled");
    }

    Ok(())
}

fn current_agent_id(state: &AppState) -> String {
    state
        .runtime_state
        .read()
        .unwrap()
        .as_ref()
        .map(|runtime| runtime.agent_id.clone())
        .unwrap_or_else(|| state.config.agent_id.clone())
}

fn advertised_name(config: &AgentRuntimeConfig) -> String {
    config
        .advertised_name
        .clone()
        .unwrap_or_else(|| config.agent_id.clone())
}

fn advertised_environment(config: &AgentRuntimeConfig) -> String {
    config
        .environment
        .clone()
        .unwrap_or_else(|| "default".to_owned())
}

fn advertised_location(config: &AgentRuntimeConfig) -> String {
    config.location.clone().unwrap_or_else(detect_hostname)
}

fn advertised_endpoint(config: &AgentRuntimeConfig) -> String {
    config
        .advertised_base_url
        .clone()
        .unwrap_or_else(|| format!("http://{}", config.listen_addr))
}

fn advertised_capabilities(config: &AgentRuntimeConfig) -> Vec<String> {
    let mut capabilities = vec![
        "health_check".to_owned(),
        "collect_metrics".to_owned(),
        "fetch_logs".to_owned(),
    ];
    if !config.commands.is_empty() {
        capabilities.push("run_command".to_owned());
    }
    if config
        .commands
        .iter()
        .any(|command| command.kind == AgentCommandKind::FileCollection)
    {
        capabilities.push("file_collection".to_owned());
    }
    capabilities
}

fn advertised_commands(config: &AgentRuntimeConfig) -> Vec<String> {
    config.commands.iter().map(|command| command.id.clone()).collect()
}

async fn health(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AgentHealth>, (StatusCode, String)> {
    require_agent_token(&state, &headers)?;

    Ok(Json(AgentHealth {
        online: true,
        status: "online".to_owned(),
        detail: format!("agent {} ready", current_agent_id(&state)),
        last_seen: Utc::now(),
    }))
}

async fn submit_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(submission): Json<JobSubmission>,
) -> Result<Json<JobAcceptance>, (StatusCode, String)> {
    require_agent_token(&state, &headers)?;

    let job_id = Uuid::new_v4();
    let record = JobRecord {
        job_id,
        agent_id: current_agent_id(&state),
        action: submission.action.clone(),
        status: JobStatus::Pending,
        submitted_at: Utc::now(),
        started_at: None,
        completed_at: None,
        summary: "Queued by control plane".to_owned(),
        details: serde_json::json!({ "phase": "queued" }),
    };

    state.jobs.write().unwrap().insert(job_id, record);

    let worker_state = state.clone();
    tokio::spawn(async move {
        run_job(worker_state, job_id, submission).await;
    });

    Ok(Json(JobAcceptance {
        job_id,
        status: JobStatus::Pending,
    }))
}

async fn get_job(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<JobRecord>, (StatusCode, String)> {
    require_agent_token(&state, &headers)?;

    let job = state
        .jobs
        .read()
        .unwrap()
        .get(&id)
        .cloned()
        .ok_or((StatusCode::NOT_FOUND, "job not found".to_owned()))?;
    Ok(Json(job))
}

fn require_agent_token(state: &AppState, headers: &HeaderMap) -> Result<(), (StatusCode, String)> {
    let expected = state
        .runtime_state
        .read()
        .unwrap()
        .as_ref()
        .map(|runtime| runtime.inbound_auth_token.clone())
        .or_else(|| state.config.auth_token.clone());

    let Some(expected) = expected else {
        return Ok(());
    };

    let provided = headers
        .get("x-wraith-agent-token")
        .and_then(|value| value.to_str().ok())
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "missing x-wraith-agent-token header".to_owned(),
        ))?;

    if provided != expected {
        return Err((
            StatusCode::UNAUTHORIZED,
            "invalid x-wraith-agent-token header".to_owned(),
        ));
    }

    Ok(())
}

async fn run_job(state: AppState, job_id: Uuid, submission: JobSubmission) {
    {
        let mut jobs = state.jobs.write().unwrap();
        if let Some(job) = jobs.get_mut(&job_id) {
            job.status = JobStatus::Running;
            job.started_at = Some(Utc::now());
            job.summary = format!("Running {}", job.action.label());
            job.details = serde_json::json!({ "phase": "running" });
        }
    }

    let outcome = execute_action(&state, job_id, &submission.action).await;
    let mut jobs = state.jobs.write().unwrap();
    if let Some(job) = jobs.get_mut(&job_id) {
        job.completed_at = Some(Utc::now());
        match outcome {
            Ok((summary, details)) => {
                job.status = JobStatus::Completed;
                job.summary = summary;
                job.details = details;
            }
            Err(err) => {
                job.status = JobStatus::Failed;
                job.summary = "Job failed".to_owned();
                job.details = serde_json::from_str::<serde_json::Value>(&err.to_string())
                    .unwrap_or_else(|_| serde_json::json!({ "error": err.to_string() }));
            }
        }
    }
}

async fn execute_action(
    state: &AppState,
    job_id: Uuid,
    action: &MaintenanceAction,
) -> Result<(String, serde_json::Value)> {
    let config = &state.config;
    match action {
        MaintenanceAction::HealthCheck => {
            let payload = HealthPayload {
                hostname: System::host_name().unwrap_or_else(|| "unknown".to_owned()),
                uptime_seconds: System::uptime(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
            };
            Ok((
                "Health check completed".to_owned(),
                serde_json::to_value(payload)?,
            ))
        }
        MaintenanceAction::CollectMetrics => {
            let mut system = System::new_all();
            system.refresh_all();
            let payload = MetricsPayload {
                cpu_usage_percent: system.global_cpu_usage(),
                used_memory_mb: system.used_memory() / 1024 / 1024,
                total_memory_mb: system.total_memory() / 1024 / 1024,
                used_swap_mb: system.used_swap() / 1024 / 1024,
                process_count: system.processes().len(),
            };
            Ok((
                "Metrics collected".to_owned(),
                serde_json::to_value(payload)?,
            ))
        }
        MaintenanceAction::FetchLogs { source, lines } => {
            let key = match source {
                LogSource::Application => "application",
                LogSource::Audit => "audit",
            };
            let path = config
                .log_sources
                .get(key)
                .with_context(|| format!("log source `{key}` not configured"))?;
            let content = tokio::fs::read_to_string(path)
                .await
                .with_context(|| format!("failed reading {path}"))?;
            let tail = content
                .lines()
                .rev()
                .take(*lines)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join("\n");

            Ok((
                format!("Fetched {lines} lines from {key}"),
                serde_json::json!({ "path": path, "tail": tail }),
            ))
        }
        MaintenanceAction::RunCommand { command_id, args } => {
            let command = config
                .commands
                .iter()
                .find(|command| command.id == *command_id)
                .with_context(|| format!("unknown command `{command_id}`"))?;
            validate_command_runtime(command, args)?;
            let _slot = acquire_command_slot(state, command)?;
            match command.kind {
                AgentCommandKind::ShellCommand => {
                    execute_command(state, job_id, command, args).await
                }
                AgentCommandKind::FileCollection => execute_file_collection(command, args).await,
            }
        }
    }
}

fn validate_command_runtime(command: &AgentCommandSpec, runtime_args: &[String]) -> Result<()> {
    let current_os = std::env::consts::OS;
    if !command.supported_platforms.is_empty()
        && !command.supported_platforms.iter().any(|platform| platform == current_os)
    {
        anyhow::bail!(
            "command `{}` is not supported on `{}`",
            command.id,
            current_os
        );
    }

    if !command.allow_args && !runtime_args.is_empty() {
        anyhow::bail!("command `{}` does not accept runtime arguments", command.id);
    }

    if !command.arg_schema.is_empty() {
        if runtime_args.len() > command.arg_schema.len() {
            anyhow::bail!("command `{}` received too many arguments", command.id);
        }

        for (index, spec) in command.arg_schema.iter().enumerate() {
            let arg = runtime_args.get(index);
            if spec.required && arg.is_none() {
                anyhow::bail!("command `{}` missing required arg `{}`", command.id, spec.name);
            }
            if let Some(arg) = arg {
                if !spec.allowed_values.is_empty() && !spec.allowed_values.iter().any(|value| value == arg) {
                    anyhow::bail!(
                        "argument `{}` for command `{}` must be one of: {}",
                        spec.name,
                        command.id,
                        spec.allowed_values.join(", ")
                    );
                }
            }
        }
    }

    Ok(())
}

struct CommandSlot {
    counts: Arc<RwLock<HashMap<String, usize>>>,
    command_id: String,
}

impl Drop for CommandSlot {
    fn drop(&mut self) {
        let mut counts = self.counts.write().unwrap();
        if let Some(count) = counts.get_mut(&self.command_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&self.command_id);
            }
        }
    }
}

fn acquire_command_slot(state: &AppState, command: &AgentCommandSpec) -> Result<CommandSlot> {
    let mut counts = state.active_command_counts.write().unwrap();
    let active = counts.entry(command.id.clone()).or_insert(0);
    if *active >= command.concurrency_limit {
        anyhow::bail!(
            "command `{}` reached concurrency limit {}",
            command.id,
            command.concurrency_limit
        );
    }
    *active += 1;
    Ok(CommandSlot {
        counts: state.active_command_counts.clone(),
        command_id: command.id.clone(),
    })
}

fn redacted_runtime_args(command: &AgentCommandSpec, runtime_args: &[String]) -> Vec<String> {
    runtime_args
        .iter()
        .enumerate()
        .map(|(index, arg)| {
            if command
                .arg_schema
                .get(index)
                .is_some_and(|spec| spec.redacted)
            {
                "***".to_owned()
            } else {
                arg.clone()
            }
        })
        .collect()
}

async fn execute_command(
    state: &AppState,
    job_id: Uuid,
    command: &AgentCommandSpec,
    runtime_args: &[String],
) -> Result<(String, serde_json::Value)> {
    let mut process = Command::new(&command.program);
    process.kill_on_drop(true);
    process
        .args(&command.args)
        .args(runtime_args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = process
        .spawn()
        .with_context(|| format!("failed spawning `{}`", command.program))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("failed capturing stdout for `{}`", command.id))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("failed capturing stderr for `{}`", command.id))?;
    let (tx, mut rx) = mpsc::unbounded_channel();
    tokio::spawn(read_command_stream(stdout, "stdout", tx.clone()));
    tokio::spawn(read_command_stream(stderr, "stderr", tx));

    let timeout = Duration::from_secs(command.timeout_seconds.max(1));
    let redacted_args = redacted_runtime_args(command, runtime_args);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut stdout_truncated = false;
    let mut stderr_truncated = false;
    let mut wait = Box::pin(child.wait());
    let mut timeout_sleep = Box::pin(tokio::time::sleep(timeout));
    let mut exit_status = None;
    let mut streams_closed = false;

    loop {
        tokio::select! {
            maybe_output = rx.recv(), if !streams_closed => {
                match maybe_output {
                    Some((stream_name, chunk)) => {
                        match stream_name {
                            "stdout" => append_output_chunk(&mut stdout, &chunk, command.max_output_bytes, &mut stdout_truncated),
                            "stderr" => append_output_chunk(&mut stderr, &chunk, command.max_output_bytes, &mut stderr_truncated),
                            _ => {}
                        }
                        update_running_command_job(
                            state,
                            job_id,
                            command,
                            &redacted_args,
                            &stdout,
                            stdout_truncated,
                            &stderr,
                            stderr_truncated,
                        );
                    }
                    None => streams_closed = true,
                }
            }
            status = &mut wait, if exit_status.is_none() => {
                exit_status = Some(status.context("failed waiting for command exit")?);
                if streams_closed {
                    break;
                }
            }
            _ = &mut timeout_sleep => {
                anyhow::bail!("command `{}` timed out after {}s", command.id, timeout.as_secs());
            }
        }

        if exit_status.is_some() && streams_closed {
            break;
        }
    }

    let output_stdout = truncate_bytes(&stdout, command.max_output_bytes);
    let output_stderr = truncate_bytes(&stderr, command.max_output_bytes);
    let status = exit_status.ok_or_else(|| anyhow::anyhow!("command exited without status"))?;
    let succeeded = status.success();
    let summary = if succeeded {
        format!("Command {} completed", command.id)
    } else {
        format!("Command {} failed", command.id)
    };

    let details = serde_json::json!({
        "kind": "shell_command",
        "command_id": command.id,
        "description": command.description,
        "program": command.program,
        "args": command.args,
        "runtime_args": redacted_args,
        "exit_code": status.code(),
        "stdout": output_stdout.0,
        "stdout_truncated": output_stdout.1,
        "stderr": output_stderr.0,
        "stderr_truncated": output_stderr.1,
    });

    if succeeded {
        Ok((summary, details))
    } else {
        anyhow::bail!(details.to_string())
    }
}

async fn read_command_stream(
    mut stream: impl tokio::io::AsyncRead + Unpin,
    stream_name: &'static str,
    tx: mpsc::UnboundedSender<(&'static str, Vec<u8>)>,
) {
    let mut buffer = [0u8; 1024];
    loop {
        match stream.read(&mut buffer).await {
            Ok(0) => break,
            Ok(read) => {
                if tx.send((stream_name, buffer[..read].to_vec())).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

fn append_output_chunk(
    target: &mut Vec<u8>,
    chunk: &[u8],
    limit: usize,
    truncated: &mut bool,
) {
    let remaining = limit.saturating_sub(target.len());
    let copy_len = remaining.min(chunk.len());
    if copy_len > 0 {
        target.extend_from_slice(&chunk[..copy_len]);
    }
    if copy_len < chunk.len() {
        *truncated = true;
    }
}

fn update_running_command_job(
    state: &AppState,
    job_id: Uuid,
    command: &AgentCommandSpec,
    redacted_args: &[String],
    stdout: &[u8],
    stdout_truncated: bool,
    stderr: &[u8],
    stderr_truncated: bool,
) {
    let mut jobs = state.jobs.write().unwrap();
    if let Some(job) = jobs.get_mut(&job_id) {
        job.summary = format!("Streaming output for {}", command.id);
        job.details = serde_json::json!({
            "phase": "running",
            "kind": "shell_command",
            "command_id": command.id,
            "description": command.description,
            "program": command.program,
            "args": command.args,
            "runtime_args": redacted_args,
            "stdout": String::from_utf8_lossy(stdout).to_string(),
            "stdout_truncated": stdout_truncated,
            "stderr": String::from_utf8_lossy(stderr).to_string(),
            "stderr_truncated": stderr_truncated,
        });
    }
}

async fn execute_file_collection(
    command: &AgentCommandSpec,
    runtime_args: &[String],
) -> Result<(String, serde_json::Value)> {
    let resolved = resolve_file_collection_path(command, runtime_args)?;
    let bytes = tokio::fs::read(&resolved)
        .await
        .with_context(|| format!("failed reading {}", resolved.display()))?;
    let truncated = bytes.len() > command.max_output_bytes;
    let body = &bytes[..bytes.len().min(command.max_output_bytes)];
    let redacted_args = redacted_runtime_args(command, runtime_args);

    Ok((
        format!("Collected file {}", resolved.display()),
        serde_json::json!({
            "kind": "file_collection",
            "command_id": command.id,
            "description": command.description,
            "path": resolved.display().to_string(),
            "size_bytes": bytes.len(),
            "sha256": sha256_hex_bytes(&bytes),
            "content_base64": base64::engine::general_purpose::STANDARD.encode(body),
            "content_truncated": truncated,
            "runtime_args": redacted_args,
        }),
    ))
}

fn resolve_file_collection_path(command: &AgentCommandSpec, runtime_args: &[String]) -> Result<PathBuf> {
    let base_directory = PathBuf::from(
        command
            .base_directory
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("file collection command missing base_directory"))?,
    );
    let relative = if let Some(path) = runtime_args.first() {
        path.clone()
    } else {
        command
            .source_path
            .clone()
            .ok_or_else(|| anyhow::anyhow!("file collection command missing source path"))?
    };
    let relative_path = StdPath::new(&relative);
    if relative_path.is_absolute() {
        anyhow::bail!("file collection path must be relative");
    }
    if relative_path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        anyhow::bail!("file collection path may not traverse parent directories");
    }
    Ok(base_directory.join(relative_path))
}

fn truncate_bytes(bytes: &[u8], limit: usize) -> (String, bool) {
    let truncated = bytes.len() > limit;
    let slice = &bytes[..bytes.len().min(limit)];
    (String::from_utf8_lossy(slice).to_string(), truncated)
}

fn detect_hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown-host".to_owned())
}
