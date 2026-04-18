use anyhow::{Context, Result};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use clap::Parser;
use shared::{
    AgentHealth, AgentRuntimeConfig, HealthPayload, JobAcceptance, JobRecord, JobStatus,
    JobSubmission, LogSource, MaintenanceAction, MetricsPayload,
};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use sysinfo::System;
use tokio::net::TcpListener;
use tracing::info;
use uuid::Uuid;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "examples/agent.json")]
    config: PathBuf,
}

#[derive(Clone)]
struct AppState {
    config: AgentRuntimeConfig,
    jobs: Arc<RwLock<HashMap<Uuid, JobRecord>>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let args = Args::parse();
    let config = load_config(&args.config)?;

    let state = AppState {
        config: config.clone(),
        jobs: Arc::new(RwLock::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/jobs", post(submit_job))
        .route("/jobs/:id", get(get_job))
        .with_state(state);

    let listener = TcpListener::bind(&config.listen_addr)
        .await
        .with_context(|| format!("failed to bind {}", config.listen_addr))?;

    info!(
        "agent {} listening on {}",
        config.agent_id, config.listen_addr
    );
    axum::serve(listener, app).await?;
    Ok(())
}

fn load_config(path: &PathBuf) -> Result<AgentRuntimeConfig> {
    let content =
        fs::read_to_string(path).with_context(|| format!("failed reading {}", path.display()))?;
    serde_json::from_str(&content).context("invalid agent config")
}

async fn health(State(state): State<AppState>) -> Json<AgentHealth> {
    Json(AgentHealth {
        online: true,
        status: "online".to_owned(),
        detail: format!("agent {} ready", state.config.agent_id),
        last_seen: Utc::now(),
    })
}

async fn submit_job(
    State(state): State<AppState>,
    Json(submission): Json<JobSubmission>,
) -> Result<Json<JobAcceptance>, (StatusCode, String)> {
    let job_id = Uuid::new_v4();
    let record = JobRecord {
        job_id,
        agent_id: submission.agent_id.clone(),
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
) -> Result<Json<JobRecord>, (StatusCode, String)> {
    let job = state
        .jobs
        .read()
        .unwrap()
        .get(&id)
        .cloned()
        .ok_or((StatusCode::NOT_FOUND, "job not found".to_owned()))?;
    Ok(Json(job))
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

    let outcome = execute_action(&state.config, &submission.action).await;
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
                job.details = serde_json::json!({ "error": err.to_string() });
            }
        }
    }
}

async fn execute_action(
    config: &AgentRuntimeConfig,
    action: &MaintenanceAction,
) -> Result<(String, serde_json::Value)> {
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
    }
}
