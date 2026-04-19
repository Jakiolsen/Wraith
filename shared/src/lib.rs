use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use uuid::Uuid;

pub mod proto {
    tonic::include_proto!("orchestrator");
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentDescriptor {
    pub id: String,
    pub name: String,
    pub environment: String,
    pub location: String,
    pub base_url: String,
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub command_ids: Vec<String>,
    #[serde(default)]
    pub redirector_token: Option<String>,
    #[serde(default)]
    pub auth_token: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentHealth {
    pub online: bool,
    pub status: String,
    pub detail: String,
    pub last_seen: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogSource {
    Application,
    Audit,
}

impl LogSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Application => "application",
            Self::Audit => "audit",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MaintenanceAction {
    HealthCheck,
    CollectMetrics,
    FetchLogs { source: LogSource, lines: usize },
    RunCommand { command_id: String, args: Vec<String> },
}

impl MaintenanceAction {
    pub fn label(&self) -> String {
        match self {
            Self::HealthCheck => "Health Check".to_owned(),
            Self::CollectMetrics => "Collect Metrics".to_owned(),
            Self::FetchLogs { source, lines } => {
                format!("Fetch {} Logs ({lines})", source.as_str())
            }
            Self::RunCommand { command_id, args } => {
                if args.is_empty() {
                    format!("Run Command ({command_id})")
                } else {
                    format!("Run Command ({command_id} {})", args.join(" "))
                }
            }
        }
    }

    pub fn from_proto(request: &proto::SubmitJobRequest) -> anyhow::Result<Self> {
        let job_type =
            proto::JobType::try_from(request.job_type).unwrap_or(proto::JobType::Unspecified);

        match job_type {
            proto::JobType::HealthCheck => Ok(Self::HealthCheck),
            proto::JobType::CollectMetrics => Ok(Self::CollectMetrics),
            proto::JobType::FetchLogs => {
                let source = match request.log_source.as_str() {
                    "application" | "" => LogSource::Application,
                    "audit" => LogSource::Audit,
                    other => anyhow::bail!("unsupported log source: {other}"),
                };
                Ok(Self::FetchLogs {
                    source,
                    lines: request.log_lines.max(10) as usize,
                })
            }
            proto::JobType::RunCommand => {
                if request.command_id.trim().is_empty() {
                    anyhow::bail!("command_id is required");
                }
                Ok(Self::RunCommand {
                    command_id: request.command_id.clone(),
                    args: request.command_args.clone(),
                })
            }
            proto::JobType::Unspecified => anyhow::bail!("job type is required"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

impl JobStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JobSubmission {
    pub agent_id: String,
    pub action: MaintenanceAction,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JobAcceptance {
    pub job_id: Uuid,
    pub status: JobStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JobRecord {
    pub job_id: Uuid,
    pub agent_id: String,
    pub action: MaintenanceAction,
    pub status: JobStatus,
    pub submitted_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub summary: String,
    pub details: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetricsPayload {
    pub cpu_usage_percent: f32,
    pub used_memory_mb: u64,
    pub total_memory_mb: u64,
    pub used_swap_mb: u64,
    pub process_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HealthPayload {
    pub hostname: String,
    pub uptime_seconds: u64,
    pub version: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentRuntimeConfig {
    #[serde(default)]
    pub agent_id: String,
    pub listen_addr: String,
    pub log_sources: HashMap<String, String>,
    #[serde(default)]
    pub advertised_name: Option<String>,
    #[serde(default)]
    pub environment: Option<String>,
    #[serde(default)]
    pub location: Option<String>,
    #[serde(default)]
    pub advertised_base_url: Option<String>,
    #[serde(default)]
    pub control_plane_url: Option<String>,
    #[serde(default)]
    pub bootstrap_token: Option<String>,
    #[serde(default)]
    pub state_path: Option<String>,
    #[serde(default)]
    pub commands: Vec<AgentCommandSpec>,
    #[serde(default)]
    pub auth_token: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentCommandSpec {
    pub id: String,
    pub description: String,
    #[serde(default)]
    pub kind: AgentCommandKind,
    #[serde(default)]
    pub supported_platforms: Vec<String>,
    #[serde(default)]
    pub arg_schema: Vec<AgentCommandArgSpec>,
    #[serde(default = "default_command_concurrency_limit")]
    pub concurrency_limit: usize,
    #[serde(default)]
    pub allow_args: bool,
    #[serde(default)]
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub base_directory: Option<String>,
    #[serde(default)]
    pub source_path: Option<String>,
    #[serde(default = "default_command_timeout_seconds")]
    pub timeout_seconds: u64,
    #[serde(default = "default_command_output_bytes")]
    pub max_output_bytes: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AgentCommandKind {
    #[default]
    ShellCommand,
    FileCollection,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentCommandArgSpec {
    pub name: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub redacted: bool,
    #[serde(default)]
    pub allowed_values: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentRuntimeState {
    pub agent_id: String,
    pub management_token: String,
    pub inbound_auth_token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerCatalog {
    pub agents: Vec<AgentDescriptor>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentBootstrapTokenResponse {
    pub token: String,
    pub expires_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentRegistrationRequest {
    pub bootstrap_token: String,
    pub name: String,
    pub environment: String,
    pub location: String,
    pub endpoint: String,
    pub capabilities: Vec<String>,
    pub commands: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentRegistrationResponse {
    pub agent_id: String,
    pub management_token: String,
    pub inbound_auth_token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentHeartbeatRequest {
    pub agent_id: String,
    pub management_token: String,
    pub endpoint: String,
    pub capabilities: Vec<String>,
    pub commands: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentHeartbeatResponse {
    pub accepted: bool,
    pub enabled: bool,
    pub inbound_auth_token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentAdminRecord {
    pub id: String,
    pub name: String,
    pub environment: String,
    pub location: String,
    pub endpoint: String,
    pub enabled: bool,
    pub status: String,
    pub last_seen: String,
    pub capabilities: Vec<String>,
    pub commands: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEventRecord {
    pub created_at: String,
    pub actor_username: Option<String>,
    pub actor_role: Option<String>,
    pub actor_client_id: Option<String>,
    pub action: String,
    pub target_type: String,
    pub target_id: String,
    pub success: bool,
    pub details: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct DeviceIdentity {
    pub hostname: String,
    pub username: String,
    pub platform: String,
    pub hardware_fingerprint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnrollmentRequest {
    pub enrollment_token: String,
    pub client_name: String,
    pub csr_pem: String,
    pub requested_validity_days: u32,
    pub device: DeviceIdentity,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnrollmentResponse {
    pub request_id: String,
    pub status: String,
    pub client_id: Option<String>,
    pub client_certificate_pem: Option<String>,
    pub certificate_chain_pem: Vec<String>,
    pub client_certificate_fingerprint: Option<String>,
    pub expires_at: Option<String>,
    pub mtls_endpoint: String,
    pub enrollment_summary: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnrollmentTokenRecord {
    pub label: String,
    pub token_hash: String,
    pub expires_at: String,
    #[serde(default)]
    pub single_use: bool,
    pub max_validity_days: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnrollmentTokenStore {
    pub tokens: Vec<EnrollmentTokenRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogoutRequest {
    pub session_token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub session_token: String,
    pub username: String,
    pub role: String,
    pub expires_at: String,
}

pub fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

pub fn format_timestamp(value: DateTime<Utc>) -> String {
    value.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

pub fn sample_catalog() -> ServerCatalog {
    ServerCatalog {
        agents: vec![AgentDescriptor {
            id: "edge-eu-01".to_owned(),
            name: "Edge EU 01".to_owned(),
            environment: "production".to_owned(),
            location: "Copenhagen".to_owned(),
            base_url: "http://127.0.0.1:8088".to_owned(),
            capabilities: vec![
                "health_check".to_owned(),
                "collect_metrics".to_owned(),
                "fetch_logs".to_owned(),
            ],
            command_ids: vec!["uptime".to_owned()],
            redirector_token: None,
            auth_token: None,
        }],
    }
}

pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn masked_token_hash(input: &str) -> String {
    let hash = sha256_hex(input);
    hash.chars().take(12).collect()
}

pub fn validate_device_identity(device: &DeviceIdentity) -> anyhow::Result<()> {
    if device.hostname.trim().is_empty()
        || device.username.trim().is_empty()
        || device.platform.trim().is_empty()
        || device.hardware_fingerprint.trim().is_empty()
    {
        anyhow::bail!("device identity is incomplete");
    }

    Ok(())
}

pub fn sha256_hex_bytes(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    format!("{:x}", hasher.finalize())
}

fn default_command_timeout_seconds() -> u64 {
    30
}

fn default_command_output_bytes() -> usize {
    16 * 1024
}

fn default_command_concurrency_limit() -> usize {
    1
}
