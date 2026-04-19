use anyhow::{Context, Result};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::{routing::{get, post}, Json, Router};
use axum_server::tls_rustls::RustlsConfig;
use base64::Engine;
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use rand_core::{OsRng, RngCore};
use rcgen::{
    DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType,
    SerialNumber,
};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::Client as HttpClient;
use shared::proto::orchestrator_server::{Orchestrator, OrchestratorServer};
use shared::proto::{
    AgentSnapshot, DashboardSnapshot, Empty, JobUpdate, JobWatchRequest, RecentJob,
    SubmitJobRequest, SubmitJobResponse,
};
use shared::{
    format_timestamp, masked_token_hash, now_rfc3339, sample_catalog, sha256_hex,
    sha256_hex_bytes, validate_device_identity, AgentDescriptor, DeviceIdentity,
    EnrollmentRequest, EnrollmentResponse, EnrollmentTokenStore, JobAcceptance, JobRecord,
    JobStatus, JobSubmission, LoginRequest, LoginResponse, LogoutRequest, MaintenanceAction,
    ServerCatalog, AgentBootstrapTokenResponse, AgentHeartbeatRequest, AgentHeartbeatResponse,
    AgentRegistrationRequest, AgentRegistrationResponse, AgentAdminRecord, AuditEventRecord,
};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
    Row, SqlitePool,
};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};
use tracing::{error, info};
use uuid::Uuid;
use x509_parser::{certificate::X509Certificate, prelude::FromDer};

const DEFAULT_DATABASE_URL: &str = "sqlite://data/wraith_orchestrator.db";
const LOGIN_FAILURE_WINDOW_MINUTES: i64 = 15;
const LOGIN_FAILURE_LIMIT: i64 = 5;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:50051")]
    grpc_addr: SocketAddr,
    #[arg(long, default_value = "127.0.0.1:5443")]
    enrollment_addr: SocketAddr,
    #[arg(long, default_value = "https://127.0.0.1:50051")]
    mtls_endpoint: String,
    #[arg(long, default_value = "examples/agents.json")]
    catalog: PathBuf,
    #[arg(long, default_value = "examples/enrollment-tokens.json")]
    enrollment_tokens: PathBuf,
    #[arg(long, default_value = "certs/ca.crt")]
    ca_cert: PathBuf,
    #[arg(long, default_value = "certs/ca.key")]
    ca_key: PathBuf,
    #[arg(long, default_value = "certs/server.crt")]
    server_cert: PathBuf,
    #[arg(long, default_value = "certs/server.key")]
    server_key: PathBuf,
    #[arg(long)]
    offline_ca: bool,
    #[arg(long, env = "DATABASE_URL", default_value = DEFAULT_DATABASE_URL)]
    database_url: String,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    ProvisionAdmin {
        #[arg(long, default_value = "admin")]
        username: String,
        #[arg(long)]
        rotate: bool,
    },
    ProvisionUser {
        #[arg(long)]
        username: String,
        #[arg(long)]
        role: String,
        #[arg(long)]
        rotate: bool,
    },
    ExportPendingEnrollments {
        #[arg(long)]
        out_dir: PathBuf,
        #[arg(long)]
        request_id: Option<String>,
    },
    SignEnrollmentBundle {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value = "certs/ca.crt")]
        ca_cert: PathBuf,
        #[arg(long, default_value = "certs/ca.key")]
        ca_key: PathBuf,
        #[arg(long)]
        mtls_endpoint: Option<String>,
    },
    ImportSignedEnrollment {
        #[arg(long)]
        input: PathBuf,
    },
}

#[derive(Clone)]
struct SharedState {
    event_log: VecDeque<String>,
    enrolled_clients: VecDeque<EnrolledClientRecord>,
    recent_logins: VecDeque<AuthSession>,
}

impl SharedState {
    fn new() -> Self {
        Self {
            event_log: VecDeque::with_capacity(48),
            enrolled_clients: VecDeque::with_capacity(24),
            recent_logins: VecDeque::with_capacity(24),
        }
    }

    fn push_event(&mut self, message: impl Into<String>) {
        self.event_log.push_front(message.into());
        while self.event_log.len() > 24 {
            self.event_log.pop_back();
        }
    }

    fn push_enrollment(&mut self, record: EnrolledClientRecord) {
        self.enrolled_clients.push_front(record);
        while self.enrolled_clients.len() > 12 {
            self.enrolled_clients.pop_back();
        }
    }

    fn push_login(&mut self, login: AuthSession) {
        self.recent_logins.push_front(login);
        while self.recent_logins.len() > 12 {
            self.recent_logins.pop_back();
        }
    }
}

#[derive(Clone)]
#[allow(dead_code)]
struct EnrolledClientRecord {
    client_id: String,
    client_name: String,
    hostname: String,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    method: String,
}

#[derive(Clone)]
struct AuthSession {
    username: String,
    role: String,
}

#[derive(Clone)]
struct AuthenticatedOperator {
    session: AuthSession,
    client: EnrolledClient,
}

#[derive(Clone)]
struct EnrolledClient {
    client_id: String,
}

#[derive(Clone)]
struct AppContext {
    state: Arc<RwLock<SharedState>>,
    http: HttpClient,
    auth_db: AuthDatabase,
}

#[derive(Clone)]
struct GrpcApi {
    context: AppContext,
}

#[derive(Clone)]
struct HttpsApi {
    context: AppContext,
    authority: Option<Arc<CertificateAuthority>>,
    mtls_endpoint: String,
}

struct CertificateAuthority {
    ca_cert_pem: String,
    issuer: Issuer<'static, KeyPair>,
    mtls_endpoint: String,
}

#[derive(Clone)]
struct AuthDatabase {
    pool: SqlitePool,
}

#[derive(serde::Serialize)]
struct ApiError {
    error: String,
}

#[derive(Clone)]
struct StoredJobRecord {
    record: JobRecord,
    updated_at: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PendingEnrollmentBundle {
    request_id: String,
    client_name: String,
    csr_pem: String,
    requested_validity_days: u32,
    max_validity_days: u32,
    device: DeviceIdentity,
    mtls_endpoint: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SignedEnrollmentBundle {
    request_id: String,
    client_name: String,
    device: DeviceIdentity,
    response: EnrollmentResponse,
    cert_serial: String,
    cert_spiffe_uri: String,
    issued_at: String,
}

#[tonic::async_trait]
impl Orchestrator for GrpcApi {
    type WatchJobStream = ReceiverStream<std::result::Result<JobUpdate, Status>>;

    async fn get_dashboard(
        &self,
        request: Request<Empty>,
    ) -> std::result::Result<Response<DashboardSnapshot>, Status> {
        let operator = require_operator(&request, &self.context.auth_db).await?;
        {
            let mut state = self.context.state.write().unwrap();
            state.push_login(operator.session);
        }

        let agents = self
            .context
            .auth_db
            .list_agents()
            .await
            .map_err(|err| Status::internal(err.to_string()))?;
        let agent_names: HashMap<_, _> = agents
            .iter()
            .map(|agent| (agent.id.clone(), agent.name.clone()))
            .collect();
        let recent_jobs = self
            .context
            .auth_db
            .list_recent_jobs(18)
            .await
            .map_err(|err| Status::internal(err.to_string()))?;
        let agents = agents
            .into_iter()
            .map(|agent| {
                let last_seen_time = DateTime::parse_from_rfc3339(&agent.last_seen)
                    .ok()
                    .map(|time| time.with_timezone(&Utc));
                let online = agent.enabled
                    && agent.status != "disabled"
                    && last_seen_time
                        .is_some_and(|timestamp| Utc::now() - timestamp < chrono::Duration::seconds(30));
                let status = if online {
                    agent.status.clone()
                } else if agent.enabled && agent.last_seen != "never" {
                    "stale".to_owned()
                } else {
                    agent.status.clone()
                };
                AgentSnapshot {
                    id: agent.id.clone(),
                    name: agent.name.clone(),
                    environment: agent.environment.clone(),
                    location: agent.location.clone(),
                    endpoint: agent.endpoint.clone(),
                    online,
                    status,
                    last_seen: agent.last_seen.clone(),
                    capabilities: agent.capabilities.clone(),
                    enabled: agent.enabled,
                    commands: agent.commands.clone(),
                }
            })
            .collect();

        let recent_jobs = recent_jobs
            .iter()
            .map(|job| RecentJob {
                job_id: job.job_id.to_string(),
                agent_id: job.agent_id.clone(),
                agent_name: agent_names
                    .get(&job.agent_id)
                    .cloned()
                    .unwrap_or_else(|| job.agent_id.clone()),
                action: job.action.label(),
                status: job.status.as_str().to_owned(),
                submitted_at: format_timestamp(job.submitted_at),
                summary: job.summary.clone(),
                details_json: job.details.to_string(),
            })
            .collect();

        Ok(Response::new(DashboardSnapshot {
            agents,
            recent_jobs,
            generated_at: format_timestamp(Utc::now()),
        }))
    }

    async fn submit_job(
        &self,
        request: Request<SubmitJobRequest>,
    ) -> std::result::Result<Response<SubmitJobResponse>, Status> {
        let operator = require_operator(&request, &self.context.auth_db).await?;
        ensure_role(&operator.session, &["operator", "admin"])
            .map_err(|err| Status::permission_denied(err.to_string()))?;
        let payload = request.into_inner();
        let action = MaintenanceAction::from_proto(&payload)
            .map_err(|err| Status::invalid_argument(err.to_string()))?;
        let agent_id = payload.agent_id.clone();
        let job_id = Uuid::new_v4();
        let summary = format!("Queued {}", action.label());
        let pending = JobRecord {
            job_id,
            agent_id: agent_id.clone(),
            action: action.clone(),
            status: JobStatus::Pending,
            submitted_at: Utc::now(),
            started_at: None,
            completed_at: None,
            summary: summary.clone(),
            details: serde_json::json!({ "phase": "queued" }),
        };
        self.context
            .auth_db
            .upsert_job_record(&pending)
            .await
            .map_err(|err| Status::internal(err.to_string()))?;
        tokio::spawn(dispatch_and_track(
            self.context.clone(),
            job_id,
            agent_id.clone(),
            action.clone(),
            Duration::from_secs(30 * 60),
        ));

        self.context.state.write().unwrap().push_event(format!(
            "Operator {} on {} submitted {}",
            operator.session.username, operator.client.client_id, summary
        ));
        let _ = self
            .context
            .auth_db
            .record_audit(
                Some(&operator),
                "submit_job",
                "agent",
                &agent_id,
                true,
                serde_json::json!({
                    "action": action.label(),
                    "job_id": job_id.to_string(),
                    "status": "pending",
                }),
            )
            .await;

        Ok(Response::new(SubmitJobResponse {
            accepted: true,
            job_id: job_id.to_string(),
            status: JobStatus::Pending.as_str().to_owned(),
            summary,
            details_json: serde_json::json!({ "phase": "queued" }).to_string(),
        }))
    }

    async fn watch_job(
        &self,
        request: Request<JobWatchRequest>,
    ) -> std::result::Result<Response<Self::WatchJobStream>, Status> {
        let operator = require_operator(&request, &self.context.auth_db).await?;
        ensure_role(&operator.session, &["viewer", "operator", "admin"])
            .map_err(|err| Status::permission_denied(err.to_string()))?;
        let job_id = request.into_inner().job_id;
        let auth_db = self.context.auth_db.clone();
        let (tx, rx) = mpsc::channel(16);

        tokio::spawn(async move {
            let mut last_seen_update = None::<String>;
            loop {
                match auth_db.get_job_record(&job_id).await {
                    Ok(stored) => {
                        if last_seen_update.as_deref() != Some(stored.updated_at.as_str()) {
                            last_seen_update = Some(stored.updated_at.clone());
                            if tx
                                .send(Ok(job_record_to_update(&stored.record)))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        if matches!(
                            stored.record.status,
                            JobStatus::Completed | JobStatus::Failed
                        ) {
                            break;
                        }
                    }
                    Err(err) => {
                        let _ = tx.send(Err(Status::not_found(err.to_string()))).await;
                        break;
                    }
                }
                sleep(Duration::from_millis(250)).await;
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

impl AuthDatabase {
    async fn connect(database_url: &str) -> Result<Self> {
        ensure_sqlite_parent_dir(database_url)?;
        let options = database_url
            .parse::<SqliteConnectOptions>()
            .with_context(|| format!("failed parsing sqlite database url `{database_url}`"))?
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full);

        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(options)
            .await
            .with_context(|| format!("failed connecting to sqlite at {database_url}"))?;

        Ok(Self { pool })
    }

    async fn add_column_if_missing(&self, statement: &str) -> Result<()> {
        match sqlx::query(statement).execute(&self.pool).await {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(error))
                if error.message().contains("duplicate column name") =>
            {
                Ok(())
            }
            Err(err) => Err(err.into()),
        }
    }

    async fn init_schema(&self) -> Result<()> {
        sqlx::query(
            r#"
            create table if not exists users (
                id text primary key,
                username text not null unique,
                password_hash text not null,
                role text not null,
                is_active boolean not null default true,
                created_at text not null
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            create table if not exists sessions (
                id text primary key,
                user_id text not null references users(id) on delete cascade,
                token_hash text not null unique,
                expires_at text not null,
                created_at text not null,
                revoked_at text
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            create table if not exists enrollment_tokens (
                token_hash text primary key,
                label text not null,
                expires_at text not null,
                single_use boolean not null default false,
                max_validity_days integer not null,
                used_at text,
                used_by_request_id text
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            create table if not exists enrollment_requests (
                request_id text primary key,
                enrollment_token_hash text not null,
                client_name text not null,
                csr_pem text not null,
                requested_validity_days integer not null,
                max_validity_days integer not null,
                device_json text not null,
                status text not null,
                created_at text not null,
                approved_at text,
                client_id text,
                cert_pem text,
                cert_fingerprint text,
                cert_serial text,
                cert_spiffe_uri text,
                expires_at text
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            create table if not exists enrolled_clients (
                client_id text primary key,
                client_name text not null,
                hostname text not null,
                username text not null,
                platform text not null,
                hardware_fingerprint text not null,
                cert_fingerprint text not null unique,
                cert_serial text not null unique,
                cert_spiffe_uri text not null unique,
                issued_at text not null,
                expires_at text not null,
                revoked_at text
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            create table if not exists login_attempts (
                id integer primary key autoincrement,
                username text not null,
                attempted_at text not null,
                was_success boolean not null
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            create table if not exists audit_log (
                id integer primary key autoincrement,
                created_at text not null,
                actor_username text,
                actor_role text,
                actor_client_id text,
                action text not null,
                target_type text not null,
                target_id text not null,
                success boolean not null,
                details_json text not null
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            create table if not exists jobs (
                job_id text primary key,
                agent_id text not null,
                action_json text not null,
                status text not null,
                submitted_at text not null,
                started_at text,
                completed_at text,
                summary text not null,
                details_json text not null,
                updated_at text not null
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            create table if not exists agent_bootstrap_tokens (
                token_hash text primary key,
                label text not null,
                expires_at text not null,
                created_at text not null,
                used_at text,
                issued_agent_id text
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            create table if not exists agents (
                id text primary key,
                name text not null,
                environment text not null,
                location text not null,
                endpoint text not null,
                capabilities_json text not null,
                commands_json text not null,
                redirector_token text,
                management_token_hash text not null,
                inbound_auth_token text not null,
                is_enabled boolean not null default true,
                status text not null default 'registered',
                last_seen text,
                created_at text not null,
                updated_at text not null
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        self.add_column_if_missing("alter table agents add column redirector_token text")
            .await?;

        Ok(())
    }

    async fn sync_enrollment_tokens(&self, store: EnrollmentTokenStore) -> Result<()> {
        for token in store.tokens {
            sqlx::query(
                r#"
                insert into enrollment_tokens (
                    token_hash, label, expires_at, single_use, max_validity_days, used_at, used_by_request_id
                )
                values ($1, $2, $3, $4, $5, null, null)
                on conflict (token_hash) do update
                set label = excluded.label,
                    expires_at = excluded.expires_at,
                    single_use = excluded.single_use,
                    max_validity_days = excluded.max_validity_days;
                "#,
            )
            .bind(token.token_hash)
            .bind(token.label)
            .bind(token.expires_at)
            .bind(token.single_use)
            .bind(token.max_validity_days as i64)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    async fn sync_seed_agents(&self, catalog: ServerCatalog) -> Result<()> {
        for agent in catalog.agents {
            let management_token = generate_secret_token();
            let inbound_auth_token = agent
                .auth_token
                .clone()
                .unwrap_or_else(generate_secret_token);
            sqlx::query(
                r#"
                insert into agents (
                    id, name, environment, location, endpoint, capabilities_json, commands_json,
                    redirector_token, management_token_hash, inbound_auth_token, is_enabled, status, last_seen,
                    created_at, updated_at
                )
                values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, true, 'seeded', null, $11, $11)
                on conflict (id) do update
                set name = excluded.name,
                    environment = excluded.environment,
                    location = excluded.location,
                    endpoint = excluded.endpoint,
                    capabilities_json = excluded.capabilities_json,
                    commands_json = excluded.commands_json,
                    redirector_token = excluded.redirector_token,
                    inbound_auth_token = excluded.inbound_auth_token,
                    updated_at = excluded.updated_at
                "#,
            )
            .bind(agent.id)
            .bind(agent.name)
            .bind(agent.environment)
            .bind(agent.location)
            .bind(agent.base_url)
            .bind(serde_json::to_string(&agent.capabilities)?)
            .bind(serde_json::to_string(&agent.command_ids)?)
            .bind(agent.redirector_token)
            .bind(sha256_hex(&management_token))
            .bind(inbound_auth_token)
            .bind(now_rfc3339())
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    async fn list_agents(&self) -> Result<Vec<AgentAdminRecord>> {
        let rows = sqlx::query(
            r#"
            select id, name, environment, location, endpoint, is_enabled, status, last_seen,
                   capabilities_json, commands_json
            from agents
            order by name asc
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(Self::agent_row_to_record).collect()
    }

    async fn upsert_job_record(&self, record: &JobRecord) -> Result<()> {
        let updated_at = now_rfc3339();
        sqlx::query(
            r#"
            insert into jobs (
                job_id, agent_id, action_json, status, submitted_at, started_at, completed_at,
                summary, details_json, updated_at
            )
            values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            on conflict (job_id) do update
            set agent_id = excluded.agent_id,
                action_json = excluded.action_json,
                status = excluded.status,
                submitted_at = excluded.submitted_at,
                started_at = excluded.started_at,
                completed_at = excluded.completed_at,
                summary = excluded.summary,
                details_json = excluded.details_json,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(record.job_id.to_string())
        .bind(&record.agent_id)
        .bind(serde_json::to_string(&record.action)?)
        .bind(record.status.as_str())
        .bind(record.submitted_at.to_rfc3339())
        .bind(record.started_at.map(|time| time.to_rfc3339()))
        .bind(record.completed_at.map(|time| time.to_rfc3339()))
        .bind(&record.summary)
        .bind(record.details.to_string())
        .bind(updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_recent_jobs(&self, limit: i64) -> Result<Vec<JobRecord>> {
        let rows = sqlx::query(
            r#"
            select job_id, agent_id, action_json, status, submitted_at, started_at, completed_at,
                   summary, details_json, updated_at
            from jobs
            order by submitted_at desc
            limit $1
            "#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(Self::job_row_to_record)
            .map(|item| item.map(|stored| stored.record))
            .collect()
    }

    async fn get_job_record(&self, job_id: &str) -> Result<StoredJobRecord> {
        let row = sqlx::query(
            r#"
            select job_id, agent_id, action_json, status, submitted_at, started_at, completed_at,
                   summary, details_json, updated_at
            from jobs
            where job_id = $1
            "#,
        )
        .bind(job_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| anyhow::anyhow!("job not found"))?;

        Self::job_row_to_record(row)
    }

    async fn mark_incomplete_jobs_interrupted(&self) -> Result<()> {
        sqlx::query(
            r#"
            update jobs
            set status = 'failed',
                completed_at = $1,
                summary = 'Control plane restarted before job completed',
                details_json = $2,
                updated_at = $1
            where status in ('pending', 'running')
            "#,
        )
        .bind(now_rfc3339())
        .bind(serde_json::json!({ "error": "control plane restarted" }).to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_audit_events(&self, limit: i64) -> Result<Vec<AuditEventRecord>> {
        let rows = sqlx::query(
            r#"
            select created_at, actor_username, actor_role, actor_client_id, action, target_type,
                   target_id, success, details_json
            from audit_log
            order by id desc
            limit $1
            "#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                Ok(AuditEventRecord {
                    created_at: row.try_get("created_at")?,
                    actor_username: row.try_get("actor_username")?,
                    actor_role: row.try_get("actor_role")?,
                    actor_client_id: row.try_get("actor_client_id")?,
                    action: row.try_get("action")?,
                    target_type: row.try_get("target_type")?,
                    target_id: row.try_get("target_id")?,
                    success: row.try_get("success")?,
                    details: serde_json::from_str(&row.try_get::<String, _>("details_json")?)?,
                })
            })
            .collect()
    }

    async fn record_audit(
        &self,
        actor: Option<&AuthenticatedOperator>,
        action: &str,
        target_type: &str,
        target_id: &str,
        success: bool,
        details: serde_json::Value,
    ) -> Result<()> {
        sqlx::query(
            r#"
            insert into audit_log (
                created_at, actor_username, actor_role, actor_client_id, action, target_type,
                target_id, success, details_json
            )
            values ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind(now_rfc3339())
        .bind(actor.map(|item| item.session.username.clone()))
        .bind(actor.map(|item| item.session.role.clone()))
        .bind(actor.map(|item| item.client.client_id.clone()))
        .bind(action)
        .bind(target_type)
        .bind(target_id)
        .bind(success)
        .bind(details.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn record_system_audit(
        &self,
        action: &str,
        target_type: &str,
        target_id: &str,
        success: bool,
        details: serde_json::Value,
    ) -> Result<()> {
        self.record_audit(None, action, target_type, target_id, success, details)
            .await
    }

    async fn get_agent_descriptor(&self, agent_id: &str) -> Result<AgentDescriptor> {
        let row = sqlx::query(
            r#"
            select id, name, environment, location, endpoint, capabilities_json, commands_json,
                   redirector_token,
                   inbound_auth_token, is_enabled
            from agents
            where id = $1
            "#,
        )
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| anyhow::anyhow!("unknown agent: {agent_id}"))?;

        let is_enabled: bool = row.try_get("is_enabled")?;
        if !is_enabled {
            anyhow::bail!("agent is disabled");
        }

        Ok(AgentDescriptor {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            environment: row.try_get("environment")?,
            location: row.try_get("location")?,
            base_url: row.try_get("endpoint")?,
            capabilities: serde_json::from_str(&row.try_get::<String, _>("capabilities_json")?)?,
            command_ids: serde_json::from_str(&row.try_get::<String, _>("commands_json")?)?,
            redirector_token: row.try_get("redirector_token")?,
            auth_token: Some(row.try_get("inbound_auth_token")?),
        })
    }

    async fn issue_agent_bootstrap_token(&self, label: &str) -> Result<AgentBootstrapTokenResponse> {
        let raw = generate_secret_token();
        let expires_at = (Utc::now() + chrono::Duration::hours(24)).to_rfc3339();
        sqlx::query(
            r#"
            insert into agent_bootstrap_tokens (token_hash, label, expires_at, created_at, used_at, issued_agent_id)
            values ($1, $2, $3, $4, null, null)
            "#,
        )
        .bind(sha256_hex(&raw))
        .bind(label)
        .bind(&expires_at)
        .bind(now_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(AgentBootstrapTokenResponse {
            token: raw,
            expires_at,
        })
    }

    async fn register_agent(
        &self,
        request: AgentRegistrationRequest,
    ) -> Result<AgentRegistrationResponse> {
        let token_hash = sha256_hex(&request.bootstrap_token);
        let mut tx = self.pool.begin().await?;
        let token = sqlx::query(
            r#"
            select label, expires_at, used_at
            from agent_bootstrap_tokens
            where token_hash = $1
            "#,
        )
        .bind(&token_hash)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| anyhow::anyhow!("invalid bootstrap token"))?;

        let expires_at: String = token.try_get("expires_at")?;
        let used_at: Option<String> = token.try_get("used_at")?;
        if used_at.is_some() {
            anyhow::bail!("bootstrap token has already been used");
        }
        if expires_at <= now_rfc3339() {
            anyhow::bail!("bootstrap token has expired");
        }

        let agent_id = format!("agent-{}", Uuid::new_v4().simple());
        let management_token = generate_secret_token();
        let inbound_auth_token = generate_secret_token();
        let now = now_rfc3339();

        sqlx::query(
            r#"
            insert into agents (
                id, name, environment, location, endpoint, capabilities_json, commands_json,
                redirector_token, management_token_hash, inbound_auth_token, is_enabled, status, last_seen,
                created_at, updated_at
            )
            values ($1, $2, $3, $4, $5, $6, $7, null, $8, $9, true, 'online', $10, $10, $10)
            "#,
        )
        .bind(&agent_id)
        .bind(&request.name)
        .bind(&request.environment)
        .bind(&request.location)
        .bind(&request.endpoint)
        .bind(serde_json::to_string(&request.capabilities)?)
        .bind(serde_json::to_string(&request.commands)?)
        .bind(sha256_hex(&management_token))
        .bind(&inbound_auth_token)
        .bind(&now)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            update agent_bootstrap_tokens
            set used_at = $2, issued_agent_id = $3
            where token_hash = $1
            "#,
        )
        .bind(&token_hash)
        .bind(&now)
        .bind(&agent_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(AgentRegistrationResponse {
            agent_id,
            management_token,
            inbound_auth_token,
        })
    }

    async fn heartbeat_agent(
        &self,
        request: AgentHeartbeatRequest,
    ) -> Result<AgentHeartbeatResponse> {
        let row = sqlx::query(
            r#"
            select management_token_hash, is_enabled, inbound_auth_token
            from agents
            where id = $1
            "#,
        )
        .bind(&request.agent_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| anyhow::anyhow!("unknown agent"))?;

        let expected_hash: String = row.try_get("management_token_hash")?;
        if expected_hash != sha256_hex(&request.management_token) {
            anyhow::bail!("invalid management token");
        }

        let enabled: bool = row.try_get("is_enabled")?;
        let inbound_auth_token: String = row.try_get("inbound_auth_token")?;
        let status = if enabled { "online" } else { "disabled" };
        sqlx::query(
            r#"
            update agents
            set endpoint = $2,
                capabilities_json = $3,
                commands_json = $4,
                status = $5,
                last_seen = $6,
                updated_at = $6
            where id = $1
            "#,
        )
        .bind(&request.agent_id)
        .bind(&request.endpoint)
        .bind(serde_json::to_string(&request.capabilities)?)
        .bind(serde_json::to_string(&request.commands)?)
        .bind(status)
        .bind(now_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(AgentHeartbeatResponse {
            accepted: true,
            enabled,
            inbound_auth_token,
        })
    }

    async fn disable_agent(&self, agent_id: &str) -> Result<()> {
        let updated = sqlx::query(
            r#"
            update agents
            set is_enabled = false, status = 'disabled', updated_at = $2
            where id = $1
            "#,
        )
        .bind(agent_id)
        .bind(now_rfc3339())
        .execute(&self.pool)
        .await?;
        if updated.rows_affected() == 0 {
            anyhow::bail!("agent not found");
        }
        Ok(())
    }

    async fn rotate_agent_job_token(&self, agent_id: &str) -> Result<AgentBootstrapTokenResponse> {
        let new_token = generate_secret_token();
        let updated = sqlx::query(
            r#"
            update agents
            set inbound_auth_token = $2, updated_at = $3
            where id = $1
            "#,
        )
        .bind(agent_id)
        .bind(&new_token)
        .bind(now_rfc3339())
        .execute(&self.pool)
        .await?;
        if updated.rows_affected() == 0 {
            anyhow::bail!("agent not found");
        }
        Ok(AgentBootstrapTokenResponse {
            token: new_token,
            expires_at: "rotated".to_owned(),
        })
    }

    fn agent_row_to_record(row: sqlx::sqlite::SqliteRow) -> Result<AgentAdminRecord> {
        Ok(AgentAdminRecord {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            environment: row.try_get("environment")?,
            location: row.try_get("location")?,
            endpoint: row.try_get("endpoint")?,
            enabled: row.try_get("is_enabled")?,
            status: row.try_get("status")?,
            last_seen: row
                .try_get::<Option<String>, _>("last_seen")?
                .unwrap_or_else(|| "never".to_owned()),
            capabilities: serde_json::from_str(&row.try_get::<String, _>("capabilities_json")?)?,
            commands: serde_json::from_str(&row.try_get::<String, _>("commands_json")?)?,
        })
    }

    fn job_row_to_record(row: sqlx::sqlite::SqliteRow) -> Result<StoredJobRecord> {
        Ok(StoredJobRecord {
            record: JobRecord {
                job_id: Uuid::parse_str(&row.try_get::<String, _>("job_id")?)
                    .context("invalid stored job id")?,
                agent_id: row.try_get("agent_id")?,
                action: serde_json::from_str(&row.try_get::<String, _>("action_json")?)?,
                status: match row.try_get::<String, _>("status")?.as_str() {
                    "pending" => JobStatus::Pending,
                    "running" => JobStatus::Running,
                    "completed" => JobStatus::Completed,
                    "failed" => JobStatus::Failed,
                    other => anyhow::bail!("invalid stored job status `{other}`"),
                },
                submitted_at: parse_db_timestamp(&row.try_get::<String, _>("submitted_at")?)?,
                started_at: row
                    .try_get::<Option<String>, _>("started_at")?
                    .as_deref()
                    .map(parse_db_timestamp)
                    .transpose()?,
                completed_at: row
                    .try_get::<Option<String>, _>("completed_at")?
                    .as_deref()
                    .map(parse_db_timestamp)
                    .transpose()?,
                summary: row.try_get("summary")?,
                details: serde_json::from_str(&row.try_get::<String, _>("details_json")?)?,
            },
            updated_at: row.try_get("updated_at")?,
        })
    }

    async fn provision_user(
        &self,
        username: &str,
        role: &str,
        password: &str,
        rotate_existing: bool,
    ) -> Result<()> {
        if !matches!(role, "viewer" | "operator" | "admin") {
            anyhow::bail!("role must be one of: viewer, operator, admin");
        }
        let existing = sqlx::query("select id from users where username = $1")
            .bind(username)
            .fetch_optional(&self.pool)
            .await?;

        if existing.is_some() && !rotate_existing {
            anyhow::bail!(
                "admin user `{username}` already exists; rerun with `provision-admin --rotate` to replace its password"
            );
        }

        let salt = SaltString::generate(&mut OsRng);
        let password_hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|err| anyhow::anyhow!("failed hashing admin password: {err}"))?
            .to_string();

        sqlx::query(
            r#"
            insert into users (id, username, password_hash, role, is_active, created_at)
            values ($1, $2, $3, $4, true, $5)
            on conflict (username) do update
            set password_hash = excluded.password_hash,
                role = excluded.role,
                is_active = excluded.is_active;
            "#,
        )
        .bind(Uuid::new_v4().to_string())
        .bind(username)
        .bind(password_hash)
        .bind(role)
        .bind(now_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn authenticate(&self, username: &str, password: &str) -> Result<LoginResponse> {
        self.ensure_login_not_rate_limited(username).await?;

        let row = sqlx::query(
            r#"
            select id, password_hash, role, is_active
            from users
            where username = $1
            "#,
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            self.record_login_attempt(username, false).await?;
            anyhow::bail!("invalid username or password");
        };

        let user_id: String = row.try_get("id")?;
        let password_hash: String = row.try_get("password_hash")?;
        let role: String = row.try_get("role")?;
        let is_active: bool = row.try_get("is_active")?;
        if !is_active {
            self.record_login_attempt(username, false).await?;
            anyhow::bail!("user account is disabled");
        }

        let parsed = PasswordHash::new(&password_hash)
            .map_err(|err| anyhow::anyhow!("stored password hash is invalid: {err}"))?;
        if Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_err()
        {
            self.record_login_attempt(username, false).await?;
            anyhow::bail!("invalid username or password");
        }

        self.record_login_attempt(username, true).await?;

        let raw_token = format!("{}.{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let token_hash = sha256_hex(&raw_token);
        let expires_at = (Utc::now() + chrono::Duration::hours(8)).to_rfc3339();

        sqlx::query(
            r#"
            insert into sessions (id, user_id, token_hash, expires_at, created_at, revoked_at)
            values ($1, $2, $3, $4, $5, null)
            "#,
        )
        .bind(Uuid::new_v4().to_string())
        .bind(user_id)
        .bind(token_hash)
        .bind(&expires_at)
        .bind(now_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(LoginResponse {
            session_token: raw_token,
            username: username.to_owned(),
            role,
            expires_at,
        })
    }

    async fn ensure_login_not_rate_limited(&self, username: &str) -> Result<()> {
        let cutoff = (Utc::now() - chrono::Duration::minutes(LOGIN_FAILURE_WINDOW_MINUTES))
            .to_rfc3339();
        let row = sqlx::query(
            r#"
            select count(*) as failure_count
            from login_attempts
            where username = $1
              and was_success = false
              and attempted_at >= $2
            "#,
        )
        .bind(username)
        .bind(cutoff)
        .fetch_one(&self.pool)
        .await?;

        let failure_count: i64 = row.try_get("failure_count")?;
        if failure_count >= LOGIN_FAILURE_LIMIT {
            anyhow::bail!("too many failed login attempts; try again later");
        }
        Ok(())
    }

    async fn record_login_attempt(&self, username: &str, was_success: bool) -> Result<()> {
        sqlx::query(
            r#"
            insert into login_attempts (username, attempted_at, was_success)
            values ($1, $2, $3)
            "#,
        )
        .bind(username)
        .bind(now_rfc3339())
        .bind(was_success)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn validate_session(&self, raw_token: &str) -> Result<AuthSession> {
        let token_hash = sha256_hex(raw_token);
        let row = sqlx::query(
            r#"
            select u.username, u.role
            from sessions s
            join users u on u.id = s.user_id
            where s.token_hash = $1
              and s.revoked_at is null
              and s.expires_at > $2
              and u.is_active = true
            "#,
        )
        .bind(token_hash)
        .bind(now_rfc3339())
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| anyhow::anyhow!("invalid or expired session"))?;

        Ok(AuthSession {
            username: row.try_get("username")?,
            role: row.try_get("role")?,
        })
    }

    async fn revoke_session(&self, raw_token: &str) -> Result<()> {
        let result = sqlx::query(
            r#"
            update sessions
            set revoked_at = $2
            where token_hash = $1 and revoked_at is null
            "#,
        )
        .bind(sha256_hex(raw_token))
        .bind(now_rfc3339())
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            anyhow::bail!("session token is invalid or already revoked");
        }
        Ok(())
    }

    async fn create_enrollment_request(&self, request: &EnrollmentRequest) -> Result<String> {
        let token_hash = sha256_hex(&request.enrollment_token);
        let request_id = Uuid::new_v4().to_string();
        let mut tx = self.pool.begin().await?;

        let row = sqlx::query(
            r#"
            select expires_at, single_use, max_validity_days, used_at
            from enrollment_tokens
            where token_hash = $1
            "#,
        )
        .bind(&token_hash)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| anyhow::anyhow!("invalid enrollment token"))?;

        let expires_at: String = row.try_get("expires_at")?;
        let single_use: bool = row.try_get("single_use")?;
        let max_validity_days: i64 = row.try_get("max_validity_days")?;
        let used_at: Option<String> = row.try_get("used_at")?;

        if expires_at <= now_rfc3339() {
            anyhow::bail!("enrollment token has expired");
        }
        if single_use && used_at.is_some() {
            anyhow::bail!("enrollment token has already been used");
        }

        if single_use {
            sqlx::query(
                r#"
                update enrollment_tokens
                set used_at = $2, used_by_request_id = $3
                where token_hash = $1 and used_at is null
                "#,
            )
            .bind(&token_hash)
            .bind(now_rfc3339())
            .bind(&request_id)
            .execute(&mut *tx)
            .await?;
        }

        sqlx::query(
            r#"
            insert into enrollment_requests (
                request_id, enrollment_token_hash, client_name, csr_pem, requested_validity_days,
                max_validity_days, device_json, status, created_at
            )
            values ($1, $2, $3, $4, $5, $6, $7, 'pending', $8)
            "#,
        )
        .bind(&request_id)
        .bind(&token_hash)
        .bind(&request.client_name)
        .bind(&request.csr_pem)
        .bind(request.requested_validity_days as i64)
        .bind(max_validity_days)
        .bind(serde_json::to_string(&request.device)?)
        .bind(now_rfc3339())
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(request_id)
    }

    async fn get_pending_bundle(
        &self,
        request_id: &str,
        mtls_endpoint: &str,
    ) -> Result<PendingEnrollmentBundle> {
        let row = sqlx::query(
            r#"
            select client_name, csr_pem, requested_validity_days, max_validity_days, device_json, status
            from enrollment_requests
            where request_id = $1
            "#,
        )
        .bind(request_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| anyhow::anyhow!("enrollment request not found"))?;

        let status: String = row.try_get("status")?;
        if status != "pending" {
            anyhow::bail!("enrollment request is not pending");
        }

        Ok(PendingEnrollmentBundle {
            request_id: request_id.to_owned(),
            client_name: row.try_get("client_name")?,
            csr_pem: row.try_get("csr_pem")?,
            requested_validity_days: row.try_get::<i64, _>("requested_validity_days")? as u32,
            max_validity_days: row.try_get::<i64, _>("max_validity_days")? as u32,
            device: serde_json::from_str::<DeviceIdentity>(&row.try_get::<String, _>("device_json")?)?,
            mtls_endpoint: mtls_endpoint.to_owned(),
        })
    }

    async fn get_enrollment_response(
        &self,
        request_id: &str,
        mtls_endpoint: &str,
    ) -> Result<EnrollmentResponse> {
        let row = sqlx::query(
            r#"
            select status, client_id, cert_pem, cert_fingerprint, expires_at
            from enrollment_requests
            where request_id = $1
            "#,
        )
        .bind(request_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| anyhow::anyhow!("enrollment request not found"))?;

        let status: String = row.try_get("status")?;
        if status == "issued" {
            Ok(EnrollmentResponse {
                request_id: request_id.to_owned(),
                status,
                client_id: row.try_get("client_id")?,
                client_certificate_pem: row.try_get("cert_pem")?,
                certificate_chain_pem: Vec::new(),
                client_certificate_fingerprint: row.try_get("cert_fingerprint")?,
                expires_at: row.try_get("expires_at")?,
                mtls_endpoint: mtls_endpoint.to_owned(),
                enrollment_summary: "Enrollment certificate has been issued.".to_owned(),
            })
        } else {
            Ok(EnrollmentResponse {
                request_id: request_id.to_owned(),
                status: "pending".to_owned(),
                client_id: None,
                client_certificate_pem: None,
                certificate_chain_pem: Vec::new(),
                client_certificate_fingerprint: None,
                expires_at: None,
                mtls_endpoint: mtls_endpoint.to_owned(),
                enrollment_summary: "Enrollment request is pending offline CA approval.".to_owned(),
            })
        }
    }

    async fn finalize_signed_enrollment(&self, bundle: SignedEnrollmentBundle) -> Result<EnrollmentResponse> {
        let mut tx = self.pool.begin().await?;

        let existing = sqlx::query(
            r#"
            select status
            from enrollment_requests
            where request_id = $1
            "#,
        )
        .bind(&bundle.request_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| anyhow::anyhow!("enrollment request not found"))?;
        let status: String = existing.try_get("status")?;
        if status == "issued" {
            anyhow::bail!("enrollment request is already issued");
        }

        let response = bundle.response.clone();
        let client_id = response
            .client_id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("signed enrollment bundle missing client_id"))?;
        let cert_pem = response
            .client_certificate_pem
            .clone()
            .ok_or_else(|| anyhow::anyhow!("signed enrollment bundle missing certificate"))?;
        let cert_fingerprint = response
            .client_certificate_fingerprint
            .clone()
            .ok_or_else(|| anyhow::anyhow!("signed enrollment bundle missing fingerprint"))?;
        let expires_at = response
            .expires_at
            .clone()
            .ok_or_else(|| anyhow::anyhow!("signed enrollment bundle missing expiry"))?;

        sqlx::query(
            r#"
            insert into enrolled_clients (
                client_id, client_name, hostname, username, platform, hardware_fingerprint,
                cert_fingerprint, cert_serial, cert_spiffe_uri, issued_at, expires_at, revoked_at
            )
            values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, null)
            "#,
        )
        .bind(&client_id)
        .bind(&bundle.client_name)
        .bind(&bundle.device.hostname)
        .bind(&bundle.device.username)
        .bind(&bundle.device.platform)
        .bind(&bundle.device.hardware_fingerprint)
        .bind(&cert_fingerprint)
        .bind(&bundle.cert_serial)
        .bind(&bundle.cert_spiffe_uri)
        .bind(&bundle.issued_at)
        .bind(&expires_at)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            update enrollment_requests
            set status = 'issued',
                approved_at = $2,
                client_id = $3,
                cert_pem = $4,
                cert_fingerprint = $5,
                cert_serial = $6,
                cert_spiffe_uri = $7,
                expires_at = $8
            where request_id = $1
            "#,
        )
        .bind(&bundle.request_id)
        .bind(&bundle.issued_at)
        .bind(&client_id)
        .bind(&cert_pem)
        .bind(&cert_fingerprint)
        .bind(&bundle.cert_serial)
        .bind(&bundle.cert_spiffe_uri)
        .bind(&expires_at)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(response)
    }

    async fn validate_enrolled_client(&self, fingerprint: &str) -> Result<EnrolledClient> {
        let row = sqlx::query(
            r#"
            select client_id, client_name
            from enrolled_clients
            where cert_fingerprint = $1
              and revoked_at is null
              and expires_at > $2
            "#,
        )
        .bind(fingerprint)
        .bind(now_rfc3339())
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| anyhow::anyhow!("client certificate is not enrolled or has expired"))?;

        Ok(EnrolledClient {
            client_id: row.try_get("client_id")?,
        })
    }

    async fn export_pending_enrollments(
        &self,
        out_dir: &Path,
        request_id: Option<&str>,
        mtls_endpoint: &str,
    ) -> Result<usize> {
        fs::create_dir_all(out_dir)
            .with_context(|| format!("failed creating {}", out_dir.display()))?;

        let rows = if let Some(request_id) = request_id {
            sqlx::query(
                r#"
                select request_id
                from enrollment_requests
                where status = 'pending' and request_id = $1
                "#,
            )
            .bind(request_id)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                r#"
                select request_id
                from enrollment_requests
                where status = 'pending'
                order by created_at asc
                "#,
            )
            .fetch_all(&self.pool)
            .await?
        };

        let mut count = 0usize;
        for row in rows {
            let request_id: String = row.try_get("request_id")?;
            let bundle = self.get_pending_bundle(&request_id, mtls_endpoint).await?;
            let output = out_dir.join(format!("{request_id}.json"));
            fs::write(&output, serde_json::to_vec_pretty(&bundle)?)
                .with_context(|| format!("failed writing {}", output.display()))?;
            count += 1;
        }
        Ok(count)
    }
}

async fn login_operator(
    State(api): State<HttpsApi>,
    Json(request): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, Json<ApiError>)> {
    if request.username.trim().is_empty() || request.password.is_empty() {
        return Err(to_http_error(anyhow::anyhow!(
            "username and password are required"
        )));
    }

    let response = match api
        .context
        .auth_db
        .authenticate(&request.username, &request.password)
        .await
    {
        Ok(response) => response,
        Err(err) => {
            let _ = api
                .context
                .auth_db
                .record_system_audit(
                    "login",
                    "operator",
                    &request.username,
                    false,
                    serde_json::json!({ "reason": err.to_string() }),
                )
                .await;
            return Err(to_http_error(err));
        }
    };

    api.context.state.write().unwrap().push_event(format!(
        "Operator {} authenticated with role {}",
        response.username, response.role
    ));
    let _ = api
        .context
        .auth_db
        .record_system_audit(
            "login",
            "operator",
            &response.username,
            true,
            serde_json::json!({ "role": response.role }),
        )
        .await;

    Ok(Json(response))
}

async fn logout_operator(
    State(api): State<HttpsApi>,
    Json(request): Json<LogoutRequest>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let session = api
        .context
        .auth_db
        .validate_session(&request.session_token)
        .await
        .ok();
    api.context
        .auth_db
        .revoke_session(&request.session_token)
        .await
        .map_err(to_http_error)?;
    let _ = api
        .context
        .auth_db
        .record_system_audit(
            "logout",
            "operator",
            &session
                .as_ref()
                .map(|item| item.username.clone())
                .unwrap_or_else(|| "unknown".to_owned()),
            true,
            serde_json::json!({ "role": session.as_ref().map(|item| item.role.clone()) }),
        )
        .await;
    Ok(StatusCode::NO_CONTENT)
}

async fn create_agent_bootstrap_token(
    State(api): State<HttpsApi>,
    headers: axum::http::HeaderMap,
) -> Result<Json<AgentBootstrapTokenResponse>, (StatusCode, Json<ApiError>)> {
    let session = require_http_session(&headers, &api.context.auth_db)
        .await
        .map_err(to_http_error)?;
    ensure_role(&session, &["admin"]).map_err(to_http_error)?;
    let token = api
        .context
        .auth_db
        .issue_agent_bootstrap_token("operator-issued")
        .await
        .map_err(to_http_error)?;
    let _ = api
        .context
        .auth_db
        .record_system_audit(
            "issue_agent_bootstrap_token",
            "agent_bootstrap_token",
            "operator-issued",
            true,
            serde_json::json!({ "actor_username": session.username, "expires_at": token.expires_at }),
        )
        .await;
    Ok(Json(token))
}

async fn register_agent_http(
    State(api): State<HttpsApi>,
    Json(request): Json<AgentRegistrationRequest>,
) -> Result<Json<AgentRegistrationResponse>, (StatusCode, Json<ApiError>)> {
    let response = api
        .context
        .auth_db
        .register_agent(request.clone())
        .await
        .map_err(to_http_error)?;
    let _ = api
        .context
        .auth_db
        .record_system_audit(
            "register_agent",
            "agent",
            &response.agent_id,
            true,
            serde_json::json!({
                "name": request.name,
                "environment": request.environment,
                "location": request.location,
            }),
        )
        .await;
    Ok(Json(response))
}

async fn heartbeat_agent_http(
    State(api): State<HttpsApi>,
    Json(request): Json<AgentHeartbeatRequest>,
) -> Result<Json<AgentHeartbeatResponse>, (StatusCode, Json<ApiError>)> {
    let response = api
        .context
        .auth_db
        .heartbeat_agent(request)
        .await
        .map_err(to_http_error)?;
    Ok(Json(response))
}

async fn list_agents_http(
    State(api): State<HttpsApi>,
    headers: axum::http::HeaderMap,
) -> Result<Json<Vec<AgentAdminRecord>>, (StatusCode, Json<ApiError>)> {
    let _ = require_http_session(&headers, &api.context.auth_db)
        .await
        .map_err(to_http_error)?;
    let agents = api.context.auth_db.list_agents().await.map_err(to_http_error)?;
    Ok(Json(agents))
}

async fn list_audit_http(
    State(api): State<HttpsApi>,
    headers: axum::http::HeaderMap,
) -> Result<Json<Vec<AuditEventRecord>>, (StatusCode, Json<ApiError>)> {
    let session = require_http_session(&headers, &api.context.auth_db)
        .await
        .map_err(to_http_error)?;
    ensure_role(&session, &["admin"]).map_err(to_http_error)?;
    let events = api
        .context
        .auth_db
        .list_audit_events(50)
        .await
        .map_err(to_http_error)?;
    Ok(Json(events))
}

async fn disable_agent_http(
    State(api): State<HttpsApi>,
    AxumPath(agent_id): AxumPath<String>,
    headers: axum::http::HeaderMap,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let session = require_http_session(&headers, &api.context.auth_db)
        .await
        .map_err(to_http_error)?;
    ensure_role(&session, &["admin"]).map_err(to_http_error)?;
    api.context
        .auth_db
        .disable_agent(&agent_id)
        .await
        .map_err(to_http_error)?;
    let _ = api
        .context
        .auth_db
        .record_system_audit(
            "disable_agent",
            "agent",
            &agent_id,
            true,
            serde_json::json!({ "actor_username": session.username }),
        )
        .await;
    Ok(StatusCode::NO_CONTENT)
}

async fn rotate_agent_token_http(
    State(api): State<HttpsApi>,
    AxumPath(agent_id): AxumPath<String>,
    headers: axum::http::HeaderMap,
) -> Result<Json<AgentBootstrapTokenResponse>, (StatusCode, Json<ApiError>)> {
    let session = require_http_session(&headers, &api.context.auth_db)
        .await
        .map_err(to_http_error)?;
    ensure_role(&session, &["admin"]).map_err(to_http_error)?;
    let token = api
        .context
        .auth_db
        .rotate_agent_job_token(&agent_id)
        .await
        .map_err(to_http_error)?;
    let _ = api
        .context
        .auth_db
        .record_system_audit(
            "rotate_agent_token",
            "agent",
            &agent_id,
            true,
            serde_json::json!({ "actor_username": session.username }),
        )
        .await;
    Ok(Json(token))
}

async fn enroll_client(
    State(api): State<HttpsApi>,
    Json(request): Json<EnrollmentRequest>,
) -> Result<Json<EnrollmentResponse>, (StatusCode, Json<ApiError>)> {
    validate_device_identity(&request.device).map_err(to_http_error)?;
    let request_id = api
        .context
        .auth_db
        .create_enrollment_request(&request)
        .await
        .map_err(to_http_error)?;

    let response = if let Some(authority) = &api.authority {
        let pending = api
            .context
            .auth_db
            .get_pending_bundle(&request_id, &authority.mtls_endpoint)
            .await
            .map_err(to_http_error)?;
        let signed = authority.issue_from_bundle(&pending).map_err(to_http_error)?;
        api.context
            .auth_db
            .finalize_signed_enrollment(signed)
            .await
            .map_err(to_http_error)?
    } else {
        api.context
            .auth_db
            .get_enrollment_response(&request_id, &api.mtls_endpoint)
            .await
            .map_err(to_http_error)?
    };

    {
        let mut state = api.context.state.write().unwrap();
        state.push_event(format!(
            "Enrolled client request {} using token {}",
            request.client_name,
            masked_token_hash(&request.enrollment_token)
        ));
        if response.status == "issued" {
            state.push_enrollment(EnrolledClientRecord {
                client_id: response.client_id.clone().unwrap_or_default(),
                client_name: request.client_name.clone(),
                hostname: request.device.hostname.clone(),
                issued_at: Utc::now(),
                expires_at: response
                    .expires_at
                    .as_deref()
                    .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
                    .map(|time| time.with_timezone(&Utc))
                    .unwrap_or_else(Utc::now),
                method: "certificate".to_owned(),
            });
        }
    }
    let _ = api
        .context
        .auth_db
        .record_system_audit(
            if response.status == "issued" {
                "issue_enrollment"
            } else {
                "queue_enrollment"
            },
            "client",
            &request.client_name,
            true,
            serde_json::json!({
                "request_id": response.request_id,
                "status": response.status,
                "hostname": request.device.hostname,
            }),
        )
        .await;

    Ok(Json(response))
}

async fn get_enrollment_status(
    State(api): State<HttpsApi>,
    AxumPath(request_id): AxumPath<String>,
) -> Result<Json<EnrollmentResponse>, (StatusCode, Json<ApiError>)> {
    let response = api
        .context
        .auth_db
        .get_enrollment_response(&request_id, &api.mtls_endpoint)
        .await
        .map_err(to_http_error)?;
    Ok(Json(response))
}

fn to_http_error(err: anyhow::Error) -> (StatusCode, Json<ApiError>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ApiError {
            error: err.to_string(),
        }),
    )
}

async fn require_http_session(
    headers: &axum::http::HeaderMap,
    auth_db: &AuthDatabase,
) -> Result<AuthSession> {
    let bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| anyhow::anyhow!("missing authorization header"))?;
    let token = bearer
        .strip_prefix("Bearer ")
        .ok_or_else(|| anyhow::anyhow!("expected bearer token"))?;
    auth_db.validate_session(token).await
}

fn ensure_role(session: &AuthSession, allowed: &[&str]) -> Result<()> {
    if allowed.iter().any(|role| *role == session.role) {
        Ok(())
    } else {
        anyhow::bail!("role `{}` is not permitted for this action", session.role);
    }
}

impl CertificateAuthority {
    fn new(ca_cert: &Path, ca_key: &Path, mtls_endpoint: &str) -> Result<Self> {
        let ca_cert_pem = fs::read_to_string(ca_cert)
            .with_context(|| format!("failed reading {}", ca_cert.display()))?;
        let ca_key_pem = fs::read_to_string(ca_key)
            .with_context(|| format!("failed reading {}", ca_key.display()))?;
        let issuer = Issuer::from_ca_cert_pem(
            &ca_cert_pem,
            KeyPair::from_pem(&ca_key_pem).context("invalid ca private key")?,
        )
        .context("failed constructing signing issuer from CA cert")?;

        Ok(Self {
            ca_cert_pem,
            issuer,
            mtls_endpoint: mtls_endpoint.to_owned(),
        })
    }

    fn issue_from_bundle(&self, bundle: &PendingEnrollmentBundle) -> Result<SignedEnrollmentBundle> {
        let validity_days = bundle
            .requested_validity_days
            .min(bundle.max_validity_days.max(1));
        let client_id = format!("client-{}", bundle.request_id.replace('-', ""));
        let cert_spiffe_uri = format!("spiffe://wraith/clients/{client_id}");
        let mut csr = rcgen::CertificateSigningRequestParams::from_pem(&bundle.csr_pem)
            .context("invalid CSR PEM submitted by client")?;
        csr.params.not_before = OffsetDateTime::now_utc() - time::Duration::minutes(5);
        csr.params.not_after =
            OffsetDateTime::now_utc() + time::Duration::days(validity_days as i64);
        csr.params.serial_number = Some(SerialNumber::from_slice(Uuid::new_v4().as_bytes()));
        csr.params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        csr.params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        csr.params.use_authority_key_identifier_extension = true;
        csr.params.is_ca = IsCa::ExplicitNoCa;
        csr.params
            .distinguished_name
            .push(DnType::CommonName, bundle.client_name.clone());
        csr.params
            .distinguished_name
            .push(DnType::OrganizationName, "Wraith Operators");
        csr.params.subject_alt_names.push(SanType::URI(
            cert_spiffe_uri
                .clone()
                .try_into()
                .context("invalid client URI SAN")?,
        ));
        if let Ok(hostname) = bundle.device.hostname.clone().try_into() {
            csr.params
                .subject_alt_names
                .push(SanType::DnsName(hostname));
        }
        csr.params
            .subject_alt_names
            .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        let certificate = csr
            .signed_by(&self.issuer)
            .context("failed signing client certificate")?;

        let cert_der = certificate.der().as_ref().to_vec();
        let cert_pem = certificate.pem();
        let cert_fingerprint = sha256_hex_bytes(&cert_der);
        let cert_serial = parse_certificate_serial(&cert_der)?;
        let expires_at =
            chrono::DateTime::<Utc>::from_timestamp(csr.params.not_after.unix_timestamp(), 0)
                .unwrap_or_else(Utc::now)
                .to_rfc3339();
        let issued_at = now_rfc3339();

        Ok(SignedEnrollmentBundle {
            request_id: bundle.request_id.clone(),
            client_name: bundle.client_name.clone(),
            device: bundle.device.clone(),
            cert_serial,
            cert_spiffe_uri: cert_spiffe_uri.clone(),
            issued_at: issued_at.clone(),
            response: EnrollmentResponse {
                request_id: bundle.request_id.clone(),
                status: "issued".to_owned(),
                client_id: Some(client_id),
                client_certificate_pem: Some(cert_pem),
                certificate_chain_pem: vec![self.ca_cert_pem.clone()],
                client_certificate_fingerprint: Some(cert_fingerprint),
                expires_at: Some(expires_at),
                mtls_endpoint: bundle.mtls_endpoint.clone(),
                enrollment_summary: format!(
                    "Issued a {}-day client certificate signed by the Wraith root CA",
                    validity_days
                ),
            },
        })
    }
}

async fn require_operator<T>(
    request: &Request<T>,
    auth_db: &AuthDatabase,
) -> std::result::Result<AuthenticatedOperator, Status> {
    let session = require_session_token(request, auth_db).await?;
    let peer_cert = request
        .peer_certs()
        .and_then(|certs| certs.first().cloned())
        .ok_or_else(|| Status::unauthenticated("missing client certificate"))?;
    let fingerprint = sha256_hex_bytes(peer_cert.as_ref());
    let client = auth_db
        .validate_enrolled_client(&fingerprint)
        .await
        .map_err(|err| Status::unauthenticated(err.to_string()))?;

    Ok(AuthenticatedOperator { session, client })
}

async fn require_session_token<T>(
    request: &Request<T>,
    auth_db: &AuthDatabase,
) -> std::result::Result<AuthSession, Status> {
    let header = request
        .metadata()
        .get("authorization")
        .ok_or_else(|| Status::unauthenticated("missing authorization metadata"))?;
    let bearer = header
        .to_str()
        .map_err(|_| Status::unauthenticated("invalid authorization metadata"))?;
    let token = bearer
        .strip_prefix("Bearer ")
        .ok_or_else(|| Status::unauthenticated("expected bearer token"))?;

    auth_db
        .validate_session(token)
        .await
        .map_err(|err| Status::unauthenticated(err.to_string()))
}

async fn dispatch_and_track(
    context: AppContext,
    job_id: Uuid,
    agent_id: String,
    action: MaintenanceAction,
    timeout: Duration,
) {
    let result = async {
        let agent = context.auth_db.get_agent_descriptor(&agent_id).await?;

        let pending = JobRecord {
            job_id,
            agent_id: agent.id.clone(),
            action: action.clone(),
            status: JobStatus::Pending,
            submitted_at: Utc::now(),
            started_at: None,
            completed_at: None,
            summary: format!("Queued {}", action.label()),
            details: serde_json::json!({ "phase": "queued" }),
        };

        {
            let mut state = context.state.write().unwrap();
            state.push_event(format!("{} -> {}", agent.name, pending.summary));
        }
        context.auth_db.upsert_job_record(&pending).await?;

        let acceptance = context
            .http
            .post(format!("{}/jobs", agent.base_url))
            .headers(agent_proxy_headers(&agent)?)
            .json(&JobSubmission {
                agent_id: agent.id.clone(),
                action: action.clone(),
            })
            .send()
            .await
            .context("failed to dispatch job")?
            .error_for_status()
            .context("agent rejected job")?
            .json::<JobAcceptance>()
            .await
            .context("failed to decode job acceptance")?;

        context
            .auth_db
            .upsert_job_record(&JobRecord {
                job_id,
                agent_id: agent.id.clone(),
                action: action.clone(),
                status: JobStatus::Running,
                submitted_at: pending.submitted_at,
                started_at: Some(Utc::now()),
                completed_at: None,
                summary: format!("Executing {}", action.label()),
                details: serde_json::json!({
                    "phase": "running",
                    "agent_job_id": acceptance.job_id.to_string(),
                }),
            })
            .await?;

        let started = std::time::Instant::now();
        loop {
            let job = context
                .http
                .get(format!("{}/jobs/{}", agent.base_url, acceptance.job_id))
                .headers(agent_proxy_headers(&agent)?)
                .send()
                .await
                .context("failed polling job state")?
                .error_for_status()
                .context("agent job status request failed")?
                .json::<JobRecord>()
                .await
                .context("failed decoding agent job state")?;

            let persisted = JobRecord {
                job_id,
                agent_id: job.agent_id.clone(),
                action: action.clone(),
                status: job.status.clone(),
                submitted_at: pending.submitted_at,
                started_at: job.started_at,
                completed_at: job.completed_at,
                summary: job.summary.clone(),
                details: job.details.clone(),
            };
            context.auth_db.upsert_job_record(&persisted).await?;

            if matches!(job.status, JobStatus::Completed | JobStatus::Failed) {
                break;
            }

            if started.elapsed() > timeout {
                anyhow::bail!("timed out waiting for agent response");
            }

            sleep(Duration::from_millis(250)).await;
        }

        Result::<()>::Ok(())
    }
    .await;

    if let Err(err) = result {
        let failed = JobRecord {
            job_id,
            agent_id,
            action,
            status: JobStatus::Failed,
            submitted_at: Utc::now(),
            started_at: None,
            completed_at: Some(Utc::now()),
            summary: "Job failed".to_owned(),
            details: serde_json::json!({ "error": err.to_string() }),
        };
        let _ = context.auth_db.upsert_job_record(&failed).await;
        context
            .state
            .write()
            .unwrap()
            .push_event(format!("Job {} failed: {}", job_id, err));
    }
}

fn load_catalog(path: &PathBuf) -> ServerCatalog {
    fs::read_to_string(path)
        .ok()
        .and_then(|content| serde_json::from_str::<ServerCatalog>(&content).ok())
        .unwrap_or_else(sample_catalog)
}

fn ensure_sqlite_parent_dir(database_url: &str) -> Result<()> {
    let Some(path) = database_url.strip_prefix("sqlite://") else {
        return Ok(());
    };
    if path == ":memory:" {
        return Ok(());
    }
    let db_path = PathBuf::from(path);
    if let Some(parent) = db_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed creating sqlite directory {}", parent.display())
            })?;
        }
    }
    Ok(())
}

fn load_token_store(path: &PathBuf) -> Result<EnrollmentTokenStore> {
    let content =
        fs::read_to_string(path).with_context(|| format!("failed reading {}", path.display()))?;
    serde_json::from_str(&content).context("invalid enrollment token store")
}

fn tls_config(args: &Args) -> Result<ServerTlsConfig> {
    let ca = fs::read(&args.ca_cert)
        .with_context(|| format!("failed reading {}", args.ca_cert.display()))?;
    let cert = fs::read(&args.server_cert)
        .with_context(|| format!("failed reading {}", args.server_cert.display()))?;
    let key = fs::read(&args.server_key)
        .with_context(|| format!("failed reading {}", args.server_key.display()))?;

    Ok(ServerTlsConfig::new()
        .identity(Identity::from_pem(cert, key))
        .client_ca_root(Certificate::from_pem(ca)))
}

fn generate_admin_password() -> String {
    let mut bytes = [0u8; 48];
    OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn generate_secret_token() -> String {
    generate_admin_password()
}

fn agent_proxy_headers(agent: &AgentDescriptor) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    if let Some(token) = &agent.auth_token {
        headers.insert(
            "x-wraith-agent-token",
            HeaderValue::from_str(token).context("invalid agent auth token")?,
        );
    }
    if let Some(token) = &agent.redirector_token {
        headers.insert(
            "x-wraith-redirector-token",
            HeaderValue::from_str(token).context("invalid redirector auth token")?,
        );
    }
    Ok(headers)
}

fn parse_db_timestamp(value: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.with_timezone(&Utc))
        .with_context(|| format!("invalid stored timestamp `{value}`"))
}

fn job_record_to_update(record: &JobRecord) -> JobUpdate {
    JobUpdate {
        job_id: record.job_id.to_string(),
        agent_id: record.agent_id.clone(),
        status: record.status.as_str().to_owned(),
        summary: record.summary.clone(),
        details_json: record.details.to_string(),
        submitted_at: format_timestamp(record.submitted_at),
        started_at: record
            .started_at
            .map(format_timestamp)
            .unwrap_or_default(),
        completed_at: record
            .completed_at
            .map(format_timestamp)
            .unwrap_or_default(),
        action: record.action.label(),
    }
}

fn parse_certificate_serial(cert_der: &[u8]) -> Result<String> {
    let (_, cert) =
        X509Certificate::from_der(cert_der).map_err(|err| anyhow::anyhow!("invalid cert der: {err}"))?;
    Ok(cert.tbs_certificate.raw_serial_as_string())
}

fn sign_enrollment_bundle_file(
    input: &Path,
    output: &Path,
    ca_cert: &Path,
    ca_key: &Path,
    mtls_endpoint: &str,
) -> Result<()> {
    let bundle = serde_json::from_slice::<PendingEnrollmentBundle>(
        &fs::read(input).with_context(|| format!("failed reading {}", input.display()))?,
    )
    .context("invalid pending enrollment bundle")?;
    let authority = CertificateAuthority::new(ca_cert, ca_key, mtls_endpoint)?;
    let signed = authority.issue_from_bundle(&bundle)?;
    fs::write(output, serde_json::to_vec_pretty(&signed)?)
        .with_context(|| format!("failed writing {}", output.display()))?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let args = Args::parse();
    let auth_db = AuthDatabase::connect(&args.database_url).await?;
    auth_db.init_schema().await?;
    auth_db.mark_incomplete_jobs_interrupted().await?;
    auth_db
        .sync_enrollment_tokens(load_token_store(&args.enrollment_tokens)?)
        .await?;

    match &args.command {
        Some(Command::ProvisionAdmin { username, rotate }) => {
            let generated_password = generate_admin_password();
            auth_db
                .provision_user(username, "admin", &generated_password, *rotate)
                .await?;
            println!("Provisioned admin user: {username}");
            println!("Generated password (shown once): {generated_password}");
            println!("Store this password in your secrets manager and rotate it after first use.");
            return Ok(());
        }
        Some(Command::ProvisionUser {
            username,
            role,
            rotate,
        }) => {
            let generated_password = generate_admin_password();
            auth_db
                .provision_user(username, role, &generated_password, *rotate)
                .await?;
            println!("Provisioned user: {username} ({role})");
            println!("Generated password (shown once): {generated_password}");
            return Ok(());
        }
        Some(Command::ExportPendingEnrollments { out_dir, request_id }) => {
            let count = auth_db
                .export_pending_enrollments(out_dir, request_id.as_deref(), &args.mtls_endpoint)
                .await?;
            println!("Exported {count} pending enrollment request(s) to {}", out_dir.display());
            return Ok(());
        }
        Some(Command::SignEnrollmentBundle {
            input,
            output,
            ca_cert,
            ca_key,
            mtls_endpoint,
        }) => {
            sign_enrollment_bundle_file(
                input,
                output,
                ca_cert,
                ca_key,
                mtls_endpoint.as_deref().unwrap_or(&args.mtls_endpoint),
            )?;
            println!("Signed enrollment bundle written to {}", output.display());
            return Ok(());
        }
        Some(Command::ImportSignedEnrollment { input }) => {
            let bundle = serde_json::from_slice::<SignedEnrollmentBundle>(
                &fs::read(input).with_context(|| format!("failed reading {}", input.display()))?,
            )
            .context("invalid signed enrollment bundle")?;
            let request_id = bundle.request_id.clone();
            let response = auth_db.finalize_signed_enrollment(bundle).await?;
            let _ = auth_db
                .record_system_audit(
                    "import_signed_enrollment",
                    "enrollment_request",
                    &request_id,
                    true,
                    serde_json::json!({
                        "client_id": response.client_id.clone(),
                        "status": response.status,
                    }),
                )
                .await;
            println!(
                "Imported signed enrollment for request {} ({})",
                response.request_id,
                response.client_id.unwrap_or_else(|| "unknown".to_owned())
            );
            return Ok(());
        }
        None => {}
    }

    let authority = if args.offline_ca {
        None
    } else {
        Some(Arc::new(CertificateAuthority::new(
            &args.ca_cert,
            &args.ca_key,
            &args.mtls_endpoint,
        )?))
    };

    let catalog = load_catalog(&args.catalog);
    auth_db.sync_seed_agents(catalog).await?;
    let state = Arc::new(RwLock::new(SharedState::new()));
    let http = HttpClient::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .context("failed to build http client")?;
    let context = AppContext {
        state: state.clone(),
        http,
        auth_db,
    };

    let grpc_context = context.clone();
    let grpc_addr = args.grpc_addr;
    let tls = tls_config(&args)?;
    tokio::spawn(async move {
        info!("starting gRPC server on {grpc_addr}");
        if let Err(err) = Server::builder()
            .tls_config(tls)
            .expect("invalid tls config")
            .add_service(OrchestratorServer::new(GrpcApi {
                context: grpc_context,
            }))
            .serve(grpc_addr)
            .await
        {
            error!("gRPC server exited: {err}");
        }
    });

    let https_context = context.clone();
    let https_api = HttpsApi {
        context: https_context,
        authority,
        mtls_endpoint: args.mtls_endpoint.clone(),
    };
    let https_router = Router::new()
        .route("/api/v1/enroll", post(enroll_client))
        .route("/api/v1/enroll/:request_id", get(get_enrollment_status))
        .route("/api/v1/auth/login", post(login_operator))
        .route("/api/v1/auth/logout", post(logout_operator))
        .route("/api/v1/agents", get(list_agents_http))
        .route("/api/v1/audit", get(list_audit_http))
        .route("/api/v1/agents/bootstrap-token", post(create_agent_bootstrap_token))
        .route("/api/v1/agents/register", post(register_agent_http))
        .route("/api/v1/agents/heartbeat", post(heartbeat_agent_http))
        .route("/api/v1/agents/:agent_id/disable", post(disable_agent_http))
        .route("/api/v1/agents/:agent_id/rotate-token", post(rotate_agent_token_http))
        .with_state(https_api);
    let enrollment_addr = args.enrollment_addr;
    let server_cert = args.server_cert.clone();
    let server_key = args.server_key.clone();
    tokio::spawn(async move {
        match RustlsConfig::from_pem_file(server_cert, server_key).await {
            Ok(config) => {
                info!("starting HTTPS auth/enrollment server on https://{enrollment_addr}");
                if let Err(err) = axum_server::bind_rustls(enrollment_addr, config)
                    .serve(https_router.into_make_service())
                    .await
                {
                    error!("https server exited: {err}");
                }
            }
            Err(err) => error!("failed loading HTTPS TLS config: {err}"),
        }
    });
    tokio::signal::ctrl_c()
        .await
        .context("failed waiting for shutdown signal")?;
    info!("shutdown signal received");
    Ok(())
}
