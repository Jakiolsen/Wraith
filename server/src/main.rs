use anyhow::{Context, Result};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use axum::extract::State;
use axum::http::StatusCode;
use axum::{Json, Router, routing::post};
use axum_server::tls_rustls::RustlsConfig;
use base64::Engine;
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use rand_core::OsRng;
use rand_core::RngCore;
use rcgen::{
    DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType, SerialNumber,
};
use reqwest::Client as HttpClient;
use shared::proto::orchestrator_server::{Orchestrator, OrchestratorServer};
use shared::proto::{
    AgentSnapshot, DashboardSnapshot, Empty, RecentJob, SubmitJobRequest, SubmitJobResponse,
};
use shared::{
    AgentDescriptor, AgentHealth, EnrollmentRequest, EnrollmentResponse, EnrollmentTokenRecord,
    EnrollmentTokenStore, JobAcceptance, JobRecord, JobStatus, JobSubmission, LoginRequest,
    LoginResponse, MaintenanceAction, ServerCatalog, format_timestamp, masked_token_hash,
    sample_catalog, sha256_hex, validate_device_identity,
};
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use time::OffsetDateTime;
use tokio::time::sleep;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};
use tracing::{error, info};
use uuid::Uuid;

const DEFAULT_DATABASE_URL: &str = "sqlite://data/wraith_orchestrator.db";

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
}

#[derive(Clone)]
struct SharedState {
    catalog: Vec<AgentDescriptor>,
    health: HashMap<String, AgentHealth>,
    recent_jobs: VecDeque<JobRecord>,
    event_log: VecDeque<String>,
    enrolled_clients: VecDeque<EnrolledClientRecord>,
    recent_logins: VecDeque<AuthSession>,
}

impl SharedState {
    fn new(catalog: Vec<AgentDescriptor>) -> Self {
        Self {
            catalog,
            health: HashMap::new(),
            recent_jobs: VecDeque::with_capacity(32),
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

    fn upsert_job(&mut self, record: JobRecord) {
        if let Some(existing) = self
            .recent_jobs
            .iter_mut()
            .find(|item| item.job_id == record.job_id)
        {
            *existing = record;
        } else {
            self.recent_jobs.push_front(record);
            while self.recent_jobs.len() > 18 {
                self.recent_jobs.pop_back();
            }
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
    authority: Arc<CertificateAuthority>,
    token_store: Arc<TokenStore>,
}

struct CertificateAuthority {
    ca_cert_pem: String,
    issuer: Issuer<'static, KeyPair>,
    mtls_endpoint: String,
}

struct TokenStore {
    tokens: Vec<EnrollmentTokenRecord>,
    used_token_hashes: RwLock<HashSet<String>>,
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
struct CompletedJob {
    job_id: Uuid,
    status: JobStatus,
    summary: String,
    details: serde_json::Value,
}

#[tonic::async_trait]
impl Orchestrator for GrpcApi {
    async fn get_dashboard(
        &self,
        request: Request<Empty>,
    ) -> std::result::Result<Response<DashboardSnapshot>, Status> {
        let session = require_session(&request, &self.context.auth_db).await?;
        {
            let mut state = self.context.state.write().unwrap();
            state.push_login(session);
        }

        let state = self.context.state.read().unwrap().clone();
        let agents = state
            .catalog
            .iter()
            .map(|agent| {
                let health = state.health.get(&agent.id);
                AgentSnapshot {
                    id: agent.id.clone(),
                    name: agent.name.clone(),
                    environment: agent.environment.clone(),
                    location: agent.location.clone(),
                    endpoint: agent.base_url.clone(),
                    online: health.is_some_and(|item| item.online),
                    status: health
                        .map(|item| item.status.clone())
                        .unwrap_or_else(|| "unknown".to_owned()),
                    last_seen: health
                        .map(|item| format_timestamp(item.last_seen))
                        .unwrap_or_else(|| "never".to_owned()),
                    capabilities: agent.capabilities.clone(),
                }
            })
            .collect();

        let recent_jobs = state
            .recent_jobs
            .iter()
            .map(|job| RecentJob {
                job_id: job.job_id.to_string(),
                agent_id: job.agent_id.clone(),
                agent_name: state
                    .catalog
                    .iter()
                    .find(|item| item.id == job.agent_id)
                    .map(|item| item.name.clone())
                    .unwrap_or_else(|| job.agent_id.clone()),
                action: job.action.label(),
                status: job.status.as_str().to_owned(),
                submitted_at: format_timestamp(job.submitted_at),
                summary: job.summary.clone(),
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
        let session = require_session(&request, &self.context.auth_db).await?;
        let payload = request.into_inner();
        let action = MaintenanceAction::from_proto(&payload)
            .map_err(|err| Status::invalid_argument(err.to_string()))?;

        let result = dispatch_and_track(
            self.context.clone(),
            payload.agent_id,
            action,
            Duration::from_secs(20),
        )
        .await
        .map_err(|err| Status::internal(err.to_string()))?;

        self.context.state.write().unwrap().push_event(format!(
            "Operator {} submitted {}",
            session.username, result.summary
        ));

        Ok(Response::new(SubmitJobResponse {
            accepted: true,
            job_id: result.job_id.to_string(),
            status: result.status.as_str().to_owned(),
            summary: result.summary,
            details_json: result.details.to_string(),
        }))
    }
}

impl TokenStore {
    fn new(store: EnrollmentTokenStore) -> Self {
        Self {
            tokens: store.tokens,
            used_token_hashes: RwLock::new(HashSet::new()),
        }
    }

    fn consume(&self, raw_token: &str) -> Result<EnrollmentTokenRecord> {
        let token_hash = sha256_hex(raw_token);
        let record = self
            .tokens
            .iter()
            .find(|record| record.token_hash == token_hash)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("invalid enrollment token"))?;

        let expires_at = DateTime::parse_from_rfc3339(&record.expires_at)
            .context("invalid enrollment token expiry")?
            .with_timezone(&Utc);
        if expires_at < Utc::now() {
            anyhow::bail!("enrollment token has expired");
        }

        if record.single_use {
            let mut used = self.used_token_hashes.write().unwrap();
            if !used.insert(token_hash) {
                anyhow::bail!("enrollment token has already been used");
            }
        }

        Ok(record)
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

    async fn init_schema(&self) -> Result<()> {
        sqlx::query(
            r#"
            create table if not exists users (
                id uuid primary key,
                username text not null unique,
                password_hash text not null,
                role text not null,
                is_active boolean not null default true,
                created_at timestamptz not null
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            create table if not exists sessions (
                id uuid primary key,
                user_id uuid not null references users(id) on delete cascade,
                token_hash text not null unique,
                expires_at timestamptz not null,
                created_at timestamptz not null,
                revoked_at timestamptz
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn provision_admin_user(
        &self,
        username: &str,
        password: &str,
        rotate_existing: bool,
    ) -> Result<()> {
        let existing = sqlx::query(
            r#"
            select id
            from users
            where username = $1
            "#,
        )
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
            values ($1, $2, $3, 'admin', true, $4)
            on conflict (username) do update
            set password_hash = excluded.password_hash,
                role = excluded.role,
                is_active = excluded.is_active;
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(username)
        .bind(password_hash)
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn authenticate(&self, username: &str, password: &str) -> Result<LoginResponse> {
        let row = sqlx::query(
            r#"
            select id, password_hash, role, is_active
            from users
            where username = $1
            "#,
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| anyhow::anyhow!("invalid username or password"))?;

        let user_id: Uuid = row.try_get("id")?;
        let password_hash: String = row.try_get("password_hash")?;
        let role: String = row.try_get("role")?;
        let is_active: bool = row.try_get("is_active")?;
        if !is_active {
            anyhow::bail!("user account is disabled");
        }

        let parsed = PasswordHash::new(&password_hash)
            .map_err(|err| anyhow::anyhow!("stored password hash is invalid: {err}"))?;
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .map_err(|_| anyhow::anyhow!("invalid username or password"))?;

        let raw_token = format!("{}.{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let token_hash = sha256_hex(&raw_token);
        let expires_at = Utc::now() + chrono::Duration::hours(8);

        sqlx::query(
            r#"
            insert into sessions (id, user_id, token_hash, expires_at, created_at, revoked_at)
            values ($1, $2, $3, $4, $5, null)
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(user_id)
        .bind(token_hash)
        .bind(expires_at)
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;

        Ok(LoginResponse {
            session_token: raw_token,
            username: username.to_owned(),
            role,
            expires_at: expires_at.to_rfc3339(),
        })
    }

    async fn validate_session(&self, raw_token: &str) -> Result<AuthSession> {
        let token_hash = sha256_hex(raw_token);
        let row = sqlx::query(
            r#"
            select u.username
            from sessions s
            join users u on u.id = s.user_id
            where s.token_hash = $1
              and s.revoked_at is null
              and s.expires_at > now()
              and u.is_active = true
            "#,
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| anyhow::anyhow!("invalid or expired session"))?;

        Ok(AuthSession {
            username: row.try_get("username")?,
        })
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

    let response = api
        .context
        .auth_db
        .authenticate(&request.username, &request.password)
        .await
        .map_err(to_http_error)?;

    api.context.state.write().unwrap().push_event(format!(
        "Operator {} authenticated with role {}",
        response.username, response.role
    ));

    Ok(Json(response))
}

async fn enroll_client(
    State(api): State<HttpsApi>,
    Json(request): Json<EnrollmentRequest>,
) -> Result<Json<EnrollmentResponse>, (StatusCode, Json<ApiError>)> {
    let token = api
        .token_store
        .consume(&request.enrollment_token)
        .map_err(to_http_error)?;
    validate_device_identity(&request.device).map_err(to_http_error)?;
    let response = api
        .authority
        .issue_client_certificate(&request, token.max_validity_days)
        .map_err(to_http_error)?;

    {
        let mut state = api.context.state.write().unwrap();
        state.push_event(format!(
            "Enrolled client {} using token {}",
            request.client_name,
            masked_token_hash(&request.enrollment_token)
        ));
        state.push_enrollment(EnrolledClientRecord {
            client_id: response.client_id.clone(),
            client_name: request.client_name.clone(),
            hostname: request.device.hostname.clone(),
            issued_at: Utc::now(),
            expires_at: DateTime::parse_from_rfc3339(&response.expires_at)
                .map(|time| time.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            method: "certificate".to_owned(),
        });
    }

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

impl CertificateAuthority {
    fn new(args: &Args) -> Result<Self> {
        let ca_cert_pem = fs::read_to_string(&args.ca_cert)
            .with_context(|| format!("failed reading {}", args.ca_cert.display()))?;
        let ca_key_pem = fs::read_to_string(&args.ca_key)
            .with_context(|| format!("failed reading {}", args.ca_key.display()))?;
        let issuer = Issuer::from_ca_cert_pem(
            &ca_cert_pem,
            KeyPair::from_pem(&ca_key_pem).context("invalid ca private key")?,
        )
        .context("failed constructing signing issuer from CA cert")?;

        Ok(Self {
            ca_cert_pem,
            issuer,
            mtls_endpoint: args.mtls_endpoint.clone(),
        })
    }

    fn issue_client_certificate(
        &self,
        request: &EnrollmentRequest,
        max_validity_days: u32,
    ) -> Result<EnrollmentResponse> {
        if request.client_name.trim().is_empty() {
            anyhow::bail!("client_name is required");
        }
        if request.requested_validity_days == 0 {
            anyhow::bail!("requested_validity_days must be greater than zero");
        }

        let validity_days = request
            .requested_validity_days
            .min(max_validity_days.max(1));
        let client_id = format!("client-{}", Uuid::new_v4().simple());
        let mut csr = rcgen::CertificateSigningRequestParams::from_pem(&request.csr_pem)
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
            .push(DnType::CommonName, request.client_name.clone());
        csr.params
            .distinguished_name
            .push(DnType::OrganizationName, "Wraith Operators");
        csr.params.subject_alt_names.push(SanType::URI(
            format!("spiffe://wraith/clients/{client_id}")
                .try_into()
                .context("invalid client URI SAN")?,
        ));
        if let Ok(hostname) = request.device.hostname.clone().try_into() {
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
        let cert_pem = certificate.pem();
        let expires_at =
            chrono::DateTime::<Utc>::from_timestamp(csr.params.not_after.unix_timestamp(), 0)
                .unwrap_or_else(Utc::now)
                .to_rfc3339();

        Ok(EnrollmentResponse {
            client_id,
            client_certificate_pem: cert_pem,
            certificate_chain_pem: vec![self.ca_cert_pem.clone()],
            expires_at,
            mtls_endpoint: self.mtls_endpoint.clone(),
            enrollment_summary: format!(
                "Issued a {}-day client certificate signed by the Wraith root CA",
                validity_days
            ),
        })
    }
}

async fn require_session<T>(
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
    agent_id: String,
    action: MaintenanceAction,
    timeout: Duration,
) -> Result<CompletedJob> {
    let agent = {
        let state = context.state.read().unwrap();
        state
            .catalog
            .iter()
            .find(|item| item.id == agent_id)
            .cloned()
            .with_context(|| format!("unknown agent: {agent_id}"))?
    };

    let pending = JobRecord {
        job_id: Uuid::new_v4(),
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
        state.upsert_job(pending.clone());
    }

    let acceptance = context
        .http
        .post(format!("{}/jobs", agent.base_url))
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

    {
        let mut state = context.state.write().unwrap();
        state.upsert_job(JobRecord {
            job_id: acceptance.job_id,
            agent_id: agent.id.clone(),
            action: action.clone(),
            status: JobStatus::Running,
            submitted_at: pending.submitted_at,
            started_at: Some(Utc::now()),
            completed_at: None,
            summary: format!("Executing {}", action.label()),
            details: serde_json::json!({ "phase": "running" }),
        });
    }

    let started = std::time::Instant::now();
    loop {
        let job = context
            .http
            .get(format!("{}/jobs/{}", agent.base_url, acceptance.job_id))
            .send()
            .await
            .context("failed polling job state")?
            .error_for_status()
            .context("agent job status request failed")?
            .json::<JobRecord>()
            .await
            .context("failed decoding agent job state")?;

        {
            let mut state = context.state.write().unwrap();
            state.upsert_job(job.clone());
        }

        if matches!(job.status, JobStatus::Completed | JobStatus::Failed) {
            return Ok(CompletedJob {
                job_id: job.job_id,
                status: job.status,
                summary: job.summary,
                details: job.details,
            });
        }

        if started.elapsed() > timeout {
            anyhow::bail!("timed out waiting for agent response");
        }

        sleep(Duration::from_millis(350)).await;
    }
}

async fn refresh_agent_health(context: AppContext) {
    loop {
        let agents = {
            let state = context.state.read().unwrap();
            state.catalog.clone()
        };

        for agent in agents {
            let health = match context
                .http
                .get(format!("{}/health", agent.base_url))
                .send()
                .await
            {
                Ok(response) => match response.error_for_status() {
                    Ok(ok) => ok.json::<AgentHealth>().await.unwrap_or(AgentHealth {
                        online: false,
                        status: "degraded".to_owned(),
                        detail: "health payload parse error".to_owned(),
                        last_seen: Utc::now(),
                    }),
                    Err(err) => AgentHealth {
                        online: false,
                        status: "offline".to_owned(),
                        detail: err.to_string(),
                        last_seen: Utc::now(),
                    },
                },
                Err(err) => AgentHealth {
                    online: false,
                    status: "offline".to_owned(),
                    detail: err.to_string(),
                    last_seen: Utc::now(),
                },
            };

            let mut state = context.state.write().unwrap();
            state.health.insert(agent.id.clone(), health);
        }

        sleep(Duration::from_secs(5)).await;
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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let args = Args::parse();
    let auth_db = AuthDatabase::connect(&args.database_url).await?;
    auth_db.init_schema().await?;

    if let Some(Command::ProvisionAdmin { username, rotate }) = &args.command {
        let generated_password = generate_admin_password();
        auth_db
            .provision_admin_user(username, &generated_password, *rotate)
            .await?;
        println!("Provisioned admin user: {username}");
        println!("Generated password (shown once): {generated_password}");
        println!("Store this password in your secrets manager and rotate it after first use.");
        return Ok(());
    }

    let catalog = load_catalog(&args.catalog);
    let token_store = Arc::new(TokenStore::new(load_token_store(&args.enrollment_tokens)?));
    let authority = Arc::new(CertificateAuthority::new(&args)?);
    let state = Arc::new(RwLock::new(SharedState::new(catalog.agents)));
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
        token_store,
    };
    let https_router = Router::new()
        .route("/api/v1/enroll", post(enroll_client))
        .route("/api/v1/auth/login", post(login_operator))
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

    tokio::spawn(refresh_agent_health(context));

    tokio::signal::ctrl_c()
        .await
        .context("failed waiting for shutdown signal")?;
    info!("shutdown signal received");
    Ok(())
}
