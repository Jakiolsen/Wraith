use anyhow::{Context, Result};
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use clap::Parser;
use profiles::C2Profile;
use reqwest::Client;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(about = "Wraith redirector — profile-aware HTTP(S) traffic relay")]
struct Args {
    /// Address to listen on.
    #[arg(long, default_value = "0.0.0.0:8080")]
    listen: SocketAddr,
    /// Directory containing *.toml profile files.
    #[arg(long, default_value = "profiles/examples")]
    profiles_dir: PathBuf,
    /// Single profile file (alternative to --profiles-dir).
    #[arg(long)]
    profile: Option<PathBuf>,
    /// Upstream C2 server base URL (e.g. http://127.0.0.1:8081).
    #[arg(long, default_value = "http://127.0.0.1:8081")]
    upstream: String,
    /// TLS certificate (PEM) for HTTPS listener. If omitted, plain HTTP.
    #[arg(long)]
    tls_cert: Option<PathBuf>,
    /// TLS key (PEM) for HTTPS listener.
    #[arg(long)]
    tls_key: Option<PathBuf>,
    /// Verbosity level (info, debug, warn).
    #[arg(long, default_value = "info")]
    log_level: String,
}

/// A URI route derived from one or more loaded profiles.
#[derive(Clone, Debug)]
struct Route {
    profile_name: String,
    /// The external URI pattern (e.g. "/ajax/libs/jquery/3.7.1/jquery.min.js").
    external_uri: String,
    /// The internal server URI the traffic is forwarded to.
    internal_uri: String,
    redirector_token: String,
    decoy_url: Option<String>,
}

#[derive(Clone)]
struct AppState {
    routes: Arc<Vec<Route>>,
    upstream: String,
    http: Client,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(format!("redirector={}", args.log_level))
        .init();

    let profiles = load_profiles(&args)?;
    if profiles.is_empty() {
        anyhow::bail!("no profiles loaded — check --profiles-dir or --profile");
    }

    let routes = build_routes(&profiles);
    info!(
        "loaded {} profile(s), {} route(s)",
        profiles.len(),
        routes.len()
    );
    for route in &routes {
        info!(
            "  [{}] {} → {}{}",
            route.profile_name, route.external_uri, args.upstream, route.internal_uri
        );
    }

    let state = AppState {
        routes: Arc::new(routes),
        upstream: args.upstream.clone(),
        http: Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .context("failed building HTTP client")?,
    };

    let app = Router::new()
        .fallback(handle_request)
        .with_state(state);

    let listener = TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("failed to bind {}", args.listen))?;
    info!("redirector listening on {}", args.listen);

    axum::serve(listener, app).await?;
    Ok(())
}

async fn handle_request(
    State(state): State<AppState>,
    req: Request,
) -> Response {
    let method = req.method().clone();
    let uri = req.uri().path().to_owned();
    let headers = req.headers().clone();

    let route = match state.routes.iter().find(|r| r.external_uri == uri || uri.starts_with(&r.external_uri)) {
        Some(r) => r.clone(),
        None => return handle_no_route(&state, uri).await,
    };

    info!("[{}] {} {} → forward", route.profile_name, method, uri);

    let body_bytes = match axum::body::to_bytes(req.into_body(), 16 * 1024 * 1024).await {
        Ok(b) => b,
        Err(err) => {
            warn!("failed reading request body: {err}");
            return (StatusCode::BAD_REQUEST, "body read error").into_response();
        }
    };

    let upstream_url = format!("{}{}", state.upstream, route.internal_uri);
    let mut req_builder = state.http.request(method, &upstream_url);

    // Forward safe headers, strip hop-by-hop headers
    let mut fwd_headers = HeaderMap::new();
    for (name, value) in &headers {
        let skip = matches!(
            name.as_str(),
            "host" | "connection" | "transfer-encoding" | "te" | "trailers" | "upgrade"
        );
        if !skip {
            fwd_headers.insert(name.clone(), value.clone());
        }
    }

    // Add redirector authentication token
    if let Ok(v) = HeaderValue::from_str(&route.redirector_token) {
        fwd_headers.insert(
            HeaderName::from_static("x-wraith-redirector-token"),
            v,
        );
    }

    req_builder = req_builder.headers(fwd_headers).body(body_bytes.to_vec());

    match req_builder.send().await {
        Ok(resp) => proxy_response(resp).await,
        Err(err) => {
            warn!("upstream request failed: {err}");
            (StatusCode::BAD_GATEWAY, "upstream error").into_response()
        }
    }
}

async fn handle_no_route(state: &AppState, uri: String) -> Response {
    // Use the decoy URL from any loaded profile (they all share the same decoy if configured).
    let decoy = state.routes.first().and_then(|r| r.decoy_url.clone());
    if let Some(decoy_url) = decoy.filter(|u| !u.is_empty()) {
        let target = format!("{decoy_url}{uri}");
        match state.http.get(&target).send().await {
            Ok(resp) => return proxy_response(resp).await,
            Err(err) => {
                warn!("decoy proxy failed: {err}");
            }
        }
    }
    (StatusCode::NOT_FOUND, "Not Found").into_response()
}

async fn proxy_response(resp: reqwest::Response) -> Response {
    let status = StatusCode::from_u16(resp.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    let mut headers = HeaderMap::new();
    for (name, value) in resp.headers() {
        let skip = matches!(
            name.as_str(),
            "connection" | "transfer-encoding" | "x-wraith-redirector-token"
        );
        if skip {
            continue;
        }
        if let Ok(n) = HeaderName::from_str(name.as_str()) {
            headers.insert(n, value.clone());
        }
    }

    let body = match resp.bytes().await {
        Ok(b) => b,
        Err(err) => {
            warn!("failed reading upstream body: {err}");
            return (StatusCode::BAD_GATEWAY, "upstream body error").into_response();
        }
    };

    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
}

fn load_profiles(args: &Args) -> Result<Vec<C2Profile>> {
    if let Some(single) = &args.profile {
        return Ok(vec![C2Profile::from_file(single)?]);
    }
    C2Profile::load_directory(&args.profiles_dir)
}

fn build_routes(profiles: &[C2Profile]) -> Vec<Route> {
    let mut seen: HashMap<String, bool> = HashMap::new();
    let mut routes = Vec::new();

    for p in profiles {
        let checkin_key = p.http.checkin_uri.clone();
        let result_key = p.http.result_uri.clone();

        if seen.insert(checkin_key.clone(), true).is_none() {
            routes.push(Route {
                profile_name: p.profile.name.clone(),
                external_uri: p.http.checkin_uri.clone(),
                internal_uri: p.server.internal_checkin_uri.clone(),
                redirector_token: p.server.redirector_token.clone(),
                decoy_url: p.server.decoy_url.clone(),
            });
        }

        if seen.insert(result_key.clone(), true).is_none() {
            routes.push(Route {
                profile_name: p.profile.name.clone(),
                external_uri: p.http.result_uri.clone(),
                internal_uri: p.server.internal_result_uri.clone(),
                redirector_token: p.server.redirector_token.clone(),
                decoy_url: p.server.decoy_url.clone(),
            });
        }
    }

    routes
}
