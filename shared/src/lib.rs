use serde::{Deserialize, Serialize};

pub mod proto {
    tonic::include_proto!("orchestrator");
}

// ── Implant wire types (HTTP) ─────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImplantCheckin {
    pub session_id:  Option<String>,
    pub hostname:    String,
    pub username:    String,
    pub os:          String,
    pub arch:        String,
    pub internal_ip: String,
    pub profile:     String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImplantCheckinResponse {
    pub session_id: String,
    pub tasks:      Vec<ImplantTask>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImplantTask {
    pub task_id: String,
    pub module:  String,
    pub args:    Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImplantTaskResult {
    pub session_id: String,
    pub task_id:    String,
    pub module:     String,
    pub success:    bool,
    pub output:     serde_json::Value,
}
