use super::Module;
use base64::Engine;
use serde_json::Value;

pub struct FileGetModule;

impl Module for FileGetModule {
    fn name(&self) -> &'static str {
        "file_get"
    }

    fn execute(&self, args: &[String]) -> Value {
        let Some(path) = args.first() else {
            return serde_json::json!({ "error": "path argument required" });
        };
        match std::fs::read(path) {
            Ok(bytes) => serde_json::json!({
                "path":        path,
                "size_bytes":  bytes.len(),
                "content_b64": base64::engine::general_purpose::STANDARD.encode(&bytes),
            }),
            Err(err) => serde_json::json!({ "error": err.to_string() }),
        }
    }
}
