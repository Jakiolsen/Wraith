use super::Module;
use base64::Engine;
use serde_json::Value;

pub struct FilePutModule;

impl Module for FilePutModule {
    fn name(&self) -> &'static str { "file_put" }

    /// args[0] = destination path, args[1] = base64-encoded content
    fn execute(&self, args: &[String]) -> Value {
        let (Some(path), Some(b64)) = (args.first(), args.get(1)) else {
            return serde_json::json!({ "error": "path and content_b64 arguments required" });
        };
        let bytes = match base64::engine::general_purpose::STANDARD.decode(b64) {
            Ok(b)    => b,
            Err(err) => return serde_json::json!({ "error": format!("invalid base64: {err}") }),
        };
        if let Some(parent) = std::path::Path::new(path).parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        match std::fs::write(path, &bytes) {
            Ok(()) => serde_json::json!({ "path": path, "size_bytes": bytes.len(), "success": true }),
            Err(err) => serde_json::json!({ "error": err.to_string() }),
        }
    }
}
