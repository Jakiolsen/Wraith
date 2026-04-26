use super::Module;
use serde_json::Value;
use std::process::Command;

pub struct ShellModule;

impl Module for ShellModule {
    fn name(&self) -> &'static str { "shell" }

    fn execute(&self, args: &[String]) -> Value {
        let command = args.join(" ");
        if command.trim().is_empty() {
            return serde_json::json!({ "error": "no command provided" });
        }

        #[cfg(windows)]
        let result = Command::new("cmd").args(["/C", &command]).output();

        #[cfg(not(windows))]
        let result = Command::new("sh").args(["-c", &command]).output();

        match result {
            Ok(output) => serde_json::json!({
                "command":   command,
                "exit_code": output.status.code(),
                "stdout":    String::from_utf8_lossy(&output.stdout).trim().to_owned(),
                "stderr":    String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            }),
            Err(err) => serde_json::json!({ "error": err.to_string() }),
        }
    }
}
