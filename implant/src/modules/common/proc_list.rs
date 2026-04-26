use super::Module;
use serde_json::Value;
use sysinfo::{System, Users};

pub struct ProcListModule;

impl Module for ProcListModule {
    fn name(&self) -> &'static str { "proc_list" }

    fn execute(&self, _args: &[String]) -> Value {
        let mut sys = System::new_all();
        sys.refresh_all();
        let users = Users::new_with_refreshed_list();

        let processes: Vec<Value> = sys
            .processes()
            .iter()
            .map(|(pid, proc)| {
                let user = proc.user_id()
                    .and_then(|uid| users.get_user_by_id(uid))
                    .map(|u| u.name().to_string())
                    .unwrap_or_default();
                let path = proc.exe()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();
                serde_json::json!({
                    "pid":    pid.as_u32(),
                    "ppid":   proc.parent().map(|p| p.as_u32()).unwrap_or(0),
                    "name":   proc.name().to_string_lossy(),
                    "user":   user,
                    "mem_kb": proc.memory() / 1024,
                    "path":   path,
                })
            })
            .collect();

        let count = processes.len();
        serde_json::json!({ "processes": processes, "count": count })
    }
}
