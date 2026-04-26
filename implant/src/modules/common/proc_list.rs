use super::Module;
use serde_json::Value;
use sysinfo::System;

pub struct ProcListModule;

impl Module for ProcListModule {
    fn name(&self) -> &'static str { "proc_list" }

    fn execute(&self, _args: &[String]) -> Value {
        let mut sys = System::new_all();
        sys.refresh_all();
        let processes: Vec<Value> = sys
            .processes()
            .iter()
            .map(|(pid, proc)| serde_json::json!({
                "pid":    pid.as_u32(),
                "name":   proc.name().to_string_lossy().to_string(),
                "cpu":    proc.cpu_usage(),
                "mem_kb": proc.memory() / 1024,
                "status": format!("{:?}", proc.status()),
            }))
            .collect();
        let count = processes.len();
        serde_json::json!({ "processes": processes, "count": count })
    }
}
