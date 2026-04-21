use super::Module;
use serde_json::Value;
use sysinfo::System;

pub struct SysinfoModule;

impl Module for SysinfoModule {
    fn name(&self) -> &'static str {
        "sysinfo"
    }

    fn execute(&self, _args: &[String]) -> Value {
        let mut sys = System::new_all();
        sys.refresh_all();
        serde_json::json!({
            "hostname":        System::host_name().unwrap_or_else(|| "unknown".to_owned()),
            "os":              System::long_os_version().unwrap_or_else(|| std::env::consts::OS.to_owned()),
            "kernel":          System::kernel_version().unwrap_or_default(),
            "arch":            std::env::consts::ARCH,
            "cpu_count":       sys.cpus().len(),
            "total_memory_mb": sys.total_memory() / 1024 / 1024,
            "used_memory_mb":  sys.used_memory() / 1024 / 1024,
            "uptime_secs":     System::uptime(),
        })
    }
}
