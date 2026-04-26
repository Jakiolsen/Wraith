pub mod common;

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "linux")]
pub mod linux;

use serde_json::Value;

pub trait Module: Send + Sync {
    fn name(&self) -> &'static str;
    fn execute(&self, args: &[String]) -> Value;
}

pub fn registry() -> Vec<Box<dyn Module>> {
    let mut modules = common::modules();

    #[cfg(target_os = "windows")]
    modules.extend(windows::modules());

    #[cfg(target_os = "linux")]
    modules.extend(linux::modules());

    modules
}

pub fn dispatch(name: &str, args: &[String]) -> (bool, Value) {
    match registry().iter().find(|m| m.name() == name) {
        Some(m) => (true, m.execute(args)),
        None    => (false, serde_json::json!({ "error": format!("unknown module: {name}") })),
    }
}
