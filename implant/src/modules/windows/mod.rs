// Windows-specific modules.
// Add a file per capability and register it in `modules()` below.
//
// Planned:
//   screenshot  — capture screen via BitBlt / PrintWindow
//   token       — list / steal / make tokens (OpenProcessToken, LogonUser)
//   inject      — VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
//   persist     — registry run key / scheduled task

#[allow(unused_imports)]
use super::Module;

pub fn modules() -> Vec<Box<dyn Module>> {
    vec![]
}
