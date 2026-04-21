// Linux-specific modules.
// Add a file per capability and register it in `modules()` below.
//
// Planned:
//   persist  — crontab / systemd user unit
//   privesc  — SUID binary search, sudo -l enumeration

#[allow(unused_imports)]
use super::Module;

pub fn modules() -> Vec<Box<dyn Module>> {
    vec![]
}
