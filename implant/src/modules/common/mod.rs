pub mod file_get;
pub mod file_put;
pub mod proc_list;
pub mod shell;
pub mod sysinfo;

pub use super::Module;

pub fn modules() -> Vec<Box<dyn Module>> {
    vec![
        Box::new(shell::ShellModule),
        Box::new(file_get::FileGetModule),
        Box::new(file_put::FilePutModule),
        Box::new(proc_list::ProcListModule),
        Box::new(sysinfo::SysinfoModule),
    ]
}
