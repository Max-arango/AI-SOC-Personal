//! Process Collector Framework
//!
//! Cross-platform process event collection.

mod process_collector;
mod platform;

pub use process_collector::ProcessCollector;
pub use platform::{OsProcessCollector, ProcessEvent, ProcessInfo};

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;