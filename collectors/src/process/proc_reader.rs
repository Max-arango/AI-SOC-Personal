//! `/proc` filesystem reader for process metadata extraction.
//!
//! Reads `/proc/<pid>/cmdline`, `/proc/<pid>/status`, and
//! `/proc/<pid>/exe` to build rich process context.  All reads
//! are synchronous (tiny files) and safe to call from async
//! contexts via `tokio::task::spawn_blocking`.

use sha2::{Digest, Sha256};
use std::io;

/// Full metadata extracted from `/proc` for a single PID
#[derive(Debug, Clone)]
pub struct ProcPidInfo {
    pub pid: u32,
    pub ppid: u32,
    pub tgid: u32,
    pub name: String,
    pub exe_path: String,
    pub cmdline: String,
    pub uid: u32,
    pub username: String,
    pub cwd: String,
    pub sha256: String,
    pub start_time_ticks: u64,
}

/// Read `/proc/<pid>/cmdline` — returns the full command-line string
/// (null-separated fields joined by spaces).
pub fn read_cmdline(pid: u32) -> io::Result<String> {
    let path = format!("/proc/{}/cmdline", pid);
    let data = std::fs::read(&path)?;
    if data.is_empty() {
        return Ok(String::new());
    }
    Ok(data
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect::<Vec<_>>()
        .join(" "))
}

/// Read `/proc/<pid>/status` — parses `Name`, `PPid`, `Tgid`, `Uid`,
/// and `Gid` fields.
pub fn read_status(pid: u32) -> io::Result<StatusInfo> {
    let path = format!("/proc/{}/status", pid);
    let data = std::fs::read_to_string(&path)?;

    let mut info = StatusInfo::default();
    for line in data.lines() {
        if let Some((key, val)) = line.split_once(':') {
            let val = val.trim();
            match key {
                "Name" => info.name = val.to_string(),
                "PPid" => info.ppid = val.parse().unwrap_or(0),
                "Tgid" => info.tgid = val.parse().unwrap_or(0),
                "Uid" => {
                    let parts: Vec<&str> = val.split_whitespace().collect();
                    info.uid = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
                },
                _ => {},
            }
        }
    }
    Ok(info)
}

#[derive(Debug, Clone, Default)]
pub struct StatusInfo {
    pub name: String,
    pub ppid: u32,
    pub tgid: u32,
    pub uid: u32,
}

/// Resolve `/proc/<pid>/cwd` to an absolute path.
pub fn read_cwd(pid: u32) -> String {
    let link = format!("/proc/{}/cwd", pid);
    std::fs::read_link(&link)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Read `/proc/<pid>/exe` (symlink) to get the real binary path.
pub fn read_exe_path(pid: u32) -> String {
    let link = format!("/proc/{}/exe", pid);
    match std::fs::read_link(&link) {
        Ok(p) => p.to_string_lossy().into_owned(),
        Err(_) => {
            // Fallback: try /proc/<pid>/comm for kernel threads
            let comm = format!("/proc/{}/comm", pid);
            std::fs::read_to_string(&comm)
                .map(|s| format!("[{}]", s.trim()))
                .unwrap_or_else(|_| String::new())
        },
    }
}

/// Compute SHA-256 hash of the binary at `/proc/<pid>/exe`.
///
/// Returns empty string if the file cannot be opened (permissions,
/// kernel thread, short-lived process).
pub fn hash_exe_sha256(pid: u32) -> String {
    let exe = format!("/proc/{}/exe", pid);
    if std::fs::metadata(&exe).map(|m| m.len()).unwrap_or(0) > 50 * 1024 * 1024 {
        return String::new();
    }
    match std::fs::read(&exe) {
        Ok(data) => {
            let mut hasher = Sha256::new();
            hasher.update(&data);
            format!("{:x}", hasher.finalize())
        },
        Err(_) => String::new(),
    }
}

/// Resolve UID → username via `getpwuid_r`.
pub fn uid_to_username(uid: u32) -> String {
    let mut buf = vec![0u8; 1024];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };

    let ret = unsafe {
        libc::getpwuid_r(
            uid,
            &mut pwd,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            &mut result,
        )
    };
    if ret == 0 && !result.is_null() {
        unsafe {
            std::ffi::CStr::from_ptr((*result).pw_name)
                .to_string_lossy()
                .into_owned()
        }
    } else {
        uid.to_string()
    }
}

/// Read process start time from `/proc/<pid>/stat`.
///
/// Field 22 (0-indexed field 21) is `starttime` in clock ticks.
pub fn read_start_time_ticks(pid: u32) -> u64 {
    let path = format!("/proc/{}/stat", pid);
    match std::fs::read_to_string(&path) {
        Ok(data) => {
            // Field 22 is after the comm field (which is in parens)
            let after_paren = data.rfind(')').map(|i| &data[i + 2..]).unwrap_or("");
            after_paren
                .split_whitespace()
                .nth(19) // 0-indexed after removing pid+comm = field 19
                .and_then(|s| s.parse().ok())
                .unwrap_or(0)
        },
        Err(_) => 0,
    }
}

/// Convenience: gather all proc info for a PID.
pub fn gather_pid_info(pid: u32) -> ProcPidInfo {
    let status = read_status(pid).unwrap_or_default();
    let sha256 = hash_exe_sha256(pid);

    ProcPidInfo {
        pid,
        ppid: status.ppid,
        tgid: status.tgid,
        name: if status.name.is_empty() {
            read_exe_path(pid)
                .rsplit('/')
                .next()
                .unwrap_or("?")
                .to_string()
        } else {
            status.name
        },
        exe_path: read_exe_path(pid),
        cmdline: read_cmdline(pid).unwrap_or_default(),
        uid: status.uid,
        username: uid_to_username(status.uid),
        cwd: read_cwd(pid),
        sha256,
        start_time_ticks: read_start_time_ticks(pid),
    }
}

/// Async wrapper: gather all proc info without blocking the runtime.
pub async fn gather_pid_info_async(pid: u32) -> ProcPidInfo {
    tokio::task::spawn_blocking(move || gather_pid_info(pid))
        .await
        .unwrap_or_else(|_| ProcPidInfo {
            pid,
            ppid: 0,
            tgid: 0,
            name: "?".into(),
            exe_path: String::new(),
            cmdline: String::new(),
            uid: 0,
            username: String::new(),
            cwd: String::new(),
            sha256: String::new(),
            start_time_ticks: 0,
        })
}
