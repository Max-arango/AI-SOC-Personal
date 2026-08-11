//! Fanotify file event watcher — real-time kernel notifications
//! for file create, modify, delete, and execute events.
//!
//! Uses the Linux `fanotify(7)` interface via raw `libc` syscalls.
//! Falls back gracefully if the kernel doesn't support it or if we
//! lack `CAP_SYS_ADMIN`.

use std::io;
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use tracing::{debug, error, info, warn};

// ── fanotify constants (from linux/fanotify.h) ────────────────────

const FAN_CLASS_NOTIF: u32 = 0x0000_0000;
const FAN_CLASS_CONTENT: u32 = 0x0000_0004;
const FAN_REPORT_FID: u32 = 0x0000_0200;
const FAN_REPORT_DFID_NAME: u32 = 0x0000_2400;

const FAN_MARK_ADD: u32 = 0x0000_0001;
const FAN_MARK_REMOVE: u32 = 0x0000_0002;
const FAN_MARK_MOUNT: u32 = 0x0000_0010;
const FAN_MARK_FILESYSTEM: u32 = 0x0000_0100;
const FAN_MARK_ONLYDIR: u32 = 0x0000_0008;

const FAN_ACCESS: u64 = 0x0000_0001;
const FAN_MODIFY: u64 = 0x0000_0002;
const FAN_CLOSE_WRITE: u64 = 0x0000_0008;
const FAN_CLOSE_NOWRITE: u64 = 0x0000_0010;
const FAN_OPEN: u64 = 0x0000_0020;
const FAN_OPEN_EXEC: u64 = 0x0000_1000;
const FAN_DELETE: u64 = 0x0000_0200;
const FAN_DELETE_SELF: u64 = 0x0000_0400;
const FAN_MOVE_SELF: u64 = 0x0000_0800;
const FAN_ONDIR: u64 = 0x4000_0000;

const FAN_EVENT_OK: u32 = 0x0000_0001;

// ── Fanotify event metadata (from kernel) ────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
struct FanotifyEventMetadata {
    event_len: u32,
    vers: u8,
    reserved: u8,
    metadata_len: u16,
    mask: u64,
    fd: i32,
    pid: i32,
}

/// High-level decoded file event
#[derive(Debug, Clone)]
pub struct FileEvent {
    pub action: FileAction,
    pub path: String,
    pub pid: i32,
    pub timestamp_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FileAction {
    Open,
    Modify,
    CloseWrite,
    Delete,
    Exec,
}

/// Fanotify watcher handle
pub struct FanotifyWatcher {
    fan_fd: Option<RawFd>,
    watched: Vec<PathBuf>,
}

impl FanotifyWatcher {
    pub fn new() -> Self {
        Self { fan_fd: None, watched: Vec::new() }
    }

    /// Initialize fanotify and add marks for all watch paths.
    ///
    /// Returns `Ok(())` if fanotify is available and marks were
    /// successfully set, or `Err` if fallback polling should be used.
    pub fn init(&mut self, watch_paths: &[PathBuf]) -> io::Result<()> {
        let fd = fanotify_init()?;

        for path in watch_paths {
            if !path.exists() {
                debug!("Skipping non-existent watch path: {}", path.display());
                continue;
            }
            fanotify_mark(fd, path)?;
            self.watched.push(path.to_path_buf());
        }

        if self.watched.is_empty() {
            unsafe { libc::close(fd) };
            return Err(io::Error::new(io::ErrorKind::NotFound, "No valid watch paths"));
        }

        self.fan_fd = Some(fd);
        info!("Fanotify watcher initialized: {} paths, fd={}", self.watched.len(), fd);
        Ok(())
    }

    /// Read fanotify events in a blocking loop. Call from
    /// `tokio::task::spawn_blocking`. Each event is pushed through
    /// the provided channel.
    pub fn run_blocking(&self, tx: std::sync::mpsc::Sender<FileEvent>) {
        let fd = match self.fan_fd {
            Some(f) => f,
            None => return,
        };

        let mut buf = vec![0u8; 4096];

        loop {
            let n = unsafe {
                libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len() as libc::size_t)
            };

            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                error!("Fanotify read error: {e}");
                break;
            }

            if n == 0 {
                debug!("Fanotify EOF — shutting down");
                break;
            }

            let events = parse_events(&buf[..n as usize]);
            for ev in events {
                if tx.send(ev).is_err() {
                    return;
                }
            }
        }
    }
}

impl Drop for FanotifyWatcher {
    fn drop(&mut self) {
        if let Some(fd) = self.fan_fd {
            unsafe { libc::close(fd) };
        }
    }
}

// ── Internal syscall wrappers ─────────────────────────────────────

fn fanotify_init() -> io::Result<RawFd> {
    let flags = libc::O_RDONLY | libc::O_LARGEFILE | libc::O_CLOEXEC;
    let event_f_flags = FAN_CLASS_NOTIF | FAN_REPORT_FID;

    let fd = unsafe {
        libc::syscall(libc::SYS_fanotify_init, event_f_flags as libc::c_uint, flags as libc::c_uint)
    };

    if fd < 0 {
        let e = io::Error::last_os_error();
        warn!("fanotify_init failed: {e}");
        return Err(e);
    }
    Ok(fd as RawFd)
}

fn fanotify_mark(fd: RawFd, path: &Path) -> io::Result<()> {
    let mask = FAN_OPEN
        | FAN_MODIFY
        | FAN_CLOSE_WRITE
        | FAN_DELETE
        | FAN_DELETE_SELF
        | FAN_MOVE_SELF
        | FAN_OPEN_EXEC
        | FAN_ONDIR;

    let path_c = std::ffi::CString::new(path.to_string_lossy().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let ret = unsafe {
        libc::syscall(
            libc::SYS_fanotify_mark,
            fd as libc::c_int,
            (FAN_MARK_ADD | FAN_MARK_MOUNT) as libc::c_uint,
            mask as libc::c_ulonglong,
            libc::AT_FDCWD as libc::c_int,
            path_c.as_ptr() as *const libc::c_char,
        )
    };

    if ret < 0 {
        let e = io::Error::last_os_error();
        warn!("fanotify_mark failed for {}: {e}", path.display());
        return Err(e);
    }

    debug!("Watching: {}", path.display());
    Ok(())
}

// ── Parser ────────────────────────────────────────────────────────

fn parse_events(buf: &[u8]) -> Vec<FileEvent> {
    let mut events = Vec::new();
    let mut offset = 0;

    while offset + std::mem::size_of::<FanotifyEventMetadata>() <= buf.len() {
        let meta = unsafe { &*(buf.as_ptr().add(offset) as *const FanotifyEventMetadata) };

        if meta.event_len == 0 || meta.event_len as usize > buf.len() - offset {
            break;
        }

        let path = resolve_path(meta);
        let action = classify_action(meta.mask);

        if action == FileAction::Open {
            offset += meta.event_len as usize;
            continue;
        }

        events.push(FileEvent { action, path, pid: meta.pid, timestamp_secs: current_unix_secs() });

        offset += meta.event_len as usize;
        if meta.event_len == 0 {
            break;
        }
    }

    events
}

fn resolve_path(meta: &FanotifyEventMetadata) -> String {
    if meta.fd >= 0 {
        let link = format!("/proc/self/fd/{}", meta.fd);
        match std::fs::read_link(&link) {
            Ok(p) => {
                let path = p.to_string_lossy().into_owned();
                unsafe { libc::close(meta.fd as libc::c_int) };
                return path;
            },
            Err(_) => {
                unsafe { libc::close(meta.fd as libc::c_int) };
            },
        }
    }
    String::new()
}

fn classify_action(mask: u64) -> FileAction {
    if mask & FAN_DELETE != 0 || mask & FAN_DELETE_SELF != 0 {
        FileAction::Delete
    } else if mask & FAN_OPEN_EXEC != 0 {
        FileAction::Exec
    } else if mask & FAN_CLOSE_WRITE != 0 {
        FileAction::CloseWrite
    } else if mask & FAN_MODIFY != 0 {
        FileAction::Modify
    } else if mask & FAN_OPEN != 0 {
        FileAction::Open
    } else if mask & FAN_MOVE_SELF != 0 {
        FileAction::Delete
    } else {
        FileAction::Modify
    }
}

fn current_unix_secs() -> u64 {
    UNIX_EPOCH.elapsed().map(|d| d.as_secs()).unwrap_or(0)
}
