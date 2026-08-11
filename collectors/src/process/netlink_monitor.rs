//! Netlink CN_PROC monitor — subscribes to kernel process events
//! and parses fork/exec/exit/comms in real time.
//!
//! Opens `AF_NETLINK` socket with `NETLINK_CONNECTOR` protocol,
//! registers for `CN_IDX_PROC` multicast, and spawns an async
//! read loop that produces `ProcessEvent` items via a channel.

use std::io;
use std::os::fd::{AsRawFd, RawFd};

use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use super::netlink_bindings::*;

/// High-level decoded process event
#[derive(Debug, Clone)]
pub enum ProcNetlinkEvent {
    Fork {
        parent_pid: i32,
        parent_tgid: i32,
        child_pid: i32,
        child_tgid: i32,
        timestamp_ns: u64,
    },
    Exec {
        process_pid: i32,
        process_tgid: i32,
        timestamp_ns: u64,
    },
    Exit {
        process_pid: i32,
        process_tgid: i32,
        exit_code: u32,
        exit_signal: u32,
        timestamp_ns: u64,
    },
    Comm {
        process_pid: i32,
        process_tgid: i32,
        comm: [u8; 16],
        timestamp_ns: u64,
    },
    Uid {
        process_pid: i32,
        process_tgid: i32,
        ruid: u32,
        euid: u32,
        timestamp_ns: u64,
    },
    Ptrace {
        process_pid: i32,
        process_tgid: i32,
        tracer_pid: i32,
        tracer_tgid: i32,
        timestamp_ns: u64,
    },
    Coredump {
        process_pid: i32,
        process_tgid: i32,
        parent_pid: i32,
        parent_tgid: i32,
        timestamp_ns: u64,
    },
}

/// Netlink CN_PROC monitor handle
pub struct NetlinkMonitor {
    fd: Option<RawFd>,
}

impl NetlinkMonitor {
    pub const fn new() -> Self {
        Self { fd: None }
    }

    pub fn connect(&mut self) -> io::Result<()> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                NETLINK_CONNECTOR,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let addr = sockaddr_nl {
            nl_family: AF_NETLINK as u16,
            nl_pad: 0,
            nl_pid: unsafe { libc::getpid() as u32 },
            nl_groups: 0,
        };

        let bound = unsafe {
            libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<sockaddr_nl>() as u32,
            )
        };
        if bound < 0 {
            unsafe { libc::close(fd) };
            return Err(io::Error::last_os_error());
        }

        Self::send_control(fd, PROC_CN_MCAST_LISTEN)?;

        info!("Netlink CN_PROC monitor connected (fd={})", fd);
        self.fd = Some(fd);
        Ok(())
    }

    pub async fn run(mut self, tx: mpsc::UnboundedSender<ProcNetlinkEvent>) {
        let fd = match self.fd.take() {
            Some(fd) => fd,
            None => {
                warn!("NetlinkMonitor::run called without connect");
                return;
            },
        };

        let async_fd = match AsyncFd::new(fd) {
            Ok(a) => a,
            Err(e) => {
                error!("Failed to wrap netlink fd: {e}");
                return;
            },
        };

        let mut buf = vec![0u8; 4096];

        loop {
            let mut guard = match async_fd.readable().await {
                Ok(g) => g,
                Err(e) => {
                    error!("Netlink fd became unreadable: {e}");
                    break;
                },
            };

            let raw_fd = guard.get_ref().as_raw_fd();
            let n = match unsafe {
                libc::read(raw_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
            } {
                -1 => {
                    let e = io::Error::last_os_error();
                    if e.kind() == io::ErrorKind::WouldBlock {
                        guard.clear_ready();
                        continue;
                    }
                    error!("Netlink read error: {e}");
                    break;
                },
                0 => {
                    debug!("Netlink EOF");
                    break;
                },
                x => x as usize,
            };
            guard.clear_ready();

            let events = parse_netlink_messages(&buf[..n]);
            for ev in events {
                if tx.send(ev).is_err() {
                    debug!("Netlink event channel closed");
                    return;
                }
            }
        }

        let fd = async_fd.into_inner();
        let _ = Self::send_control(fd, PROC_CN_MCAST_IGNORE);
        unsafe { libc::close(fd) };
    }

    fn send_control(fd: RawFd, op: u32) -> io::Result<()> {
        let op_slice: [u8; 4] = op.to_ne_bytes();

        let cn = cn_msg {
            id: cb_id { idx: CN_IDX_PROC, val: CN_VAL_PROC },
            seq: 0,
            ack: 0,
            len: 4,
            flags: 0,
        };

        let pid = unsafe { libc::getpid() as u32 };
        let nlh = nlmsghdr {
            nlmsg_len: (std::mem::size_of::<nlmsghdr>() + std::mem::size_of::<cn_msg>() + 4) as u32,
            nlmsg_type: NLMSG_DONE,
            nlmsg_flags: 0,
            nlmsg_seq: 1,
            nlmsg_pid: pid,
        };

        let mut packet = Vec::with_capacity(nlh.nlmsg_len as usize);
        packet.extend_from_slice(unsafe {
            std::slice::from_raw_parts(
                &nlh as *const _ as *const u8,
                std::mem::size_of::<nlmsghdr>(),
            )
        });
        packet.extend_from_slice(unsafe {
            std::slice::from_raw_parts(&cn as *const _ as *const u8, std::mem::size_of::<cn_msg>())
        });
        packet.extend_from_slice(&op_slice);

        let sent = unsafe { libc::write(fd, packet.as_ptr() as *const libc::c_void, packet.len()) };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

// ── Parser ────────────────────────────────────────────────────────

fn parse_netlink_messages(buf: &[u8]) -> Vec<ProcNetlinkEvent> {
    let mut events = Vec::new();
    let mut offset = 0;

    while offset + std::mem::size_of::<nlmsghdr>() <= buf.len() {
        let nlh = unsafe { &*(buf.as_ptr().add(offset) as *const nlmsghdr) };

        if nlh.nlmsg_len == 0 || nlh.nlmsg_len as usize > buf.len() - offset {
            break;
        }

        let total = nlh.nlmsg_len as usize;
        let payload_offset = offset + std::mem::size_of::<nlmsghdr>();
        let payload_end = offset + total;

        if payload_offset + std::mem::size_of::<cn_msg>() <= payload_end {
            let cn = unsafe { &*(buf.as_ptr().add(payload_offset) as *const cn_msg) };

            if cn.id.idx == CN_IDX_PROC && cn.id.val == CN_VAL_PROC {
                let proc_offset = payload_offset + std::mem::size_of::<cn_msg>();
                if proc_offset + std::mem::size_of::<proc_event>() <= payload_end {
                    let pe = unsafe { &*(buf.as_ptr().add(proc_offset) as *const proc_event) };
                    if let Some(ev) = decode_proc_event(pe) {
                        events.push(ev);
                    }
                }
            }
        }

        offset += total.max(std::mem::size_of::<nlmsghdr>());
        if total == 0 {
            break;
        }
    }
    events
}

fn decode_proc_event(pe: &proc_event) -> Option<ProcNetlinkEvent> {
    let what = pe.what;
    let ts = pe.timestamp_ns;

    let ev = unsafe {
        match what {
            PROC_EVENT_FORK => {
                let f = &pe.event_data.fork;
                ProcNetlinkEvent::Fork {
                    parent_pid: f.parent_pid,
                    parent_tgid: f.parent_tgid,
                    child_pid: f.child_pid,
                    child_tgid: f.child_tgid,
                    timestamp_ns: ts,
                }
            },
            PROC_EVENT_EXEC => {
                let e = &pe.event_data.exec;
                ProcNetlinkEvent::Exec {
                    process_pid: e.process_pid,
                    process_tgid: e.process_tgid,
                    timestamp_ns: ts,
                }
            },
            PROC_EVENT_EXIT => {
                let x = &pe.event_data.exit;
                ProcNetlinkEvent::Exit {
                    process_pid: x.process_pid,
                    process_tgid: x.process_tgid,
                    exit_code: x.exit_code,
                    exit_signal: x.exit_signal,
                    timestamp_ns: ts,
                }
            },
            PROC_EVENT_UID => {
                let u = &pe.event_data.id;
                ProcNetlinkEvent::Uid {
                    process_pid: u.process_pid,
                    process_tgid: u.process_tgid,
                    ruid: u.ruid,
                    euid: u.euid,
                    timestamp_ns: ts,
                }
            },
            PROC_EVENT_PTRACE => {
                let p = &pe.event_data.ptrace;
                ProcNetlinkEvent::Ptrace {
                    process_pid: p.process_pid,
                    process_tgid: p.process_tgid,
                    tracer_pid: p.tracer_pid,
                    tracer_tgid: p.tracer_tgid,
                    timestamp_ns: ts,
                }
            },
            PROC_EVENT_COMM => {
                let c = &pe.event_data.comm;
                ProcNetlinkEvent::Comm {
                    process_pid: c.process_pid,
                    process_tgid: c.process_tgid,
                    comm: c.comm,
                    timestamp_ns: ts,
                }
            },
            PROC_EVENT_COREDUMP => {
                let d = &pe.event_data.coredump;
                ProcNetlinkEvent::Coredump {
                    process_pid: d.process_pid,
                    process_tgid: d.process_tgid,
                    parent_pid: d.parent_pid,
                    parent_tgid: d.parent_tgid,
                    timestamp_ns: ts,
                }
            },
            _ => return None,
        }
    };
    Some(ev)
}
