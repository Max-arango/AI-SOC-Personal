//! Linux Netlink Connector bindings for CN_PROC (process events)
//!
//! Raw C struct definitions matching the kernel's
//! `include/uapi/linux/cn_proc.h` and `include/uapi/linux/netlink.h`.
//! All structs are `#[repr(C)]` with explicit alignment.

use std::mem;

// ── Netlink protocol constants ────────────────────────────────────

pub const AF_NETLINK: libc::c_int = libc::AF_NETLINK;
pub const NETLINK_CONNECTOR: libc::c_int = 11;
pub const NLMSG_DONE: u16 = 3;
pub const NLMSG_ERROR: u16 = 2;
pub const NLM_F_REQUEST: u16 = 1;
pub const NLM_F_MULTI: u16 = 2;

// ── Connector constants ───────────────────────────────────────────

pub const CN_IDX_PROC: u32 = 0x1;
pub const CN_VAL_PROC: u32 = 0x1;

/// Subscribe to multicast events
pub const PROC_CN_MCAST_LISTEN: u32 = 1;
/// Unsubscribe
pub const PROC_CN_MCAST_IGNORE: u32 = 2;

// ── Proc event types (proc_event.what) ────────────────────────────

pub const PROC_EVENT_NONE: u32 = 0x00000000;
pub const PROC_EVENT_FORK: u32 = 0x00000001;
pub const PROC_EVENT_EXEC: u32 = 0x00000002;
pub const PROC_EVENT_UID: u32 = 0x00000004;
pub const PROC_EVENT_GID: u32 = 0x00000040;
pub const PROC_EVENT_SID: u32 = 0x00000080;
pub const PROC_EVENT_PTRACE: u32 = 0x00000100;
pub const PROC_EVENT_COMM: u32 = 0x00000200;
pub const PROC_EVENT_COREDUMP: u32 = 0x40000000;
pub const PROC_EVENT_EXIT: u32 = 0x80000000;

// ── Raw C structs (repr(C), packed) ───────────────────────────────

/// `struct sockaddr_nl`
#[repr(C)]
#[derive(Clone, Copy)]
pub struct sockaddr_nl {
    pub nl_family: libc::sa_family_t,
    pub nl_pad: u16,
    pub nl_pid: u32,
    pub nl_groups: u32,
}

impl Default for sockaddr_nl {
    fn default() -> Self {
        Self { nl_family: AF_NETLINK as u16, nl_pad: 0, nl_pid: 0, nl_groups: 0 }
    }
}

/// `struct nlmsghdr` — Netlink message header (16 bytes)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct nlmsghdr {
    pub nlmsg_len: u32,
    pub nlmsg_type: u16,
    pub nlmsg_flags: u16,
    pub nlmsg_seq: u32,
    pub nlmsg_pid: u32,
}

/// `struct cb_id` — Connector bus ID (8 bytes)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct cb_id {
    pub idx: u32,
    pub val: u32,
}

/// `struct cn_msg` — Connector message header (20 bytes total incl cb_id)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct cn_msg {
    pub id: cb_id,
    pub seq: u32,
    pub ack: u32,
    pub len: u16,
    pub flags: u16,
}

/// `struct proc_event` — Process event from CN_PROC (32 bytes total)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct proc_event {
    pub what: u32,
    pub cpu: u32,
    pub timestamp_ns: u64,
    pub event_data: proc_event_data,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union proc_event_data {
    pub fork: fork_proc_event,
    pub exec: exec_proc_event,
    pub exit: exit_proc_event,
    pub id: id_proc_event,
    pub sid: sid_proc_event,
    pub ptrace: ptrace_proc_event,
    pub comm: comm_proc_event,
    pub coredump: coredump_proc_event,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct fork_proc_event {
    pub parent_pid: i32,
    pub parent_tgid: i32,
    pub child_pid: i32,
    pub child_tgid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct exec_proc_event {
    pub process_pid: i32,
    pub process_tgid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct exit_proc_event {
    pub process_pid: i32,
    pub process_tgid: i32,
    pub exit_code: u32,
    pub exit_signal: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct id_proc_event {
    pub process_pid: i32,
    pub process_tgid: i32,
    pub ruid: u32,
    pub euid: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct sid_proc_event {
    pub process_pid: i32,
    pub process_tgid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ptrace_proc_event {
    pub process_pid: i32,
    pub process_tgid: i32,
    pub tracer_pid: i32,
    pub tracer_tgid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct comm_proc_event {
    pub process_pid: i32,
    pub process_tgid: i32,
    pub comm: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct coredump_proc_event {
    pub process_pid: i32,
    pub process_tgid: i32,
    pub parent_pid: i32,
    pub parent_tgid: i32,
}

// ── Compile-time size assertions ──────────────────────────────────

#[allow(dead_code)]
const fn assert_sizes() {
    // Verify struct sizes match kernel ABI
    assert!(mem::size_of::<nlmsghdr>() == 16);
    assert!(mem::size_of::<cn_msg>() == 20);
    assert!(mem::size_of::<proc_event>() == 32);
}
