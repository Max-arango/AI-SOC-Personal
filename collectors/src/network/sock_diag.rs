//! Netlink INET_DIAG socket monitor — fast socket state queries.
//!
//! Uses `NETLINK_SOCK_DIAG` (the same protocol `ss` uses) to query
//! TCP and UDP socket tables directly from the kernel. Returns PID,
//! inode, addresses, ports, and state natively — no /proc/<pid>/fd/*
//! scanning required.
//!
//! Protocol: send `inet_diag_req_v2` → receive `inet_diag_msg` + attrs.

use std::io;
use std::net::IpAddr;
use std::os::fd::RawFd;

use tracing::{debug, warn};

const NETLINK_SOCK_DIAG: libc::c_int = 4;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_DUMP: u16 = 0x300;
const SOCK_DIAG_BY_FAMILY: u16 = 20;

const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const INET_DIAG_INFO: u8 = 1;

const TCPF_ALL: u32 = 0xFFF;
const TCP_LISTEN: u32 = 0x0A;

#[repr(C)]
struct nlmsghdr {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

#[repr(C)]
struct inet_diag_req_v2 {
    sdiag_family: u8,
    sdiag_protocol: u8,
    idiag_ext: u8,
    pad: u8,
    idiag_states: u32,
    id: inet_diag_sockid,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct inet_diag_sockid {
    idiag_sport: u16,
    idiag_dport: u16,
    idiag_src: [u32; 4],
    idiag_dst: [u32; 4],
    idiag_if: u32,
    idiag_cookie: [u32; 2],
}

#[derive(Clone, Copy)]
struct inet_diag_msg {
    family: u8,
    state: u8,
    timer: u8,
    retrans: u8,
    id: inet_diag_sockid,
    expires: u32,
    rqueue: u32,
    wqueue: u32,
    uid: u32,
    inode: u32,
}

/// Raw socket query result
#[derive(Debug, Clone)]
pub struct DiagSocket {
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    pub protocol: u8, // IPPROTO_TCP or IPPROTO_UDP
    pub state: u8,
    pub inode: u32,
    pub uid: u32,
}

impl DiagSocket {
    pub fn display(&self) -> String {
        format!(
            "{}:{} → {}:{}",
            self.local_addr, self.local_port, self.remote_addr, self.remote_port
        )
    }
}

pub struct SockDiagMonitor {
    fd: Option<RawFd>,
}

impl SockDiagMonitor {
    pub fn new() -> Self {
        Self { fd: None }
    }

    pub fn connect(&mut self) -> io::Result<()> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                NETLINK_SOCK_DIAG,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let addr = super::super::process::netlink_bindings::sockaddr_nl {
            nl_family: libc::AF_NETLINK as u16,
            nl_pad: 0,
            nl_pid: 0,
            nl_groups: 0,
        };

        let bound = unsafe {
            libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<super::super::process::netlink_bindings::sockaddr_nl>() as u32,
            )
        };
        if bound < 0 {
            unsafe { libc::close(fd) };
            return Err(io::Error::last_os_error());
        }

        debug!("SockDiag monitor connected (fd={})", fd);
        self.fd = Some(fd);
        Ok(())
    }

    /// Query all TCP sockets and parse them.
    pub fn query_tcp(&self) -> io::Result<Vec<DiagSocket>> {
        self.query(AF_INET, IPPROTO_TCP, TCPF_ALL & !TCP_LISTEN)
    }

    /// Query all UDP sockets and parse them.
    pub fn query_udp(&self) -> io::Result<Vec<DiagSocket>> {
        self.query(AF_INET, IPPROTO_UDP, 0)
    }

    fn query(&self, family: u8, protocol: u8, states: u32) -> io::Result<Vec<DiagSocket>> {
        let fd = self.fd.ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "sock_diag not connected")
        })?;

        let mut buf = Vec::with_capacity(1024);

        // Build request
        let req = inet_diag_req_v2 {
            sdiag_family: family,
            sdiag_protocol: protocol,
            idiag_ext: 1 << (INET_DIAG_INFO - 1),
            pad: 0,
            idiag_states: states,
            id: inet_diag_sockid {
                idiag_sport: 0,
                idiag_dport: 0,
                idiag_src: [0; 4],
                idiag_dst: [0; 4],
                idiag_if: 0,
                idiag_cookie: [0; 2],
            },
        };

        let pid = unsafe { libc::getpid() as u32 };
        let nlh = nlmsghdr {
            nlmsg_len: (std::mem::size_of::<nlmsghdr>()
                + std::mem::size_of::<inet_diag_req_v2>()) as u32,
            nlmsg_type: SOCK_DIAG_BY_FAMILY,
            nlmsg_flags: NLM_F_REQUEST | NLM_F_DUMP,
            nlmsg_seq: 0,
            nlmsg_pid: pid,
        };

        buf.extend_from_slice(unsafe {
            std::slice::from_raw_parts(
                &nlh as *const _ as *const u8,
                std::mem::size_of::<nlmsghdr>(),
            )
        });
        buf.extend_from_slice(unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<inet_diag_req_v2>(),
            )
        });

        let sent = unsafe {
            libc::sendto(
                fd,
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
                0,
                std::ptr::null(),
                0,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }

        // Read response
        let mut recv_buf = vec![0u8; 65536];
        let mut all_sockets = Vec::new();

        loop {
            let n = unsafe {
                libc::recv(fd, recv_buf.as_mut_ptr() as *mut libc::c_void, recv_buf.len(), 0)
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::WouldBlock {
                    break;
                }
                warn!("sock_diag recv error: {e}");
                break;
            }
            if n == 0 {
                break;
            }

            let sockets = parse_diag_response(&recv_buf[..n as usize]);
            all_sockets.extend(sockets);
        }

        Ok(all_sockets)
    }
}

impl Drop for SockDiagMonitor {
    fn drop(&mut self) {
        if let Some(fd) = self.fd {
            unsafe { libc::close(fd) };
        }
    }
}

fn parse_diag_response(buf: &[u8]) -> Vec<DiagSocket> {
    let mut sockets = Vec::new();
    let mut offset = 0;

    while offset + std::mem::size_of::<nlmsghdr>() <= buf.len() {
        let nlh = unsafe { &*(buf.as_ptr().add(offset) as *const nlmsghdr) };

        if nlh.nlmsg_type == NLMSG_DONE || nlh.nlmsg_type == 3 {
            break;
        }

        if nlh.nlmsg_type == SOCK_DIAG_BY_FAMILY {
            let msg_offset = offset + std::mem::size_of::<nlmsghdr>();
            let min_msg_size = std::mem::size_of::<inet_diag_msg>();

            if msg_offset + min_msg_size <= buf.len() {
                let msg = unsafe {
                    std::ptr::read_unaligned(
                        buf.as_ptr().add(msg_offset) as *const inet_diag_msg
                    )
                };

                let local = sockid_to_addr(&msg.id, true);
                let remote = sockid_to_addr(&msg.id, false);

                if let (Some(local_addr), Some(remote_addr)) = (local, remote) {
                    sockets.push(DiagSocket {
                        local_addr,
                        local_port: u16::from_be(msg.id.idiag_sport),
                        remote_addr,
                        remote_port: u16::from_be(msg.id.idiag_dport),
                        protocol: if msg.family == AF_INET6 { IPPROTO_TCP } else { IPPROTO_TCP },
                        state: msg.state,
                        inode: msg.inode,
                        uid: msg.uid,
                    });
                }
            }
        }

        if nlh.nlmsg_len == 0 {
            break;
        }
        offset += nlh.nlmsg_len as usize;
        if nlh.nlmsg_len as usize > buf.len() - offset {
            break;
        }
    }

    sockets
}

fn sockid_to_addr(id: &inet_diag_sockid, local: bool) -> Option<IpAddr> {
    let words = if local { &id.idiag_src } else { &id.idiag_dst };
    // IPv4: first word is the address, stored in host byte order via netlink
    // Actually for IPv4 addresses in netlink diag, they're stored as __be32[4]
    // where only the first element is used.
    let addr = u32::from_be(words[0]);
    if words[1] == 0 && words[2] == 0 && words[3] == 0 {
        Some(IpAddr::V4(std::net::Ipv4Addr::from(addr.to_be_bytes())))
    } else {
        // IPv6
        let mut bytes = [0u8; 16];
        for i in 0..4 {
            let w = u32::from_be(words[i]);
            bytes[i * 4] = (w >> 24) as u8;
            bytes[i * 4 + 1] = (w >> 16) as u8;
            bytes[i * 4 + 2] = (w >> 8) as u8;
            bytes[i * 4 + 3] = w as u8;
        }
        Some(IpAddr::V6(std::net::Ipv6Addr::from(bytes)))
    }
}
