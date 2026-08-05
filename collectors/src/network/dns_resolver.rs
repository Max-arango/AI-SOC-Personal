//! DNS resolver — async reverse lookups with TTL-based caching.
//!
//! Resolves IP addresses to hostnames using libc `getnameinfo` in
//! a blocking thread pool. Results are cached to avoid hammering
//! DNS on every poll.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tracing::debug;

struct DnsEntry {
    hostname: String,
    resolved_at: Instant,
}

pub struct DnsResolver {
    cache: HashMap<String, DnsEntry>,
    ttl: Duration,
}

impl DnsResolver {
    pub fn new(ttl: Duration) -> Self {
        Self {
            cache: HashMap::new(),
            ttl,
        }
    }

    pub async fn reverse_lookup(&mut self, ip: &str) -> String {
        if is_private_ip(ip) {
            return ip.to_string();
        }

        if let Some(entry) = self.cache.get(ip) {
            if entry.resolved_at.elapsed() < self.ttl {
                return entry.hostname.clone();
            }
        }

        let ip_owned = ip.to_string();
        let hostname = tokio::task::spawn_blocking(move || {
            libc_reverse_dns(&ip_owned).unwrap_or_else(|| ip_owned.clone())
        })
        .await
        .unwrap_or_else(|_| ip.to_string());

        if hostname != ip {
            debug!("DNS resolved: {} → {}", ip, hostname);
        }
        self.cache.insert(
            ip.to_string(),
            DnsEntry {
                hostname: hostname.clone(),
                resolved_at: Instant::now(),
            },
        );
        hostname
    }

    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }

    pub fn prune(&mut self) {
        self.cache
            .retain(|_, entry| entry.resolved_at.elapsed() < self.ttl);
    }
}

fn libc_reverse_dns(ip: &str) -> Option<String> {
    let addr: IpAddr = ip.parse().ok()?;

    let (sockaddr, socklen) = match addr {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let sa = unsafe { &mut *(std::ptr::addr_of_mut!(storage) as *mut libc::sockaddr_in) };
            sa.sin_family = libc::AF_INET as u16;
            sa.sin_port = 0;
            sa.sin_addr.s_addr = u32::from_ne_bytes(octets);
            (std::ptr::addr_of!(storage) as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in>() as u32)
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let sa = unsafe { &mut *(std::ptr::addr_of_mut!(storage) as *mut libc::sockaddr_in6) };
            sa.sin6_family = libc::AF_INET6 as u16;
            sa.sin6_port = 0;
            sa.sin6_flowinfo = 0;
            sa.sin6_scope_id = 0;
            for (i, &seg) in segments.iter().enumerate() {
                sa.sin6_addr.s6_addr[i * 2] = (seg >> 8) as u8;
                sa.sin6_addr.s6_addr[i * 2 + 1] = (seg & 0xff) as u8;
            }
            (std::ptr::addr_of!(storage) as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in6>() as u32)
        }
    };

    let mut host_buf = vec![0u8; libc::NI_MAXHOST as usize];
    let ret = unsafe {
        libc::getnameinfo(
            sockaddr,
            socklen,
            host_buf.as_mut_ptr() as *mut libc::c_char,
            libc::NI_MAXHOST as u32,
            std::ptr::null_mut(),
            0,
            libc::NI_NAMEREQD,
        )
    };

    if ret == 0 {
        let cstr = unsafe { std::ffi::CStr::from_ptr(host_buf.as_ptr() as *const libc::c_char) };
        let host = cstr.to_string_lossy().into_owned();
        if host != ip && !host.is_empty() {
            return Some(host);
        }
    }
    None
}

fn is_private_ip(ip: &str) -> bool {
    if ip == "0.0.0.0" || ip == "127.0.0.1" || ip == "::1" {
        return true;
    }
    if ip.starts_with("10.")
        || ip.starts_with("192.168.")
        || ip.starts_with("172.16.")
        || ip.starts_with("172.17.")
        || ip.starts_with("172.18.")
        || ip.starts_with("172.19.")
        || ip.starts_with("172.20.")
        || ip.starts_with("172.21.")
        || ip.starts_with("172.22.")
        || ip.starts_with("172.23.")
        || ip.starts_with("172.24.")
        || ip.starts_with("172.25.")
        || ip.starts_with("172.26.")
        || ip.starts_with("172.27.")
        || ip.starts_with("172.28.")
        || ip.starts_with("172.29.")
        || ip.starts_with("172.30.")
        || ip.starts_with("172.31.")
        || ip.starts_with("127.")
        || ip.starts_with("169.254.")
        || ip.starts_with("fe80:")
        || ip.starts_with("fc")
        || ip.starts_with("fd")
    {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_private_ips() {
        assert!(is_private_ip("127.0.0.1"));
        assert!(is_private_ip("10.1.2.3"));
        assert!(is_private_ip("192.168.1.1"));
        assert!(is_private_ip("172.16.0.1"));
        assert!(is_private_ip("0.0.0.0"));
        assert!(is_private_ip("169.254.1.1"));
    }

    #[test]
    fn detects_public_ips() {
        assert!(!is_private_ip("8.8.8.8"));
        assert!(!is_private_ip("1.1.1.1"));
        assert!(!is_private_ip("93.184.216.34"));
    }

    #[test]
    fn cache_hit_present() {
        let mut resolver = DnsResolver::new(Duration::from_secs(300));
        resolver.cache.insert(
            "8.8.8.8".into(),
            DnsEntry {
                hostname: "dns.google".into(),
                resolved_at: Instant::now(),
            },
        );
        assert_eq!(resolver.cache_size(), 1);
    }
}
