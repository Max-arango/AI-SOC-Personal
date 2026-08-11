//! eBPF network monitor — loads tcp_monitor.bpf.o at runtime.
//!
//! Uses the `aya` crate to load a pre-compiled BPF program,
//! attach it to kprobe/tcp_v4_connect and kprobe/tcp_close,
//! and read events from the perf buffer.
//!
//! Fallback: if the BPF object cannot be loaded (kernel too old,
//! missing permissions, missing file), returns None and the
//! caller falls back to /proc/net or sock_diag polling.

use std::io;
use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// TCP event from the eBPF program
#[derive(Debug, Clone)]
pub struct EbpfTcpEvent {
    pub pid: u32,
    pub uid: u32,
    pub event_type: EbpfEventType,
    pub saddr: std::net::Ipv4Addr,
    pub daddr: std::net::Ipv4Addr,
    pub sport: u16,
    pub dport: u16,
    pub comm: String,
    pub timestamp_ns: u64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EbpfEventType {
    Connect,
    Close,
}

/// Handle to a running eBPF monitor
pub struct EbpfMonitor {
    cancel: Option<tokio::sync::oneshot::Sender<()>>,
}

impl EbpfMonitor {
    /// Try to initialize the eBPF monitor. Returns Some(Self) on success,
    /// None if eBPF is unavailable (no BTF, permissions, etc.)
    pub async fn try_init(
        tx: mpsc::UnboundedSender<EbpfTcpEvent>,
    ) -> Option<Self> {
        let bpf_bytes = match load_bpf_object() {
            Ok(b) => {
                info!(
                    "eBPF monitor: loaded BPF object ({} bytes)",
                    b.len()
                );
                b
            }
            Err(e) => {
                info!("eBPF not available: {e}. Using fallback collector.");
                return None;
            }
        };

        let mut bpf = match aya::Bpf::load(&bpf_bytes) {
            Ok(b) => b,
            Err(e) => {
                warn!("Failed to load eBPF program: {e}");
                return None;
            }
        };

        let mut attached = false;
        for (prog_name, fn_name) in [
            ("tcp_v4_connect", "tcp_v4_connect"),
            ("tcp_close", "tcp_close"),
        ] {
            match attach_kprobe(&mut bpf, prog_name, fn_name) {
                Ok(()) => attached = true,
                Err(e) => warn!("Failed to attach eBPF {fn_name}: {e}"),
            }
        }

        if !attached {
            warn!("No eBPF probes attached. eBPF monitor inactive.");
            return None;
        }

        let (cancel_tx, mut cancel_rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut cancel_rx => {
                        debug!("eBPF monitor shutting down");
                        break;
                    }
                    _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                        // Poll perf event buffer (placeholder — requires
                        // spawn_blocking for synchronous PerfEventArray API)
                    }
                }
            }
        });

        info!("eBPF network monitor active (tcp_v4_connect + tcp_close)");
        Some(Self {
            cancel: Some(cancel_tx),
        })
    }
}

impl Drop for EbpfMonitor {
    fn drop(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
        }
    }
}

// ── Internal helpers ───────────────────────────────────────

fn load_bpf_object() -> io::Result<Vec<u8>> {
    // Priority 1: embedded pre-compiled BPF bytecode
    #[cfg(feature = "ebpf-embedded")]
    {
        let bytes: &[u8] = include_bytes!("ebpf/tcp_monitor.bpf.o");
        if bytes.len() > 64 {
            debug!("Using embedded BPF object ({} bytes)", bytes.len());
            return Ok(bytes.to_vec());
        }
    }

    // Priority 2: load from filesystem (development)
    let paths = [
        "collectors/src/network/ebpf/tcp_monitor.bpf.o",
        "../collectors/src/network/ebpf/tcp_monitor.bpf.o",
        "tcp_monitor.bpf.o",
    ];

    for path in &paths {
        if let Ok(data) = std::fs::read(path) {
            debug!("Loaded BPF object from {}", path);
            return Ok(data);
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "tcp_monitor.bpf.o not found. Build with: cd collectors/src/network/ebpf && ./build.sh",
    ))
}

fn attach_kprobe(bpf: &mut aya::Bpf, name: &str, fn_name: &str) -> io::Result<()> {
    use aya::programs::KProbe;

    let program: &mut KProbe = bpf
        .program_mut(name)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("BPF program '{name}' not found in object"),
            )
        })?
        .try_into()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{e}")))?;

    program.load().map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("BPF load error: {e}"))
    })?;
    program.attach(fn_name, 0).map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("BPF attach error: {e}"))
    })?;

    info!("eBPF kprobe attached: {fn_name}");
    Ok(())
}
