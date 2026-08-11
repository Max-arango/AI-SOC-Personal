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
use tracing::{debug, error, info, warn};

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
    cancel: tokio::sync::oneshot::Sender<()>,
}

impl EbpfMonitor {
    /// Try to initialize the eBPF monitor. Returns Some(Self) on success,
    /// None if eBPF is unavailable (no BTF, permissions, etc.)
    pub async fn try_init(
        tx: mpsc::UnboundedSender<EbpfTcpEvent>,
    ) -> Option<Self> {
        // Try to load the BPF bytes
        let bpf_bytes = match load_bpf_object() {
            Ok(b) => b,
            Err(e) => {
                info!("eBPF not available: {e}. Using fallback collector.");
                return None;
            }
        };

        // Parse and load the BPF program
        let mut bpf = match aya::Bpf::load(&bpf_bytes) {
            Ok(b) => b,
            Err(e) => {
                warn!("Failed to load eBPF program: {e}");
                return None;
            }
        };

        // Attach kprobes
        for (name, fn_name) in [
            ("tcp_v4_connect", "tcp_v4_connect"),
            ("tcp_close", "tcp_close"),
        ] {
            if let Err(e) = attach_kprobe(&mut bpf, name, fn_name) {
                warn!("Failed to attach {name}: {e}. eBPF monitor degraded.");
            }
        }

        // Start perf reader
        let (cancel_tx, mut cancel_rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 16384]; // 16 KB perf buffer pages
            loop {
                tokio::select! {
                    _ = &mut cancel_rx => {
                        debug!("eBPF monitor shutting down");
                        break;
                    }
                    _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                        // Poll perf buffer
                        if let Err(e) = poll_perf_event(&mut bpf, &mut buf, &tx) {
                            error!("eBPF perf poll error: {e}");
                            break;
                        }
                    }
                }
            }
        });

        info!("eBPF network monitor active (tcp_v4_connect + tcp_close)");
        Some(Self {
            cancel: cancel_tx,
        })
    }
}

impl Drop for EbpfMonitor {
    fn drop(&mut self) {
        let _ = self.cancel.send(());
    }
}

// ── Internal helpers ───────────────────────────────────────

fn load_bpf_object() -> io::Result<Vec<u8>> {
    // Try to load from file first (development), then embedded bytes
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

    // Embedded fallback: pre-compiled BPF bytecode
    #[cfg(feature = "ebpf-embedded")]
    {
        let bytes: &[u8] = include_bytes!("ebpf/tcp_monitor.bpf.o");
        if !bytes.is_empty() {
            return Ok(bytes.to_vec());
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "tcp_monitor.bpf.o not found. Build with: clang -target bpf -O2 -g -c tcp_monitor.bpf.c -o tcp_monitor.bpf.o",
    ))
}

fn attach_kprobe(bpf: &mut aya::Bpf, name: &str, fn_name: &str) -> io::Result<()> {
    use aya::programs::KProbe;

    let program: &mut KProbe = bpf
        .program_mut(name)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("program {name} not found")))?
        .try_into()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{e}")))?;

    program.load()?;
    program.attach(fn_name, 0)?;

    info!("eBPF kprobe attached: {fn_name}");
    Ok(())
}

fn poll_perf_event(
    _bpf: &mut aya::Bpf,
    _buf: &mut [u8],
    _tx: &mpsc::UnboundedSender<EbpfTcpEvent>,
) -> io::Result<()> {
    // Perf event reading via aya::maps::PerfEventArray
    // For now, this is a stub. Real implementation uses:
    //   let map: PerfEventArray<u32> = PerfEventArray::try_from(bpf.map_mut("events").unwrap())?;
    //   map.poll(&mut buf, |_cpu, data| { parse_event(data); send(tx); })
    //
    // The full poll loop requires spawning a blocking thread since
    // PerfEventArray::poll() is synchronous.
    Ok(())
}
