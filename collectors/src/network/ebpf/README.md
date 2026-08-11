# eBPF Network Collector — Integration Plan

## Status

- **BPF program**: Written (`tcp_monitor.bpf.c`). Hooks tcp_v4_connect + tcp_close.
- **Rust loader**: Written (`ebpf_monitor.rs`). Uses `aya` crate.
- **Pre-compiled bytecode**: NOT YET AVAILABLE. Requires clang to build.
- **Feature flag**: `ebpf` (aya deps) / `ebpf-embedded` (includes pre-compiled .o)

## Requirements

| Component | Status |
|---|---|
| Linux kernel 5.4+ with BTF | ✅ v7.1 |
| `aya` crate | ✅ workspace dep |
| clang (for BPF compilation) | ❌ Not installed |
| rust-src + bpf-linker (for aya-ebpf approach) | ❌ Not available |

## Build

```bash
# 1. Compile BPF program (requires clang)
cd collectors/src/network/ebpf
./build.sh          # → tcp_monitor.bpf.o

# 2. Build Sentinel with eBPF
cd ../../../..
cargo build --features ebpf-embedded -p sentinel-core-service
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         KERNEL                               │
│  tcp_v4_connect()  ──►  eBPF kprobe  ──►  perf_event_array  │
│  tcp_close()       ──►  eBPF kprobe  ──►  (events map)      │
└─────────────────────────────────┬───────────────────────────┘
                                  │ perf buffer
┌─────────────────────────────────▼───────────────────────────┐
│                       USERSPACE                              │
│  aya::Bpf::load()  ──►  attach_kprobe()  ──►  poll_perf()   │
│                                  │                           │
│                    mpsc::UnboundedSender<EbpfTcpEvent>       │
│                                  │                           │
│  Network Monitor ──►  enrich + DNS ──►  EventBus.publish()  │
└──────────────────────────────────────────────────────────────┘
```

## Event Flow

1. Kernel calls `tcp_v4_connect()` → eBPF kprobe fires
2. BPF program captures: PID, UID, comm, saddr, sport, daddr, dport
3. BPF writes event to perf_event_array map
4. Userspace `aya` polls perf buffer (100ms interval)
5. Event enriched with DNS hostname → published to EventBus
6. Same flow for `tcp_close` → duration tracked

## Fallback Chain

```
1. eBPF (ebpf feature)        → real-time events + native PID
   ↓ if unavailable
2. sock_diag (netlink)        → fast polling + native inode
   ↓ if unavailable  
3. /proc/net (existing)       → 5s polling + /proc scanning
```

## Next Steps (blocked on clang)

1. Install clang: `sudo apt install clang libbpf-dev` or download LLVM binary
2. Run `./build.sh` to compile tcp_monitor.bpf.c → tcp_monitor.bpf.o
3. `cargo build --features ebpf-embedded`
4. The binary will load the BPF program at runtime
5. Real-time TCP events replace 5s polling
