// SPDX-License-Identifier: GPL-2.0
// Sentinel AI — eBPF Network Monitor
//
// Hooks tcp_v4_connect and tcp_close to capture TCP connection
// events in real time. Uses BPF CO-RE (Compile Once, Run Everywhere)
// via BTF — no kernel headers required at build time.
//
// Build:
//   clang -target bpf -O2 -g -c tcp_monitor.bpf.c -o tcp_monitor.bpf.o
//
// The resulting .o file is embedded in the Rust binary via
// include_bytes!() and loaded at runtime by the aya crate.

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define TASK_COMM_LEN 16

// Event types
#define EVENT_CONNECT 1
#define EVENT_CLOSE   2

// Event sent to userspace via perf buffer
struct tcp_event {
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 event_type;       // EVENT_CONNECT or EVENT_CLOSE
    __u32 saddr;            // source IP (network byte order)
    __u32 daddr;            // dest IP
    __u16 sport;            // source port (network byte order)
    __u16 dport;            // dest port
    __u8  comm[TASK_COMM_LEN];
    __u64 timestamp_ns;
};

// Perf buffer map shared with userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1024);
} events SEC(".maps");

// Helper: send event to userspace
static __always_inline int send_event(struct tcp_event *evt) {
    return bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, evt, sizeof(*evt));
}

// ── kprobe/tcp_v4_connect ────────────────────────────────

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
    struct tcp_event evt = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // Process identity
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt.pid = pid_tgid >> 32;           // TGID (process ID)
    evt.tid = (__u32)pid_tgid;          // PID (thread ID)
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.event_type = EVENT_CONNECT;

    // Process name
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    // Source address (from sock)
    struct inet_sock *inet = (struct inet_sock *)sk;
    // CO-RE: read saddr and sport from inet_sock
    evt.saddr = BPF_CORE_READ(inet, inet_saddr);
    evt.sport = BPF_CORE_READ(inet, inet_sport);

    // Destination address (from sockaddr)
    struct sockaddr_in *daddr_in = (struct sockaddr_in *)uaddr;
    bpf_probe_read_user(&evt.daddr, sizeof(evt.daddr), &daddr_in->sin_addr.s_addr);
    bpf_probe_read_user(&evt.dport, sizeof(evt.dport), &daddr_in->sin_port);

    evt.timestamp_ns = bpf_ktime_get_ns();

    send_event(&evt);
    return 0;
}

// ── kprobe/tcp_close ──────────────────────────────────────

SEC("kprobe/tcp_close")
int BPF_KPROBE(tcp_close, struct sock *sk, long timeout)
{
    struct tcp_event evt = {};

    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.tid = (__u32)bpf_get_current_pid_tgid();
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.event_type = EVENT_CLOSE;

    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    // Read socket addresses from sock
    struct inet_sock *inet = (struct inet_sock *)sk;
    evt.saddr = BPF_CORE_READ(inet, inet_saddr);
    evt.daddr = BPF_CORE_READ(inet, inet_daddr);
    evt.sport = BPF_CORE_READ(inet, inet_sport);
    evt.dport = BPF_CORE_READ(inet, inet_dport);

    evt.timestamp_ns = bpf_ktime_get_ns();

    send_event(&evt);
    return 0;
}

char _license[] SEC("license") = "GPL";
