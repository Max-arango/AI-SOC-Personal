// SPDX-License-Identifier: GPL-2.0
// Sentinel AI — eBPF Network Monitor
//
// Hooks tcp_v4_connect and tcp_close to capture TCP connection
// events in real time. Uses raw kprobe interface (no CO-RE needed).
//
// Compile:
//   clang -target bpf -O2 -g -nostdinc \
//     -isystem /usr/lib/clang/22/include \
//     -I/usr/include -I/usr/include/x86_64-linux-gnu \
//     -D__TARGET_ARCH_x86 \
//     -c tcp_monitor.bpf.c -o tcp_monitor.bpf.o

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// x86_64 register offsets for kprobe arguments
// PT_REGS_PARM1 → rdi (offset 112)
// We access ctx directly via pointer arithmetic

#define TASK_COMM_LEN 16

struct tcp_event {
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 event_type;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  comm[TASK_COMM_LEN];
    __u64 timestamp_ns;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1024);
} events SEC(".maps");

// ── kprobe/tcp_v4_connect ──────────────────────────────────

SEC("kprobe/tcp_v4_connect")
int tcp_v4_connect_prog(struct pt_regs *ctx)
{
    // Argument 1 (rdi) = sk — read via byte offset
    void *sk;
    bpf_probe_read_kernel(&sk, sizeof(sk), ((unsigned char *)ctx) + 112);

    struct tcp_event evt = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt.pid = pid_tgid >> 32;
    evt.tid = (__u32)pid_tgid;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.event_type = 1; // EVENT_CONNECT
    evt.timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    // Read sock addresses via bpf_probe_read_kernel
    // struct sock_common offsets: skc_rcv_saddr=0, skc_daddr=4,
    //   skc_num=18, skc_dport=20 (stable for Linux 6.x/7.x)
    __u32 saddr = 0, daddr = 0;
    __u16 sport = 0, dport = 0;
    bpf_probe_read_kernel(&saddr, sizeof(saddr), sk + 0);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), sk + 4);
    bpf_probe_read_kernel(&sport, sizeof(sport), sk + 18);
    bpf_probe_read_kernel(&dport, sizeof(dport), sk + 20);
    evt.saddr = saddr;
    evt.daddr = daddr;
    evt.sport = sport;
    evt.dport = dport;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}

// ── kprobe/tcp_close ────────────────────────────────────────

SEC("kprobe/tcp_close")
int tcp_close_prog(struct pt_regs *ctx)
{
    void *sk;
    bpf_probe_read_kernel(&sk, sizeof(sk), ((unsigned char *)ctx) + 112);

    struct tcp_event evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.tid = (__u32)bpf_get_current_pid_tgid();
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.event_type = 2; // EVENT_CLOSE
    evt.timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    __u32 saddr = 0, daddr = 0;
    __u16 sport = 0, dport = 0;
    bpf_probe_read_kernel(&saddr, sizeof(saddr), sk + 0);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), sk + 4);
    bpf_probe_read_kernel(&sport, sizeof(sport), sk + 18);
    bpf_probe_read_kernel(&dport, sizeof(dport), sk + 20);
    evt.saddr = saddr;
    evt.daddr = daddr;
    evt.sport = sport;
    evt.dport = dport;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}

char _license[] SEC("license") = "GPL";
