#!/bin/bash
# Build the eBPF program for Sentinel AI network monitor
#
# Requires: clang >= 12, libbpf headers (linux-libc-dev)
#
# Usage:
#   ./build.sh          # Build tcp_monitor.bpf.o
#   ./build.sh --strip  # Build and strip debug info (smaller)
#
# The resulting tcp_monitor.bpf.o is loaded at runtime by the
# Sentinel eBPF monitor (feature flag: ebpf-embedded).

set -euo pipefail

SRC="tcp_monitor.bpf.c"
OUT="tcp_monitor.bpf.o"

CLANG="${CLANG:-clang}"
CLANG_FLAGS="-target bpf -O2 -g -Wall -Werror"
INCLUDES="-I/usr/include -I/usr/include/x86_64-linux-gnu"

if [[ "${1:-}" == "--strip" ]]; then
    echo "Building $OUT (release, no debug info)..."
    $CLANG $CLANG_FLAGS $INCLUDES -c "$SRC" -o "$OUT"
    llvm-strip --strip-debug "$OUT" 2>/dev/null || true
    ls -lh "$OUT"
else
    echo "Building $OUT (with BTF debug info)..."
    $CLANG $CLANG_FLAGS $INCLUDES -c "$SRC" -o "$OUT"
    ls -lh "$OUT"
fi

echo "Done. To use: cargo build --features ebpf-embedded"
