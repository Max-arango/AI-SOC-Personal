#!/bin/bash
# Build the eBPF program for Sentinel AI network monitor
#
# Compiles tcp_monitor.bpf.c → tcp_monitor.bpf.o using clang.
# The resulting .o is loaded at runtime by aya.
#
# Requires: clang (tested with clang-22)

set -euo pipefail
cd "$(dirname "$0")"

SRC="tcp_monitor.bpf.c"
OUT="tcp_monitor.bpf.o"
CLANG="${CLANG:-/usr/bin/clang-22}"

CLANG_VER=$("$CLANG" --version 2>/dev/null | head -1 || echo "unknown")
echo "Compiler: $CLANG_VER"
echo "Building $OUT..."

"$CLANG" \
  -target bpf -O2 -g -Wall \
  -nostdinc \
  -isystem "$(dirname "$(dirname "$("$CLANG" -print-resource-dir 2>/dev/null)")")" \
  -I/usr/include -I/usr/include/x86_64-linux-gnu \
  -D__TARGET_ARCH_x86 \
  -c "$SRC" -o "$OUT"

echo "SUCCESS: $(ls -lh "$OUT" | awk '{print $5}')"
echo ""
echo "Now build with:"
echo "  cd ../../../.. && cargo build --features ebpf-embedded --release"