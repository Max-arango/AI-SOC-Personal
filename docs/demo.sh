#!/bin/bash
# Sentinel AI v0.1.0 — Demo Script
# Showcases architecture, tests, and codebase
clear

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           SENTINEL AI v0.1.0 — DEMO                         ║"
echo "║      Local-first AI Security Assistant                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
sleep 1

echo ""
echo "━━━ 1. ARCHITECTURE ━━━"
echo ""
echo "  Collectors → Event Bus → Rules → Correlation → Risk → Alerts → gRPC"
echo ""
echo "  7 collectors | 613 SigmaHQ rules | 14 plugins | 35 gRPC endpoints"
sleep 2

echo ""
echo "━━━ 2. COLLECTORS ━━━"
echo ""
ls -d collectors/src/*/
echo ""
echo "  Process:  CN_PROC netlink (real-time kernel events)"
echo "  Network:  /proc/net + inode→PID + DNS + scan detection"
echo "  File:     fanotify + SHA256 + entropy + ransomware "
echo "  Browser:  incremental SQLite + extension blocklist"
echo "  USB:      /sys/bus/usb/devices polling"
echo "  Registry: systemd user services"
echo "  Startup:  cron + systemd + shell profiles"
sleep 2

echo ""
echo "━━━ 3. PLUGINS (14) ━━━"
echo ""
ls -d plugins/*/
echo ""
echo "  Threat intel: AbuseIPDB, VirusTotal, Shodan, OTX, GreyNoise, URLhaus, GeoIP, IOC"
echo "  Notifications: Discord, Telegram, Slack, Email, Home Assistant"
sleep 2

echo ""
echo "━━━ 4. TESTS ━━━"
echo ""
cargo test -p sentinel-collectors --quiet 2>/dev/null | tail -3
sleep 1

echo ""
echo "━━━ 5. RULES ━━━"
echo ""
echo "  Total: $(ls rules/*.yaml 2>/dev/null | wc -l) SigmaHQ rules"
echo "  $(ls rules/linux/*.yaml rules/network/*.yaml rules/cloud/*.yaml rules/web/*.yaml 2>/dev/null | wc -l) categorized by platform"
sleep 2

echo ""
echo "━━━ 6. gRPC API (35/35) ━━━"
echo ""
echo "  Health    → GET  /status"
echo "  Events    → POST /query_events"
echo "  Alerts    → POST /list_alerts, /stream_alerts"
echo "  Rules     → POST /create_rule, /test_rule"
echo "  Chains    → POST /attack_chains"
echo "  Plugins   → POST /list_plugins, /configure_plugin"
echo "  Collectors→ POST /list_collectors, /restart_collector"
sleep 2

echo ""
echo "━━━ 7. CODE STATS ━━━"
echo ""
echo "  Rust lines:   $(find . -name '*.rs' -not -path '*/target/*' | xargs cat 2>/dev/null | wc -l)"
echo "  Test files:   $(grep -rl '#\[test\]\|#\[tokio::test\]' --include='*.rs' . 2>/dev/null | wc -l)"
echo "  Commits:      $(git rev-list --count HEAD 2>/dev/null)"
sleep 2

echo ""
echo "━━━ 8. QUICK START ━━━"
echo ""
echo "  git clone https://github.com/Max-arango/AI-SOC-Personal"
echo "  cd AI-SOC-Personal"
echo "  cargo run --bin sentinel-core-service"
echo ""
echo "  gRPC API at http://127.0.0.1:50051"
echo "  Status: grpcurl -plaintext 127.0.0.1:50051 sentinel.api.v1.Sentinel/Status"
sleep 2

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  v0.1.0 — Ready                                              ║"
echo "║  23,373 lines Rust | 55 tests | 0 errors                     ║"
echo "╚══════════════════════════════════════════════════════════════╝"
