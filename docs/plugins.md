# Plugins — Sentinel AI

Sentinel AI has 12 built-in plugins across 3 categories.

## Notification Plugins

Send alerts to external services. Configured via environment variables. All are opt-in.

### Discord
```bash
export SENTINEL_DISCORD_WEBHOOK=https://discord.com/api/webhooks/...
```
Sends rich embed messages with severity color coding, risk score, source, and alert ID.

### Telegram
```bash
export SENTINEL_TELEGRAM_BOT_TOKEN=123:abc
export SENTINEL_TELEGRAM_CHAT_ID=-100123
```
Sends Markdown-formatted messages with emoji severity indicators.

### Slack
```bash
export SENTINEL_SLACK_WEBHOOK=https://hooks.slack.com/...
```
Block Kit messages with header, section fields, divider, and context footer.

### Email
```bash
export SENTINEL_EMAIL_TO=admin@example.com
export SENTINEL_EMAIL_FROM=sentinel@example.com
```
Uses system `sendmail` command. Plain text with rule, severity, risk, source, and alert ID.

### Home Assistant
```bash
export SENTINEL_HA_URL=http://homeassistant.local:8123
export SENTINEL_HA_TOKEN=long-lived-access-token
```
- Sends persistent notifications to Home Assistant
- Updates a sensor (`sensor.sentinel_last_alert`) with alert data

---

## Threat Intel Plugins

Enrich network and process events with external threat intelligence. Configured via environment variables. All use free API tiers.

### AbuseIPDB
```bash
export SENTINEL_ABUSEIPDB_API_KEY=your-key
```
- Check IP reputation via AbuseIPDB API v2
- Returns: abuse_score (0-100), total_reports, country, ISP
- Enrichment: +15 risk (medium), +30 risk (high)
- Tags: `threat_intel:abuseipdb:high`, `:medium`, `:N_reports`

### Shodan
```bash
export SENTINEL_SHODAN_API_KEY=your-key
```
- Host scan via Shodan API
- Returns: open_ports, vulnerabilities (CVEs), organization, ISP, country
- Enrichment: +10 risk (medium), +25 risk (high)
- Tags: `threat_intel:shodan:high`, `:cve`, `:N_ports`

### VirusTotal
```bash
export SENTINEL_VIRUSTOTAL_API_KEY=your-key
```
- File hash lookup via VirusTotal API v3
- Returns: malicious, suspicious, harmless, undetected counts
- Enrichment: risk += threat_ratio × 50
- Tags: `threat_intel:virustotal:malicious_N`, `:high`

### AlienVault OTX
```bash
export SENTINEL_OTX_API_KEY=your-key
```
- Community threat intelligence via OTX API
- Returns: pulse_count, reputation, malware_families, adversary
- Enrichment: +10 risk (medium), +25 risk (high)
- Tags: `threat_intel:otx:high`, `:N_pulses`, `:malware`

### GeoIP (local — no API key)
```bash
# Download free databases from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
mkdir -p ~/.config/sentinel/geoip/
# Place .mmdb files in the directory
```
- Local MaxMind GeoLite2 database lookup
- Returns: country_code, city, region, lat/lon, ASN, ASN org
- Enrichment: +10 risk for anonymous/hosting IPs
- Tags: `geoip:cc:XX`, `:city:XXX`, `:asn:XXX`, `:anonymous`

### IOC Database (local — no API key)
```bash
mkdir -p ~/.config/sentinel/iocs/
```
**CSV format:**
```csv
type,indicator,risk_score,description
ip,10.0.0.1,80,Known C2 server
domain,evil.com,90,Phishing domain
hash,abc123def456,95,Known malware
```
**STIX JSON format:**
```json
{"objects": [{"type": "indicator", "pattern": "[ipv4-addr:value = '10.0.0.1']", "name": "C2 Server"}]}
```
- Loads indicators from CSV/STIX files at startup
- O(1) HashMap lookup
- Enrichment: risk += IOC_risk / 3
- Tags: `ioc:ip_match`, `ioc:hash_match`

---

## Pipeline Integration

All plugins integrate into the core-service event loop:

```rust
// For each event:
// 1. Network events → AbuseIPDB + Shodan + OTX + GeoIP + IOC (parallel)
// 2. Process events → VirusTotal + IOC (on SHA256)
// 3. Alerts generated → Discord + Telegram + Email + Slack + HA (parallel spawn)
```

## Creating a Custom Plugin

1. Create a new directory under `plugins/`
2. Add a `Cargo.toml` with `reqwest` + `serde` deps
3. Export `pub fn enabled() -> bool` (checks env vars)
4. Export your API function (e.g., `pub async fn check_ip(...)`)
5. Add the plugin to `apps/sentinel-core-service/Cargo.toml`
6. Wire it into `apps/sentinel-core-service/src/main.rs`

### Example: Minimal Plugin

```rust
// plugins/myplugin/src/lib.rs
use tracing::{info, warn};
use reqwest;

pub fn enabled() -> bool {
    std::env::var("SENTINEL_MYPLUGIN_KEY").is_ok()
}

pub async fn check_ip(ip: &str) -> Option<u32> {
    let key = std::env::var("SENTINEL_MYPLUGIN_KEY").ok()?;
    let url = format!("https://api.example.com/check/{}", ip);

    let resp = reqwest::Client::new()
        .get(&url)
        .header("X-API-Key", &key)
        .send().await.ok()?;

    let score: u32 = resp.json().await.ok()?;
    info!("MyPlugin: {} → score={}", ip, score);
    Some(score)
}
```
