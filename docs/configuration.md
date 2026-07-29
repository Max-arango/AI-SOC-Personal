# Configuration — Sentinel AI

## Configuration Files

Sentinel AI loads configuration from multiple sources in order:

1. **Default values** (built-in)
2. `/etc/sentinel/config.toml` (system-wide)
3. `~/.config/sentinel/config.toml` (user)
4. **Environment variables** (`SENTINEL_` prefix, highest priority)

## Main Config (TOML)

```toml
[core]
host_id = ""                           # Auto-generated ULID
instance_name = "Sentinel AI"          # Display name
graceful_shutdown_timeout = 30         # Seconds
max_memory_mb = 512                    # Soft limit
max_cpu_percent = 50                   # Throttle collectors if exceeded

[grpc]
enabled = true
address = "127.0.0.1:7777"
mtls_enabled = false

[storage]
sqlite_path = "~/.local/share/sentinel/sentinel.db"
sqlite_wal_mode = true
sqlite_busy_timeout_ms = 5000
duckdb_path = "~/.local/share/sentinel/sentinel.duckdb"

[event_bus]
ingest_channel_size = 10000
broadcast_channel_size = 1000
storage_channel_size = 5000
plugin_channel_size = 2000
ipc_channel_size = 500

[rule_engine]
rules_directories = ["rules"]
hot_reload = true
worker_threads = 2

[risk_engine]
half_life_debug_hours = 1
half_life_info_hours = 2
half_life_warning_hours = 6
half_life_error_hours = 12
half_life_critical_hours = 24
threshold_low = 100
threshold_medium = 300
threshold_high = 600
threshold_critical = 900
dedup_window_seconds = 300
flapping_max_per_hour = 10

[correlation_engine]
chain_timeout_seconds = 600
temporal_window_seconds = 300
flow_ttl_seconds = 172800
max_events_per_chain = 500

[ai_engine]
enabled = true
provider = "ollama"                    # ollama | openrouter | openai
host = "localhost"
port = 11434
model = "llama3.2:3b"
temperature = 0.3
timeout_seconds = 60
api_key = ""                           # For openrouter/openai
api_base = ""                          # Custom API endpoint

[plugin_manager]
plugin_directory = "/usr/lib/sentinel/plugins"
sandbox_enabled = true

[collectors.process]
enabled = true
sample_rate = 1.0
monitor_injection = false              # Requires kernel-level support

[collectors.network]
enabled = true
sample_rate = 1.0

[collectors.file]
enabled = true
monitor_paths = ["/etc", "/tmp", "/var/log"]

[collectors.registry]
enabled = false                        # Windows only

[collectors.usb]
enabled = false

[collectors.browser]
enabled = true
poll_interval_seconds = 120

[collectors.startup]
enabled = true

[threat_intel]
abuseipdb_enabled = false
shodan_enabled = false
virustotal_enabled = false
otx_enabled = false
geoip_enabled = false
ioc_enabled = false

[privacy]
mode = "personal"                      # personal | enterprise
ai_local_only = true
telemetry_enabled = false

[logging]
level = "info"                         # debug | info | warn | error
format = "json"
output = "file"                        # file | stdout | both
directory = "logs"
```

## Environment Variables

### AI Provider

| Variable | Default | Description |
|---|---|---|
| `SENTINEL_AI_PROVIDER` | `ollama` | `ollama`, `openrouter`, `openai` |
| `SENTINEL_AI_API_KEY` | — | API key for openrouter/openai |
| `SENTINEL_AI_MODEL` | `llama3.2:3b` | Model name |
| `SENTINEL_AI_HOST` | `localhost` | Provider host |
| `SENTINEL_AI_API_BASE` | — | Custom API base URL |
| `SENTINEL_AI_ENABLED` | `true` | Enable/disable AI |

### Threat Intel

| Variable | Service |
|---|---|
| `SENTINEL_ABUSEIPDB_API_KEY` | AbuseIPDB IP reputation |
| `SENTINEL_SHODAN_API_KEY` | Shodan host scanning |
| `SENTINEL_VIRUSTOTAL_API_KEY` | VirusTotal file/URL lookup |
| `SENTINEL_OTX_API_KEY` | AlienVault OTX pulses |

### Notifications

| Variable | Service |
|---|---|
| `SENTINEL_DISCORD_WEBHOOK` | Discord webhook URL |
| `SENTINEL_TELEGRAM_BOT_TOKEN` | Telegram bot token |
| `SENTINEL_TELEGRAM_CHAT_ID` | Telegram chat ID |
| `SENTINEL_SLACK_WEBHOOK` | Slack webhook URL |
| `SENTINEL_EMAIL_TO` | Email recipient |
| `SENTINEL_EMAIL_FROM` | Email sender |
| `SENTINEL_EMAIL_SMTP_HOST` | SMTP server |
| `SENTINEL_EMAIL_SMTP_PORT` | SMTP port (default 587) |
| `SENTINEL_EMAIL_USERNAME` | SMTP username |
| `SENTINEL_EMAIL_PASSWORD` | SMTP password |
| `SENTINEL_HA_URL` | Home Assistant URL |
| `SENTINEL_HA_TOKEN` | Home Assistant long-lived token |

### GeoIP

| Variable | Default | Description |
|---|---|---|
| `SENTINEL_GEOIP_COUNTRY_DB` | `~/.config/sentinel/geoip/GeoLite2-Country.mmdb` | Country database |
| `SENTINEL_GEOIP_CITY_DB` | `~/.config/sentinel/geoip/GeoLite2-City.mmdb` | City database |
| `SENTINEL_GEOIP_ASN_DB` | `~/.config/sentinel/geoip/GeoLite2-ASN.mmdb` | ASN database |

### Privacy

| Variable | Default | Description |
|---|---|---|
| `SENTINEL_PRIVACY_MODE` | `personal` | `personal` or `enterprise` |
| `SENTINEL_MGMT_SERVER` | — | Management server address for multi-host |

## Privacy Configuration

When `SENTINEL_PRIVACY_MODE=enterprise`, a `.privacy.toml` file controls data sharing:

```toml
[privacy]
mode = "enterprise"

[privacy.sharing]
command_lines = "redacted"     # full | redacted | none
file_paths = "anonymized"     # full | anonymized | none
network_ips = "anonymized"    # full | anonymized | none
user_names = "hashed"         # full | hashed | none
process_names = "full"        # full | hashed | none

[privacy.fleet_queries]
require_approval = true
max_rows_per_query = 1000

[privacy.ml]
federated_learning = false
differential_privacy_epsilon = 8.0
```
