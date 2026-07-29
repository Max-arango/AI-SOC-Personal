# Rule Engine — Sentinel AI

Sentinel AI uses CEL (Common Expression Language) for rule evaluation. Rules are written in YAML and loaded from the `rules/` directory.

## Rule Format

```yaml
rule:
  id: "rule-001-suspicious-powershell"
  version: 1
  name: "Suspicious PowerShell Execution"
  description: "PowerShell executing encoded or download commands"
  author: "Sentinel Team"
  created: "2026-01-01T00:00:00Z"
  modified: "2026-01-01T00:00:00Z"
  enabled: true
  category: "execution"
  subcategory: "scripting"
  mitre:
    - technique: "T1059.001"
      name: "PowerShell"
      tactic: "Execution"
  severity: "Warning"
  risk:
    base_score: 75
    confidence: 0.9
    multipliers:
      - condition: "event.process.user.is_elevated == true"
        factor: 1.5
  condition: >
    event.type == "sentinel.process.create"
    && event.process.name.contains("powershell")
    && (event.process.command_line.contains("-enc")
        || event.process.command_line.contains("downloadstring"))
  and_conditions: []
  or_conditions: []
  not_conditions: []
  actions: []
  suppressions: []
  tests: []
```

## CEL Context Variables

The rule engine injects the following variables into the CEL context:

| Variable | Type | Description |
|---|---|---|
| `event` | Map | The full event object (see below) |
| `severity` | Int | Event severity (0-7) |
| `event_type` | String | Event type (e.g. `sentinel.process.create`) |
| `SEVERITY_DEBUG` | Int | 1 |
| `SEVERITY_INFO` | Int | 2 |
| `SEVERITY_NOTICE` | Int | 3 |
| `SEVERITY_WARNING` | Int | 4 |
| `SEVERITY_ERROR` | Int | 5 |
| `SEVERITY_CRITICAL` | Int | 6 |
| `SEVERITY_ALERT` | Int | 7 |
| `SEVERITY_EMERGENCY` | Int | 8 |

### Event Fields

```
event.id                  → String
event.type                → String
event.source              → String ("process", "network", "file", etc.)
event.severity            → Int
event.risk_score          → UInt
event.host_id             → String
event.tags                → List<String>
event.timestamp_epoch     → Int (Unix seconds)
event.process.pid         → UInt
event.process.ppid        → UInt
event.process.name        → String
event.process.path        → String
event.process.command_line→ String
event.process.user.username→ String
event.process.user.is_elevated→ Bool
event.process.user.is_system→ Bool
event.process.signing.is_signed→ Bool
event.process.signing.is_trusted→ Bool
event.correlation.session_id→ String
event.correlation.correlation_id→ String
event.correlation.flow_id → String
```

## CEL Functions Available

| Function | Example | Description |
|---|---|---|
| `.contains(substr)` | `event.process.name.contains("powershell")` | Case-sensitive substring match |
| `.startsWith(prefix)` | `event.process.path.startsWith("/tmp/")` | Prefix check |
| `.endsWith(suffix)` | `event.process.name.endsWith(".exe")` | Suffix check |
| `.matches(regex)` | `event.process.command_line.matches(".*-enc.*")` | Regex match |
| `size(list)` | `size(event.tags) > 0` | List length |
| `exists(list, predicate)` | `event.tags.exists(t, t == "sensitive_path")` | Any element matches |

> **Note**: `lowerAscii()` is automatically preprocessed by the rule engine (removed before CEL compilation). Use lowercase matching strings in your rules.

## Built-in Rules (50 rules)

### By MITRE Tactic

| Tactic | Rules | Example |
|---|---|---|
| Initial Access | 2 | Phishing document, exploit public app |
| Execution | 5 | PowerShell, LOLBins, reverse shell, user scripts, system services |
| Persistence | 4 | Startup, scheduled task, account manipulation, web shell |
| Privilege Escalation | 2 | Sudo abuse, container escape |
| Defense Evasion | 7 | LOLBins, injection, clear logs, masquerade, disable tools, DLL sideload, hidden files |
| Credential Access | 3 | Credential dump, unsecured credentials, credential stores |
| Discovery | 7 | System info, network scan, file enum, process enum, network config, account enum, share enum |
| Lateral Movement | 3 | SSH, RDP, SMB shares |
| Collection | 3 | Data staging, keylogging, screen capture |
| C2 | 4 | TOR, beaconing, nonstandard port, ingress tool |
| Exfiltration | 2 | DNS exfil, C2 channel |
| Impact | 2 | Ransomware, inhibit recovery |

## Writing Custom Rules

1. Create a `.yaml` file in `rules/`
2. Follow the format above
3. Set `enabled: true`
4. The rule engine hot-reloads automatically (no restart needed)

### Severity Levels

| Level | Risk Score | When to Use |
|---|---|---|
| `Info` | 20 | Informational, expected behavior |
| `Notice` | 35 | Suspicious but likely benign |
| `Warning` | 55 | Potentially malicious activity |
| `Error` | 75 | Likely malicious |
| `Critical` | 90 | Confirmed threat, active attack |

## Importing Sigma Rules

```bash
# Single rule
sentinel-cli import-sigma -i /path/to/sigma_rule.yml -o rules/

# Whole directory
sentinel-cli import-sigma -i /path/to/sigma/rules/ --dir -o rules/
```

The importer maps:
- Sigma `logsource.category` → Sentinel event type
- Sigma field names → CEL paths (`Image` → `event.process.name`)
- Sigma modifiers (`|endswith`, `|contains`) → CEL functions
- Sigma `level` → Sentinel severity
- Sigma `tags: attack.t1059.001` → MITRE mapping
