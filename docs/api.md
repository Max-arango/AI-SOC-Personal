# gRPC API Reference — Sentinel AI

## Overview

The gRPC API runs on `127.0.0.1:7777` by default. It provides 30+ RPCs for querying events, alerts, processes, network connections, rules, and configuration.

## Service Definition

Service defined in `proto/sentinel/api/v1/sentinel.proto`.

## RPCs

### Health & Status

| RPC | Request | Response | Description |
|---|---|---|---|
| `Health` | `HealthRequest` | `HealthResponse` | Overall system health with per-component status |
| `Version` | `VersionRequest` | `VersionResponse` | Server version info |
| `Status` | `StatusRequest` | `StatusResponse` | Running state, uptime, resources, collectors |

### Events

| RPC | Request | Response | Description |
|---|---|---|---|
| `QueryEvents` | `QueryEventsRequest` | `QueryEventsResponse` | Paginated event query with filters |
| `GetEvent` | `GetEventRequest` | `Event` | Get single event by ID |
| `EventStats` | `EventStatsRequest` | `EventStatsResponse` | Aggregated event statistics |

**QueryEventsRequest fields:**
- `query.event_types: []string` — Filter by event types
- `query.sources: []string` — Filter by collectors
- `query.min_risk_score: uint32` — Minimum risk score
- `query.start_time: Timestamp` — Time range start
- `query.end_time: Timestamp` — Time range end
- `limit: int32` — Page size (default 100)
- `offset: int32` — Page offset

### Processes

| RPC | Request | Response | Description |
|---|---|---|---|
| `ListProcesses` | `ListProcessesRequest` | `ListProcessesResponse` | All running processes |
| `GetProcess` | `GetProcessRequest` | `ProcessDetail` | Single process by PID |
| `GetProcessTree` | `GetProcessTreeRequest` | `ProcessTree` | Process hierarchy tree |

### Network

| RPC | Request | Response | Description |
|---|---|---|---|
| `ListConnections` | `ListConnectionsRequest` | `ListConnectionsResponse` | Active network connections |
| `ConnectionStats` | `ConnectionStatsRequest` | `ConnectionStatsResponse` | Aggregate connection statistics |

### Alerts

| RPC | Request | Response | Description |
|---|---|---|---|
| `ListAlerts` | `ListAlertsRequest` | `ListAlertsResponse` | Paginated alert list |
| `GetAlert` | `GetAlertRequest` | `Alert` | Single alert by ID |

### Rules

| RPC | Request | Response | Description |
|---|---|---|---|
| `ListRules` | `ListRulesRequest` | `ListRulesResponse` | All rules |
| `CreateRule` | `CreateRuleRequest` | `Rule` | Create a new rule |
| `GetRule` | `GetRuleRequest` | `Rule` | Get rule by ID |
| `UpdateRule` | `UpdateRuleRequest` | `Rule` | Update existing rule |
| `DeleteRule` | `DeleteRuleRequest` | `Empty` | Delete a rule |
| `TestRule` | `TestRuleRequest` | `TestRuleResponse` | Test a rule against an event |

### Risk

| RPC | Request | Response | Description |
|---|---|---|---|
| `RiskSummary` | `RiskSummaryRequest` | `RiskSummaryResponse` | Current risk overview |
| `RiskTimeline` | `RiskTimelineRequest` | `RiskTimelineResponse` | Risk over time |
| `TopRisks` | `TopRisksRequest` | `TopRisksResponse` | Highest risk items |

### Correlation

| RPC | Request | Response | Description |
|---|---|---|---|
| `AttackChains` | `AttackChainsRequest` | `AttackChainsResponse` | Active attack chains |
| `ChainDetail` | `ChainDetailRequest` | `AttackChainDetail` | Chain by ID |

### AI

| RPC | Request | Response | Description |
|---|---|---|---|
| `ExplainAlert` | `ExplainAlertRequest` | `ExplainAlertResponse` | AI explanation for an alert |
| `Chat` | `ChatRequest` | `ChatResponse` | Conversational AI chat |

### Config

| RPC | Request | Response | Description |
|---|---|---|---|
| `GetConfig` | `GetConfigRequest` | `ConfigResponse` | Current TOML configuration |
| `UpdateConfig` | `UpdateConfigRequest` | `ConfigResponse` | Update configuration |

### Plugins

| RPC | Request | Response | Description |
|---|---|---|---|
| `ListPlugins` | `ListPluginsRequest` | `ListPluginsResponse` | All installed plugins |
| `GetPlugin` | `GetPluginRequest` | `PluginInfo` | Plugin details |
| `ConfigurePlugin` | `ConfigurePluginRequest` | `PluginConfig` | Configure a plugin |

### Collectors

| RPC | Request | Response | Description |
|---|---|---|---|
| `ListCollectors` | `ListCollectorsRequest` | `ListCollectorsResponse` | All collectors |
| `CollectorStatus` | `CollectorStatusRequest` | `CollectorStatusResponse` | Collector details |
| `RestartCollector` | `RestartCollectorRequest` | `Empty` | Restart a collector |

## Authentication

Authentication is optional and configured via:

```toml
[grpc]
mtls_enabled = false  # Enable mTLS for production
```

## Health Checks

The service exposes standard gRPC health checking:

```bash
grpcurl -plaintext localhost:7777 grpc.health.v1.Health/Check
```

## Reflection

Server reflection is enabled, allowing tools like `grpcurl` to discover services:

```bash
grpcurl -plaintext localhost:7777 list
grpcurl -plaintext localhost:7777 describe sentinel.api.v1.Sentinel
```

## Example Queries

```bash
# Health
grpcurl -plaintext localhost:7777 sentinel.api.v1.Sentinel/Health

# List alerts
grpcurl -plaintext -d '{"limit": 5}' localhost:7777 sentinel.api.v1.Sentinel/ListAlerts

# Query events by type
grpcurl -plaintext -d '{"query": {"event_types": ["sentinel.process.create"]}, "limit": 10}' \
  localhost:7777 sentinel.api.v1.Sentinel/QueryEvents

# List processes
grpcurl -plaintext localhost:7777 sentinel.api.v1.Sentinel/ListProcesses
```
