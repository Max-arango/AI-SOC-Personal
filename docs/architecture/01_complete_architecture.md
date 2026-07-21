# Sentinel AI - Complete Architecture Specification

**Version:** 1.0  
**Status:** Draft  
**Classification:** Internal - Architecture Decision Record  
**Author:** Principal Software Architect  
**Date:** 2026-07-16

---

## Table of Contents

1. [Complete System Architecture](#1-complete-system-architecture)
2. [Core Service Design](#2-core-service-design)
3. [Event Bus Architecture](#3-event-bus-architecture)
4. [Event Model Specification](#4-event-model-specification)
5. [Collectors Architecture](#5-collectors-architecture)
6. [Rule Engine Design](#6-rule-engine-design)
7. [Risk Engine Design](#7-risk-engine-design)
8. [Event Correlation Engine](#8-event-correlation-engine)
9. [AI Assistant Architecture](#9-ai-assistant-architecture)
10. [API Specification](#10-api-specification)
11. [Plugin System Architecture](#11-plugin-system-architecture)
12. [Configuration Management](#12-configuration-management)
13. [Repository Organization](#13-repository-organization)
14. [Roadmap](#14-roadmap)

---

## 1. Complete System Architecture

### 1.1 Architectural Overview

Sentinel AI follows a **modular, event-driven, microservices-inspired architecture** within a single-process boundary (for resource efficiency) with clear separation of concerns. The system is designed as a **local-first, privacy-preserving** security telemetry platform.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            SENTINEL AI SYSTEM                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────┐  │
│  │   Tauri UI   │◄───│  gRPC/IPC    │◄───│  Core        │───►│ Plugins  │  │
│  │  (React/TS)  │    │   Layer      │    │  Service     │    │ Manager  │  │
│  └──────────────┘    └──────────────┘    └──────┬───────┘    └──────────┘  │
│                                                  │                            │
│                          ┌───────────────────────┼───────────────────────┐   │
│                          ▼                       ▼                       ▼   │
│                 ┌────────────────┐      ┌────────────────┐      ┌──────────┐ │
│                 │  Event Bus     │      │  Rule Engine   │      │AI Engine │ │
│                 │  (In-Memory)   │      │  (YAML/CEL)    │      │(Ollama/  │ │
│                 └───────┬────────┘      └───────┬────────┘      │llama.cpp)│ │
│                         │                       │               └──────────┘ │
│         ┌───────────────┼───────────────┐       │                        │   │
│         ▼               ▼               ▼       ▼                        ▼   │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐      ┌──────────┐│
│  │  Process   │ │  Network   │ │   File     │ │ Registry   │      │  Risk    ││
│  │ Collector  │ │ Collector  │ │ Collector  │ │ Collector  │      │  Engine  ││
│  └────────────┘ └────────────┘ └────────────┘ └────────────┘      └──────────┘│
│         │               │               │               │                        │
│         └───────────────┼───────────────┼───────────────┘                        │
│                         ▼               ▼                                        │
│                 ┌────────────┐ ┌────────────┐                                   │
│                 │   USB      │ │  Browser   │                                   │
│                 │ Collector  │ │ Collector  │                                   │
│                 └────────────┘ └────────────┘                                   │
│                         │               │                                        │
│                         └───────────────┘                                        │
│                                    │                                             │
│                                    ▼                                             │
│                         ┌────────────────┐                                       │
│                         │  Startup       │                                       │
│                         │  Collector     │                                       │
│                         └────────────┘   │                                       │
│                                          │                                       │
└──────────────────────────────────────────┼──────────────────────────────────────┘
                                           ▼
                              ┌────────────────────────┐
                              │   OS Abstraction Layer │
                              │  (Windows/Linux/macOS) │
                              └────────────────────────┘
                                           │
                    ┌──────────────────────┼──────────────────────┐
                    ▼                      ▼                      ▼
             ┌─────────────┐        ┌─────────────┐        ┌─────────────┐
             │   Windows   │        │   Linux     │        │   macOS     │
             │   APIs      │        │   APIs      │        │   APIs      │
             │ (ETW/WMI/   │        │ (auditd/    │        │ (Endpoint   │
             │  Sysmon/    │        │  fanotify/  │        │  Security/  │
             │  Kernel     │        │  eBPF/      │        │  OpenBSM/   │
             │  Callbacks) │        │  netlink)   │        │  FSEvents)  │
             └─────────────┘        └─────────────┘        └─────────────┘
```

### 1.2 Module Responsibilities

| Module | Responsibility | Technology | Lifecycle |
|--------|---------------|------------|-----------|
| **UI Layer** | Dashboard, chat, alerts, settings | Tauri + React + TypeScript | User-session |
| **IPC/gRPC Layer** | Transport, serialization, auth | gRPC + Protobuf | Process lifetime |
| **Core Service** | Orchestration, lifecycle, health | Rust (tokio) | Process lifetime |
| **Event Bus** | Pub/sub, routing, backpressure | Tokio channels + crossbeam | Process lifetime |
| **Rule Engine** | Pattern matching, evaluation | CEL (Common Expression Language) | Hot-reloadable |
| **Correlation Engine** | Sequence detection, graph building | Custom state machine | Process lifetime |
| **Risk Engine** | Scoring, aggregation, thresholds | Configurable weighted model | Process lifetime |
| **AI Engine** | LLM inference, context building | Ollama/llama.cpp (FLA) | On-demand |
| **Plugin Manager** | Loading, sandboxing, lifecycle | Dynamic libraries (cdylib) | Hot-loadable |
| **Collectors** | OS telemetry ingestion | Rust + OS-specific crates | Per-collector |
| **Storage Layer** | Persistence, queries, retention | SQLite + DuckDB | Process lifetime |
| **Config Manager** | TOML parsing, validation, watch | config-rs + notify | Hot-reloadable |

### 1.3 Inter-Module Dependencies

```
Core Service
    │
    ├──► Event Bus (owns)
    │
    ├──► Rule Engine (uses Event Bus)
    │
    ├──► Correlation Engine (uses Event Bus, Rule Engine)
    │
    ├──► Risk Engine (uses Correlation Engine, Rule Engine)
    │
    ├──► AI Engine (uses Risk Engine output)
    │
    ├──► Plugin Manager (uses Event Bus, Risk Engine, AI Engine)
    │
    ├──► Collector Manager (owns collectors, feeds Event Bus)
    │
    ├──► Storage Service (owns SQLite + DuckDB connections)
    │
    └──► Config Service (owns, notifies all modules on change)

Collectors ──► Event Bus ──► [Rule Engine, Correlation Engine, Storage]
                                    │
                                    ▼
                              Risk Engine ──► AI Engine
                                    │
                                    ▼
                              Plugin Manager ──► External Integrations
                                    │
                                    ▼
                              IPC/gRPC ──► UI Layer
```

### 1.4 Communication Patterns

| Path | Pattern | Protocol | Serialization | Backpressure |
|------|---------|----------|---------------|--------------|
| Collector → Event Bus | Async pub/sub | In-memory channels | Zero-copy (Arc<Event>) | Bounded channels |
| Event Bus → Engines | Async fan-out | Tokio broadcast/mpsc | Zero-copy | Bounded + drop policies |
| Core ↔ UI | Request/Response + Streaming | gRPC | Protocol Buffers | gRPC flow control |
| Core ↔ Plugins | Request/Response + Events | FFI (C ABI) + callbacks | JSON/MessagePack | Plugin-defined |
| AI Engine ↔ LLM | Request/Response | HTTP/Unix socket | JSON | Client-side queuing |
| Storage → Engines | Async queries | Direct Rust API | Native types | Connection pooling |

### 1.5 Lifecycle Management

```rust
// Conceptual lifecycle states
enum SystemState {
    Initializing,  // Loading config, initializing storage, starting collectors
    Starting,      // Starting core services, rule engine, correlation
    Running,       // Normal operation
    Degraded,      // Some collectors/plugins failed, reduced functionality
    Stopping,      // Graceful shutdown: flush buffers, stop collectors, close DB
    Stopped,       // Clean exit
    Crashed,       // Unexpected termination (watchdog should restart)
}

// State transitions with hooks
Initializing → Starting → Running ↔ Degraded
    ↓              ↓           ↓           ↓
   (error)      (error)     (recover)  (shutdown)
    ↓              ↓           ↓           ↓
  Stopped      Stopped     Running    Stopping → Stopped
```

---

## 2. Core Service Design

### 2.1 Responsibilities

The **Core Service** is the central orchestration layer. It does **not** process events directly—it coordinates.

| Responsibility | Description |
|----------------|-------------|
| **Lifecycle Management** | Start/stop/restart all subsystems in correct dependency order |
| **Health Monitoring** | Heartbeats, resource usage, collector status, plugin health |
| **Configuration Distribution** | Parse, validate, distribute config changes to all modules |
| **Event Routing** | Ensure events flow from collectors → bus → engines → storage → plugins |
| **Backpressure Coordination** | Monitor channel depths, signal collectors to throttle |
| **Metric Aggregation** | Collect and expose Prometheus metrics from all modules |
| **Crash Recovery** | Checkpoint state, restart failed collectors, replay from WAL |
| **Security Boundary** | Enforce capability-based access between modules |

### 2.2 Public Interfaces (Traits)

```rust
// Core orchestration trait
#[async_trait]
trait CoreService: Send + Sync {
    async fn start(&self) -> Result<(), CoreError>;
    async fn stop(&self, graceful: bool) -> Result<(), CoreError>;
    async fn restart_subsystem(&self, name: &str) -> Result<(), CoreError>;
    fn health(&self) -> HealthStatus;
    fn metrics(&self) -> MetricsSnapshot;
}

// Module registration
trait Module: Send + Sync {
    fn name(&self) -> &'static str;
    fn dependencies(&self) -> Vec<&'static str>;
    async fn initialize(&self, ctx: &ModuleContext) -> Result<(), ModuleError>;
    async fn start(&self) -> Result<(), ModuleError>;
    async fn stop(&self, graceful: bool) -> Result<(), ModuleError>;
    fn health(&self) -> ModuleHealth;
    fn config_schema(&self) -> ConfigSchema;
}

// Module context provided by core
struct ModuleContext {
    event_bus: Arc<dyn EventBus>,
    storage: Arc<dyn Storage>,
    config: Arc<dyn ConfigProvider>,
    metrics: Arc<MetricsRegistry>,
    plugin_manager: Arc<dyn PluginManager>,
}
```

### 2.3 Internal Services

| Service | Purpose | Implementation |
|---------|---------|----------------|
| **ModuleRegistry** | Dependency graph, topological start/stop | petgraph + async lifecycle |
| **ConfigDispatcher** | Watch TOML files, validate, notify modules | notify + config-rs + serde |
| **HealthAggregator** | Aggregate module health, determine system state | Periodic checks + event-driven |
| **BackpressureController** | Monitor channel depths, apply throttling | Token bucket per collector |
| **CheckpointManager** | Periodic state snapshots for recovery | Serialize to SQLite WAL |
| **MetricExporter** | Prometheus /metrics endpoint | prometheus-client crate |

### 2.4 Event Flow Through Core

```
Collector Event
       │
       ▼
┌──────────────────┐
│  Event Bus       │──► [Rule Engine] ──► Rule Matches
│  (ingest path)   │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Correlation     │──► Correlation Chains
│  Engine          │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Risk Engine     │──► Risk Scores + Alerts
│  (scoring)       │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Storage         │──► Persisted Events
│  (async write)   │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Plugin Manager  │──► External Notifications
│  (dispatch)      │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  IPC/gRPC        │──► UI Updates (WebSocket/Streaming)
│  (broadcast)     │
└──────────────────┘
```

### 2.5 Storage Integration

The Core owns the storage layer but exposes **repository traits** to modules:

```rust
#[async_trait]
trait EventRepository: Send + Sync {
    async fn append(&self, events: &[Event]) -> Result<(), StorageError>;
    async fn query(&self, query: EventQuery) -> Result<EventCursor, StorageError>;
    async fn aggregate(&self, agg: AggregationQuery) -> Result<AggregationResult, StorageError>;
    async fn retention(&self, policy: RetentionPolicy) -> Result<u64, StorageError>;
}

#[async_trait]
trait RuleRepository: Send + Sync {
    async fn load_all(&self) -> Result<Vec<Rule>, StorageError>;
    async fn upsert(&self, rule: &Rule) -> Result<(), StorageError>;
    async fn delete(&self, id: &RuleId) -> Result<(), StorageError>;
}
```

---

## 3. Event Bus Architecture

### 3.1 Design Decision: In-Memory, Async, Zero-Copy

**Choice:** Tokio `broadcast` + `mpsc` channels with `Arc<Event>` for zero-copy fan-out.

**Rationale:**

| Option | Pros | Cons | Verdict |
|--------|------|------|---------|
| **Tokio Channels (Chosen)** | Zero-copy, built-in backpressure, async-native, no external deps | Single-process only | ✅ Best fit for local-first |
| ZeroMQ | Multi-process, language-agnostic | External dependency, complexity, serialization overhead | ❌ Overkill |
| NATS | Distributed, durable, clustering | External server, resource heavy | ❌ Violates local-first |
| gRPC Streams | Standard, bidirectional | Serialization overhead, not for internal hot path | ❌ Wrong layer |
| Crossbeam Channels | Sync, fast | No async integration, manual backpressure | ❌ Blocking risk |

### 3.2 Event Bus Topology

```
┌─────────────────────────────────────────────────────────────────┐
│                        EVENT BUS                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────┐    ┌──────────────────────────────────────┐   │
│  │  Ingest     │    │           Topic Router                │   │
│  │  Channel    │───►│  (maps event.type → subscriber sets)  │   │
│  │  (mpsc)     │    └──────────────┬───────────────────────┘   │
│  └─────────────┘                   │                           │
│                                    ▼                           │
│                    ┌────────────────────────────────┐          │
│                    │   Subscription Registry         │          │
│                    │  - topic → Vec<Sender<Arc<Event>>> │          │
│                    │  - wildcard support (process.*) │          │
│                    └──────────────┬─────────────────┘          │
│                                   │                            │
│         ┌─────────────────────────┼─────────────────────────┐  │
│         ▼                         ▼                         ▼  │
│  ┌─────────────┐          ┌─────────────┐          ┌─────────────┐│
│  │  Rule       │          │ Correlation │          │  Storage    ││
│  │  Engine     │          │  Engine     │          │  Writer     ││
│  │  (broadcast)│          │  (broadcast)│          │  (mpsc)     ││
│  └─────────────┘          └─────────────┘          └─────────────┘│
│         │                         │                         │     │
│         ▼                         ▼                         ▼     │
│  ┌─────────────┐          ┌─────────────┐          ┌─────────────┐│
│  │  Risk       │          │  Plugin     │          │  IPC/gRPC   ││
│  │  Engine     │          │  Manager    │          │  Broadcaster││
│  │  (broadcast)│          │  (mpsc)     │          │  (streams)  ││
│  └─────────────┘          └─────────────┘          └─────────────┘│
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 3.3 Channel Configuration

| Channel | Type | Capacity | Overflow Policy | Subscribers |
|---------|------|----------|-----------------|-------------|
| **Ingest** | `mpsc` | 10,000 | Block (backpressure to collectors) | 1 (Topic Router) |
| **Rule Engine** | `broadcast` | 1,000 | Drop oldest | 1 |
| **Correlation** | `broadcast` | 1,000 | Drop oldest | 1 |
| **Storage Writer** | `mpsc` | 5,000 | Block (critical path) | 1 |
| **Plugin Dispatch** | `mpsc` | 2,000 | Drop newest (non-critical) | N (per plugin) |
| **IPC Broadcast** | `broadcast` | 500 | Drop oldest | N (per UI client) |

### 3.4 Backpressure Strategy

```rust
// Backpressure signals propagated to collectors
enum BackpressureSignal {
    Normal,           // < 50% capacity
    Elevated,         // 50-75% - log warning
    High,             // 75-90% - throttle collectors 50%
    Critical,         // > 90% - throttle collectors 90%, drop non-critical
    Overflow,         // Channel full - emergency mode
}

// Collector responds to signal
impl Collector {
    async fn adjust_rate(&mut self, signal: BackpressureSignal) {
        match signal {
            BackpressureSignal::Normal => self.set_sample_rate(1.0),
            BackpressureSignal::Elevated => self.set_sample_rate(0.8),
            BackpressureSignal::High => self.set_sample_rate(0.5),
            BackpressureSignal::Critical => self.set_sample_rate(0.1),
            BackpressureSignal::Overflow => self.pause_collection(),
        }
    }
}
```

### 3.5 Event Format on the Bus

**Internal representation:** `Arc<Event>` (zero-copy, immutable)

**Serialization (for plugins/IPC/storage):** Protocol Buffers (see Section 4)

**Why not JSON/CBOR/MessagePack on the bus?**
- JSON: Parsing overhead, allocation, no schema enforcement
- CBOR: Better than JSON but still serialization cost
- MessagePack: Similar to CBOR
- **Protobuf**: Schema-first, zero-copy possible (via `bytes`), fast, versioned

---

## 4. Event Model Specification

### 4.1 Design Principles

1. **Immutable** - Events never change after creation
2. **Self-describing** - Contains all context needed for analysis
3. **Extensible** - Unknown fields preserved (protobuf `unknown_fields`)
4. **Correlatable** - Built-in correlation IDs and causality tracking
5. **Typed** - Strong typing via Protocol Buffers schema

### 4.2 Protocol Buffers Schema

```protobuf
// sentinel/events/v1/event.proto
syntax = "proto3";

package sentinel.events.v1;

import "google/protobuf/timestamp.proto";
import "google/protobuf/struct.proto";
import "google/protobuf/any.proto";

option rust_module = "sentinel_events";

// ============================================================
// BASE EVENT
// ============================================================

message Event {
  // Unique event identifier (ULID: timestamp + entropy)
  string id = 1;

  // Event type in reverse-DNS notation: "sentinel.process.create"
  string type = 2;

  // Source collector: "process", "network", "file", "registry", "usb", "browser", "startup"
  string source = 3;

  // When the event occurred on the endpoint
  google.protobuf.Timestamp timestamp = 4;

  // When the event was ingested by the core (for latency measurement)
  google.protobuf.Timestamp ingest_timestamp = 5;

  // Severity: DEBUG(0), INFO(1), NOTICE(2), WARNING(3), ERROR(4), CRITICAL(5), ALERT(6), EMERGENCY(7)
  Severity severity = 6;

  // Process context (always populated when available)
  ProcessContext process = 7;

  // Event-specific payload (oneof for type safety)
  oneof payload {
    ProcessEvent process_event = 100;
    NetworkEvent network_event = 101;
    FileEvent file_event = 102;
    RegistryEvent registry_event = 103;
    UsbEvent usb_event = 104;
    BrowserEvent browser_event = 105;
    StartupEvent startup_event = 106;
    GenericEvent generic_event = 107;
  }

  // Tags for indexing and filtering (e.g., "mitre:T1059", "signed:false")
  repeated string tags = 200;

  // Free-form metadata (structured, queryable)
  google.protobuf.Struct metadata = 201;

  // Risk contribution (0-100, set by Rule Engine)
  uint32 risk_score = 300;

  // Correlation identifiers
  CorrelationContext correlation = 301;

  // Host identifier (stable, pseudonymous)
  string host_id = 400;

  // Schema version for forward compatibility
  uint32 schema_version = 999;
}

enum Severity {
  SEVERITY_UNSPECIFIED = 0;
  SEVERITY_DEBUG = 1;
  SEVERITY_INFO = 2;
  SEVERITY_NOTICE = 3;
  SEVERITY_WARNING = 4;
  SEVERITY_ERROR = 5;
  SEVERITY_CRITICAL = 6;
  SEVERITY_ALERT = 7;
  SEVERITY_EMERGENCY = 8;
}

// ============================================================
// PROCESS CONTEXT (embedded in every event when available)
// ============================================================

message ProcessContext {
  // Process ID
  uint32 pid = 1;

  // Parent Process ID
  uint32 ppid = 2;

  // Executable name (basename)
  string name = 3;

  // Full executable path
  string path = 4;

  // Command line arguments
  string command_line = 5;

  // Current working directory
  string cwd = 6;

  // User context
  UserContext user = 7;

  // Integrity level (Windows) / capabilities (Linux)
  string integrity_level = 8;

  // Code signing info
  CodeSigningInfo signing = 9;

  // MITRE ATT&CK techniques observed for this process (so far)
  repeated string mitre_techniques = 10;

  // Process tree depth from session leader
  uint32 tree_depth = 11;

  // Hash of executable (SHA256)
  string sha256 = 12;

  // Parent process context (recursive, limited depth)
  ProcessContext parent = 13;
}

message UserContext {
  string sid = 1;           // Windows SID or Linux UID
  string username = 2;
  string domain = 3;
  bool is_elevated = 4;     // Admin/root
  bool is_system = 5;       // SYSTEM/root service
}

message CodeSigningInfo {
  bool is_signed = 1;
  bool is_trusted = 2;
  string publisher = 3;
  string issuer = 4;
  google.protobuf.Timestamp timestamp = 5;
  repeated string certificates = 6;  // PEM-encoded chain
}

// ============================================================
// CORRELATION CONTEXT
// ============================================================

message CorrelationContext {
  // Session ID: groups events from same user session / boot
  string session_id = 1;

  // Causality chain: event ID that directly caused this event
  string cause_event_id = 2;

  // Root cause: original event starting this chain
  string root_event_id = 3;

  // Correlation ID: groups related events across time (e.g., same attack)
  string correlation_id = 4;

  // Flow ID: tracks data flow (file → process → network)
  string flow_id = 5;

  // Sequence number within correlation
  uint32 sequence = 6;
}

// ============================================================
// PAYLOAD TYPES
// ============================================================

message ProcessEvent {
  enum Action {
    ACTION_UNSPECIFIED = 0;
    CREATE = 1;
    TERMINATE = 2;
    OPEN = 3;
    ACCESS = 4;
    INJECT = 5;
    HOLLOW = 6;
    DUMP = 7;
  }
  Action action = 1;
  ProcessContext target = 2;  // For open/access/inject
  uint32 desired_access = 3;  // Windows access mask
}

message NetworkEvent {
  enum Direction {
    DIRECTION_UNSPECIFIED = 0;
    INBOUND = 1;
    OUTBOUND = 2;
  }
  enum Protocol {
    PROTOCOL_UNSPECIFIED = 0;
    TCP = 1;
    UDP = 2;
    ICMP = 3;
    RAW = 4;
  }
  enum Action {
    ACTION_UNSPECIFIED = 0;
    CONNECT = 1;
    LISTEN = 2;
    ACCEPT = 3;
    SEND = 4;
    RECEIVE = 5;
    CLOSE = 6;
    DNS_QUERY = 7;
    DNS_RESPONSE = 8;
    HTTP_REQUEST = 9;
    HTTP_RESPONSE = 10;
  }
  Direction direction = 1;
  Protocol protocol = 2;
  Action action = 3;
  string local_addr = 4;
  uint32 local_port = 5;
  string remote_addr = 6;
  uint32 remote_port = 7;
  uint64 bytes_sent = 8;
  uint64 bytes_received = 9;
  string dns_query = 10;
  string http_method = 11;
  string http_url = 12;
  uint32 http_status = 13;
  string hostname = 14;  // SNI / Host header
  string ja3_fingerprint = 15;
  string ja3s_fingerprint = 16;
}

message FileEvent {
  enum Action {
    ACTION_UNSPECIFIED = 0;
    CREATE = 1;
    MODIFY = 2;
    DELETE = 3;
    RENAME = 4;
    READ = 5;
    WRITE = 6;
    EXECUTE = 7;
    MAP = 8;
    ATTRIBUTE_CHANGE = 9;
    PERMISSION_CHANGE = 10;
    HARDLINK = 11;
    SYMLINK = 12;
  }
  Action action = 1;
  string path = 2;
  string destination = 3;  // For rename
  uint64 size = 4;
  string sha256 = 5;
  string entropy = 6;      // Shannon entropy for anomaly detection
  FileAttributes attributes = 7;
  bool is_executable = 8;
  string mime_type = 9;
  bool is_sensitive_path = 10;  // e.g., ~/.ssh, /etc/passwd
}

message FileAttributes {
  bool readonly = 1;
  bool hidden = 2;
  bool system = 3;
  bool archive = 4;
  bool compressed = 5;
  bool encrypted = 6;
  google.protobuf.Timestamp created = 7;
  google.protobuf.Timestamp modified = 8;
  google.protobuf.Timestamp accessed = 9;
}

message RegistryEvent {
  enum Action {
    ACTION_UNSPECIFIED = 0;
    CREATE_KEY = 1;
    DELETE_KEY = 2;
    SET_VALUE = 3;
    DELETE_VALUE = 4;
    RENAME_KEY = 5;
    QUERY_KEY = 6;
    QUERY_VALUE = 7;
  }
  enum Hive {
    HIVE_UNSPECIFIED = 0;
    HKLM = 1;
    HKCU = 2;
    HKCR = 3;
    HKU = 4;
    HKCC = 5;
  }
  Action action = 1;
  Hive hive = 2;
  string key_path = 3;
  string value_name = 4;
  RegistryValueData value_data = 5;
  string old_value = 6;  // For modifications
}

message RegistryValueData {
  enum Type {
    TYPE_UNSPECIFIED = 0;
    STRING = 1;
    EXPAND_STRING = 2;
    BINARY = 3;
    DWORD = 4;
    QWORD = 5;
    MULTI_STRING = 6;
  }
  Type type = 1;
  bytes data = 2;
}

message UsbEvent {
  enum Action {
    ACTION_UNSPECIFIED = 0;
    DEVICE_CONNECT = 1;
    DEVICE_DISCONNECT = 2;
    MASS_STORAGE_MOUNT = 3;
    MASS_STORAGE_UNMOUNT = 4;
    HID_KEYBOARD = 5;
    HID_MOUSE = 6;
  }
  Action action = 1;
  string device_id = 2;
  string vendor_id = 3;
  string product_id = 4;
  string serial_number = 5;
  string manufacturer = 6;
  string product = 7;
  string mount_point = 8;
  bool is_encrypted = 9;
  repeated string file_hashes = 10;  // Sample of files on mount
}

message BrowserEvent {
  enum Browser {
    BROWSER_UNSPECIFIED = 0;
    CHROME = 1;
    FIREFOX = 2;
    EDGE = 3;
    SAFARI = 4;
    BRAVE = 5;
    VIVALDI = 6;
  }
  enum Action {
    ACTION_UNSPECIFIED = 0;
    NAVIGATION = 1;
    DOWNLOAD_START = 2;
    DOWNLOAD_COMPLETE = 3;
    EXTENSION_INSTALL = 4;
    EXTENSION_REMOVE = 5;
    COOKIE_ACCESS = 6;
    LOCALSTORAGE_ACCESS = 7;
    WEBSOCKET_CONNECT = 8;
    SERVICE_WORKER_REGISTER = 9;
  }
  Browser browser = 1;
  Action action = 2;
  string url = 3;
  string title = 4;
  string referrer = 5;
  string download_path = 6;
  string download_hash = 7;
  string extension_id = 8;
  string extension_name = 9;
  bool is_incognito = 10;
}

message StartupEvent {
  enum Action {
    ACTION_UNSPECIFIED = 0;
    ADD = 1;
    REMOVE = 2;
    MODIFY = 3;
    ENABLE = 4;
    DISABLE = 5;
  }
  enum Location {
    LOCATION_UNSPECIFIED = 0;
    RUN_KEY = 1;
    RUN_ONCE_KEY = 2;
    SCHEDULED_TASK = 3;
    SERVICE = 4;
    STARTUP_FOLDER = 5;
    WINLOGON = 6;
    BROWSER_EXTENSION = 7;
    SYSTEMD = 8;
    LAUNCHD = 9;
    CRON = 10;
    RC_LOCAL = 11;
    PROFILE_SCRIPT = 12;  // .bashrc, .zshrc, etc.
  }
  Action action = 1;
  Location location = 2;
  string name = 3;
  string command = 4;
  string arguments = 5;
  string user = 6;
  bool is_signed = 7;
  string publisher = 8;
}

message GenericEvent {
  // For extensibility - plugins or future collectors
  string custom_type = 1;
  google.protobuf.Struct data = 2;
}
```

### 4.3 Field-by-Field Justification

| Field | Purpose | Why Required |
|-------|---------|--------------|
| `id` | Global unique identifier | Deduplication, correlation, audit trail |
| `type` | Structured event type | Routing, filtering, schema evolution |
| `source` | Collector origin | Attribution, trust scoring |
| `timestamp` | Event occurrence time | Timeline reconstruction, TTL |
| `ingest_timestamp` | Ingestion time | Latency monitoring, out-of-order detection |
| `severity` | Syslog-compatible severity | Alerting, prioritization, SIEM integration |
| `process` | Full process context | **Critical** - 90% of analysis is process-centric |
| `payload` | Typed event data | Type safety, schema validation, IDE support |
| `tags` | Fast filtering/indexing | Pre-computed MITRE, signed status, categories |
| `metadata` | Extensible structured data | Future-proofing, plugin data, ML features |
| `risk_score` | Rule engine output | Pre-computed for UI sorting, alerting |
| `correlation` | Causality + session + flow | **Core differentiator** - enables attack chain reconstruction |
| `host_id` | Pseudonymous host ID | Multi-device correlation (future) |
| `schema_version` | Forward compatibility | Safe rolling upgrades |

### 4.4 Correlation ID Generation Strategy

```rust
// Correlation IDs are ULIDs with embedded semantics
struct CorrelationId {
    // First 48 bits: timestamp (millisecond precision)
    // Next 16 bits: host shard (for multi-host future)
    // Last 80 bits: entropy + type hints
}

// Flow ID: tracks data/object flow
// Generated when: file created → process reads → network sends
// Same flow_id links: FileEvent(CREATE) → ProcessEvent(READ) → NetworkEvent(SEND)

// Causality: direct parent-child
// cause_event_id = immediate predecessor
// root_event_id = chain origin (e.g., initial phishing email download)
```

---

## 5. Collectors Architecture

### 5.1 Collector Framework (Shared Base)

All collectors implement a common trait for unified lifecycle management:

```rust
#[async_trait]
trait Collector: Send + Sync {
    fn id(&self) -> CollectorId;
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn event_types(&self) -> Vec<EventType>;
    fn required_capabilities(&self) -> CapabilitySet;
    fn config_schema(&self) -> ConfigSchema;
    
    async fn start(&mut self, ctx: CollectorContext) -> Result<(), CollectorError>;
    async fn stop(&mut self, graceful: bool) -> Result<(), CollectorError>;
    async fn health(&self) -> CollectorHealth;
    async fn reconfigure(&mut self, config: CollectorConfig) -> Result<(), CollectorError>;
}

struct CollectorContext {
    event_tx: mpsc::Sender<Arc<Event>>,
    backpressure_rx: watch::Receiver<BackpressureSignal>,
    config: Arc<dyn ConfigProvider>,
    os: Arc<dyn OsAbstraction>,
    metrics: CollectorMetrics,
}
```

### 5.2 Process Collector

**Platform APIs:**
- Windows: ETW (Microsoft-Windows-Kernel-Process), WMI, PsSetCreateProcessNotifyRoutineEx
- Linux: auditd (auditctl), netlink (CN_PROC), eBPF (tracepoint/sys_enter_execve)
- macOS: Endpoint Security Framework (ES_EVENT_TYPE_NOTIFY_EXEC)

**Events Produced:**
- `sentinel.process.create` (with full ancestry)
- `sentinel.process.terminate`
- `sentinel.process.open` (OpenProcess with suspicious access rights)
- `sentinel.process.inject` (WriteProcessMemory, CreateRemoteThread)
- `sentinel.process.hollow` (suspicious memory patterns)
- `sentinel.process.dump` (MiniDumpWriteDump, procdump)

**Configuration:**
```toml
[collectors.process]
enabled = true
sample_rate = 1.0                    # 1.0 = 100%
include_command_line = true
include_environment = false          # Privacy: may contain secrets
resolve_signatures = true            # Code signing verification
track_ancestry_depth = 10            # Process tree depth
monitor_injection = true             # Requires kernel callback / eBPF
monitor_hollowing = true             # Heuristic: memory anomalies
monitor_dumps = true                 # Detect credential dumping
exclude_paths = [
    "C:\\Windows\\System32\\*",      # Noise reduction
    "/usr/bin/*",
    "/bin/*"
]
```

**Performance:**
- Target: < 5% CPU at 1000 processes/sec
- Memory: < 50 MB baseline
- Backpressure: Drop DEBUG/INFO events first, never drop CRITICAL

### 5.3 Network Collector

**Platform APIs:**
- Windows: ETW (Microsoft-Windows-TCPIP, Microsoft-Windows-WFP), WFP Callouts
- Linux: eBPF (tc/sockops), netlink (NFLOG), auditd (socket calls)
- macOS: Endpoint Security (network), Network Extension (deprecated), pf

**Events Produced:**
- `sentinel.network.connect` (outbound)
- `sentinel.network.listen` (inbound server)
- `sentinel.network.dns_query` / `dns_response`
- `sentinel.network.http_request` / `http_response` (parsed from TCP)
- `sentinel.network.tls_handshake` (JA3/JA3S fingerprints)

**Configuration:**
```toml
[collectors.network]
enabled = true
sample_rate = 1.0
capture_dns = true
capture_http = true                  # Parse HTTP from TCP streams
capture_tls_fingerprints = true      # JA3/JA3S
capture_payloads = false             # Privacy: never capture bodies by default
max_payload_bytes = 0                # 0 = disabled
resolve_hostnames = true             # Reverse DNS for IPs
geoip_enabled = true                 # Local MaxMind DB
exclude_ports = [53, 67, 68, 123, 1900, 5353, 5355]  # Noise: DNS, DHCP, NTP, SSDP, LLMNR
exclude_local = true                 # RFC1918, link-local, localhost
tls_sni_extraction = true
http_host_extraction = true
```

**Privacy Controls:**
- **Never** capture HTTP bodies, cookies, auth headers
- **Only** metadata: method, URL (path+query), status, headers (content-type, user-agent)
- TLS: Only SNI, JA3, certificate metadata (issuer, subject, validity)
- Local GeoIP (no external lookups)

### 5.4 File Collector

**Platform APIs:**
- Windows: USN Journal (FSCTL_READ_USN_JOURNAL), FileSystemWatcher, Minifilter (kernel)
- Linux: fanotify (FAN_CLASS_CONTENT), inotify (fallback), eBPF (tracepoint/sys_enter_openat)
- macOS: FSEvents (user), Endpoint Security (kernel, ES_EVENT_TYPE_NOTIFY_CREATE/WRITE/RENAME/UNLINK)

**Events Produced:**
- `sentinel.file.create` / `modify` / `delete` / `rename` / `execute` / `map`
- `sentinel.file.attribute_change` / `permission_change`

**Configuration:**
```toml
[collectors.file]
enabled = true
sample_rate = 1.0
monitor_paths = [
    "C:\\Users\\*\\AppData\\*",
    "C:\\ProgramData\\*",
    "C:\\Temp\\*",
    "/home/*/.config/*",
    "/home/*/.local/*",
    "/tmp/*",
    "/var/tmp/*",
    "/Library/LaunchAgents/*",
    "/Library/LaunchDaemons/*"
]
exclude_paths = [
    "C:\\Windows\\*",
    "C:\\Program Files\\*",
    "/usr/*",
    "/bin/*",
    "/sbin/*",
    "/lib*",
    "/var/log/*",
    "*/node_modules/*",
    "*/.git/*",
    "*/target/*"
]
calculate_hashes = true              # SHA256 on create/modify/execute
calculate_entropy = true             # Shannon entropy for packed/encrypted detection
max_file_size_hash = 104857600       # 100 MB max for hashing
monitor_executable_only = false      # If true, only .exe/.dll/.so/.dylib
monitor_sensitive_paths = true       # SSH keys, AWS creds, browser databases
```

**Performance:**
- USN Journal / fanotify / FSEvents are kernel-buffered, near-zero overhead
- Hashing: Async thread pool, configurable concurrency
- Entropy: Streaming calculation, no full file load

### 5.5 Registry Collector (Windows Only)

**Platform APIs:**
- Windows: Registry Callback (CmRegisterCallbackEx), ETW (Microsoft-Windows-Kernel-Registry)

**Events Produced:**
- `sentinel.registry.create_key` / `delete_key` / `set_value` / `delete_value`

**Configuration:**
```toml
[collectors.registry]
enabled = true
sample_rate = 1.0
monitor_hives = ["HKLM", "HKCU"]
monitor_paths = [
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*",
    "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run*",
    "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*",
    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\*",
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon*",
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects*",
    "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU",
    "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\*"
]
exclude_paths = [
    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\*",
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\*"
]
capture_value_data = true
max_value_size = 8192                # Truncate large values
```

### 5.6 USB Collector

**Platform APIs:**
- Windows: WM_DEVICECHANGE, SetupAPI, WMI (Win32_USBControllerDevice)
- Linux: udev (libudev), udisks2
- macOS: IOKit (IOServiceMatching), DiskArbitration

**Events Produced:**
- `sentinel.usb.device_connect` / `device_disconnect`
- `sentinel.usb.mass_storage_mount` / `mass_storage_unmount`
- `sentinel.usb.hid_keyboard` / `hid_mouse` (keylogger detection)

**Configuration:**
```toml
[collectors.usb]
enabled = true
sample_rate = 1.0
monitor_hid = true                   # Detect malicious HID (Rubber Ducky)
monitor_mass_storage = true
scan_on_mount = true                 # Hash sample of files
scan_max_files = 100
scan_max_file_size = 10485760        # 10 MB
scan_extensions = [".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".jar", ".scr", ".lnk"]
notify_on_new_device = true
```

### 5.7 Browser Collector

**Approach:** Native messaging host + browser extension (optional) + SQLite database reading

**Platform APIs:**
- Chrome/Edge/Brave/Vivaldi: Native Messaging + SQLite (History, Cookies, Downloads)
- Firefox: Native Messaging + SQLite (places.sqlite, cookies.sqlite)
- Safari: Limited (macOS sandbox), use ScreenTime API or manual export

**Events Produced:**
- `sentinel.browser.navigation` (URL, title, referrer, incognito)
- `sentinel.browser.download_start` / `download_complete` (path, hash, URL)
- `sentinel.browser.extension_install` / `extension_remove`
- `sentinel.browser.websocket_connect`

**Configuration:**
```toml
[collectors.browser]
enabled = true
sample_rate = 1.0
browsers = ["chrome", "edge", "firefox", "brave"]
monitor_history = true
monitor_downloads = true
monitor_extensions = true
monitor_cookies = false              # Privacy: sensitive
monitor_localstorage = false         # Privacy: sensitive
download_hash_calculation = true
incognito_mode = "ignore"            # ignore | metadata_only | full
extension_allowlist = []             # Empty = monitor all
native_messaging_enabled = true      # Real-time via extension
poll_interval_seconds = 30           # Fallback polling interval
```

**Privacy:**
- **Never** capture: passwords, form data, cookie values, localStorage content
- **Only** metadata: domain, path, size, timestamps, hashes of downloaded files
- Native messaging host runs in user context, no elevated privileges

### 5.8 Startup Collector

**Platform APIs:**
- Windows: Registry (Run keys), Scheduled Tasks (Task Scheduler API), Services (WMI), Startup Folder, Winlogon
- Linux: systemd (user + system), cron (system + user), /etc/rc.local, ~/.profile, ~/.bashrc, XDG autostart
- macOS: launchd (LaunchAgents, LaunchDaemons), login items, cron, ~/.zprofile

**Events Produced:**
- `sentinel.startup.add` / `remove` / `modify` / `enable` / `disable`

**Configuration:**
```toml
[collectors.startup]
enabled = true
scan_interval_hours = 4              # Full rescan interval
monitor_registry_run_keys = true
monitor_scheduled_tasks = true
monitor_services = true
monitor_startup_folder = true
monitor_winlogon = true
monitor_systemd = true
monitor_cron = true
monitor_launchd = true
monitor_shell_profiles = true
monitor_browser_extensions = true
verify_signatures = true
alert_on_unsigned = true
```

### 5.9 Collector Independence Guarantees

Each collector:
1. **Owns its OS handles** - No shared handles between collectors
2. **Has dedicated thread pool** - CPU isolation via tokio runtime per collector (or shared with affinity)
3. **Independent config** - Hot-reload without affecting others
4. **Independent failure** - Crash/restart doesn't stop other collectors
5. **Own metrics namespace** - `collector_process_events_total`, `collector_network_latency_ms`, etc.
6. **Own backpressure handling** - Respects global signal but applies locally

---

## 6. Rule Engine Design

### 6.1 Design Decision: CEL (Common Expression Language)

**Choice:** Google CEL (via `cel-rust` or `cel-go` via FFI)

**Rationale:**

| Criteria | CEL | YAML DSL | Rust Closures | Sigma | Custom AST |
|----------|-----|----------|---------------|-------|------------|
| **Safety** | ✅ Sandboxed, no code exec | ✅ Data-only | ❌ Arbitrary code | ✅ Data-only | ⚠️ Implementation-dependent |
| **Performance** | ✅ Compiled to bytecode, ~1µs/eval | ❌ Interpreted | ✅ Native | ⚠️ Interpreted | ✅ Optimizable |
| **Expressiveness** | ✅ Full logic, macros, types | ⚠️ Limited | ✅ Unlimited | ⚠️ Limited | ✅ Custom |
| **Tooling** | ✅ IDE support, playground | ✅ Human-readable | ✅ Rust analyzer | ✅ Sigma tools | ❌ Custom |
| **Hot Reload** | ✅ Recompile in ms | ✅ Instant | ❌ Requires restart | ✅ Instant | ⚠️ Varies |
| **MITRE Mapping** | ✅ Native via functions | ⚠️ Manual | ✅ Native | ✅ Native | ✅ Native |
| **Learning Curve** | Low (C-like) | Very Low | High (Rust) | Medium | High |

**CEL Example:**
```cel
// Suspicious PowerShell with network + child process
event.type == "sentinel.process.create" &&
event.process.name == "powershell.exe" &&
event.process.command_line.matches("(?i)(-enc|-e |downloadstring|invoke-expression|iex|bypass)") &&
has(event.process.network) &&
event.process.network.connections.exists(c, c.direction == "OUTBOUND") &&
event.process.children.exists(c, c.name.matches("(?i)(cmd|powershell|wscript|cscript|mshta|rundll32|regsvr32)"))
```

### 6.2 Rule Schema (YAML + CEL)

```yaml
# rules/suspicious_powershell.yaml
rule:
  id: "rule-001-suspicious-powershell"
  version: 1
  name: "Suspicious PowerShell Execution"
  description: "Detects PowerShell with encoded commands, network activity, and child process spawning"
  author: "Sentinel Team"
  created: "2026-01-15"
  modified: "2026-07-10"

  # Enable/disable without deletion
  enabled: true

  # Rule category for organization and filtering
  category: "execution"
  subcategory: "scripting"

  # MITRE ATT&CK mapping (multiple allowed)
  mitre:
    - technique: "T1059.001"
      name: "PowerShell"
      tactic: "Execution"
    - technique: "T1105"
      name: "Ingress Tool Transfer"
      tactic: "Command and Control"
    - technique: "T1059.003"
      name: "Windows Command Shell"
      tactic: "Execution"

  # Severity if rule matches (before risk aggregation)
  severity: "HIGH"

  # Risk score contribution (0-100)
  # Final risk = base_score * confidence * context_multipliers
  risk:
    base_score: 75
    confidence: 0.85
    # Context multipliers (evaluated at match time)
    multipliers:
      - condition: "event.process.user.is_elevated == true"
        factor: 1.5
      - condition: "event.process.signing.is_trusted == false"
        factor: 1.3
      - condition: "event.network.remote_addr in threat_intel.malicious_ips"
        factor: 2.0

  # CEL expression - THE core logic
  condition: |
    event.type == "sentinel.process.create" &&
    event.process.name == "powershell.exe" &&
    (
      event.process.command_line.matches("(?i)(-enc|-e\\s|downloadstring|invoke-expression|iex|bypass|hidden|windowstyle\\s+hidden)") ||
      event.process.command_line.matches("(?i)(system\\.net\\.webclient|net\\.webclient|invoke-webrequest|iwr|curl|wget).*\\.(exe|dll|ps1|bat|cmd|scr)")
    )

  # Optional: Additional conditions that must ALL be true (AND)
  # Useful for splitting complex logic
  and_conditions: []
  
  # Optional: At least one must be true (OR)
  or_conditions: []

  # Optional: Must NOT be true (NOT)
  not_conditions:
    - "event.process.path.starts_with('C:\\\\Program Files\\\\')"
    - "event.process.signing.is_trusted == true && event.process.signing.publisher == 'Microsoft Corporation'"

  # Actions to take when rule matches
  actions:
    - type: "alert"
      config:
        title: "Suspicious PowerShell Activity"
        description: "PowerShell executing encoded/downloaded commands with network activity"
        dedup_window_seconds: 300
    - type: "enrich"
      config:
        add_tags: ["mitre:T1059.001", "mitre:T1105", "powershell", "encoded_command"]
        add_metadata:
          rule_id: "rule-001-suspicious-powershell"
          detection_type: "behavioral"
    - type: "correlate"
      config:
        correlation_type: "process_tree"
        window_seconds: 600
    - type: "snapshot"
      config:
        include: ["process_tree", "network_connections", "file_writes", "registry_changes"]
        max_events: 100

  # False positive suppression
  suppressions:
    - id: "suppress-001"
      condition: "event.process.command_line.contains('Microsoft.PowerShell.ConsoleHost')"
      reason: "Legitimate PowerShell host startup"
    - id: "suppress-002"
      condition: "event.process.parent.name == 'sqlservr.exe'"
      reason: "SQL Server Agent jobs"

  # Testing
  tests:
    - name: "Encoded command with download"
      event: "testdata/powershell_encoded_download.json"
      expected_match: true
    - name: "Legitimate signed script"
      event: "testdata/powershell_signed_microsoft.json"
      expected_match: false
```

### 6.3 Rule Engine Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      RULE ENGINE                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐  │
│  │  Rule       │    │  Compiler   │    │  Runtime            │  │
│  │  Loader     │───►│  (CEL)      │───►│  (Evaluator Pool)   │  │
│  │  (YAML)     │    │  - Parse    │    │  - Worker threads   │  │
│  │  - Watch    │    │  - Type chk │    │  - LRU cache        │  │
│  │  - Validate │    │  - Compile  │    │  - Metrics          │  │
│  └─────────────┘    └─────────────┘    └──────────┬──────────┘  │
│                                                    │             │
│                              ┌─────────────────────┼────────┐   │
│                              ▼                     ▼        ▼   │
│                    ┌────────────────┐    ┌──────────────┐ ┌──────┐ │
│                    │  Match         │    │  Action      │ │ Test │ │
│                    │  Dispatcher    │    │  Executor    │ │ Runner│ │
│                    │  - Priority    │    │  - Alert     │ └──────┘ │
│                    │  - Category    │    │  - Enrich    │          │
│                    │  - Suppression │    │  - Correlate │          │
│                    └────────────────┘    └──────────────┘          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 6.4 Rule Evaluation Pipeline

```rust
struct RuleEngine {
    rules: Arc<RwLock<RuleSet>>,
    compiler: CelCompiler,
    evaluator_pool: EvaluatorPool,
    action_executor: ActionExecutor,
    suppression_engine: SuppressionEngine,
    test_runner: TestRunner,
    metrics: RuleEngineMetrics,
}

impl RuleEngine {
    async fn evaluate(&self, event: &Event) -> EvaluationResult {
        let rules = self.rules.read().await;
        
        // Phase 1: Fast pre-filter (index by event type, source, tags)
        let candidate_rules = rules.filter_candidates(event);
        
        // Phase 2: Parallel CEL evaluation
        let matches = self.evaluator_pool.eval_batch(candidate_rules, event).await;
        
        // Phase 3: Suppression check
        let unsuppressed = self.suppression_engine.filter(matches, event).await;
        
        // Phase 4: Action execution (async, fire-and-forget with tracking)
        for match_result in &unsuppressed {
            self.action_executor.execute(match_result, event).await;
        }
        
        EvaluationResult {
            matches: unsuppressed,
            evaluation_time_ns: ...,
            rules_evaluated: candidate_rules.len(),
        }
    }
}
```

### 6.5 Priority and Conflict Resolution

| Priority | Value | Use Case |
|----------|-------|----------|
| CRITICAL | 1000 | Immediate threat (ransomware, credential theft) |
| HIGH | 800 | Strong indicators (exploitation, lateral movement) |
| MEDIUM | 500 | Suspicious behavior (recon, persistence) |
| LOW | 200 | Hygiene, policy violations |
| INFO | 100 | Telemetry, baseline |

**Conflict Resolution:**
1. Higher priority wins for alerting
2. All matches contribute to risk score (additive with diminishing returns)
3. Suppressions apply regardless of priority
4. Deduplication window per rule (configurable)

### 6.6 Hot Reload & Versioning

- File watcher on rules directory (notify crate)
- Atomic swap: compile new RuleSet → validate → test (optional) → Arc::swap
- Version tracking: each rule has `version`, engine tracks `ruleset_version`
- Rollback: keep last 5 RuleSets in memory

---

## 7. Risk Engine Design

### 7.1 Design Philosophy: SIEM-Grade, Not Simple Scoring

**Not:** `risk = sum(rule_scores)`

**Is:** Multi-dimensional risk model with:
- **Temporal decay** - Old events matter less
- **Context awareness** - User, host, time, threat intel
- **Attack chain awareness** - Correlation multiplies risk
- **Confidence weighting** - High-confidence rules weigh more
- **Asset criticality** - Critical processes/users increase impact
- **Threat intelligence** - External IOC matches boost risk

### 7.2 Risk Model Mathematics

```
Risk Score = f(Events, Context, Time, Correlation, Intel)

Base Risk = Σ (rule.base_score × rule.confidence × context_multipliers)

Temporal Decay = e^(-λ × age_hours)
  λ = ln(2) / half_life_hours
  half_life: CRITICAL=72h, HIGH=48h, MEDIUM=24h, LOW=12h

Correlation Multiplier = 1 + (chain_length - 1) × 0.15
  Max 2.5x for chains of 10+

Asset Criticality:
  - SYSTEM/root process: ×1.5
  - Domain admin: ×2.0
  - Critical service (AV, EDR, backup): ×1.3
  - Standard user: ×1.0

Threat Intel Boost:
  - Malicious IP: ×2.0
  - Known malware hash: ×3.0
  - C2 domain: ×2.5
  - Exploited CVE: ×2.0

Final Risk = min(1000, Base_Risk × Temporal_Decay × Correlation × Asset × Intel)

Alert Thresholds:
  - LOW: 100-299
  - MEDIUM: 300-599
  - HIGH: 600-899
  - CRITICAL: ≥900
```

### 7.3 Risk Engine Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                       RISK ENGINE                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────┐    ┌──────────────────┐    ┌───────────────┐  │
│  │  Event      │    │  Scoring         │    │  Aggregation  │  │
│  │  Ingestion  │───►│  Pipeline        │───►│  Engine       │  │
│  │  (from Bus) │    │  - Rule matches  │    │  - Per-host   │  │
│  └─────────────┘    │  - Context       │    │  - Per-user   │  │
│                     │  - Threat Intel  │    │  - Per-process│  │
│                     │  - Asset value   │    │  - Session    │  │
│                     └──────────────────┘    └───────┬───────┘  │
│                                                      │          │
│                     ┌──────────────────┐             │          │
│                     │  Temporal        │             │          │
│                     │  Decay Manager   │             │          │
│                     │  - Background    │             │          │
│                     │    job (1min)    │             │          │
│                     └──────────────────┘             │          │
│                                                      ▼          │
│                     ┌──────────────────────────────────────┐  │
│                     │  Alert Generator                     │  │
│                     │  - Threshold crossing                │  │
│                     │  - Escalation (sustained high risk)  │  │
│                     │  - Suppression (flapping)            │  │
│                     │  - Notification routing              │  │
│                     └──────────────────────────────────────┘  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 7.4 Risk State Persistence

```rust
// Risk aggregates stored in DuckDB for analytical queries
struct RiskAggregate {
    entity_type: EntityType,      // Host, User, Process, Session
    entity_id: String,            // host_id, user_sid, pid, session_id
    time_bucket: DateTime<Utc>,   // 1-hour buckets
    
    // Current scores
    current_risk: u32,            // 0-1000
    peak_risk_24h: u32,
    peak_risk_7d: u32,
    
    // Contributing factors
    rule_contributions: HashMap<RuleId, u32>,
    mitre_tactics: HashMap<String, u32>,
    threat_intel_hits: u32,
    
    // Event counts
    event_count: u64,
    alert_count: u32,
    
    // Trend
    risk_trend_1h: f32,           // -1.0 to +1.0
    risk_trend_24h: f32,
}

// Queries enabled:
// - Top 10 riskiest processes in last 24h
// - Risk trend for specific user over 7 days
// - MITRE tactic heatmap
// - Alert fatigue analysis (rules generating most alerts)
```

### 7.5 Alert Generation & Escalation

```rust
enum AlertState {
    New,
    Acknowledged,
    Investigating,
    ResolvedTruePositive,
    ResolvedFalsePositive,
    Suppressed,
}

struct Alert {
    id: AlertId,
    rule_id: RuleId,
    correlation_id: CorrelationId,
    risk_score: u32,
    severity: Severity,
    state: AlertState,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    acknowledged_by: Option<String>,
    acknowledged_at: Option<DateTime<Utc>>,
    events: Vec<EventId>,           // Contributing events
    context: AlertContext,          // Snapshot at alert time
    ai_summary: Option<String>,     // Generated on demand
}

impl AlertGenerator {
    fn check_thresholds(&self, aggregate: &RiskAggregate) -> Vec<Alert> {
        let mut alerts = Vec::new();
        
        // Threshold crossing (rising edge)
        if aggregate.current_risk >= 900 && aggregate.previous_risk < 900 {
            alerts.push(self.create_alert(aggregate, Severity::Critical));
        } else if aggregate.current_risk >= 600 && aggregate.previous_risk < 600 {
            alerts.push(self.create_alert(aggregate, Severity::High));
        }
        // ... medium, low
        
        // Sustained high risk (escalation)
        if aggregate.current_risk >= 600 && aggregate.duration_above_600 > Duration::hours(2) {
            alerts.push(self.create_escalation_alert(aggregate));
        }
        
        // Flapping suppression
        if self.is_flapping(aggregate) {
            self.suppress_alerts(aggregate);
        }
        
        alerts
    }
}
```

---

## 8. Event Correlation Engine

### 8.1 Correlation Types

| Type | Description | Window | Example |
|------|-------------|--------|---------|
| **Temporal** | Events close in time | 5 min - 1 hr | Process create → network connect |
| **Causal** | Direct parent-child relationship | Unlimited | Process A spawns B spawns C |
| **Flow** | Data/object flow tracking | Unlimited | File write → process read → network send |
| **Behavioral** | MITRE technique chaining | 1-24 hrs | Recon → Weaponization → Delivery → Exploitation |
| **Entity** | Same host/user/process across time | Days | Repeated failed logins → success → privilege escalation |

### 8.2 Correlation Graph Model

```rust
// In-memory correlation graph (persisted periodically)
struct CorrelationGraph {
    nodes: HashMap<EventId, CorrelationNode>,
    edges: HashMap<CorrelationId, Vec<CorrelationEdge>>,
    chains: HashMap<CorrelationId, AttackChain>,
}

struct CorrelationNode {
    event_id: EventId,
    event: Arc<Event>,
    correlations: Vec<CorrelationLink>,  // Links to other nodes
    chain_membership: Vec<CorrelationId>,
}

struct CorrelationEdge {
    from: EventId,
    to: EventId,
    edge_type: EdgeType,
    confidence: f32,          // 0.0 - 1.0
    evidence: Vec<String>,    // Why correlated
}

enum EdgeType {
    Causal,       // Direct cause (spawn, write→read)
    Temporal,     // Close in time, same process
    Flow,         // Data flow (file→net)
    Behavioral,   // MITRE chain
    Entity,       // Same entity
}

struct AttackChain {
    id: CorrelationId,
    mitre_tactics: Vec<MitreTactic>,
    techniques: Vec<MitreTechnique>,
    start_time: DateTime<Utc>,
    end_time: DateTime<Utc>,
    risk_score: u32,
    status: ChainStatus,
    nodes: Vec<EventId>,
}
```

### 8.3 Correlation Algorithms

#### 8.3.1 Causal Correlation (Process Tree)
```rust
fn correlate_causal(new_event: &Event, graph: &mut CorrelationGraph) {
    if let Some(parent_id) = new_event.correlation.cause_event_id {
        if let Some(parent_node) = graph.nodes.get(&parent_id) {
            // Direct causal link
            graph.add_edge(parent_id, new_event.id, EdgeType::Causal, 1.0, 
                vec!["direct_process_spawn".to_string()]);
            
            // Inherit chain membership
            for chain_id in &parent_node.chain_membership {
                graph.add_to_chain(chain_id, new_event.id);
            }
        }
    }
}
```

#### 8.3.2 Flow Correlation (Data Tracking)
```rust
fn correlate_flow(new_event: &Event, graph: &mut CorrelationGraph) {
    // Track file → process → network flows
    match &new_event.payload {
        FileEvent { action: CREATE | WRITE, path, sha256, .. } => {
            // Register file as data source
            graph.register_data_object(DataObject {
                id: format!("file:{}:{}", path, sha256),
                type: DataType::File,
                path: path.clone(),
                hash: sha256.clone(),
                created_by: new_event.id,
            });
        }
        ProcessEvent { action: READ | MAP, .. } if new_event.process.opened_files.contains(path) => {
            // Process read file - link them
            if let Some(obj) = graph.find_data_object(path, sha256) {
                graph.add_edge(obj.created_by, new_event.id, EdgeType::Flow, 0.9,
                    vec!["file_read".to_string()]);
                // Propagate flow_id
                new_event.correlation.flow_id = obj.flow_id;
            }
        }
        NetworkEvent { action: SEND, .. } if new_event.process.sent_data_hashes.contains(sha256) => {
            // Process sent file content
            if let Some(obj) = graph.find_data_object_by_hash(sha256) {
                graph.add_edge(obj.last_process_event, new_event.id, EdgeType::Flow, 0.85,
                    vec!["data_exfiltration_candidate".to_string()]);
            }
        }
        _ => {}
    }
}
```

#### 8.3.3 Behavioral Correlation (MITRE Chaining)
```rust
fn correlate_behavioral(new_event: &Event, graph: &mut CorrelationGraph) {
    let techniques = extract_mitre_techniques(new_event);
    
    for technique in techniques {
        // Find recent events with preceding tactics
        let preceding_tactics = tactic_precedes(technique.tactic);
        
        for prev_tactic in preceding_tactics {
            let candidates = graph.find_recent_events_by_tactic(
                prev_tactic, 
                new_event.correlation.session_id,
                Duration::hours(24)
            );
            
            for candidate in candidates {
                let confidence = calculate_chain_confidence(candidate, new_event);
                if confidence > 0.6 {
                    let chain_id = graph.get_or_create_chain(candidate, new_event);
                    graph.add_to_chain(chain_id, new_event.id);
                    graph.add_edge(candidate.id, new_event.id, EdgeType::Behavioral, confidence,
                        vec![format!("mitre_chain:{}->{}", candidate.tactic, technique.tactic)]);
                }
            }
        }
    }
}

fn tactic_precedes(tactic: MitreTactic) -> Vec<MitreTactic> {
    // MITRE ATT&CK tactic ordering
    match tactic {
        MitreTactic::Execution => vec![
            MitreTactic::InitialAccess,
            MitreTactic::Persistence,
            MitreTactic::PrivilegeEscalation,
            MitreTactic::DefenseEvasion,
            MitreTactic::CredentialAccess,
            MitreTactic::Discovery,
            MitreTactic::LateralMovement,
            MitreTactic::Collection,
        ],
        MitreTactic::Exfiltration => vec![
            MitreTactic::Collection,
            MitreTactic::CommandAndControl,
        ],
        MitreTactic::Impact => vec![
            MitreTactic::Execution,
            MitreTactic::LateralMovement,
            MitreTactic::CredentialAccess,
        ],
        _ => vec![],
    }
}
```

### 8.4 Attack Chain Detection & Alerting

```rust
struct ChainAnalyzer {
    min_chain_length: usize,        // 3
    min_risk_score: u32,            // 400
    max_chain_age: Duration,        // 24 hours
}

impl ChainAnalyzer {
    fn analyze_chains(&self, graph: &CorrelationGraph) -> Vec<DetectedChain> {
        let mut detected = Vec::new();
        
        for chain in graph.chains.values() {
            if chain.nodes.len() < self.min_chain_length {
                continue;
            }
            if chain.risk_score < self.min_risk_score {
                continue;
            }
            if Utc::now() - chain.end_time > self.max_chain_age {
                continue;
            }
            
            // Check for complete kill chain
            let tactics_covered: HashSet<_> = chain.mitre_tactics.iter().collect();
            let kill_chain_stages = [
                MitreTactic::InitialAccess,
                MitreTactic::Execution,
                MitreTactic::Persistence,
                MitreTactic::PrivilegeEscalation,
                MitreTactic::DefenseEvasion,
                MitreTactic::CredentialAccess,
                MitreTactic::Discovery,
                MitreTactic::LateralMovement,
                MitreTactic::Collection,
                MitreTactic::CommandAndControl,
                MitreTactic::Exfiltration,
                MitreTactic::Impact,
            ];
            
            let coverage = kill_chain_stages.iter()
                .filter(|t| tactics_covered.contains(t))
                .count() as f32 / kill_chain_stages.len() as f32;
            
            detected.push(DetectedChain {
                chain_id: chain.id,
                risk_score: chain.risk_score,
                tactics: chain.mitre_tactics.clone(),
                techniques: chain.techniques.clone(),
                coverage,
                event_count: chain.nodes.len(),
                duration: chain.end_time - chain.start_time,
                status: if coverage > 0.5 { ChainStatus::ActiveAttack } 
                        else { ChainStatus::SuspiciousChain },
            });
        }
        
        detected.sort_by(|a, b| b.risk_score.cmp(&a.risk_score));
        detected
    }
}
```

### 8.5 Example: PowerShell Attack Chain

```
Timeline:
────────────────────────────────────────────────────────────────────►

T+0s      [Process] powershell.exe -enc "JABjAGwAaQBlAG4AdAAgPQ..."
          │  MITRE: T1059.001 (Command & Scripting Interpreter: PowerShell)
          │  Tags: encoded_command, suspicious_parent
          ▼
T+2s      [Network] TCP 192.168.1.50:54321 → 203.0.113.42:443 (TLS)
          │  JA3: 771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-51-57-47-53-10,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0
          │  SNI: malicious-c2.example.com
          │  MITRE: T1071.001 (Application Layer Protocol: Web Protocols)
          ▼
T+5s      [File] Create C:\Users\Public\Documents\update.exe (SHA256: a1b2...)
          │  Entropy: 7.9 (packed)
          │  MITRE: T1105 (Ingress Tool Transfer)
          ▼
T+7s      [Process] C:\Users\Public\Documents\update.exe (PID 4521)
          │  Parent: powershell.exe (PID 1234)
          │  MITRE: T1059.001, T1204.002 (User Execution: Malicious File)
          ▼
T+10s     [Registry] HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Update
          │  Value: "C:\Users\Public\Documents\update.exe"
          │  MITRE: T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys)
          ▼
T+15s     [Network] TCP 192.168.1.50:54322 → 203.0.113.42:443
          │  HTTP POST /beacon (C2 heartbeat)
          │  MITRE: T1071.001, T1105 (Ingress Tool Transfer)
          ▼
T+30s     [Process] whoami.exe (child of update.exe)
          │  MITRE: T1033 (System Owner/User Discovery)
          ▼
T+45s     [Process] net.exe group "Domain Admins" /domain
          │  MITRE: T1069.002 (Permission Groups Discovery: Domain Groups)

Correlation Result:
────────────────────────────────────────────────────────────────────
Chain ID: corr_01h8j2k3m4n5p6q7r8s9t0
Tactics: [InitialAccess, Execution, Persistence, DefenseEvasion, 
          CommandAndControl, Discovery, CredentialAccess]
Techniques: [T1059.001, T1105, T1204.002, T1547.001, T1071.001, 
             T1033, T1069.002, T1003.001]
Risk Score: 940 (CRITICAL)
Coverage: 58% (7/12 kill chain stages)
Status: ActiveAttack
Events: 8 correlated events
Duration: 45 seconds
```

---

## 9. AI Assistant Architecture

### 9.1 Design Principles

| Principle | Implementation |
|-----------|----------------|
| **Local-First** | Ollama/llama.cpp on device, no external API calls by default |
| **Explain-Only** | AI never makes decisions, only explains/risk-assesses/recommends |
| **Context-Rich** | AI receives pre-processed, correlated, risk-scored context |
| **Privacy** | No raw events sent to AI; only anonymized summaries |
| **Deterministic** | Same context → same explanation (temperature=0) |
| **Auditable** | All AI interactions logged with prompt/response hashes |

### 9.2 AI Engine Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                        AI ENGINE                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────┐    ┌──────────────────┐    ┌───────────────┐  │
│  │  Trigger    │    │  Context         │    │  LLM          │  │
│  │  Manager    │───►│  Builder         │───►│  Client       │  │
│  │  - Alert    │    │  - Anonymize     │    │  - Ollama     │  │
│  │  - Chat     │    │  - Summarize     │    │  - llama.cpp  │  │
│  │  - Query    │    │  - Structure     │    │  - OpenAI*    │  │
│  └─────────────┘    └──────────────────┘    └───────┬───────┘  │
│                                                     │          │
│                              ┌──────────────────────┼────────┐ │
│                              ▼                      ▼        ▼ │
│                    ┌────────────────┐    ┌──────────────┐ ┌────┐ │
│                    │  Response      │    │  Cache       │ │Log │ │
│                    │  Processor     │    │  (semantic)  │ │    │ │
│                    │  - Validate    │    └──────────────┘ └────┘ │
│                    │  - Format      │                          │
│                    │  - Guardrails  │                          │
│                    └────────────────┘                          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 9.3 Context Building (Critical for Quality)

```rust
struct AiContext {
    // What triggered this request
    trigger: AiTrigger,
    
    // Anonymized event summary (NEVER raw events)
    event_summary: EventSummary,
    
    // Correlation chain if available
    attack_chain: Option<AttackChainSummary>,
    
    // Risk assessment
    risk_assessment: RiskAssessment,
    
    // MITRE mapping
    mitre_analysis: MitreAnalysis,
    
    // Historical context
    historical_patterns: Vec<HistoricalPattern>,
    
    // Host/user context (anonymized)
    entity_context: EntityContext,
}

struct EventSummary {
    total_events: u32,
    time_range: (DateTime<Utc>, DateTime<Utc>),
    by_severity: HashMap<Severity, u32>,
    by_type: HashMap<String, u32>,
    by_mitre_tactic: HashMap<String, u32>,
    top_processes: Vec<ProcessSummary>,
    top_network: Vec<NetworkSummary>,
    anomalies: Vec<AnomalySummary>,
}

struct ProcessSummary {
    name: String,
    pid: u32,
    command_line_hash: String,  // Hash, not actual command line
    event_count: u32,
    risk_contribution: u32,
    mitre_techniques: Vec<String>,
    is_signed: bool,
    publisher: Option<String>,  // Generic: "Microsoft", "Unknown", "Self-signed"
}

struct AttackChainSummary {
    chain_id: String,
    tactics: Vec<String>,
    techniques: Vec<String>,
    event_count: usize,
    duration_seconds: u64,
    risk_score: u32,
    narrative: String,  // Pre-built human-readable summary
}
```

### 9.4 Prompt Templates

#### 9.4.1 Alert Explanation
```markdown
# System Prompt: Alert Explanation

You are Sentinel AI, a security analyst assistant. Explain the following alert 
in clear, non-technical language for a home user. Be concise but thorough.

## Alert Context
- **Trigger**: {{trigger_type}} ({{rule_name}})
- **Risk Score**: {{risk_score}}/1000 ({{severity}})
- **Time**: {{timestamp}}
- **Host**: {{host_id}}

## What Happened (Anonymized Summary)
{{event_summary.narrative}}

## Attack Chain (if detected)
{{attack_chain.narrative}}

## MITRE ATT&CK Techniques Observed
{{#each mitre_techniques}}
- **{{technique_id}}**: {{technique_name}} ({{tactic}})
{{/each}}

## Risk Factors
{{#each risk_factors}}
- {{factor}}: {{description}} ({{weight}}x multiplier)
{{/each}}

## Your Task
Provide:
1. **Plain English Explanation** (2-3 sentences): What happened in user terms
2. **Risk Level**: Low/Medium/High/Critical with justification
3. **Immediate Actions** (numbered, max 3): What the user should do NOW
4. **Investigation Steps** (numbered, max 5): For advanced users/IT
5. **Prevention Recommendations** (numbered, max 3): Long-term hardening

## Constraints
- NO markdown unless asked
- NO technical jargon without explanation
- NEVER suggest disabling security features
- NEVER recommend registry edits without backup warning
- If uncertain, say "I cannot determine" rather than guessing
```

#### 9.4.2 Chat Mode (User Questions)
```markdown
# System Prompt: Security Chat

You are Sentinel AI, a local security assistant. Answer user questions about 
their system's security posture using the provided context.

## Available Context
- Current risk level: {{current_risk}}
- Active alerts: {{active_alerts_count}}
- Recent events (1h): {{recent_events_summary}}
- Top risks: {{top_risks}}
- Host info: {{host_summary}}

## User Question
{{user_question}}

## Guidelines
- Answer based ONLY on provided context
- If context insufficient, say "I don't have enough information about X"
- Never speculate about specific files/processes not in context
- Offer to show relevant events from dashboard
- Prioritize actionable advice
- Keep responses under 200 words unless detailed explanation requested
```

### 9.5 LLM Integration

```rust
#[async_trait]
trait LlmClient: Send + Sync {
    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse, LlmError>;
    async fn stream(&self, request: CompletionRequest) -> Result<StreamingResponse, LlmError>;
    fn model_info(&self) -> ModelInfo;
}

struct CompletionRequest {
    model: String,
    prompt: String,
    system_prompt: Option<String>,
    temperature: f32,           // 0.0 for deterministic
    max_tokens: u32,
    stop_sequences: Vec<String>,
    // For Ollama
    options: Option<OllamaOptions>,
}

struct OllamaOptions {
    num_ctx: u32,               // Context window (4096/8192/16384)
    num_gpu: i32,               // -1 = all, 0 = CPU only
    num_thread: u32,            // CPU threads
    repeat_penalty: f32,
    top_k: u32,
    top_p: f32,
}

// Implementations:
// - OllamaClient (HTTP to localhost:11434)
// - LlamaCppClient (direct library binding via FFI)
// - OpenAIClient (optional, user-configured, clearly marked)
```

### 9.6 Model Selection & Management

| Model | Size | Use Case | Hardware |
|-------|------|----------|----------|
| **llama-3.2-3b-instruct** | 2 GB | Default, fast explanations | 8 GB RAM |
| **llama-3.1-8b-instruct** | 4.7 GB | Better reasoning, chat | 16 GB RAM |
| **qwen2.5-7b-instruct** | 4.4 GB | Multilingual, structured output | 16 GB RAM |
| **nemotron-3-ultra** | ~40 GB | Maximum quality (future) | 64 GB RAM + GPU |

**Model Management:**
- Auto-detect Ollama/llama.cpp at startup
- Download models on first use (with progress UI)
- Cache management (LRU, max 2 models in VRAM)
- Fallback chain: preferred → smaller → CPU-only

### 9.7 Guardrails & Safety

```rust
struct ResponseGuardrails {
    // Validate AI response before showing to user
    fn validate(&self, response: &str, context: &AiContext) -> ValidationResult {
        let mut issues = Vec::new();
        
        // Check for dangerous recommendations
        for pattern in DANGEROUS_PATTERNS {
            if pattern.is_match(response) {
                issues.push(GuardrailIssue::DangerousRecommendation(pattern.to_string()));
            }
        }
        
        // Check for hallucinated specifics
        if mentions_specific_file(response) && !context_contains_file(context, extract_file(response)) {
            issues.push(GuardrailIssue::HallucinatedFile);
        }
        
        // Check for disabled security features
        if recommends_disable_security(response) {
            issues.push(GuardrailIssue::RecommendsDisableSecurity);
        }
        
        // Check length
        if response.len() > MAX_RESPONSE_CHARS {
            issues.push(GuardrailIssue::TooLong);
        }
        
        ValidationResult { issues, sanitized: self.sanitize(response) }
    }
}

const DANGEROUS_PATTERNS: &[&str] = &[
    r"(?i)disable\s+(antivirus|defender|firewall|edr|security)",
    r"(?i)delete\s+(system32|windows|registry)",
    r"(?i)reg\s+(delete|add).*HKLM\\SYSTEM",
    r"(?i)bcdedit\s+/set\s+.*(testsigning|nointegritychecks)",
    r"(?i)powershell\s+-ep\s+bypass",
    r"(?i)certutil\s+-decode",
];
```

---

## 10. API Specification

### 10.1 API Design Principles

| Principle | Implementation |
|-----------|----------------|
| **gRPC-First** | Primary API, Protocol Buffers, HTTP/2 |
| **REST Gateway** | grpc-gateway for HTTP/JSON compatibility |
| **Versioned** | Package versioning: `sentinel.v1`, `sentinel.v2` |
| **Streaming** | Server-side events for real-time updates |
| **Authenticated** | mTLS for local, token for remote (future) |
| **Rate Limited** | Token bucket per client |
| **Observability** | OpenTelemetry tracing on all endpoints |

### 10.2 Protobuf Service Definition

```protobuf
// sentinel/api/v1/sentinel.proto
syntax = "proto3";

package sentinel.api.v1;

import "google/protobuf/timestamp.proto";
import "google/protobuf/empty.proto";
import "sentinel/events/v1/event.proto";

option rust_module = "sentinel_api";

// ============================================================
// MAIN SERVICE
// ============================================================

service SentinelService {
  // Health & Info
  rpc GetHealth(HealthRequest) returns (HealthResponse);
  rpc GetVersion(VersionRequest) returns (VersionResponse);
  rpc GetStatus(StatusRequest) returns (StatusResponse);
  
  // Events
  rpc QueryEvents(QueryEventsRequest) returns (QueryEventsResponse);
  rpc StreamEvents(StreamEventsRequest) returns (stream Event);
  rpc GetEvent(GetEventRequest) returns (Event);
  rpc GetEventStats(EventStatsRequest) returns (EventStatsResponse);
  
  // Processes
  rpc ListProcesses(ListProcessesRequest) returns (ListProcessesResponse);
  rpc GetProcess(GetProcessRequest) returns (ProcessDetail);
  rpc GetProcessTree(GetProcessTreeRequest) returns (ProcessTree);
  
  // Network
  rpc ListConnections(ListConnectionsRequest) returns (ListConnectionsResponse);
  rpc GetConnectionStats(ConnectionStatsRequest) returns (ConnectionStatsResponse);
  
  // Alerts
  rpc ListAlerts(ListAlertsRequest) returns (ListAlertsResponse);
  rpc GetAlert(GetAlertRequest) returns (Alert);
  rpc UpdateAlertState(UpdateAlertStateRequest) returns (Alert);
  rpc StreamAlerts(StreamAlertsRequest) returns (stream Alert);
  
  // Rules
  rpc ListRules(ListRulesRequest) returns (ListRulesResponse);
  rpc GetRule(GetRuleRequest) returns (Rule);
  rpc CreateRule(CreateRuleRequest) returns (Rule);
  rpc UpdateRule(UpdateRuleRequest) returns (Rule);
  rpc DeleteRule(DeleteRuleRequest) returns (google.protobuf.Empty);
  rpc TestRule(TestRuleRequest) returns (TestRuleResponse);
  
  // Risk
  rpc GetRiskSummary(RiskSummaryRequest) returns (RiskSummaryResponse);
  rpc GetRiskTimeline(RiskTimelineRequest) returns (RiskTimelineResponse);
  rpc GetTopRisks(TopRisksRequest) returns (TopRisksResponse);
  
  // Correlation
  rpc GetAttackChains(AttackChainsRequest) returns (AttackChainsResponse);
  rpc GetChainDetail(ChainDetailRequest) returns (AttackChainDetail);
  
  // AI
  rpc ExplainAlert(ExplainAlertRequest) returns (ExplainAlertResponse);
  rpc Chat(ChatRequest) returns (ChatResponse);
  rpc StreamChat(ChatRequest) returns (stream ChatChunk);
  
  // Configuration
  rpc GetConfig(GetConfigRequest) returns (ConfigResponse);
  rpc UpdateConfig(UpdateConfigRequest) returns (ConfigResponse);
  rpc ValidateConfig(ValidateConfigRequest) returns (ValidateConfigResponse);
  
  // Plugins
  rpc ListPlugins(ListPluginsRequest) returns (ListPluginsResponse);
  rpc GetPlugin(GetPluginRequest) returns (PluginInfo);
  rpc InstallPlugin(InstallPluginRequest) returns (PluginInfo);
  rpc UninstallPlugin(UninstallPluginRequest) returns (google.protobuf.Empty);
  rpc ConfigurePlugin(ConfigurePluginRequest) returns (PluginConfig);
  
  // Collectors
  rpc ListCollectors(ListCollectorsRequest) returns (ListCollectorsResponse);
  rpc GetCollectorStatus(CollectorStatusRequest) returns (CollectorStatusResponse);
  rpc RestartCollector(RestartCollectorRequest) returns (CollectorStatusResponse);
}

// ============================================================
// MESSAGES
// ============================================================

// Health
message HealthRequest {}
message HealthResponse {
  enum Status { UNKNOWN = 0; HEALTHY = 1; DEGRADED = 2; UNHEALTHY = 3; }
  Status status = 1;
  map<string, ComponentHealth> components = 2;
  google.protobuf.Timestamp timestamp = 3;
}
message ComponentHealth {
  enum Status { UNKNOWN = 0; HEALTHY = 1; DEGRADED = 2; UNHEALTHY = 3; }
  Status status = 1;
  string message = 2;
  map<string, string> details = 3;
}

// Version
message VersionRequest {}
message VersionResponse {
  string version = 1;
  string git_commit = 2;
  string build_date = 3;
  string rust_version = 4;
  map<string, string> dependencies = 5;
}

// Status
message StatusRequest {}
message StatusResponse {
  SystemState state = 1;
  google.protobuf.Timestamp uptime = 2;
  ResourceUsage resources = 3;
  CollectorStatusMap collectors = 4;
  RuleEngineStatus rules = 5;
  AiEngineStatus ai = 6;
}

// Events
message QueryEventsRequest {
  EventQuery query = 1;
  int32 limit = 2;
  int32 offset = 3;
  string sort_by = 4;      // "timestamp", "risk_score", "severity"
  bool sort_desc = 5;
}
message EventQuery {
  google.protobuf.Timestamp start_time = 1;
  google.protobuf.Timestamp end_time = 2;
  repeated string event_types = 3;
  repeated string sources = 4;
  repeated Severity severities = 5;
  repeated string process_names = 6;
  repeated uint32 pids = 7;
  repeated string hosts = 8;
  string correlation_id = 9;
  string flow_id = 10;
  uint32 min_risk_score = 11;
  repeated string tags = 12;
  string free_text = 13;   // Search in command_line, paths, etc.
}
message QueryEventsResponse {
  repeated Event events = 1;
  int64 total_count = 2;
  bool has_more = 3;
}
message StreamEventsRequest {
  EventQuery query = 1;
  bool include_historical = 2;  // If true, send matching historical first
}
message GetEventRequest {
  string event_id = 1;
}
message EventStatsRequest {
  google.protobuf.Timestamp start_time = 1;
  google.protobuf.Timestamp end_time = 2;
  string group_by = 3;  // "hour", "day", "type", "source", "severity"
}
message EventStatsResponse {
  map<string, int64> counts = 1;
  map<string, double> avg_risk = 2;
}

// Processes
message ListProcessesRequest {
  bool include_terminated = 1;
  google.protobuf.Timestamp since = 2;
  string filter = 3;
  int32 limit = 4;
}
message ListProcessesResponse {
  repeated ProcessSummary processes = 1;
}
message ProcessSummary {
  uint32 pid = 1;
  string name = 2;
  string path = 3;
  string command_line = 4;
  uint32 ppid = 5;
  google.protobuf.Timestamp start_time = 6;
  google.protobuf.Timestamp end_time = 7;
  UserContext user = 8;
  uint32 event_count = 9;
  uint32 risk_score = 10;
  repeated string mitre_techniques = 11;
  bool is_signed = 12;
  string publisher = 13;
}
message GetProcessRequest {
  uint32 pid = 1;
  google.protobuf.Timestamp at_time = 2;  // Point-in-time query
}
message ProcessDetail {
  ProcessSummary summary = 1;
  repeated Event events = 2;
  repeated NetworkConnection connections = 3;
  repeated FileActivity files = 4;
  repeated RegistryActivity registry = 5;
  ProcessTree tree = 6;
}
message GetProcessTreeRequest {
  uint32 root_pid = 1;
  int32 max_depth = 2;
}
message ProcessTree {
  ProcessTreeNode root = 1;
}
message ProcessTreeNode {
  ProcessSummary process = 1;
  repeated ProcessTreeNode children = 2;
}

// Network
message ListConnectionsRequest {
  bool active_only = 1;
  google.protobuf.Timestamp since = 2;
  string filter = 3;
}
message ListConnectionsResponse {
  repeated NetworkConnection connections = 1;
}
message NetworkConnection {
  string id = 1;
  uint32 pid = 2;
  string process_name = 3;
  NetworkEvent.Direction direction = 4;
  NetworkEvent.Protocol protocol = 5;
  string local_addr = 6;
  uint32 local_port = 7;
  string remote_addr = 8;
  uint32 remote_port = 9;
  google.protobuf.Timestamp start_time = 10;
  google.protobuf.Timestamp end_time = 11;
  uint64 bytes_sent = 12;
  uint64 bytes_received = 13;
  string hostname = 14;
  string ja3 = 15;
  string geoip_country = 16;
}
message ConnectionStatsRequest {}
message ConnectionStatsResponse {
  int64 total_connections = 1;
  int64 active_connections = 2;
  map<string, int64> by_protocol = 3;
  map<string, int64> by_country = 4;
  map<string, int64> by_process = 5;
  repeated TopTalker top_talkers = 6;
}
message TopTalker {
  string remote_addr = 1;
  string hostname = 2;
  int64 connection_count = 3;
  uint64 total_bytes = 4;
  string country = 5;
}

// Alerts
message ListAlertsRequest {
  AlertState state = 1;
  Severity min_severity = 2;
  google.protobuf.Timestamp start_time = 3;
  google.protobuf.Timestamp end_time = 4;
  int32 limit = 5;
  int32 offset = 6;
}
message ListAlertsResponse {
  repeated Alert alerts = 1;
  int64 total_count = 2;
}
message GetAlertRequest {
  string alert_id = 1;
}
message UpdateAlertStateRequest {
  string alert_id = 1;
  AlertState new_state = 2;
  string comment = 3;
}
message StreamAlertsRequest {}

// Rules
message ListRulesRequest {
  bool enabled_only = 1;
  string category = 2;
}
message ListRulesResponse {
  repeated Rule rules = 1;
}
message Rule {
  string id = 1;
  uint32 version = 2;
  string name = 3;
  string description = 4;
  string author = 5;
  google.protobuf.Timestamp created = 6;
  google.protobuf.Timestamp modified = 7;
  bool enabled = 8;
  string category = 9;
  string subcategory = 10;
  repeated MitreMapping mitre = 11;
  Severity severity = 12;
  RiskConfig risk = 13;
  string condition = 14;  // CEL expression
  repeated string and_conditions = 15;
  repeated string or_conditions = 16;
  repeated string not_conditions = 17;
  repeated RuleAction actions = 18;
  repeated SuppressionRule suppressions = 19;
}
message MitreMapping {
  string technique = 1;
  string name = 2;
  string tactic = 3;
}
message RiskConfig {
  uint32 base_score = 1;
  double confidence = 2;
  repeated RiskMultiplier multipliers = 3;
}
message RiskMultiplier {
  string condition = 1;
  double factor = 2;
}
message RuleAction {
  enum Type { TYPE_UNSPECIFIED = 0; ALERT = 1; ENRICH = 2; CORRELATE = 3; SNAPSHOT = 4; }
  Type type = 1;
  google.protobuf.Struct config = 2;
}
message SuppressionRule {
  string id = 1;
  string condition = 2;
  string reason = 3;
}
message CreateRuleRequest {
  Rule rule = 1;
}
message UpdateRuleRequest {
  string id = 1;
  Rule rule = 2;
}
message DeleteRuleRequest {
  string id = 1;
}
message TestRuleRequest {
  Rule rule = 1;
  repeated Event test_events = 2;
}
message TestRuleResponse {
  repeated TestResult results = 1;
  bool all_passed = 2;
}
message TestResult {
  string event_id = 1;
  bool matched = 2;
  bool expected_match = 3;
  string error = 4;
}

// Risk
message RiskSummaryRequest {}
message RiskSummaryResponse {
  uint32 current_risk = 1;
  uint32 peak_24h = 2;
  uint32 peak_7d = 3;
  RiskTrend trend_1h = 4;
  RiskTrend trend_24h = 5;
  map<string, uint32> by_category = 6;
  map<string, uint32> by_tactic = 7;
  int32 active_alerts = 8;
}
message RiskTimelineRequest {
  google.protobuf.Timestamp start_time = 1;
  google.protobuf.Timestamp end_time = 2;
  string granularity = 3;  // "1m", "5m", "1h", "1d"
}
message RiskTimelineResponse {
  repeated RiskPoint timeline = 1;
}
message RiskPoint {
  google.protobuf.Timestamp timestamp = 1;
  uint32 risk_score = 2;
  uint32 event_count = 3;
  uint32 alert_count = 4;
}
message TopRisksRequest {
  string entity_type = 1;  // "process", "user", "host", "session"
  int32 limit = 2;
  google.protobuf.Timestamp since = 3;
}
message TopRisksResponse {
  repeated RiskEntity top_risks = 1;
}
message RiskEntity {
  string entity_type = 1;
  string entity_id = 2;
  string display_name = 3;
  uint32 risk_score = 4;
  repeated string top_rules = 5;
  repeated string mitre_tactics = 6;
}

// Correlation
message AttackChainsRequest {
  google.protobuf.Timestamp start_time = 1;
  google.protobuf.Timestamp end_time = 2;
  ChainStatus status = 3;
  int32 min_risk = 4;
  int32 limit = 5;
}
message AttackChainsResponse {
  repeated AttackChainSummary chains = 1;
}
message AttackChainSummary {
  string id = 1;
  google.protobuf.Timestamp start_time = 2;
  google.protobuf.Timestamp end_time = 3;
  uint32 risk_score = 4;
  repeated string tactics = 5;
  repeated string techniques = 6;
  int32 event_count = 7;
  ChainStatus status = 8;
  double kill_chain_coverage = 9;
}
message ChainDetailRequest {
  string chain_id = 1;
}
message AttackChainDetail {
  AttackChainSummary summary = 1;
  repeated ChainEvent events = 2;
  repeated ChainEdge edges = 3;
  string ai_narrative = 4;
}
message ChainEvent {
  string event_id = 1;
  google.protobuf.Timestamp timestamp = 2;
  string event_type = 3;
  string summary = 4;
  repeated string mitre_techniques = 5;
  uint32 risk_contribution = 6;
}
message ChainEdge {
  string from_event = 1;
  string to_event = 2;
  string edge_type = 3;
  double confidence = 4;
  string evidence = 5;
}

// AI
message ExplainAlertRequest {
  string alert_id = 1;
  bool include_recommendations = 2;
  bool include_investigation_steps = 3;
}
message ExplainAlertResponse {
  string explanation = 1;
  string risk_level = 2;  // "Low", "Medium", "High", "Critical"
  repeated string immediate_actions = 3;
  repeated string investigation_steps = 4;
  repeated string prevention_recommendations = 5;
  google.protobuf.Timestamp generated_at = 6;
  string model_used = 7;
}
message ChatRequest {
  string message = 1;
  string conversation_id = 2;  // For context continuity
  bool stream = 3;
}
message ChatResponse {
  string response = 1;
  string conversation_id = 2;
  google.protobuf.Timestamp timestamp = 3;
}
message ChatChunk {
  string delta = 1;
  bool done = 2;
  string conversation_id = 3;
}

// Configuration
message GetConfigRequest {
  string section = 1;  // Empty = all
}
message ConfigResponse {
  string config_toml = 1;  // Full TOML as string
  uint64 version = 2;
}
message UpdateConfigRequest {
  string config_toml = 1;  // Partial or full
  bool validate_only = 2;
}
message ValidateConfigResponse {
  bool valid = 1;
  repeated ConfigError errors = 2;
  repeated ConfigWarning warnings = 3;
}
message ConfigError {
  string path = 1;
  string message = 2;
}
message ConfigWarning {
  string path = 1;
  string message = 2;
}

// Plugins
message ListPluginsRequest {}
message ListPluginsResponse {
  repeated PluginInfo plugins = 1;
}
message PluginInfo {
  string id = 1;
  string name = 2;
  string version = 3;
  string author = 4;
  string description = 5;
  PluginState state = 6;
  repeated string capabilities = 7;
  PluginConfigSchema config_schema = 8;
  google.protobuf.Timestamp installed_at = 9;
}
enum PluginState {
  PLUGIN_STATE_UNSPECIFIED = 0;
  INSTALLED = 1;
  LOADED = 2;
  RUNNING = 3;
  ERROR = 4;
  DISABLED = 5;
}
message GetPluginRequest {
  string plugin_id = 1;
}
message InstallPluginRequest {
  string source = 1;  // URL or local path
  string checksum = 2;  // SHA256
}
message UninstallPluginRequest {
  string plugin_id = 1;
}
message ConfigurePluginRequest {
  string plugin_id = 1;
  google.protobuf.Struct config = 2;
}
message PluginConfig {
  google.protobuf.Struct config = 1;
}
message PluginConfigSchema {
  google.protobuf.Struct json_schema = 1;
}

// Collectors
message ListCollectorsRequest {}
message ListCollectorsResponse {
  repeated CollectorInfo collectors = 1;
}
message CollectorInfo {
  string id = 1;
  string name = 2;
  string description = 3;
  bool enabled = 4;
  CollectorState state = 5;
  CollectorStats stats = 6;
  google.protobuf.Timestamp last_event = 7;
}
enum CollectorState {
  COLLECTOR_STATE_UNSPECIFIED = 0;
  STOPPED = 1;
  STARTING = 2;
  RUNNING = 3;
  DEGRADED = 4;
  ERROR = 5;
}
message CollectorStats {
  uint64 events_produced = 1;
  uint64 events_dropped = 2;
  uint64 errors = 3;
  double avg_latency_ms = 4;
  double cpu_percent = 5;
  uint64 memory_bytes = 6;
}
message CollectorStatusRequest {
  string collector_id = 1;
}
message CollectorStatusResponse {
  CollectorInfo info = 1;
  google.protobuf.Struct detailed_stats = 2;
}
message RestartCollectorRequest {
  string collector_id = 1;
}
```

### 10.3 Error Handling

```protobuf
// Standard error format (google.rpc.Status compatible)
message ApiError {
  int32 code = 1;           // gRPC status code
  string message = 2;       // Human-readable
  string details = 3;       // Machine-readable (JSON)
  repeated ErrorDetail error_details = 4;
}

message ErrorDetail {
  string type = 1;          // e.g., "ValidationError", "NotFound"
  google.protobuf.Struct payload = 2;
}

// Common error codes
enum ErrorCode {
  OK = 0;
  INVALID_ARGUMENT = 3;
  NOT_FOUND = 5;
  ALREADY_EXISTS = 6;
  PERMISSION_DENIED = 7;
  FAILED_PRECONDITION = 9;
  INTERNAL = 13;
  UNAVAILABLE = 14;
  DATA_LOSS = 15;
}
```

### 10.4 Versioning Strategy

| Version | Package | Compatibility |
|---------|---------|---------------|
| v1 | `sentinel.api.v1` | Stable, long-term support |
| v2 | `sentinel.api.v2` | Breaking changes, parallel run |
| v1alpha | `sentinel.api.v1alpha` | Experimental, no guarantees |

**Rules:**
- Additive changes only in same version (new fields, new methods)
- Breaking changes → new package version
- Deprecation period: 2 minor versions
- gRPC reflection enabled for discovery

---

## 11. Plugin System Architecture

### 11.1 Design Goals

| Goal | Implementation |
|------|----------------|
| **Isolation** | Plugins run in separate processes (not in-proc) |
| **Sandboxing** | Capability-based permissions, no direct OS access |
| **Hot Reload** | Install/update/remove without core restart |
| **Language Agnostic** | gRPC/JSON-RPC over stdin/stdout or Unix socket |
| **Security** | Signed plugins, checksum verification, permission manifest |
| **Observability** | Metrics, logs, traces integrated with core |

### 11.2 Plugin Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      PLUGIN SYSTEM                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────────────────────────────┐  │
│  │  Plugin      │    │         Plugin Registry              │  │
│  │  Manager     │───►│  - Metadata (name, version, caps)    │  │
│  │  (Core)      │    │  - Manifest (permissions, config)    │  │
│  └──────┬───────┘    │  - State (installed, loaded, error)  │  │
│         │            └──────────────────────────────────────┘  │
│         │                           │                            │
│         ▼                           ▼                            │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                 Plugin Runtime                          │    │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐        │    │
│  │  │  Process    │ │  Process    │ │  Process    │  ...   │    │
│  │  │  (Plugin A) │ │  (Plugin B) │ │  (Plugin C) │        │    │
│  │  │  gRPC/JSON  │ │  gRPC/JSON  │ │  gRPC/JSON  │        │    │
│  │  └──────┬──────┘ └──────┬──────┘ └──────┬──────┘        │    │
│  │         │               │               │                 │    │
│  │         └───────────────┼───────────────┘                 │    │
│  │                         ▼                                 │    │
│  │  ┌─────────────────────────────────────────────────┐      │    │
│  │  │           Plugin Host SDK (Rust/Go/Node/Python)  │      │    │
│  │  │  - gRPC client to Core                          │      │    │
│  │  │  - Capability enforcement                       │      │    │
│  │  │  - Config management                            │      │    │
│  │  │  - Logging/metrics forwarding                   │      │    │
│  │  └─────────────────────────────────────────────────┘      │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 11.3 Plugin Manifest

```yaml
# plugin.yaml (bundled with plugin)
plugin:
  id: "virustotal"
  name: "VirusTotal Integration"
  version: "1.2.0"
  author: "Sentinel Team"
  description: "Submit file hashes and URLs to VirusTotal for reputation checking"
  homepage: "https://github.com/sentinel-ai/plugins/virustotal"
  license: "MIT"
  
  # Minimum core version required
  min_core_version: "0.5.0"
  
  # Capabilities required (enforced by core)
  capabilities:
    - "event:read"              # Read events from bus
    - "event:write"             # Write enriched events
    - "config:read"             # Read plugin config
    - "config:write"            # Write plugin config
    - "network:http"            # Make HTTP requests
    - "secret:read"             # Read API keys from secret store
    - "ai:query"                # Query AI engine (optional)
  
  # Configuration schema (JSON Schema)
  config_schema:
    type: "object"
    properties:
      api_key:
        type: "string"
        description: "VirusTotal API key"
        format: "password"
      auto_submit:
        type: "boolean"
        default: false
        description: "Automatically submit new file hashes"
      submit_on_risk:
        type: "integer"
        minimum: 0
        maximum: 1000
        default: 500
        description: "Minimum risk score to auto-submit"
      rate_limit:
        type: "integer"
        default: 4
        description: "Requests per minute (free tier: 4)"
    required: ["api_key"]
  
  # Event subscriptions (what events plugin wants)
  subscriptions:
    - event_type: "sentinel.file.create"
      filter: "event.payload.file_event.is_executable == true"
    - event_type: "sentinel.network.connect"
      filter: "event.payload.network_event.direction == 'OUTBOUND'"
  
  # UI integration
  ui:
    dashboard_widget: true
    settings_page: true
    alert_actions: ["submit_to_virustotal", "view_report"]
```

### 11.4 Plugin Protocol (gRPC)

```protobuf
// sentinel/plugin/v1/plugin.proto
syntax = "proto3";

package sentinel.plugin.v1;

import "sentinel/events/v1/event.proto";
import "google/protobuf/empty.proto";
import "google/protobuf/struct.proto";

service Plugin {
  // Lifecycle
  rpc Initialize(InitializeRequest) returns (InitializeResponse);
  rpc Start(StartRequest) returns (StartResponse);
  rpc Stop(StopRequest) returns (StopResponse);
  rpc HealthCheck(HealthCheckRequest) returns (HealthCheckResponse);
  
  // Configuration
  rpc Configure(ConfigureRequest) returns (ConfigureResponse);
  rpc GetConfig(GetConfigRequest) returns (GetConfigResponse);
  
  // Event processing
  rpc ProcessEvent(ProcessEventRequest) returns (ProcessEventResponse);
  rpc ProcessEventBatch(ProcessEventBatchRequest) returns (ProcessEventBatchResponse);
  
  // Actions (triggered from UI/alerts)
  rpc ExecuteAction(ExecuteActionRequest) returns (ExecuteActionResponse);
  
  // Metrics
  rpc GetMetrics(GetMetricsRequest) returns (GetMetricsResponse);
}

// Capability-based: plugin declares what it needs
message InitializeRequest {
  string plugin_id = 1;
  map<string, string> core_info = 2;  // version, host_id, etc.
  repeated string granted_capabilities = 3;
}
message InitializeResponse {
  bool success = 1;
  string error = 2;
  PluginManifest manifest = 3;
}

// Event processing with context
message ProcessEventRequest {
  sentinel.events.v1.Event event = 1;
  PluginContext context = 2;
}
message PluginContext {
  map<string, string> config = 1;
  repeated string secrets = 2;  // Decrypted secret names
  map<string, string> host_info = 3;
}

// Action execution (e.g., "Submit to VirusTotal")
message ExecuteActionRequest {
  string action_id = 1;
  google.protobuf.Struct parameters = 2;
  sentinel.events.v1.Event triggering_event = 3;
}
message ExecuteActionResponse {
  bool success = 1;
  string result = 2;
  google.protobuf.Struct data = 3;
}
```

### 11.5 Built-in Plugin Examples

#### 11.5.1 VirusTotal
```rust
// Capabilities: event:read, network:http, secret:read
// Subscriptions: file.create (executable), network.connect (outbound)
// Actions: submit_hash, submit_url, view_report
// Config: api_key, auto_submit, rate_limit
```

#### 11.5.2 Discord/Telegram/Slack/Email Notifications
```rust
// Capabilities: event:read, network:http (or native libs)
// Subscriptions: alert.created (filtered by severity)
// Actions: test_notification
// Config: webhook_url / bot_token / chat_id / smtp_config
// Template: Jinja2/Handlebars for message formatting
```

#### 11.5.3 AbuseIPDB / Shodan / Hybrid Analysis
```rust
// Capabilities: event:read, network:http, secret:read
// Subscriptions: network.connect (outbound, risk > threshold)
// Actions: check_ip, check_hash, submit_sample
// Enrichment: Adds tags/metadata to events
```

#### 11.5.4 Home Assistant
```rust
// Capabilities: event:read, network:http, secret:read
// Subscriptions: alert.created (critical)
// Actions: trigger_automation, set_state
// Config: ha_url, long_lived_token
// Entity mapping: alert → binary_sensor, risk → sensor
```

### 11.6 Plugin Security Model

| Layer | Protection |
|-------|------------|
| **Distribution** | Signed packages (cosign/sigstore), checksum verification |
| **Installation** | User consent, capability review UI, sandbox profile selection |
| **Runtime** | Separate process, seccomp (Linux), sandbox (macOS), AppContainer (Windows) |
| **Communication** | gRPC over Unix socket/localhost, mTLS, capability tokens |
| **Secrets** | Core-managed secret store (encrypted at rest), plugin requests by name |
| **Network** | Core proxies HTTP requests (audit, rate limit, allowlist) |
| **File System** | No direct access; core provides `read_file(path)` / `write_file(path)` with allowlist |
| **Observability** | All plugin actions logged, metrics exported, traces correlated |

---

## 12. Configuration Management

### 12.1 Configuration Philosophy

| Principle | Implementation |
|-----------|----------------|
| **Single Source** | All config in TOML files, no env vars for structure |
| **Layered** | Default → System → User → Local overrides |
| **Validated** | Schema validation on load, hot-reload with validation |
| **Documented** | Every field has description, type, default, example |
| **Versioned** | Config version in file, migration on upgrade |
| **Secrets** | Separate `secrets.toml` (encrypted), never in main config |

### 12.2 Configuration Files

```
/etc/sentinel/                    # System-wide (root)
├── config.toml                   # Main configuration
├── secrets.toml                  # Encrypted secrets (age/sops)
├── rules/                        # Rule files (*.yaml)
│   ├── builtin/                  # Shipped rules (read-only)
│   └── custom/                   # User rules
├── plugins/                      # Plugin configs
│   ├── virustotal.yaml
│   └── discord.yaml
└── collectors.d/                 # Collector overrides
    ├── process.toml
    └── network.toml

~/.config/sentinel/               # User-specific (per-user service)
├── config.toml
├── secrets.toml
└── rules/custom/

./sentinel-local/                 # Project-local (dev override)
└── config.toml
```

### 12.3 Main Configuration (config.toml)

```toml
# sentinel/config.toml
# Sentinel AI Configuration
# Version: 1
# All durations in seconds unless specified

[core]
# Service identity
host_id = ""                    # Auto-generated on first run
instance_name = "Sentinel AI"   # Display name

# Lifecycle
graceful_shutdown_timeout = 30  # Seconds to wait for flush
health_check_interval = 10      # Seconds
metrics_enabled = true
metrics_port = 9090             # Prometheus /metrics

# Resource limits
max_memory_mb = 512             # Soft limit (triggers GC/backpressure)
max_cpu_percent = 25            # Soft limit (triggers throttling)
event_buffer_size = 10000       # In-memory event buffer

# Feature flags
features = [
    "ai_engine",                # Enable AI explanations
    "correlation_engine",       # Enable attack chain detection
    "plugin_system",            # Enable plugin manager
    "grpc_api",                 # Enable gRPC server
    "rest_gateway",             # Enable REST proxy
]

[grpc]
enabled = true
address = "127.0.0.1:7777"
tls_enabled = false             # Local only, use mTLS for remote
max_message_size_mb = 16
max_concurrent_streams = 100

[rest_gateway]
enabled = true
address = "127.0.0.1:7778"
cors_origins = ["http://localhost:3000", "tauri://localhost"]

[storage]
# SQLite for config, metadata, alerts
sqlite_path = "data/sentinel.db"
sqlite_wal_mode = true
sqlite_busy_timeout_ms = 5000

# DuckDB for analytical queries
duckdb_path = "data/events.duckdb"
duckdb_memory_limit_mb = 256
duckdb_threads = 2

# Retention policies
retention = [
    { event_type = "sentinel.process.*", max_age_days = 30, max_count = 1000000 },
    { event_type = "sentinel.network.*", max_age_days = 14, max_count = 500000 },
    { event_type = "sentinel.file.*", max_age_days = 30, max_count = 200000 },
    { event_type = "sentinel.registry.*", max_age_days = 90, max_count = 100000 },
    { event_type = "sentinel.usb.*", max_age_days = 90, max_count = 10000 },
    { event_type = "sentinel.browser.*", max_age_days = 7, max_count = 50000 },
    { event_type = "sentinel.startup.*", max_age_days = 180, max_count = 5000 },
    { event_type = "*", max_age_days = 7, max_count = 100000 },  # Catch-all
]

# Aggregation tables (pre-computed for dashboards)
aggregations = [
    { name = "hourly_risk", interval = "1h", retention_days = 90 },
    { name = "daily_mitre", interval = "1d", retention_days = 365 },
    { name = "process_behavior", interval = "1h", retention_days = 30 },
]

[event_bus]
# Channel capacities
ingest_channel_size = 10000
broadcast_channel_size = 1000
storage_channel_size = 5000
plugin_channel_size = 2000
ipc_channel_size = 500

# Backpressure thresholds (percent of capacity)
backpressure = { elevated = 50, high = 75, critical = 90 }

[rule_engine]
rules_directories = [
    "/etc/sentinel/rules/builtin",
    "/etc/sentinel/rules/custom",
    "~/.config/sentinel/rules/custom",
]
hot_reload = true
validation_on_load = true
max_rules = 10000
evaluation_timeout_ms = 50
worker_threads = 4

# Default risk multipliers (can be overridden per rule)
default_multipliers = [
    { condition = "event.process.user.is_elevated", factor = 1.5 },
    { condition = "event.process.signing.is_trusted == false", factor = 1.3 },
    { condition = "event.network.geoip.country in ['CN', 'RU', 'KP', 'IR']", factor = 1.2 },
]

[risk_engine]
# Temporal decay half-lives (hours)
decay_half_life = { critical = 72, high = 48, medium = 24, low = 12 }

# Alert thresholds
alert_thresholds = { low = 100, medium = 300, high = 600, critical = 900 }

# Escalation
escalation = {
    sustained_high_hours = 2,
    flapping_max_alerts_per_hour = 10,
    auto_acknowledge_low_after_hours = 24,
}

# Asset criticality (multipliers)
asset_criticality = {
    system_process = 1.5,
    domain_admin = 2.0,
    critical_service = 1.3,
    standard_user = 1.0,
}

[correlation_engine]
enabled = true
max_chains = 10000
chain_timeout_hours = 24
min_chain_length = 3
min_chain_risk = 400

# Flow tracking
flow_tracking = {
    enabled = true,
    max_objects = 50000,
    ttl_hours = 48,
}

[ai_engine]
enabled = true
provider = "ollama"             # ollama | llama_cpp | openai
model = "llama-3.2-3b-instruct"
fallback_models = ["llama-3.1-8b-instruct", "qwen2.5-7b-instruct"]

# Ollama
ollama = {
    base_url = "http://127.0.0.1:11434"
    timeout_seconds = 60
    keep_alive = "5m"
    num_ctx = 8192
    num_gpu = -1
    num_thread = 4
}

# llama.cpp (direct)
llama_cpp = {
    model_path = "models/llama-3.2-3b-instruct-Q4_K_M.gguf"
    n_gpu_layers = -1
    n_threads = 4
    n_ctx = 8192
    n_batch = 512
}

# Generation parameters
generation = {
    temperature = 0.0           # Deterministic
    top_p = 0.9
    top_k = 40
    repeat_penalty = 1.1
    max_tokens = 2048
    stop_sequences = ["###", "User:", "Assistant:"]
}

# Context building
context = {
    max_events = 100
    max_chain_events = 50
    anonymize = true
    include_process_tree = true
    include_network_summary = true
    include_file_summary = true
}

[plugin_manager]
enabled = true
plugin_directories = [
    "/etc/sentinel/plugins",
    "~/.config/sentinel/plugins",
    "./plugins"
]
max_plugins = 50
# Sandbox profiles: none | basic | strict
default_sandbox = "basic"
allowed_capabilities = [
    "event:read", "event:write",
    "config:read", "config:write",
    "network:http", "secret:read",
    "ai:query", "storage:read",
]

[collectors]
# Global collector settings
sample_rate = 1.0               # Global multiplier (0.0-1.0)
backpressure_response = "throttle"  # throttle | drop | pause

[collectors.process]
enabled = true
sample_rate = 1.0
include_command_line = true
include_environment = false
resolve_signatures = true
track_ancestry_depth = 10
monitor_injection = true
monitor_hollowing = true
monitor_dumps = true
exclude_paths = [
    "C:\\Windows\\System32\\*",
    "C:\\Program Files\\*",
    "/usr/bin/*", "/bin/*", "/sbin/*", "/lib*",
]

[collectors.network]
enabled = true
sample_rate = 1.0
capture_dns = true
capture_http = true
capture_tls_fingerprints = true
capture_payloads = false
max_payload_bytes = 0
resolve_hostnames = true
geoip_enabled = true
geoip_db_path = "data/GeoLite2-Country.mmdb"
exclude_ports = [53, 67, 68, 123, 1900, 5353, 5355]
exclude_local = true
tls_sni_extraction = true
http_host_extraction = true

[collectors.file]
enabled = true
sample_rate = 1.0
monitor_paths = [
    "C:\\Users\\*\\AppData\\*",
    "C:\\ProgramData\\*",
    "C:\\Temp\\*",
    "/home/*/.config/*",
    "/home/*/.local/*",
    "/tmp/*", "/var/tmp/*",
    "/Library/LaunchAgents/*",
    "/Library/LaunchDaemons/*",
]
exclude_paths = [
    "C:\\Windows\\*", "C:\\Program Files\\*",
    "/usr/*", "/bin/*", "/sbin/*", "/lib*",
    "/var/log/*", "*/node_modules/*", "*/.git/*", "*/target/*",
]
calculate_hashes = true
calculate_entropy = true
max_file_size_hash = 104857600
monitor_executable_only = false
monitor_sensitive_paths = true

[collectors.registry]
enabled = true
sample_rate = 1.0
monitor_hives = ["HKLM", "HKCU"]
monitor_paths = [
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*",
    "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run*",
    "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*",
    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\*",
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon*",
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects*",
]
exclude_paths = [
    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\*",
]
capture_value_data = true
max_value_size = 8192

[collectors.usb]
enabled = true
sample_rate = 1.0
monitor_hid = true
monitor_mass_storage = true
scan_on_mount = true
scan_max_files = 100
scan_max_file_size = 10485760
scan_extensions = [".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".jar", ".scr", ".lnk"]
notify_on_new_device = true

[collectors.browser]
enabled = true
sample_rate = 1.0
browsers = ["chrome", "edge", "firefox", "brave"]
monitor_history = true
monitor_downloads = true
monitor_extensions = true
monitor_cookies = false
monitor_localstorage = false
download_hash_calculation = true
incognito_mode = "ignore"
extension_allowlist = []
native_messaging_enabled = true
poll_interval_seconds = 30

[collectors.startup]
enabled = true
scan_interval_hours = 4
monitor_registry_run_keys = true
monitor_scheduled_tasks = true
monitor_services = true
monitor_startup_folder = true
monitor_winlogon = true
monitor_systemd = true
monitor_cron = true
monitor_launchd = true
monitor_shell_profiles = true
monitor_browser_extensions = true
verify_signatures = true
alert_on_unsigned = true

[threat_intel]
enabled = true
providers = [
    { name = "local", type = "file", path = "data/threat_intel/" },
    # { name = "abuseipdb", type = "api", api_key_secret = "abuseipdb_key" },
    # { name = "otx", type = "api", api_key_secret = "otx_key" },
]
update_interval_hours = 6
max_iocs = 1000000

[privacy]
# Privacy controls
telemetry_enabled = false
crash_reporting = false
ai_local_only = true            # Never send to external AI
data_sharing = false
anonymize_host_id = true
strip_command_line_secrets = true
strip_environment_secrets = true

[logging]
level = "info"                  # trace, debug, info, warn, error
format = "json"                 # json | text | pretty
output = "file"                 # stdout | file | both
file_path = "logs/sentinel.log"
max_file_size_mb = 100
max_files = 10
include_timestamp = true
include_thread = true
include_location = false
```

### 12.4 Secrets Configuration (secrets.toml)

```toml
# sentinel/secrets.toml
# ENCRYPTED WITH AGE (age-encryption.org)
# DO NOT COMMIT TO VERSION CONTROL

# This file is encrypted at rest. The core decrypts it on startup
# using a key derived from hardware-bound secrets (TPM/Keychain/DPAPI)
# or a user-provided passphrase.

[virustotal]
api_key = "vt_api_key_here"

[abuseipdb]
api_key = "abuseipdb_key_here"

[otx]
api_key = "otx_key_here"

[shodan]
api_key = "shodan_key_here"

[hybrid_analysis]
api_key = "ha_key_here"

[discord]
webhook_url = "https://discord.com/api/webhooks/..."

[telegram]
bot_token = "bot_token_here"
chat_id = "123456789"

[slack]
webhook_url = "https://hooks.slack.com/services/..."
bot_token = "xoxb-..."

[email]
smtp_host = "smtp.gmail.com"
smtp_port = 587
smtp_user = "alerts@example.com"
smtp_password = "app_password_here"
from_address = "sentinel@example.com"
to_addresses = ["admin@example.com"]

[home_assistant]
url = "http://homeassistant.local:8123"
long_lived_token = "eyJ..."

[openai]
api_key = "sk-..."              # Only if using OpenAI provider
```

### 12.5 Configuration Validation

```rust
// Config schema validation using schemars + validator
#[derive(Deserialize, Validate, JsonSchema)]
struct Config {
    #[validate(nested)]
    core: CoreConfig,
    
    #[validate(nested)]
    grpc: GrpcConfig,
    
    #[validate(nested)]
    storage: StorageConfig,
    
    // ... all sections
    
    #[serde(default)]
    privacy: PrivacyConfig,
}

// Validation rules
impl Validate for CoreConfig {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut