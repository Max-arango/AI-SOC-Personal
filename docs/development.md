# Development Guide — Sentinel AI

## Project Structure

```
sentinel-ai/
├── apps/               # Binary applications
│   ├── sentinel-core-service/  # Main daemon (collectors, pipeline, plugins)
│   ├── sentinel-cli/           # CLI (sigma import, health check)
│   └── sentinel-mgmt/          # Management Server (multi-host)
├── crates/             # Internal libraries
│   ├── sentinel-core/          # Types, traits, errors, Ulid
│   ├── sentinel-events/        # Protobuf + generated code
│   ├── sentinel-config/        # TOML config, validation, hot-reload
│   ├── sentinel-storage/       # SQLite + DuckDB (slow compile)
│   ├── sentinel-event-bus/     # tokio mpsc pub/sub
│   ├── sentinel-rule-engine/   # CEL rule compiler + evaluator
│   ├── sentinel-correlation/   # Event chain tracking
│   ├── sentinel-risk/          # Scoring, decay, dedup, alerts
│   ├── sentinel-ai/            # Ollama/OpenRouter/OpenAI providers
│   ├── sentinel-plugins/       # Plugin framework
│   ├── sentinel-api/           # gRPC server (30 RPCs)
│   ├── sentinel-privacy/       # PrivacyFilter + anonymization
│   └── sentinel-sigma/         # Sigma→CEL importer
├── collectors/         # OS telemetry
│   └── src/                    # process, network, file, startup, browser
├── plugins/            # Notification + threat intel (12 plugins)
├── proto/              # Protocol Buffers (.proto files)
├── rules/              # 50 YAML detection rules
├── ui/tauri-app/       # Tauri v2 + React/TypeScript
├── docker/             # Docker Compose (6 services)
└── tests/              # Integration tests
```

## Building

```bash
# Full workspace (warning: DuckDB takes ~20 min on first build)
cargo build --release --workspace

# Skip storage to speed up iteration
cargo build --release -p sentinel-core-service -p sentinel-cli

# Frontend
cd ui/tauri-app && npm install && npm run build
```

## Testing

```bash
# All tests
cargo test --workspace

# Skip DuckDB tests (fast)
cargo test -p sentinel-ai -p sentinel-risk -p sentinel-rule-engine \
  -p sentinel-correlation -p sentinel-event-bus -p sentinel-collectors \
  -p sentinel-privacy -p sentinel-sigma

# Frontend
cd ui/tauri-app && npx tsc --noEmit
```

## Code Quality

```bash
# Format
cargo fmt --all

# Lint
cargo clippy --workspace -- -D warnings

# Audit
cargo deny check
cargo audit
```

## Adding a New Crate

1. Create `crates/my-crate/Cargo.toml` + `src/lib.rs`
2. Add to workspace `Cargo.toml` members (already covered by `crates/*`)
3. Add dependencies referencing workspace deps: `tokio = { workspace = true }`
4. Link to `sentinel-core` for traits: `sentinel-core = { path = "../sentinel-core" }`

## Adding a New Collector

1. Create `collectors/src/my_collector/mod.rs`
2. Add `pub mod my_collector;` to `collectors/src/lib.rs`
3. Follow the pattern: `pub async fn start_my_collector(bus: Arc<dyn EventBus>)`
4. Use `tokio::spawn` + `tokio::time::interval` for polling
5. Publish `Arc::new(Event { ... })` to `bus.publish(event).await`
6. Wire into `apps/sentinel-core-service/src/main.rs`

## Adding a New Plugin

1. Create `plugins/myplugin/Cargo.toml` + `src/lib.rs`
2. Export `pub fn enabled() -> bool` checking env vars
3. Export your API function
4. Add plugin dep to `apps/sentinel-core-service/Cargo.toml`
5. Wire into `main.rs` event loop

## Protobuf

Edit proto files in `proto/`. The `sentinel-events/build.rs` uses `tonic-build` to generate Rust code automatically.

```bash
# Regenerate (happens automatically on build)
cd crates/sentinel-events
cargo build
```

Generated code is in `target/debug/build/sentinel-events-*/out/`.

## Performance Tips

| Issue | Fix |
|---|---|
| Slow compilation | Exclude `sentinel-storage` + `sentinel-core-service` from workspace checks |
| DuckDB recompiles every time | Keep build artifacts, avoid `cargo clean` |
| Rust-analyzer slow | Exclude `target/` from workspace |
| Frontend bundle large | Code split in `vite.config.ts` |

## Debugging

```bash
# Run with debug logging
RUST_LOG=debug cargo run --bin sentinel-core-service

# Print event stream
# Add info!("Event: {:?}", event) in the event loop

# Inspect SQLite
sqlite3 ~/.local/share/sentinel/sentinel.db "SELECT COUNT(*) FROM events;"
sqlite3 ~/.local/share/sentinel/sentinel.db "SELECT * FROM alerts LIMIT 10;"
```
