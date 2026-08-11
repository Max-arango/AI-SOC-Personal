# Project State — Sentinel AI

## Stack
- **Backend**: Rust (cargo workspace, 20+ crates)
- **Frontend**: React 18 + Tauri v2 (TypeScript)
- **Build**: `cargo build --workspace`, `npm run tauri build`
- **Tests**: `cargo test -p sentinel-collectors` (45 tests), `cargo test --test integration_test -p sentinel-core-service`
- **Lint**: `cargo clippy --workspace -- -D warnings`
- **gRPC API**: 35/35 endpoints, server on `127.0.0.1:50051`

## Git
- **Branch**: main
- **Last commit**: 04371e9 (Add demo recording + embed in README)
- **Status**: working tree clean (all changes committed)

## Current Task
- **TASK-001**: Connect React UI dashboard to real backend data
- **Context**: UI exists at `ui/tauri-app/` with Tauri commands + React pages
- **Gap**: 4 data sources return hardcoded/empty data
  - get_status() → hardcoded CPU/RAM
  - get_network_connections() → empty
  - chat_ai() → placeholder
  - get_config() → placeholder
- **Fix applied (pending compilation)**: Rewrote AppState methods in `ui/tauri-app/src-tauri/src/state/mod.rs`
- **Blocked**: Tauri app excluded from workspace, compilation pending
