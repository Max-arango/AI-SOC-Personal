---
id: TASK-001
title: "Connect React UI to real backend data"
status: ANALYZING
iteration: 1
created: 2026-08-10
---

## Objective
Fix 4 data sources in Tauri AppState that return hardcoded/empty data:
1. get_status() → real CPU/RAM/alerts count
2. get_network_connections() → real network events from SQLite
3. chat_ai() → real AI provider status
4. get_config() → real config file

## State
- Fixes applied to `ui/tauri-app/src-tauri/src/state/mod.rs`
- Pending: compilation verification, integration test

## Acceptance Criteria
- Tauri app compiles without errors
- 45 existing tests pass
- status() returns real CPU/RAM/event counts
- network_connections() returns entries from DB
- chat_ai() reflects actual AI provider
- config() reads real file or env vars
