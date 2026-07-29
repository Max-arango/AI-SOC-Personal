# ANÁLISIS DE GAPS + PLAN DE IMPLEMENTACIÓN — Sentinel AI

> Auditoría completa del proyecto. Cada gap evaluado como ESENCIAL, MEJORA, u OVERENGINEERING. Plan priorizado con estimaciones.

---

## 📊 GAPS ENCONTRADOS (31 total)

### CRÍTICOS (6) — Bloquean funcionalidad o seguridad

| # | Gap | Clasificación | Overengineering? | Archivo |
|---|---|---|---|---|
| C1 | 13 crates stub (6 core + 7 collectors) — nunca implementados | ESENCIAL eliminar | ❌ Sí si se implementan — las implementaciones reales ya existen en `collectors/src/` | `crates/sentinel-os-*/`, `collectors/*-collector/` |
| C2 | 80 `unwrap()` en código de producción — pueden causar panics | ESENCIAL | ❌ No | Múltiples archivos |
| C3 | `docker/config/` no existe — docker-compose rompe | ESENCIAL | ❌ No | `docker/docker-compose.yml` |
| C4 | Docker-compose hardcodea GPU NVIDIA — inusable sin GPU | ESENCIAL | ❌ No | `docker/docker-compose.yml:39` |
| C5 | OTX/GeoIP/IOC corren DENTRO del if-let de Shodan — bug de scope | ESENCIAL | ❌ No | `apps/sentinel-core-service/src/main.rs:391` |
| C6 | Agent client nunca envía eventos reales — solo `sleep(60)` | ESENCIAL para multi-host | ❌ No | `apps/sentinel-core-service/src/agent.rs:71` |

### ALTOS (8) — Afectan funcionalidad importante

| # | Gap | Clasificación | Overengineering? |
|---|---|---|---|
| H1 | Network collector Linux-only (macOS/Windows no-op) | ESENCIAL para cross-platform | ❌ No para Linux. Para Win/Mac: post-MVP |
| H2 | Windows/macOS process collectors son stubs vacíos | MEJORA | ❌ No — pero requiere mucho esfuerzo |
| H3 | 15 gRPC endpoints devuelven "not yet" | MEJORA | ⚠️ Parcial: los de gestión de reglas pueden esperar. Los de eventos/alertas deben funcionar |
| H4 | Event bus usa trait object + runner separados — frágil | ESENCIAL | ❌ No |
| H5 | `ConfigManager::watch()` devuelve watcher que nunca dispara | MEJORA | ❌ No |
| H6 | `SqliteStorage` usa `unwrap()` en repos lazy-init — puede panicar | ESENCIAL | ❌ No |
| H7 | UI Network y Files muestran "coming soon" a pesar de que el backend funciona | MEJORA | ❌ No — rápido de arreglar |
| H8 | Threats page tiene datos hardcodeados (no consulta al backend) | MEJORA | ❌ No — backend ya tiene el endpoint |

### MEDIOS (10) — Mejoras de calidad

| # | Gap | Clasificación |
|---|---|---|
| M1 | Solo 50 reglas YAML | MEJORA — añadir más reglas Sigma importadas |
| M2 | AI Assistant básico (sin contexto de alertas, sin Markdown) | MEJORA |
| M3 | Settings page read-only | MEJORA |
| M4 | DuckDB analytics sin usar en producción | MEJORA — o se usa o se quita |
| M5 | `lib_trimmed.rs` — código muerto duplicado | ESENCIAL eliminar |
| M6 | 7 collector crates individuales duplican `collectors/src/` | ESENCIAL eliminar del workspace |
| M7 | Logging inconsistente — algunos collectors silencian errores | MEJORA |
| M8 | Sin tests de integración end-to-end (collector → pipeline completo) | MEJORA |
| M9 | Sin benchmarks ni property-based tests | MEJORA |
| M10 | Sin CI en Windows/macOS | MEJORA |

### BAJOS (7) — Polish

| # | Gap | Clasificación |
|---|---|---|
| L1 | Faltan docstrings en funciones públicas de collectors | MEJORA |
| L2 | `cargo-deny` no corre en CI | MEJORA |
| L3 | Makefile no actualizado para estructura actual | MEJORA |
| L4 | Dockerfiles usan Rust 1.75 (obsoleto) | MEJORA |
| L5 | `sentinel.toml` de docker tiene campos que no matchean structs Rust | ESENCIAL arreglar |
| L6 | Sin release workflow en CI | MEJORA |
| L7 | Sin `docker-compose.prod.yml` | MEJORA |

---

## 🚫 OVERENGINEERING — Lo que NO se debe hacer

| Propuesta | Por qué es overengineering |
|---|---|
| **Implementar los 13 crates stub** (os-common, os-linux, etc.) | Las implementaciones reales ya existen en `collectors/src/`. Los crates stub deben ELIMINARSE del workspace, no implementarse. |
| **Escribir 500 reglas YAML manualmente** | Usar el Sigma importer para importar reglas comunitarias. Las reglas manuales solo para casos específicos no cubiertos por Sigma. |
| **Implementar todos los 15 gRPC endpoints "not yet"** | Algunos como `create_rule`, `update_rule`, `delete_rule` son para gestión administrativa que no es prioritaria para un MVP. Los de queries (events, alerts, processes) sí deben completarse. |
| **Reescribir collectors con el framework `CollectorManager`** | El CollectorManager existe pero es más complejo de lo necesario. Los collectors actuales con `tokio::spawn` + `interval` funcionan bien para el MVP. |
| **Añadir Kubernetes operator** | Fuera de scope para un asistente de seguridad personal. |
| **Implementar mTLS en todas partes** | PSK es suficiente para el MVP multi-host. mTLS es para producción enterprise. |
| **Migrar a NATS/Kafka para el event bus** | Tokio channels son suficientes para single-host. NATS se necesita solo en multi-host con >100 agentes. |
| **Añadir WebAssembly (WASM) para plugins** | Process isolation vía subprocesos es suficiente y más seguro. WASM añade complejidad sin beneficio claro. |
| **Auto-generar `lower_ascii` como función CEL nativa** | Intentamos 3 approaches, todos fallaron porque cel-rs 0.14 no soporta custom functions. `preprocess_cel()` funciona. |
| **Migrar de Tauri a Electron** | Tauri v2 ya funciona. Electron es más pesado y menos seguro. |

---

## 📋 PLAN DE IMPLEMENTACIÓN PRIORIZADO

### FASE 0: Limpieza y Estabilización (1-2 días)

**Objetivo:** Eliminar código muerto, arreglar bugs críticos, estabilizar lo existente.

| # | Tarea | Esfuerzo | Archivos |
|---|---|---|---|
| 0.1 | **Eliminar del workspace los 7 crates collector stub** (`collectors/*-collector/`) que duplican `collectors/src/` | 30 min | `Cargo.toml`, `collectors/*-collector/Cargo.toml` |
| 0.2 | **Eliminar del workspace los 5 crates OS stub** (`sentinel-os-*`) no implementados | 30 min | `Cargo.toml`, `crates/sentinel-os-*/` |
| 0.3 | **Eliminar `lib_trimmed.rs`** — código duplicado muerto | 5 min | `crates/sentinel-rule-engine/src/lib_trimmed.rs` |
| 0.4 | **Arreglar bug de scope H7**: OTX/GeoIP/IOC fuera del if-let de Shodan | 30 min | `apps/sentinel-core-service/src/main.rs` |
| 0.5 | **Reemplazar `unwrap()` críticos**: event_tx.unwrap(), repo.unwrap(), RwLock.unwrap() | 1h | `collectors/src/process/process_collector.rs:61`, `crates/sentinel-storage/src/sqlite.rs:108`, `plugins/ioc/` |
| 0.6 | **Arreglar docker config**: crear `docker/config/`, añadir CPU-only compose | 30 min | `docker/` |
| 0.7 | **Arreglar `sentinel.toml`** de docker con campos correctos | 20 min | `docker/sentinel.toml` |

### FASE 1: Backend Funcionalidad Core (3-4 días)

**Objetivo:** Completar lo que debería funcionar pero no funciona.

| # | Tarea | Esfuerzo |
|---|---|---|
| 1.1 | **Implementar bidirectional streaming en agent client** — heartbeat + eventos reales | 4h |
| 1.2 | **Completar gRPC endpoints de queries**: `get_process`, `get_process_tree`, `get_alert` — ya tienen lógica en Tauri state, solo falta exponer | 3h |
| 1.3 | **Arreglar `ConfigManager::watch()`** para que notifique a subscribers | 2h |
| 1.4 | **Unificar logging de errores** en collectors — warn! en publish failures | 1h |
| 1.5 | **Integrar DuckDB analytics** en el pipeline o marcarlo como opcional | 2h |

### FASE 2: Detección — Más Reglas (2-3 días)

**Objetivo:** Ampliar cobertura de detección usando el Sigma importer ya existente.

| # | Tarea | Esfuerzo |
|---|---|---|
| 2.1 | **Clonar repositorio SigmaHQ** y ejecutar `sentinel-cli import-sigma --dir` | 1h |
| 2.2 | **Revisar y curar reglas importadas**: eliminar Windows-only, adaptar logsource | 3h |
| 2.3 | **Añadir 30 reglas adicionales** para tácticas no cubiertas | 3h |
| 2.4 | **Crear tests para reglas importadas**: verificar que compilan en CEL | 2h |

### FASE 3: UI — Completar Páginas (2-3 días)

**Objetivo:** Que todas las páginas de la UI muestren datos reales.

| # | Tarea | Esfuerzo |
|---|---|---|
| 3.1 | **Network page**: conectar a `getNetworkGraph()` → mostrar conexiones reales | 2h |
| 3.2 | **Files page**: conectar a events con source=file → mostrar actividad real | 2h |
| 3.3 | **Threats page**: conectar a `getMitreHeatmap()` → datos reales | 1h |
| 3.4 | **AI Assistant**: añadir contexto de alertas/eventos actuales, Markdown rendering | 3h |
| 3.5 | **Settings**: añadir editor TOML con save (usando Tauri fs plugin) | 3h |

### FASE 4: CI/CD + Calidad (1-2 días)

**Objetivo:** Pipeline de CI completo.

| # | Tarea | Esfuerzo |
|---|---|---|
| 4.1 | **Añadir `cargo-deny` al CI** | 30 min |
| 4.2 | **Añadir benchmarks con criterion** para event bus, rule engine, risk engine | 3h |
| 4.3 | **Añadir release workflow**: build binarios + docker push + GitHub Release | 2h |
| 4.4 | **Actualizar Dockerfiles** a Rust stable más reciente | 15 min |
| 4.5 | **Crear `docker-compose.prod.yml`** sin hot-reload, con healthchecks | 1h |

---

## 📊 RESUMEN DE ESFUERZO

| Fase | Días | Tareas | Impacto |
|---|---|---|---|
| F0 — Limpieza | 1-2 | 7 | Estabiliza el proyecto, elimina deuda técnica |
| F1 — Backend | 3-4 | 5 | Completa funcionalidad core pendiente |
| F2 — Reglas | 2-3 | 4 | Amplía cobertura de detección significativamente |
| F3 — UI | 2-3 | 5 | Todas las páginas muestran datos reales |
| F4 — CI/CD | 1-2 | 5 | Pipeline profesional, releases automatizados |
| **Total** | **9-14 días** | **26 tareas** | — |

---

## 🎯 QUÉ EMPEZAR AHORA

La Fase 0 es la más urgente: arreglar bugs y eliminar código muerto. Son tareas rápidas (1-2 días) que despejan el camino para todo lo demás.

Recomiendo empezar por **0.1 + 0.2** (eliminar 12 crates stub del workspace) porque:
- Reduce tiempos de compilación
- Elimina confusión sobre cuál es la implementación canónica
- Es puramente sustractivo (bajo riesgo)
