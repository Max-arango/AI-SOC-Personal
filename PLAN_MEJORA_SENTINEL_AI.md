# 🚀 Plan de Mejora Integral — Sentinel AI

> Documento maestro con las 6 fases, objetivos, tareas concretas, métricas de éxito y prioridades para transformar Sentinel AI de un prototipo alpha (~20% implementado) a un MVP funcional.

---

## 📋 Resumen Ejecutivo

**Estado actual:** Alpha temprano. ~80% del código son stubs vacíos. El rule engine tiene un bug crítico (contexto CEL vacío). El frontend muestra datos ficticios. Los componentes clave (AI, correlation, risk, collectors, plugins) no están implementados.

**Objetivo:** MVP funcional donde los datos fluyan desde collectors reales → event bus → rule engine → correlation → risk → storage → UI.

**Esfuerzo estimado:** 6 fases, ~8-12 semanas de desarrollo enfocado.

---

## 📊 Mapa de Dependencias

```
                 ┌─────────────────────────────────────┐
                 │          FASE 1: FUNDACIÓN            │
                 │  Rule Engine fix + Storage + Config   │
                 └──────────┬──────────────────────────┘
                            │
                 ┌──────────▼──────────────────────────┐
                 │          FASE 2: PIPELINE             │
                 │  1 Collector real → Event Bus real   │
                 └──────────┬──────────────────────────┘
                            │
                 ┌──────────▼──────────────────────────┐
                 │       FASE 3: CORRELACIÓN + RISK     │
                 │  Correlation Engine + Risk Engine    │
                 └──────────┬──────────────────────────┘
                            │
                 ┌──────────▼──────────────────────────┐
                 │         FASE 4: BACKEND-FRONTEND      │
                 │  Tauri commands reales + Dashboard    │
                 └──────────┬──────────────────────────┘
                            │
                 ┌──────────▼──────────────────────────┐
                 │         FASE 5: AI + PLUGINS          │
                 │  AI Engine (Ollama) + Plugin system   │
                 └──────────┬──────────────────────────┘
                            │
                 ┌──────────▼──────────────────────────┐
                 │      FASE 6: POLISH + DEVOPS          │
                 │  gRPC + Docker + CI/CD + Tests        │
                 └─────────────────────────────────────┘
```

---

# 🔴 FASE 1: Fundación (Semanas 1-2)

## 1.1 🐛 Bug crítico: Reparar `create_activation` en Rule Engine

**Problema:** `fn create_activation(&self, _event: &Event) -> cel::Context` siempre devuelve `cel::Context::default()`, haciendo que **TODAS las reglas CEL fallen**.

**Solución:** Implementar el mapeo completo del evento al contexto CEL.

```rust
fn create_activation(&self, event: &Event) -> cel::Context {
    let mut ctx = cel::Context::default();
    
    // Mapear el evento completo al contexto CEL
    ctx.add_variable("event", event_to_cel_value(event));
    
    // Variables auxiliares para reglas comunes
    ctx.add_variable("severity", cel::Value::Int(event.severity as i64));
    ctx.add_variable("event_type", cel::Value::String(event.r#type.clone()));
    
    // Información de proceso (el más común en reglas)
    if let Some(proc) = &event.process {
        let mut proc_ctx = cel::Context::default();
        proc_ctx.add_variable("name", cel::Value::String(proc.name.clone()));
        proc_ctx.add_variable("pid", cel::Value::Int(proc.pid as i64));
        proc_ctx.add_variable("command_line", cel::Value::String(proc.command_line.clone()));
        // ... más campos
        ctx.add_variable("process", cel::Value::from(proc_ctx));
    }
    
    ctx
}
```

### Tareas:
- [ ] Crear `event_to_cel_value()` que convierta recursivamente `Event` → `cel::Value`
- [ ] Registrar variables estándar: `event`, `severity`, `event_type`, `process`, `network`, `file`
- [ ] Agregar constantes de severidad: `SEVERITY_INFO = 1`, `SEVERITY_WARNING = 3`, etc.
- [ ] Escribir tests unitarios que verifiquen reglas CEL reales
- [ ] Escribir test de integración: cargar regla YAML → publicar evento → verificar match

**📐 Métrica de éxito:** Test de regla `event.type == "test.event"` evaluado correctamente.

---

## 1.2 🔧 Storage: Reparar repositorios SQLite

**Problema:** 
- `SqliteEventCursor` siempre devuelve `None` (stub vacío)
- `SqliteEventRepository::query()` usa `execute()` en vez de `fetch_all()` y nunca devuelve datos
- `row_to_event()` devuelve `Event::default()`

**Solución:** Implementar los cursores correctamente.

### Tareas:
- [ ] `SqliteEventRepository::query()`: usar `query_as()` o `fetch_all()` con mapeo real
- [ ] `SqliteEventCursor`: implementar con `Vec<Arc<Event>>` real
- [ ] `row_to_event()`: parsear JSON de columnas `process`, `payload`, `metadata`, `correlation`
- [ ] Agregar `query_as_event()` helper que convierta fila SQLite → `Event`
- [ ] Tests: insertar evento → consultar → verificar campos

**📐 Métrica de éxito:** Consulta de eventos en SQLite devuelve datos correctos con sus campos anidados.

---

## 1.3 📦 Unificar tipos duplicados

**Problema:** `sentinel-core/src/lib.rs` tiene tipos como `Ulid`, `ConfigValue`, `BackpressureConfig`, `ChannelConfig` que también se definen en otros crates.

### Tareas:
- [ ] Mover `BackpressureConfig` de `sentinel-config` → `sentinel-core` (está en ambos)
- [ ] Mover `EventBusConfig` relacionado a `sentinel-core` si es posible
- [ ] Eliminar duplicación de `RetentionPolicy` (está en `sentinel-core/traits.rs` y `sentinel-config/src/lib.rs`)
- [ ] Verificar que no haya incoherencias de tipo entre crates

---

# 🟡 FASE 2: Pipeline de Datos (Semanas 3-4)

## 2.1 🛠️ Implementar primer collector real: Process Collector

**Problema:** Todos los 7 collectors y 3 OS abstraction layers (`sentinel-os-*`) son stubs. El framework del collector tiene logs de prueba pero el collector `process_collector.rs` solo escribe un evento falso.

**Solución:** Implementar el Process Collector completo con platform backends reales usando `sysinfo`.

### Tareas:
- **Platform-agnóstico (`collectors/src/process/`):**
  - [ ] Usar crate `sysinfo` para enumeración de procesos multiplataforma
  - [ ] Eventos: `process.created`, `process.terminated`, `process.injection_detected`
  - [ ] Sampling periódico (thread separado) vs. eventos del OS
  - [ ] Encolar eventos en el `event_tx` del `CollectorContext`
- **Framework (`collectors/src/framework/`):**
  - [ ] Completar `CollectorManager` que gestione ciclo de vida de collectors
  - [ ] Implementar health checks y métricas reales
  - [ ] Manejar backpressure (throttle, drop, pause según config)

### Dependencias:
```toml
# collectors/Cargo.toml (agregar)
sysinfo = "0.30"  # Procesos, CPU, memoria
```

**📐 Métrica de éxito:** `ProcessCollector` emite eventos reales al EventBus con datos de procesos del SO.

---

## 2.2 🔌 Conectar pipeline completo: Collector → EventBus → Storage

### Tareas:
- [ ] En `main.rs`: instanciar `ProcessCollector`, conectarlo al `EventBus`
- [ ] Crear task de background que suscriba al EventBus y persista eventos en DuckDB
- [ ] Verificar almacenamiento DuckDB funcional con datos reales
- [ ] Agregar métricas de pipeline: eventos/segundo, latencia, tasa de drop

**📐 Métrica de éxito:** Evento emitido por collector → visible en DuckDB.

---

## 2.3 🧪 Implementar Network Collector básico

### Tareas:
- [ ] Usar `pcap` o `netstat-rs` para monitoreo de conexiones de red
- [ ] Detectar nuevas conexiones y cambios de estado
- [ ] Implementar JA3 fingerprinting básico (o placeholder configurable)
- [ ] Tests unitarios con datos mock

---

# 🟠 FASE 3: Correlación y Riesgo (Semanas 5-6)

## 3.1 🧩 Implementar Correlation Engine

**Problema:** `crates/sentinel-correlation/src/lib.rs` = `//! sentinel-correlation crate (stub).`

**Solución:** Implementar 3 tipos de correlación.

### Tareas:
- [ ] **Correlación causal:** Detectar chains de procesos (PID parent→child→grandchild)
  - Estructura: `CorrelationChain { id, events[], risk_score, started_at, timeout_at }`
  - Algoritmo: hash map `process_id → chain_id`
  - Timeout: cerrar chains inactivas según config
- [ ] **Correlación de flujo:** Rastrear objetos (archivos, registros) a través del sistema
  - `FlowObject { id, type, path, accessed_by[], events[] }`
  - TTL configurable (default 48h)
- [ ] **Correlación temporal:** Agrupar eventos cercanos en tiempo
  - Ventana de tiempo sliding (default 5 min)
  - Misma fuente o mismo proceso
- [ ] Tests unitarios para cada tipo de correlación
- [ ] Benchmarks: throughput con 10k eventos

**📐 Métrica de éxito:** 3 eventos de proceso que forman una chain → chain detectada con risk_score calculado.

---

## 3.2 ⚖️ Implementar Risk Engine

**Problema:** `crates/sentinel-risk/src/lib.rs` = `//! sentinel-risk crate (stub).`

### Tareas:
- [ ] **Risk Scoring:**
  - Score base del evento + decay temporal (half-life según severidad)
  - Multiplicadores: asset criticality, user type, time-of-day
  - Fórmula: `final_score = base_score × asset_mult × user_mult × time_mult × decay_factor`
- [ ] **Alert Generation:**
  - Thresholds: LOW (100), MEDIUM (300), HIGH (600), CRITICAL (900)
  - Alert deduplication: mismo tipo + misma fuente en ventana
  - Flapping detection: >10 alerts/hora = suppress
- [ ] **Temporal Decay:**
  - Half-life configurable por severidad
  - Decaimiento exponencial: `score(t) = initial_score × 0.5^(t / half_life)`
- [ ] **Asset Criticality:**
  - System processes: 1.5x, Domain admin: 2.0x, Standard user: 1.0x
- [ ] Tests unitarios con casos de borde

**📐 Métrica de éxito:** Evento con riesgo 500 → alerta MEDIUM generada. Mismo evento repetido → suprimido por flapping.

---

## 3.3 🔗 Integrar Rule Engine → Correlation → Risk

### Tareas:
- [ ] Conectar el pipeline: RuleEngine evalúa evento → si hay match → pasa a Correlation → si hay chain suficiente → pasa a Risk → si supera threshold → genera Alert
- [ ] Implementar `AlertRepository` completo en SQLite (no stub)
- [ ] Crear módulo `AlertManager` que centralice la lógica de alertas

---

# 🟢 FASE 4: Backend ↔ Frontend (Semanas 7-8)

## 4.1 🔥 Tauri Commands Reales

**Problema:** `ui/tauri-app/src-tauri/src/state/mod.rs` devuelve datos ficticios (arrays vacíos, strings placeholder).

**Solución:** Conectar cada comando Tauri a su componente real del backend Rust.

### Tareas:
- [ ] `health_check`: Consultar health de storage, event_bus, rule_engine
- [ ] `query_events`: Conectar a `DuckDbEventRepository::query()`
- [ ] `get_alerts`: Conectar a `SqliteAlertRepository::query()`
- [ ] `get_processes`: Consultar lista de procesos via `sysinfo`
- [ ] `get_network_connections`: Consultar conexiones de red reales
- [ ] `explain_alert`: Preparar contexto para AI engine (aunque AI sea stub aún)
- [ ] `chat_ai`: Placeholder mejorado con respuestas predefinidas
- [ ] `get_config` / `update_config`: Conectar a `ConfigManager`
- [ ] Agregar polling periódico para actualización en tiempo real

### Arquitectura Tauri:
```rust
// commands.rs
#[tauri::command]
async fn query_events(
    state: tauri::State<'_, Arc<AppState>>,
    query: EventQueryParams
) -> Result<EventsResponse, String> {
    let storage = state.storage(); // AppState ahora tiene referencia a StorageManager
    let events = storage.events().await.query(query.into()).await.map_err(|e| e.to_string())?;
    Ok(EventsResponse::from(events))
}
```

**📐 Métrica de éxito:** Dashboard muestra datos reales del sistema (procesos, conexiones) sin mock data.

---

## 4.2 🖥️ Dashboard React: Datos Reales + Visualizaciones

### Tareas:
- [ ] **Event Timeline:** Mostrar eventos en tiempo real con WebSocket o polling
  - Usar `react-virtual` para manejar miles de eventos
  - Filtros combinables: tipo, severidad, fuente, texto libre
- [ ] **Alert List:** Tabla de alertas con estados (new, acknowledged, resolved)
  - Acciones: acknowledge, dismiss, mark as false positive
  - AI explanation button (aunque use placeholder hasta Fase 5)
- [ ] **Process Tree:** Visualización jerárquica de procesos (usar `react-tree-graph` o D3)
  - Colores por riesgo, severidad
  - Click para ver detalles del proceso
- [ ] **Network Map:** Conexiones activas con geolocalización
  - Usar `react-flow` para grafos de conexiones
- [ ] **Risk Timeline:** Gráfico de riesgo a lo largo del tiempo
  - Usar `recharts` o `visx`
- [ ] **MITRE ATT&CK Heatmap:** Mapa de técnicas MITRE detectadas
- [ ] **Loading states:** Skeletons, spinners para cada widget
- [ ] **Error states:** Mensajes de error amigables, retry buttons

### Dependencias:
```json
{
  "react-virtual": "^2.10.0",
  "react-flow": "^11.10.0",
  "recharts": "^2.12.0",
  "react-tree-graph": "^5.0.0"
}
```

**📐 Métrica de éxito:** Dashboard completamente funcional con datos reales y todas las visualizaciones operativas.

---

## 4.3 📱 Responsive + UX mejorado

### Tareas:
- [ ] Sidebar colapsable en mobile
- [ ] Notificaciones push (Tauri notifications)
- [ ] System tray con menú contextual (minimizar a bandeja)
- [ ] Shortcuts de teclado
- [ ] Tour interactivo para nuevos usuarios

---

# 🔵 FASE 5: AI + Plugins (Semanas 9-10)

## 5.1 🤖 Implementar AI Engine

**Problema:** `crates/sentinel-ai/src/lib.rs` = `//! sentinel-ai crate (stub).`

**Solución:** Implementar integración con Ollama para análisis de seguridad local.

### Tareas:
- [ ] **Context Builder:** Preparar contexto de eventos para el LLM
  - Seleccionar eventos relevantes (más recientes, mayor riesgo)
  - Formatear como prompt estructurado
  - Anonimizar datos sensibles si configurado
- [ ] **Provider Interface:** Abstracción sobre Ollama (y futuro llama.cpp, OpenAI)
  ```rust
  #[async_trait]
  pub trait AiProvider: Send + Sync {
      async fn chat(&self, messages: Vec<ChatMessage>, config: GenerationConfig) -> Result<String>;
      async fn stream_chat(&self, messages: Vec<ChatMessage>) -> Result<BoxStream<ChatChunk>>;
      fn is_available(&self) -> bool;
  }
  ```
- [ ] **Prompt Templates:**
  - `explain_alert`: "Eres un analista de seguridad. Explica este alerta..."
  - `summarize_events`: "Resume estos eventos en lenguaje natural..."
  - `investigate_chain`: "Analiza esta cadena de eventos..."
- [ ] **Guardrails:** Validar que la respuesta del LLM sea segura y estructurada
  - Parsear respuesta como JSON estructurado
  - Fallback a template si el LLM falla
- [ ] **Caching:** Cachear respuestas similares para evitar llamadas redundantes
- [ ] **Streaming:** Soporte para streaming de respuestas via Tauri events
- [ ] Tests: mock provider para tests unitarios

**📐 Métrica de éxito:** `ai.explain_alert(alert_id)` devuelve explicación coherente usando Ollama local.

---

## 5.2 🔌 Plugin System Real

**Problema:** `PluginManager` es stub que acepta args pero no hace nada. Los 8 plugins comerciales (VirusTotal, AbuseIPDB, Discord, Telegram, Slack, Email, Home Assistant, Shodan) son stubs.

### Tareas:
- [ ] **Plugin Manager:** Cargar plugins dinámicamente
  - Soporte para plugins nativos (cargo) y WASM
  - Sandboxing básico: capabilities system
  - Comunicación: EventBus como canal principal
- [ ] **Plugin SDK:** Traits y helpers para desarrolladores de plugins
- [ ] **Implementar plugins de notificación:**
  - `discord`: Webhook con embed de alerta
  - `telegram`: Mensaje formateado con bot token
  - `slack`: Webhook con blocks layout
  - `email`: SMTP con template HTML
- [ ] **Implementar plugins de threat intel:**
  - `virustotal`: Consultar hash de archivo
  - `abuseipdb`: Consultar IP
  - `shodan`: Consultar IP/puerto
- [ ] **Implementar `home-assistant`:** Automatizaciones de seguridad
- [ ] Tests de integración para cada plugin

**📐 Métrica de éxito:** Alerta de alto riesgo → notificación por Discord con detalles del evento.

---

# 🟣 FASE 6: Polish + DevOps (Semanas 11-12)

## 6.1 🌐 gRPC Server + REST Gateway

**Problema:** `crates/sentinel-api/src/lib.rs` = `//! sentinel-api crate (stub).`

### Tareas:
- [ ] Implementar gRPC server con tonic basado en `proto/sentinel/api/v1/sentinel.proto`
- [ ] Implementar REST gateway (actix-web o axum) que envuelva gRPC
- [ ] Autenticación básica (API key o mTLS)
- [ ] Rate limiting
- [ ] Health/readiness endpoints
- [ ] Swagger/OpenAPI docs

---

## 6.2 🐳 Docker + CI/CD

### Tareas:
- [ ] **Docker compose:** Verificar que funcione correctamente
  - `Dockerfile.prod`: Multi-stage build (builder → runner)
  - `Dockerfile.dev`: Hot-reload con cargo-watch
  - Volumes: config, data, logs
- [ ] **CI/CD (`.github/workflows/ci.yml`):**
  - Lint: `cargo clippy --all-targets`
  - Build: `cargo build --release`
  - Test: `cargo test --workspace`
  - Audit: `cargo deny check`
  - Docker build & push
- [ ] **Makefile:** Actualizar targets
  - `make build`, `make test`, `make lint`, `make docker`, `make deploy`

---

## 6.3 🧪 Tests + Calidad

### Tareas:
- [ ] **Test de integración del pipeline completo:**
  ```rust
  #[tokio::test]
  async fn test_full_pipeline() {
      // 1. Inicializar config, storage, event_bus, rule_engine
      // 2. Cargar regla YAML de prueba
      // 3. Emitir evento simulado
      // 4. Verificar que el evento se evalúa y genera alerta en DB
  }
  ```
- [ ] **Property-based testing con proptest** para:
  - Serialización/deserialización de eventos
  - Risk scoring con valores extremos
- [ ] **Benchmarks con criterion** para:
  - Rule engine throughput
  - Event bus latency
  - Storage write throughput
- [ ] **Documentación:**
  - `ARCHITECTURE.md` actualizado (el actual es muy básico)
  - `DEVELOPMENT.md` con guía de contribución
  - Docstrings en todas las funciones públicas
  - Ejemplos de reglas YAML

---

## 6.4 🎯 Lints y Configuración de Calidad

### Tareas:
- [ ] Habilitar `clippy::pedantic` con excepciones específicas
- [ ] Configurar `rustfmt` con el archivo existente
- [ ] Eliminar `allow` innecesarios
- [ ] Agregar `#[deny(unsafe_code)]` en crates que no necesiten unsafe
- [ ] Verificar que `deny.toml` esté actualizado

---

# 📊 Priorización por Impacto

| Prioridad | Tarea | Impacto | Esfuerzo | Dependencias |
|-----------|-------|---------|----------|--------------|
| 🔴 P0 | Fix `create_activation` en Rule Engine | **Crítico** (bug blocker) | 2-3 días | Ninguna |
| 🔴 P0 | Implementar `SqliteEventCursor` real | **Crítico** (datos no fluyen) | 2-3 días | Storage |
| 🔴 P0 | Implementar Process Collector | **Alto** (primeros datos reales) | 1 semana | Fase 1 |
| 🟡 P1 | Implementar Correlation Engine | **Alto** (chains de eventos) | 1.5 semanas | Fase 2 |
| 🟡 P1 | Implementar Risk Engine | **Alto** (alertas) | 1 semana | Correlation |
| 🟡 P1 | Conectar Tauri commands reales | **Alto** (UI con datos reales) | 1 semana | Fase 2+3 |
| 🟢 P2 | Implementar AI Engine | **Medio** (explicaciones) | 1.5 semanas | Fase 3 |
| 🟢 P2 | Implementar plugins (Discord, Telegram) | **Medio** (notificaciones) | 1 semana | Fase 2 |
| 🔵 P3 | gRPC + REST Gateway | **Bajo** (API externa) | 1.5 semanas | Fase 4 |
| 🔵 P3 | Dashboard React con visualizaciones | **Alto** (UX) | 2 semanas | Fase 4 |
| ⚪ P4 | CI/CD, Docker, Benchmarks | **Medio** (calidad) | 1 semana | Todo lo anterior |

---

# 💡 Recomendaciones Estratégicas

## Arquitectura de EventBus (optimización)
**Problema actual:** El EventBus usa canales de broadcast. Para alta carga, un patrón más eficiente es usar un **ring buffer lock-free + batch processing**.

**Recomendación:** Investigar `tokio::sync::broadcast` vs `crossbeam::channel` para el EventBus. Para tráfico de 10k+ eventos/segundo, considerar un canal lock-free compartido con batches.

## Serialización de Eventos
**Problema actual:** Los eventos Protobuf se convierten a JSON para almacenamiento SQLite/DuckDB. Esto es ineficiente.

**Recomendación:** 
- Usar formato **binario** para almacenamiento DuckDB (columnas `BYTES` con Protobuf nativo)
- Solo convertir a JSON para queries ad-hoc
- Añadir columna `risk_score` calculada y materializada para queries rápidas

## Error Handling Centralizado
**Problema actual:** `SentinelError` tiene 30 variantes pero el manejo es inconsistente entre crates.

**Recomendación:** Implementar un middleware de error handling que:
- Capture todos los errores en un punto central
- Los clasifique por recoverability (retryable, fatal, transient)
- Genere logs estructurados con contexto
- Exponga métricas de error por tipo

## Observabilidad desde el Día 1
**Recomendación:** Instrumentar **cada componente** con:
- 3 métricas key: latencia (histograma), throughput (contador), errores (contador)
- Tracing spans para requests completas
- Health endpoint que refleje estado de todos los subsistemas

---

# 📈 Roadmap Visual

```
Sem 1-2    Sem 3-4    Sem 5-6    Sem 7-8     Sem 9-10    Sem 11-12
┌────────┐ ┌────────┐ ┌────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐
│ FASE 1 │→│ FASE 2 │→│ FASE 3 │→│ FASE 4  │→│ FASE 5  │→│ FASE 6  │
│ Fundac.│ │Pipeline│ │Corr+Risk││Back-Front││ AI+Plug ││Polish   │
└────────┘ └────────┘ └────────┘ └─────────┘ └─────────┘ └─────────┘
    │          │          │          │           │          │
    ▼          ▼          ▼          ▼           ▼          ▼
 RuleEng  Process   Corr.     Tauri      Ollama     gRPC
   fix    Collector  Engine   Commands    Engine    Server
 Storage  EventBus   Risk     Dashboard  Plugins  CI/CD
   fix    →DuckDB   Engine   Realtime    Discord   Tests
                    Alerts   Visualiz.  Telegram  Benchmarks
```

---

## 🏁 Conclusión

Este plan convierte Sentinel AI de un **prototipo alpha con ~20% del código funcional** a un **MVP real con pipeline de datos completo**, en aproximadamente **12 semanas de desarrollo enfocado**.

Las fases están diseñadas para que **cada fase produzca valor entregable**:
- **Fase 1:** Rule engine que funciona + storage que persiste datos
- **Fase 2:** Primeros datos reales del sistema fluyendo
- **Fase 3:** Alertas reales basadas en correlación y riesgo
- **Fase 4:** Dashboard que muestra datos reales
- **Fase 5:** AI explicando alertas + notificaciones
- **Fase 6:** Producto listo para deploy

**Siguiente paso recomendado:** Comenzar con Fase 1 (reparar `create_activation` + storage cursors), que son los blockers más críticos que impiden que cualquier pipeline funcione.
