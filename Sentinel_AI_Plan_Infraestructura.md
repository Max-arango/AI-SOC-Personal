# Sentinel AI - Plan de Infraestructura

## Visión

Crear un Asistente Inteligente de Seguridad para computadores personales
que monitoree el sistema, detecte comportamientos anómalos, correlacione
eventos, explique riesgos mediante IA y recomiende acciones. No
reemplaza un antivirus; actúa como una capa adicional de observabilidad
y asistencia.

## Filosofía

-   Explicar amenazas en lenguaje natural.
-   Funcionar principalmente de forma local.
-   Priorizar privacidad.
-   Arquitectura modular y extensible.

## Arquitectura General

``` text
Usuario
   │
Desktop UI (Dashboard, Chat IA, Alertas)
   │
IPC/gRPC
   │
Sentinel Core Service
 ├─ Rule Engine
 ├─ Event Correlator
 ├─ Risk Scoring
 ├─ AI Engine
 └─ Plugin Manager
   │
Event Collection Layer
 ├─ Process Monitor
 ├─ Network Monitor
 ├─ File Monitor
 ├─ USB Monitor
 ├─ Registry Monitor
 ├─ Browser Monitor
 └─ Startup Monitor
   │
Windows / Linux / macOS APIs
```

## Componentes

### Core Service

-   Recibe eventos.
-   Correlaciona información.
-   Calcula riesgo.
-   Consulta IA.
-   Genera alertas.
-   Guarda historial.

### Collectors

-   Process Monitor
-   Network Monitor
-   File Monitor
-   Registry Monitor
-   USB Monitor
-   Browser Monitor

Cada colector publica eventos al bus interno.

## Event Bus

``` text
Collectors
    ↓
 Event Bus
    ↓
Core Service
    ↓
 IA / UI
```

Tecnologías posibles: - Tokio Channels - ZeroMQ - NATS - gRPC Streams

## Bases de Datos

### SQLite

-   Configuración
-   Preferencias
-   Historial

### DuckDB

-   Eventos
-   Consultas analíticas

### Futuro

-   Tantivy o Meilisearch para búsquedas.

## Motor de Reglas

Ejemplo:

``` yaml
rule:
  name: Suspicious PowerShell
  conditions:
    - process.name == "powershell.exe"
    - network.connection == true
    - child_process == true
  score: 85
```

## Sistema de Riesgo

Cada evento suma una puntuación.

Ejemplo: - PowerShell: +30 - Descarga: +20 - Persistencia: +30 - TOR:
+40

> =100 → Alerta crítica.

## IA

Entrada: - Contexto - Eventos - Riesgo - Historial reciente

Salida: - Explicación - Nivel de riesgo - Recomendaciones - Resumen

## Plugins

Integraciones futuras: - VirusTotal - AbuseIPDB - Shodan - Hybrid
Analysis - ANY.RUN - Discord - Telegram - Slack - Webhooks

## API Local

    localhost:7777
    /events
    /processes
    /network
    /history
    /chat
    /settings
    /rules

## Stack Tecnológico

  Componente      Tecnología
  --------------- --------------------
  Core            Rust
  Agentes         Rust
  UI              Tauri + React
  Comunicación    gRPC
  Configuración   SQLite
  Eventos         DuckDB
  IA              Ollama / llama.cpp
  Reglas          YAML

## Roadmap MVP

1.  Core Service.
2.  Process Monitor.
3.  Network Monitor.
4.  Rule Engine.
5.  Dashboard.
6.  Chat IA.
7.  File Monitor.
8.  Plugins.

## Objetivo final

Convertirse en un copiloto de seguridad para usuarios de PC, explicando
amenazas de forma comprensible, preservando la privacidad y funcionando
principalmente de manera local.
