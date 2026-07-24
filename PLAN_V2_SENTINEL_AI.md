# Sentinel AI v2.0 — Plan Maestro Hardened

> Documento estratégico blindado contra los riesgos identificados en la auditoría de seguridad (AUDITORIA_CRITICA_V2.md). Cada feature incluye sus mitigaciones como requisito obligatorio, no como "nice to have".

---

## Principios de Seguridad (Override All)

Estos principios son **vinculantes**. Ninguna feature de v2.0 puede violarlos. Si una feature los contradice, la feature se rediseña o se descarta.

| # | Principio | Significado |
|---|---|---|
| P1 | **Local-first permanente** | El agente debe ser 100% funcional sin conexión al Management Server. El servidor añade valor, no es requisito de funcionamiento. |
| P2 | **Data minimization by default** | El agente nunca envía datos crudos al servidor. Solo agregados, hashes, o datos con redacción automática de PII. |
| P3 | **Privacy budget por host** | Cada host tiene un perfil de privacidad configurable que controla qué comparte y con quién. |
| P4 | **Human-in-the-loop para acciones destructivas** | Kill, quarantine, isolate, y remote shell requieren confirmación humana. Nunca automático. |
| P5 | **Opt-in granular** | Cada feature que comparte datos fuera del host es opt-in individual. No hay "all or nothing". |
| P6 | **Defense in depth** | Cada capa asume que la anterior fue comprometida. mTLS no es suficiente; los datos se protegen en tránsito Y en reposo Y en uso. |
| P7 | **Supply chain integrity** | Todo artefacto descargable (plugins, modelos ML, reglas) debe ser firmado, verificable, y con transparencia log. |
| P8 | **Threat model primero** | Ninguna feature se implementa sin un threat model documentado que cubra los 4 adversarios: externo, interno, supply chain, pasivo. |

---

## Modo Dual: Personal + Enterprise

v2.0 ofrece **dos modos de operación mutuamente excluyentes** que comparten el mismo core pero difieren en arquitectura de despliegue.

### Modo Personal (hereda v0.1.0)

```
┌──────────────────────────────┐
│         Modo Personal         │
│                               │
│  ┌─────────────────────────┐ │
│  │   Tauri UI (local)      │ │
│  └───────────┬─────────────┘ │
│              │ IPC            │
│  ┌───────────▼─────────────┐ │
│  │   Core Service (local)  │ │
│  │   Collectors             │ │
│  │   Rules → Risk → Alerts │ │
│  │   AI (Ollama local)     │ │
│  │   SQLite + DuckDB       │ │
│  └─────────────────────────┘ │
│                               │
│  ┌─────────────────────────┐ │
│  │   Plugins (local)       │ │
│  │   Notificaciones salen  │ │
│  │   solo si el usuario    │ │
│  │   configura webhooks    │ │
│  └─────────────────────────┘ │
└──────────────────────────────┘
   Cero dependencia externa.
   Cero datos a la nube.
   Cero servidor central.
```

### Modo Enterprise (v2.0)

```
┌──────────────────────────────────────────────────────────────┐
│                     Modo Enterprise                           │
│                                                               │
│  Management Server (HA: active-passive)                       │
│  ┌──────────────────────────────────────────────────────┐    │
│  │ Fleet Manager │ Cross-Host Correl │ Alert Aggregator │    │
│  │ Policy Engine │ Compliance Engine │ Plugin Registry  │    │
│  └──────────────────────┬───────────────────────────────┘    │
│                         │ gRPC + mTLS (PSK fallback)         │
│         ┌───────────────┼───────────────┐                    │
│         ▼               ▼               ▼                    │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐               │
│  │ Agent A  │    │ Agent B  │    │ Agent N  │               │
│  │ (Local)  │    │ (Local)  │    │ (Local)  │               │
│  │ ┌──────┐ │    │ ┌──────┐ │    │ ┌──────┐ │               │
│  │ │Core  │ │    │ │Core  │ │    │ │Core  │ │               │
│  │ │Local │ │    │ │Local │ │    │ │Local │ │               │
│  │ └──────┘ │    │ └──────┘ │    │ └──────┘ │               │
│  └──────────┘    └──────────┘    └──────────┘               │
│       │               │               │                      │
│       └───────────────┴───────────────┘                      │
│                       │                                       │
│              ┌────────▼────────┐                              │
│              │ Cloud Sync      │  (opt-in por feature)       │
│              │ Encrypted Backup│                              │
│              │ Threat Intel    │                              │
│              │ Remote UI Proxy │                              │
│              └─────────────────┘                              │
└──────────────────────────────────────────────────────────────┘

Cada agente es completamente funcional SIN el Management Server.
El servidor central añade: fleet view, cross-host correlation, central policy, compliance reports.
Si el servidor cae → los agentes siguen funcionando localmente.
```

---

## Privacy Budget por Host

Cada agente expone un perfil de privacidad que controla **exactamente qué datos comparte** con el Management Server. El usuario configura esto desde la UI local del agente.

```yaml
# ~/.config/sentinel/privacy.toml
[privacy]
mode = "enterprise"  # personal | enterprise

[privacy.sharing]
command_lines = "redacted"     # full | redacted | none
file_paths = "anonymized"     # full | anonymized | none
network_ips = "anonymized"    # full | anonymized | none
user_names = "hashed"          # full | hashed | none
process_names = "full"         # full | hashed | none

[privacy.fleet_queries]
require_approval = true        # el usuario del host debe aprobar cada fleet query
auto_approve_localhost = true  # queries desde la misma máquina se auto-aprueban
max_rows_per_query = 1000

[privacy.ml]
federated_learning = false     # compartir pesos de modelo
differential_privacy_epsilon = 8.0  # ε para DP-SGD (solo si federated=true)

[privacy.notifications]
silent_push_only = true        # Firebase/APNs solo despiertan la app, sin datos
local_websocket_fallback = true

[privacy.siem]
enabled = false
redact_pii = true
field_whitelist = ["event_type", "severity", "risk_score", "source"]
```

---

## Agent Autonomy Guarantee

**Regla dura:** el agente (core-service) debe ser 100% funcional sin el Management Server. El servidor central es un add-on, no un dependency.

| Capacidad | Sin Management Server | Con Management Server |
|---|---|---|
| Collectors | ✅ Funcionan | ✅ Funcionan |
| Rules (CEL) | ✅ Evalúan localmente | ✅ + reciben actualizaciones del servidor |
| Correlation | ✅ Cadenas locales | ✅ + cross-host chains |
| Risk Scoring | ✅ Scores locales | ✅ + fleet risk aggregation |
| Alertas | ✅ Generadas localmente | ✅ + fleet alert dashboard |
| Notificaciones | ✅ Discord/Telegram/Email directos | ✅ + notificaciones centralizadas |
| AI (Ollama) | ✅ Explicaciones locales | ✅ + fleet AI insights |
| Storage | ✅ SQLite local | ✅ + PostgreSQL central (backup) |
| Dashboard | ✅ Tauri UI local | ✅ + Web Console multi-host |
| EDR Actions | ✅ Kill/Quarantine locales | ✅ + fleet-wide commands |
| Compliance | ❌ Sin reports centralizados | ✅ CIS/GDPR reports |

**Fallback automático:** el agente monitorea el heartbeat con el Management Server. Si pierde conexión por más de 60 segundos, entra en **Modo Autónomo**. Cuando el servidor vuelve, sincroniza eventos buffereados (con backpressure para no saturar).

---

## Threat Model (STRIDE)

Antes de implementar cualquier feature de v2.0, se debe evaluar contra estos 4 adversarios:

### Adversario A1 — Externo (compromete el Management Server)

| Vector | Mitigación |
|---|---|
| Robo de credenciales admin | MFA obligatorio para admins, WebAuthn |
| Exploit en gRPC endpoint | Input validation estricto, fuzzing de protobuf |
| Acceso a DB del servidor | Encryption at rest con clave por host, no clave maestra |
| Interceptar stream de eventos | mTLS + certificate pinning + PSK fallback |

### Adversario A2 — Interno (administrador malicioso)

| Vector | Mitigación |
|---|---|
| Fleet query abusiva | Query audit log inmutable, approval del host, rate limiting |
| EDR command no autorizado | Human-in-the-loop, quorum requirement, audit |
| Acceso a eventos de otros deptos | RBAC + host groups + data segmentation |
| Modificar políticas para debilitar seguridad | Policy versioning + rollback + firma de políticas |

### Adversario A3 — Supply Chain (plugin/actualización maliciosa)

| Vector | Mitigación |
|---|---|
| Plugin malicioso en marketplace | Sandbox obligatorio por capability, reproducible builds, Rekor log |
| Update automático comprometido | Gradual rollout (1% → 10% → 100%), checksum verification, TUF |
| Modelo ML envenenado | Entrenamiento solo con datos locales verificados, modelo baseline comparación |
| Regla YAML maliciosa | CEL sandbox ya limita capacidades, review de reglas comunitarias |

### Adversario A4 — Pasivo (observador de red/metadatos)

| Vector | Mitigación |
|---|---|
| Metadatos de notificaciones push | Silent push: Firebase/APNs solo despierta, sin contenido |
| Patrones de tráfico agente↔servidor | Padding de mensajes, timing randomization, traffic shaping |
| Fingerprinting de versión | No exponer versión exacta en handshake, usar version ranges |
| Análisis de frecuencia de heartbeat | Heartbeat interval con jitter aleatorio |

---

## Features Hardened

### 1. Multi-Host Management (HARDENED)

**Requisitos de seguridad sobre el plan original:**

| # | Requisito | Obligatorio |
|---|---|---|
| 1.1 | Agente funcional sin Management Server (Agent Autonomy Guarantee) | ✅ |
| 1.2 | Privacy budget por host antes de que el agente envíe su primer evento | ✅ |
| 1.3 | mTLS con PSK como fallback permanente, no solo fase inicial | ✅ |
| 1.4 | Certificados con fingerprint pinning (TOFU) para entornos sin PKI | ✅ |
| 1.5 | Data minimization pipeline: eventos redactados/anonymizados antes de salir del agente | ✅ |
| 1.6 | Event buffering local con backpressure: si el servidor no responde, buffer local con límite | ✅ |
| 1.7 | Heartbeat con jitter aleatorio para evitar fingerprinting de red | ✅ |

**Arquitectura de datos:**

```
Agente
  │
  ├─► Pipeline Local (siempre activo)
  │     Collectors → Rules → Correlation → Risk → Storage (SQLite)
  │
  ├─► Privacy Filter (configurable)
  │     Redact command_lines, anonimizar paths/users/IPs
  │     → Produce "evento compartible"
  │
  ├─► Event Buffer (ring buffer, 10k eventos máx)
  │     Si Management Server no responde, almacena aquí
  │     Con backpressure: si se llena, droppea eventos de baja severidad
  │
  └─► StreamEvents (gRPC bidireccional)
        Solo envía eventos que pasaron el Privacy Filter
        Tipos de evento: aggregated_stats, alert_summary, event_sample
```

### 2. EDR — Response Actions (HARDENED)

**Tiered Response Model (obligatorio):**

| Tier | Acciones | Requiere |
|---|---|---|
| **T1 — Automático** | Notificar, enriquecer evento, actualizar risk score, loggear | Nada |
| **T2 — Confirmación** | Kill process, quarantine file, block IP | Confirmación de 1 admin |
| **T3 — Quorum** | Isolate host, network block amplio, remote shell | Confirmación de 2+ admins |
| **T4 — Break-glass** | Des-aislar host, revertir quarantine, rollback | 1 admin con justificación |

**Nunca automático:** isolate, kill, quarantine, shell. Siempre requieren T2 o superior.

**Playbook re-diseñado:**

```yaml
playbook:
  id: "ransomware-response"
  name: "Ransomware Response"
  trigger:
    rule_ids: ["ransomware-file-encryption"]
    min_risk: 800
    cooldown: 3600  # máximo 1 ejecución por hora
    blast_radius: 3  # máximo 3 hosts afectados simultáneamente
  actions:
    - action: notify_all
      tier: T1
      channels: [discord, telegram, email]
    - action: collect_snapshot
      tier: T1
    - action: kill_process_tree
      tier: T2
      require_confirmation: true
      timeout: 300  # si no hay confirmación en 5 min, escala
    - action: isolate_host
      tier: T3
      require_quorum: 2
      auto_revert: 3600  # revertir aislamiento tras 1h si no hay confirmación adicional
```

**Remote Shell específico:**

- Solo commands whitelist: `ps`, `netstat`, `ss`, `ls`, `cat /proc/*`, `find`, `lsof`, `last`, `who`, `systemctl status`
- Proceso con seccomp/AppContainer que bloquea syscalls de escritura, exec, y network
- Máximo 5 minutos por sesión, requiere T3
- Auditoría completa: cada comando tecleado se registra con timestamp y hash
- El agente puede rechazar la sesión si detecta anomalías en el management server

### 3. Machine Learning On-Device (HARDENED)

| # | Requisito | Obligatorio |
|---|---|---|
| 3.1 | ML 100% local por defecto. Federated learning desactivado. | ✅ |
| 3.2 | Federated learning: si se activa, requiere Differential Privacy (DP-SGD, ε < 8) | ✅ |
| 3.3 | Secure Aggregation: el servidor no ve contribuciones individuales, solo el agregado | ✅ |
| 3.4 | Entrenamiento solo con datos locales verificados (no datos de otros agentes sin sanitizar) | ✅ |
| 3.5 | Modelo baseline de comparación para detectar envenenamiento de modelo | ✅ |
| 3.6 | Opt-in granular: el usuario elige qué modelos participan (proceso sí, red no, etc.) | ✅ |

### 4. Compliance Automation (HARDENED)

**Requisitos de arquitectura para cumplimiento real:**

| # | Requisito | Obligatorio |
|---|---|---|
| 4.1 | El compliance engine corre LOCALMENTE en cada agente, no en el servidor central | ✅ |
| 4.2 | Los reports de compliance se generan por host y se agregan voluntariamente | ✅ |
| 4.3 | GDPR: data minimization pipeline es obligatorio (Privacy Filter) | ✅ |
| 4.4 | GDPR: derecho al olvido — borrar todos los datos de un host en el servidor central | ✅ |
| 4.5 | GDPR: registro de transferencias internacionales (qué datos salieron, a dónde, cuándo) | ✅ |
| 4.6 | Cifrado en reposo en el management server con claves por host | ✅ |

### 5. SIEM Connectors (HARDENED)

| # | Requisito | Obligatorio |
|---|---|---|
| 5.1 | Field whitelist por destino SIEM (nunca enviar todo) | ✅ |
| 5.2 | Transformer pipeline: redactar PII antes de enviar | ✅ |
| 5.3 | Data residency: forzar endpoint del SIEM en misma región | ✅ |
| 5.4 | Audit log de exfiltración: cuántos eventos, de qué tipo, a qué destino | ✅ |
| 5.5 | Opt-in por tipo de evento, no all-or-nothing | ✅ |

### 6. Plugin Marketplace (HARDENED)

| # | Requisito | Obligatorio |
|---|---|---|
| 6.1 | Sandbox obligatorio: cada plugin se ejecuta con capabilities explícitas, enforce por seccomp/AppContainer | ✅ |
| 6.2 | Reproducible builds: hash del binario verificable desde el fuente | ✅ |
| 6.3 | Transparency log (Rekor/Sigstore): cada release registrada en log inmutable | ✅ |
| 6.4 | Gradual rollout: actualizaciones a 1% → 10% → 50% → 100% | ✅ |
| 6.5 | Firmado con hardware keys (YubiKey/HSM), no solo SSH | ✅ |
| 6.6 | Review obligatorio para plugins con capability `network:*` o `event:read` | ✅ |
| 6.7 | Auto-update deshabilitable por el usuario | ✅ |

### 7. Cloud Sync (HARDENED)

| # | Requisito | Obligatorio |
|---|---|---|
| 7.1 | Cada feature de Cloud Sync es opt-in individual | ✅ |
| 7.2 | Backup cifrado con clave derivada de frase del usuario (nunca en el servidor) | ✅ |
| 7.3 | Threat intel compartida: solo IOCs, nunca datos de eventos | ✅ |
| 7.4 | Remote UI proxy: túnel WireGuard, no simple TCP forward | ✅ |

### 8. Mobile Companion (HARDENED)

| # | Requisito | Obligatorio |
|---|---|---|
| 8.1 | Silent push: Firebase/APNs solo despierta la app, zero contenido | ✅ |
| 8.2 | La app consulta al Management Server directamente por los datos (no pasan por Google/Apple) | ✅ |
| 8.3 | Modo LAN: WebSocket directo al Management Server en red local (sin push, sin cloud) | ✅ |
| 8.4 | Frecuencia máxima de push: 1 por minuto (anti-timing analysis) | ✅ |
| 8.5 | Push deshabilitable por el usuario (solo polling) | ✅ |

---

## Roadmap v2.0 (Ajustado por Seguridad)

```
MES  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16 17 18 19 20
      ├─────────────┤├──────────────────────┤├──────────────────────┤
      │   FASE 1     ││       FASE 2         ││       FASE 3         │
      │ Multi-Host   ││   EDR + ML +         ││ Compliance +         │
      │ + Privacy    ││   Seguridad          ││ Ecosystem            │
      ├─────────────┤├──────────────────────┤├──────────────────────┤
      │ Threat Model ││ Tiered EDR (T1-T4)   ││ CIS Engine (local)   │
      │ Privacy Busget││ Human-in-the-loop   ││ GDPR Module          │
      │ Agent Autonomy││ Playbooks auditados ││ SIEM + Transformer   │
      │ Mgmt Server HA││ Remote Shell seguro ││ Plugin Sandbox       │
      │ Data Minimiz. ││ ML + DP-SGD + SecAgg││ Marketplace          │
      │ mTLS + PSK    ││ Fleet Query limits  ││ Mobile (silent push) │
      │ Fleet API     ││ Forensic Snapshots  ││ Cloud Sync (opt-in)  │
      │ Cross-Host    ││                     ││ SOAR (TheHive)       │
      │ RBAC + Audit  ││                     ││                      │
      └─────────────┘└──────────────────────┘└──────────────────────┘
```

---

## Matriz de Riesgos Actualizada (15 riesgos rastreados)

| # | Riesgo | Mitigado por | Estado |
|---|---|---|---|
| 1 | Concentración datos en Mgmt Server | Privacy Filter + Data Minimization Pipeline | ✅ Mitigado |
| 2 | Remote Shell puerta trasera | Command whitelist + seccomp + T3 quorum + JIT | ✅ Mitigado |
| 3 | EDR playbooks automáticos | Tiered Response (T1-T4) + human-in-the-loop | ✅ Mitigado |
| 4 | Plugin supply chain | Sandbox + reproducible builds + Rekor + gradual rollout | ✅ Mitigado |
| 5 | Management Server SPOF | Agent Autonomy Guarantee + HA active-passive + local buffer | ✅ Mitigado |
| 6 | Mobile push metadatos | Silent push + local fetch + WebSocket LAN mode | ✅ Mitigado |
| 7 | Fleet queries abusivas | Approval del host + audit log + rate limiting + row limit | ✅ Mitigado |
| 8 | SIEM exfiltración | Field whitelist + transformer pipeline + data residency | ✅ Mitigado |
| 9 | Federated learning filtración | DP-SGD (ε<8) + Secure Aggregation + opt-in granular | ✅ Mitigado |
| 10 | StreamEvents buffer explosion | Batching + sampling adaptativo + NATS pub/sub | ✅ Mitigado |
| 11 | mTLS dependencia PKI | PSK fallback permanente + TOFU fingerprint pinning | ✅ Mitigado |
| 12 | Fleet queries DoS | Timeout + row limit + rate limiting + async queries | ✅ Mitigado |
| 13 | Anonimato inexistente | Documentado como no-anónimo. Modo Personal para anonimato. | ✅ Aceptado |
| 14 | Cumplimiento auto-contradictorio | Data minimization pipeline + cifrado en reposo + residency control | ✅ Mitigado |
| 15 | Model inversion ML | DP-SGD + entrenamiento solo local + baseline comparison | ✅ Mitigado |

---

## Definición de Done (por Feature v2.0)

Toda feature de v2.0 debe cumplir este checklist antes de marcarse como completada:

- [ ] Threat model documentado (A1-A4 evaluados)
- [ ] Data minimization aplicada (Privacy Filter configurado)
- [ ] Agent Autonomy verificado (funciona sin Management Server)
- [ ] Human-in-the-loop para T2+ actions
- [ ] Audit log de todas las acciones
- [ ] Tests de seguridad: fuzzing + penetration testing específico de la feature
- [ ] Documentación de implicaciones de privacidad para el usuario final
- [ ] Opt-in granular (no all-or-nothing)
- [ ] Review de código por al menos 1 security engineer

---

*Plan Version: 2.0-hardened — Blindado contra 15 riesgos identificados en auditoría*
