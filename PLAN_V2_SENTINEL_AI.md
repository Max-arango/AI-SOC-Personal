# Sentinel AI v2.0 — Plan Maestro

> Documento estratégico con la visión, fases, y roadmap desde el MVP actual (v0.1.0) hasta la plataforma enterprise-ready (v2.0).

---

## Resumen Ejecutivo

**Estado actual (v0.1.0):** MVP funcional en Linux con pipeline completo (collectors → rules → correlation → risk → alerts), 8 plugins de notificación/threat intel, gRPC API, y UI Tauri v2 con datos reales.

**Objetivo v2.0:** Plataforma de seguridad multiplataforma con capacidades EDR, correlación multi-host, ML on-device, compliance automatizado, y marketplace de plugins.

**Esfuerzo estimado:** v1.0 (~6 meses) + v2.0 (~12 meses) = ~18 meses desde v0.1.0.

---

## Mapa de Versiones

```
v0.1.0 (HOY)        v1.0 (6 meses)         v2.0 (18 meses)
┌──────────┐       ┌────────────────┐      ┌─────────────────────────┐
│ MVP Linux│──────►│ Multiplataforma │─────►│ Plataforma Enterprise    │
│ Pipeline │       │ Colectores real │      │ Multi-host + ML + EDR   │
│ 8 plugins│       │ Windows/macOS   │      │ Cloud + Compliance      │
└──────────┘       │ Browser + UI    │      │ Mobile + Marketplace    │
                    └────────────────┘      └─────────────────────────┘
```

---

# PARTE 1: CAMINO A v1.0 (Prerrequisito de v2.0)

v1.0 debe ser un producto completo y estable antes de abordar las capacidades enterprise de v2.0.

## v1.0 — Milestones

### M1: Windows + macOS (Meses 1-3)

| Tarea | Detalle |
|---|---|
| Process Collector Windows | ETW (Microsoft-Windows-Kernel-Process) |
| Process Collector macOS | Endpoint Security Framework (ES_EVENT_TYPE_NOTIFY_EXEC) |
| Network Collector Windows | ETW (Microsoft-Windows-TCPIP) + WFP |
| Network Collector macOS | Endpoint Security + /dev/bpf |
| File Collector Windows | USN Journal + ReadDirectoryChangesW |
| File Collector macOS | FSEvents + Endpoint Security |
| Registry Collector (Windows) | CmRegisterCallbackEx |
| USB Collector cross-platform | udev (Linux), IOKit (macOS), WM_DEVICECHANGE (Windows) |
| Browser Collector | Native messaging + SQLite (Chrome, Firefox, Edge) |
| OS Abstraction Crates | Implementar `sentinel-os-windows`, `sentinel-os-macos`, `sentinel-os-common` |
| Installers | .exe/.msi (Windows), .dmg/.pkg (macOS), .deb/.AppImage (Linux) |
| Code Signing | EV certificates + notarization |

### M2: Dashboard Completo (Meses 2-4)

| Tarea | Detalle |
|---|---|
| Process Tree View | D3.js / react-flow con colores por riesgo |
| Network Map | Conexiones con geolocalización (MaxMind GeoIP local) |
| MITRE ATT&CK Heatmap | Técnicas detectadas coloreadas por frecuencia |
| File Timeline | Actividad de archivos con hashes y entropía |
| Alert Workflow | acknowledge, investigate, resolve, false positive |
| Event Explorer | Filtros avanzados + virtual scrolling para millones de eventos |
| AI Chat Panel | Contexto de eventos + alertas, respuestas streaming |
| Plugin Manager UI | Instalar, configurar, habilitar/deshabilitar plugins |
| System Tray | Minimizar a bandeja, notificaciones push, menú contextual |
| Keyboard Shortcuts | Navegación rápida entre vistas |

### M3: Reglas + Threat Intel (Meses 3-5)

| Tarea | Detalle |
|---|---|
| 50+ reglas YAML | Cobertura completa MITRE ATT&CK (todas las tácticas) |
| Sigma Rule Importer | Convertir reglas Sigma → CEL automáticamente |
| Threat Intel Framework | IOC local (STIX/CSV), feeds remotos |
| TI Plugins adicionales | AlienVault OTX, Hybrid Analysis, URLhaus |
| Rule Testing Framework | Tests unitarios para reglas, fixtures de eventos simulados |
| Community Rule Repo | Repositorio GitHub de reglas comunitarias |

### M4: Hardening (Meses 4-6)

| Tarea | Detalle |
|---|---|
| Performance | <5% CPU, <100MB RAM, benchmarks en CI |
| Backpressure System | Rate limiting adaptativo por collector |
| Error Recovery | Watchdog, reinicio automático de collectors caídos |
| Security Audit | Revisión de seguridad third-party |
| Fuzzing | libFuzzer para parsing de eventos, protobuf, reglas CEL |
| Penetration Testing | Pruebas de sandbox escape en plugins |
| Accessibility | WCAG 2.1 AA en UI |
| i18n | EN, ES, FR, DE, PT, JA (react-i18next) |
| Documentation | Guía de usuario, admin, developer, API reference |
| CI/CD | Multi-OS build matrix, release automation, SBOM |

---

# PARTE 2: v2.0 — PLATAFORMA ENTERPRISE

## Visión v2.0

Sentinel AI evoluciona de un asistente de seguridad **single-host** a una **plataforma de seguridad distribuida** con capacidades EDR, correlación avanzada, ML on-device, y gestión centralizada.

## Pilares de v2.0

| Pilar | Descripción | Valor |
|---|---|---|
| **Multi-Host** | Gestión centralizada de múltiples endpoints | Empresas, familias, labs |
| **EDR** | Response actions: kill process, quarantine file, isolate host | Respuesta activa a amenazas |
| **ML On-Device** | Detección de anomalías sin enviar datos a la nube | Zero-trust, privacidad |
| **Cloud Sync (opt-in)** | Backup cifrado, threat intel compartida, UI remota | Continuidad, colaboración |
| **Compliance** | CIS Benchmarks, informe GDPR, STIG | Empresas reguladas |
| **SIEM/SOAR** | Conectores Splunk, Elastic, Sentinel, webhooks | Integración enterprise |
| **Plugin Marketplace** | Plugins firmados, revisados, auto-update | Ecosistema |
| **Mobile Companion** | Dashboard read-only, push alerts | Movilidad |

---

## Arquitectura v2.0

```
┌──────────────────────────────────────────────────────────────────────┐
│                     SENTINEL AI v2.0                                  │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌─────────────┐   ┌──────────────┐   ┌──────────────┐              │
│  │ Mobile App  │   │ Desktop UI   │   │ Web Console  │              │
│  │ (iOS/Android)│   │ (Tauri v2)  │   │ (React SPA)  │              │
│  └──────┬──────┘   └──────┬───────┘   └──────┬───────┘              │
│         │                 │                  │                        │
│         └─────────┬───────┴──────────────────┘                        │
│                   ▼                                                   │
│  ┌─────────────────────────────────────────┐                         │
│  │          Management Server               │                         │
│  │  ┌─────────┐ ┌────────┐ ┌────────────┐  │                         │
│  │  │Fleet    │ │Cross-  │ │Alert       │  │                         │
│  │  │Manager  │ │Host    │ │Aggregator  │  │                         │
│  │  │         │ │Correl. │ │            │  │                         │
│  │  └─────────┘ └────────┘ └────────────┘  │                         │
│  │  ┌─────────┐ ┌────────┐ ┌────────────┐  │                         │
│  │  │Policy   │ │Compli- │ │Plugin      │  │                         │
│  │  │Engine   │ │ance    │ │Registry    │  │                         │
│  │  └─────────┘ └────────┘ └────────────┘  │                         │
│  └──────────────────┬──────────────────────┘                         │
│                     │ gRPC + mTLS                                     │
│         ┌───────────┼───────────┐                                     │
│         ▼           ▼           ▼                                     │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐                              │
│  │ Agent    │ │ Agent    │ │ Agent    │  ... (N agents)              │
│  │ Host A   │ │ Host B   │ │ Host C   │                              │
│  │ (Linux)  │ │ (Win)    │ │ (macOS)  │                              │
│  └──────────┘ └──────────┘ └──────────┘                              │
│         │           │           │                                     │
│         └───────────┴───────────┘                                     │
│                     │                                                 │
│  ┌──────────────────┴──────────────────────┐                         │
│  │           Cloud Sync (opt-in)            │                         │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ │                         │
│  │  │Encrypted │ │Threat    │ │Remote UI │ │                         │
│  │  │Backup    │ │Intel     │ │Proxy     │ │                         │
│  │  └──────────┘ └──────────┘ └──────────┘ │                         │
│  └─────────────────────────────────────────┘                         │
│                                                                       │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Features Detalladas

### 1. Multi-Host Management

| Componente | Descripción |
|---|---|
| **Management Server** | `sentinel-mgmt` binary: API central, fleet queries, policy distribution |
| **Agent Registration** | Enrolamiento con PSK o mTLS, certificados x509 |
| **Fleet Overview** | Dashboard multi-host: health, risk, alerts por endpoint |
| **Fleet Queries** | Osquery-style: `SELECT * FROM processes WHERE name LIKE '%powershell%'` |
| **Policy Engine** | Distribuir reglas, configuraciones, exclusiones a grupos de hosts |
| **Cross-Host Correlation** | Detectar ataques que saltan entre hosts (lateral movement chains) |
| **Host Groups** | Tags: production, staging, user-workstations, servers |
| **RBAC** | Roles: admin, analyst, viewer; permisos por grupo de hosts |
| **Audit Log** | Quién hizo qué, cuándo (para compliance) |

#### Protocolo de Comunicación

```
Agent ←→ Management Server via gRPC + mTLS

Services:
  AgentService:
    rpc Register(RegisterRequest) returns (RegisterResponse);
    rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);
    rpc StreamEvents(stream Event) returns (stream Command);
    rpc ExecuteCommand(CommandRequest) returns (CommandResponse);

  ManagementService:
    rpc QueryFleet(FleetQuery) returns (FleetResponse);
    rpc PushPolicy(PolicyUpdate) returns (stream PolicyAck);
    rpc GetAgentStatus(AgentId) returns (AgentStatus);
```

### 2. EDR — Endpoint Detection & Response

| Acción | Descripción | Riesgo |
|---|---|---|
| **Kill Process** | Terminar PID sospechoso | Medio |
| **Quarantine File** | Mover archivo a zona segura, hashear | Medio |
| **Block Network** | Añadir regla iptables/nftables/WFP | Alto |
| **Isolate Host** | Bloquear todo tráfico excepto al management server | Alto |
| **Collect Forensic Snapshot** | Process list, network, files, registry, memory strings | Bajo |
| **Remote Shell** | Shell read-only (auditado) para investigación | Alto |
| **Remediation Playbook** | Secuencia de acciones automatizadas (ej: detect → kill → quarantine → notify) | — |

#### Ejemplo Playbook YAML:

```yaml
playbook:
  id: "ransomware-response"
  name: "Ransomware Response"
  trigger:
    rule_ids: ["ransomware-file-encryption", "shadow-copy-delete"]
    min_risk: 800
  actions:
    - action: isolate_host
    - action: kill_process_tree
    - action: collect_snapshot
    - action: notify_all
      channels: [discord, telegram, email]
    - action: create_ticket
      system: "jira"
```

### 3. Machine Learning On-Device

| Modelo | Técnica | Detección |
|---|---|---|
| **Process Anomaly** | Isolation Forest | Process behavior outlier detection |
| **Network Anomaly** | Autoencoder (LSTM) | Unusual traffic patterns, C2 beaconing |
| **File Entropy** | Statistical + Heuristic | Packed/encrypted executables |
| **User Behavior** | Bayesian Changepoint | Deviations from normal activity |
| **Parent-Child** | Markov Chain | Unusual process lineage |

#### Arquitectura ML:

```
┌──────────────────────────────────────────┐
│              ML Engine (per-agent)        │
├──────────────────────────────────────────┤
│  Feature Extractor                        │
│    └─► Process features (256-dim vector)  │
│    └─► Network features (128-dim)         │
│    └─► File features (64-dim)             │
│                                           │
│  Model Runtime (ONNX)                     │
│    └─► Isolation Forest (sklearn → ONNX)  │
│    └─► Autoencoder (PyTorch → ONNX)       │
│    └─► Inference < 5ms CPU                │
│                                           │
│  Training (offline)                       │
│    └─► Periodic retraining with local data│
│    └─► Federated: share model weights,    │
│        never raw data                     │
└──────────────────────────────────────────┘
```

### 4. Compliance Automation

| Framework | Checks |
|---|---|
| **CIS Benchmarks** | Level 1 + 2 para Linux, Windows, macOS |
| **GDPR** | Inventario de datos personales, datos en logs, retention |
| **PCI-DSS** | Segmentación de red, acceso a datos de tarjeta |
| **STIG** | DISA STIGs para RHEL, Windows Server |
| **ISO 27001** | Controles de acceso, monitoreo, respuesta a incidentes |

#### Compliance Engine:

```
Policy as Code (Rego/OPA):

package sentinel.compliance.cis_ubuntu_22

deny[msg] {
  input.sysctl["net.ipv4.ip_forward"] != 0
  msg := "CIS 3.1.1: IP forwarding must be disabled"
}

deny[msg] {
  input.sshd_config["PermitRootLogin"] != "no"
  msg := "CIS 5.2.10: Root login must be disabled"
}
```

### 5. SIEM/SOAR Integrations

| Sistema | Tipo | Protocolo |
|---|---|---|
| **Splunk** | SIEM | HEC (HTTP Event Collector) |
| **Elastic Stack** | SIEM | Elasticsearch Bulk API |
| **Microsoft Sentinel** | SIEM | Log Analytics Data Collector |
| **Wazuh** | XDR | wazuh-syscheckd protocol |
| **TheHive** | SOAR | REST API (alertas → casos) |
| **Webhook Genérico** | Custom | JSON POST |

### 6. Plugin Marketplace

| Funcionalidad | Detalle |
|---|---|
| **Registry** | GitHub Releases + checksums |
| **Signing** | Plugins firmados con cosign/SSH key |
| **Review Process** | Automated + manual para featured |
| **Auto-update** | Check for updates, verify checksum, hot-reload |
| **Ratings** | Community reviews, downloads, security score |
| **Categories** | Threat Intel, Notification, Automation, SIEM |

### 7. Cloud Sync (Opt-in)

| Feature | Descripción |
|---|---|
| **Encrypted Backup** | Config, reglas, eventos cifrados con age/XChaCha20 |
| **Shared Threat Intel** | IOCs anonimizados compartidos (opt-in) |
| **Remote UI Proxy** | Acceder al dashboard via tunnel cifrado |
| **Mobile Push** | Notificaciones push via Firebase/APNs |
| **Sync Dashboard** | Estado de todos los hosts desde cualquier lugar |

### 8. Mobile Companion

| Plataforma | Tecnología |
|---|---|
| iOS | SwiftUI + gRPC client |
| Android | Jetpack Compose + gRPC client |
| Funciones | Dashboard read-only, alert push, acknowledge, chat AI |
| Autenticación | PSK + mTLS al management server |

---

## Roadmap v2.0

```
MES  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16 17 18
      ├─────────────┤├─────────────────────┤├──────────────────┤
      │   FASE 1     ││      FASE 2         ││     FASE 3       │
      │ Multi-Host   ││   EDR + ML          ││ Compliance +     │
      │ Foundation   ││                     ││ Ecosystem        │
      ├─────────────┤├─────────────────────┤├──────────────────┤
      │ Agent Comm   ││ ML Engine (ONNX)    ││ CIS Benchmarks   │
      │ Mgmt Server  ││ ML Models Training  ││ SIEM Connectors  │
      │ Fleet API    ││ Kill/Quarantine     ││ Plugin Registry  │
      │ Cross-Host   ││ Isolate Host        ││ Mobile App       │
      │ RBAC/Audit   ││ Forensic Snapshots  ││ Cloud Sync (opt) │
      │ Policy Engine││ Remediation PBooks  ││ SOAR (TheHive)   │
      │ Osquery-style││ Remote Shell        ││ Marketplace      │
      └─────────────┘└─────────────────────┘└──────────────────┘
                          │ Release v2.0-beta  │   Release v2.0  │
                          │ Mes 12              │   Mes 18         │
```

---

## Fases Detalladas

### FASE 1: Multi-Host Foundation (Meses 1-6)

**Objetivo:** Un management server central que gestione múltiples agentes con políticas centralizadas.

| # | Tarea | Semanas |
|---|---|---|
| 1.1 | **Agent Communication Layer**: gRPC bidirectional streaming con mTLS, heartbeats, reconnect | 3 |
| 1.2 | **Management Server Binary** (`sentinel-mgmt`): API Gateway, agent registry, fleet state | 3 |
| 1.3 | **Agent Enrolment**: PSK o certificado x509, registro automático, host identity | 2 |
| 1.4 | **Fleet Dashboard**: vista multi-host en UI (health cards, risk summary, alert feed agregado) | 3 |
| 1.5 | **Cross-Host Correlation**: chains que saltan entre hosts (ej: phishing → RDP → lateral movement) | 4 |
| 1.6 | **Policy Engine**: distribuir rules/configs/plugins a grupos de hosts, versionado de políticas | 3 |
| 1.7 | **Fleet Queries**: Osquery-style SQL para consultar cualquier host en tiempo real | 3 |
| 1.8 | **RBAC + Audit Log**: roles admin/analyst/viewer, log de todas las acciones | 2 |
| 1.9 | **Host Groups + Tags**: agrupar hosts por entorno, criticidad, SO | 1 |

**Entregable:** Management server funcional gestionando N agentes, fleet dashboard, cross-host correlation chains.

### FASE 2: EDR + Machine Learning (Meses 7-12)

**Objetivo:** Capacidades de respuesta activa y detección de anomalías con ML local.

| # | Tarea | Semanas |
|---|---|---|
| 2.1 | **Process Kill**: matar proceso por PID, con confirmación y registro | 1 |
| 2.2 | **File Quarantine**: mover archivo a directorio seguro, conservar hash + metadata | 1 |
| 2.3 | **Network Block**: iptables/nftables (Linux), WFP (Windows), pf (macOS) | 2 |
| 2.4 | **Host Isolation**: regla DROP all except management server, botón de des-aislar | 2 |
| 2.5 | **Forensic Snapshot**: colectar procesos, conexiones, archivos, registros en un ZIP cifrado | 2 |
| 2.6 | **Remote Shell**: terminal read-only vía gRPC stream, auditado, sin ejecución | 2 |
| 2.7 | **Remediation Playbooks**: YAML-based workflows con acciones encadenadas + condiciones | 2 |
| 2.8 | **ML Engine Core**: feature extractor pipeline + ONNX runtime integrado | 3 |
| 2.9 | **Anomaly Detection Models**: Isolation Forest para procesos, Autoencoder para red | 4 |
| 2.10| **Model Training Pipeline**: scripts offline para entrenar con datos históricos | 3 |
| 2.11| **Federated Learning (opt-in)**: compartir pesos de modelo, nunca datos crudos | 3 |

**Entregable:** EDR response actions funcionales, ML engine integrado con detección de anomalías, playbooks automatizados.

### FASE 3: Compliance + Ecosystem (Meses 13-18)

**Objetivo:** Cumplimiento normativo automatizado, marketplace de plugins, y mobile companion.

| # | Tarea | Semanas |
|---|---|---|
| 3.1 | **CIS Benchmark Engine**: evaluador de políticas OPA/Rego, reportes HTML/PDF | 3 |
| 3.2 | **CIS Profiles**: Ubuntu 22.04 L1/L2, Windows 11 L1, macOS Ventura L1 | 3 |
| 3.3 | **GDPR Module**: escaneo de datos personales en logs, métricas de retención | 2 |
| 3.4 | **SIEM Connectors**: Splunk HEC, Elasticsearch Bulk, Sentinel Log Analytics | 3 |
| 3.5 | **SOAR Integration**: TheHive API (crear casos desde alertas), webhooks | 2 |
| 3.6 | **Plugin Registry**: GitHub Releases + API para listar, descargar, verificar plugins | 2 |
| 3.7 | **Plugin Marketplace UI**: buscar, instalar, calificar plugins desde la UI | 2 |
| 3.8 | **Mobile iOS App**: SwiftUI dashboard read-only, push notifications, acknowledge alert | 3 |
| 3.9 | **Mobile Android App**: Jetpack Compose, mismas capacidades | 3 |
| 3.10| **Cloud Sync**: backup cifrado, threat intel compartida, remote UI proxy | 3 |
| 3.11| **v2.0 GA**: release completo, docs, migration guide v1→v2, anuncio | 2 |

**Entregable:** Compliance engine con CIS/GDPR reports, SIEM/SOAR conectores, marketplace público, mobile apps.

---

## Stack Tecnológico v2.0

| Componente | v0.1.0 (actual) | v1.0 | v2.0 |
|---|---|---|---|
| **Core** | Rust | Rust | Rust |
| **UI** | Tauri + React | Tauri v2 + React | + React SPA (Web Console) |
| **Mobile** | — | — | SwiftUI + Jetpack Compose |
| **API** | gRPC (tonic) | gRPC + mTLS | gRPC + REST Gateway |
| **DB** | SQLite + DuckDB | + PostgreSQL (mgmt server) | + TimescaleDB |
| **ML** | — | — | ONNX Runtime |
| **Compliance** | — | — | OPA/Rego |
| **Fleet Queries** | — | — | osquery-style SQL |
| **Auth** | — | PSK | LDAP/OIDC + mTLS |
| **Message Queue** | Tokio channels | + NATS (mgmt ↔ agent) | NATS |
| **Cloud** | — | — | Optional: S3/MinIO |
| **Observability** | Prometheus + Loki | + Grafana dashboards | + OpenTelemetry traces |

---

## Estimación de Recursos

| Perfil | Fase 1 | Fase 2 | Fase 3 |
|---|---|---|---|
| Backend Engineer 1 (Rust, sistemas) | 6 meses | 6 meses | 6 meses |
| Backend Engineer 2 (Rust, networking, crypto) | 6 meses | 6 meses | 6 meses |
| ML/Data Engineer | — | 3 meses | 3 meses |
| Frontend Engineer (React/TS) | 4 meses | 3 meses | 3 meses |
| Mobile Engineer (Swift/Kotlin) | — | — | 4 meses |
| Security Engineer (rules, compliance) | 3 meses | 3 meses | 4 meses |
| DevOps/SRE | 2 meses | 3 meses | 3 meses |

**Total:** ~4-7 personas × 18 meses para v2.0 completo. Con un equipo de 2-3, priorizar Fase 1 + Fase 2 parcial.

---

## Riesgos y Mitigaciones

| Riesgo | Prob. | Impacto | Mitigación |
|---|---|---|---|
| Complejidad mTLS + cert management | Alta | Alto | Empezar con PSK, migrar a mTLS en v2.1 |
| ML falsos positivos | Alta | Medio | Modo "solo alerta" inicial, feedback loop |
| Latencia fleet queries (>100 agents) | Media | Alto | Arquitectura pub/sub con NATS, queries async |
| EDR acciones destructivas (kill/isolate) | Media | Crítico | Confirmación manual, dry-run mode, undo |
| Plugin seguridad (sandbox escape) | Baja | Crítico | gRPC sandbox, seccomp/AppContainer, firmas |
| Adopción mobile apps | Media | Bajo | Priorizar Web Console responsive primero |

---

## Métricas de Éxito v2.0

| Métrica | Target |
|---|---|
| Agentes gestionados simultáneamente | 1,000+ |
| Latencia fleet query (P95) | < 2 segundos |
| Falsos positivos ML | < 5% |
| Tiempo de respuesta EDR (alert → acción) | < 30 segundos |
| Cobertura MITRE ATT&CK | > 80% de técnicas |
| Plugins en marketplace | 50+ |
| CSAT (customer satisfaction) | > 4.5/5 |

---

## Próximos Pasos Inmediatos

1. Completar v0.1.0 → v1.0 (colectores Windows/macOS, browser, dashboard visualizaciones, hardening)
2. Definir protocolo Agent ↔ Management Server (protobuf)
3. Prototipo de management server con 2 agentes locales
4. Primer fleet dashboard con datos mock

---

*Plan Version: 1.0 — Para revisión y priorización*
