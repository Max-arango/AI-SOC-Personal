# Auditoría Crítica del Plan v2.0 — Análisis Multidimensional

> Este documento audita el plan v2.0 de Sentinel AI desde las dimensiones de seguridad, privacidad, confidencialidad, integridad, disponibilidad, escalabilidad y anonimato. No es un documento de aprobación — es un documento de tensión. Cada riesgo se expone sin suavizar.

---

## 0. Contradicción Fundacional

**El plan v2.0 entra en conflicto directo con la filosofía original del proyecto.**

| Principio fundacional | Qué dice | Qué hace v2.0 |
|---|---|---|
| *"Local-first"* (README) | Los datos no salen de la máquina del usuario | StreamEvents envía **todos** los eventos al Management Server central |
| *"Priorizar privacidad"* (Plan Infra) | Funcionar principalmente local | Fleet queries permiten consultar procesos, archivos y conexiones de cualquier host remotamente |
| *"No data leaves without consent"* (README) | Opt-in explícito por feature | Mobile push (Firebase/APNs) filtra metadatos aunque el contenido esté cifrado; SIEM connectors exponen datos a terceros |
| *"Privacy-preserving"* (README) | IA local, sin telemetría | Federated learning comparte pesos de modelo entrenados con datos del usuario — membership inference risk |
| *"AI local only"* (config) | Ollama/llama.cpp local | Remote UI expone el dashboard a través de la nube; Remote Shell permite acceso remoto al endpoint |

**Conclusión:** v2.0 transforma Sentinel AI de un asistente local a un **sistema de vigilancia centralizado con capacidades de control remoto**. Esto no es inherentemente malo (es lo que hace cualquier EDR empresarial), pero **contradice la misión fundacional del proyecto**. El plan debe reconocer explícitamente este cambio de paradigma y ofrecer un modo "solo local" que mantenga la filosofía original como opción permanente.

---

## 1. Confidencialidad — Riesgos de Exposición de Datos

### 1.1 Concentración de Datos en Management Server (CRÍTICO)

**Problema:** `StreamEvents(stream Event) returns (stream Command)` envía cada evento de cada agente al servidor central. Esto incluye:

- Command lines completas con argumentos (posibles contraseñas en línea de comandos)
- Paths de archivos (estructura del sistema de archivos del usuario)
- Conexiones de red (IPs, puertos, protocolos — perfil de navegación)
- Procesos (qué software usa el usuario, cuándo)
- Hashes de archivos (huella digital de binarios)
- Contexto de correlación (cadenas de ataque que revelan vulnerabilidades)

**Impacto:** Un solo punto de compromiso expone los datos de telemetría de seguridad de TODOS los hosts. Si el Management Server es comprometido, el atacante obtiene:

- Inventario completo de software y versiones en todos los hosts → superficies de ataque
- Hábitos de navegación y conexiones de red
- Estructura de directorios sensible
- Posibles credenciales en líneas de comandos

**Mitigación existente en el plan:** mTLS en tránsito. **Insuficiente.** mTLS protege el canal, no los datos en reposo en el servidor.

**Mitigación necesaria NO en el plan:**
- **Data minimization**: no enviar command_lines completas, solo hashes o primeras N tokens
- **Anonymization pipeline**: antes de llegar al management server, redactar PII (paths de home, usuarios, IPs internas)
- **Encryption at rest** en el management server con claves por host (no una clave maestra)
- **Retention policy automática**: eliminar eventos tras N días, con auditoría de eliminación
- **Campo `privacy_level` por evento**: el agente marca eventos como `high` (nunca salir), `medium` (agregado), `low` (completo), y el stream respeta estos niveles

---

### 1.2 Mobile Push — Filtración de Metadatos (ALTO)

**Problema:** Firebase (Android) y APNs (iOS) requieren que el servidor envíe la notificación a los servidores de Google/Apple. Aunque el *contenido* esté cifrado, los metadatos NO:

- **Frecuencia de alertas** → revela si el usuario está bajo ataque activo
- **Timestamp de notificaciones** → patrón de actividad del usuario
- **Token de dispositivo** → vinculación con identidad Google/Apple
- **Severidad agregada** → perfil de riesgo del entorno

**Impacto:** Google/Apple pueden inferir el estado de seguridad del usuario. Un adversario con acceso a metadatos de notificaciones (ej: empleado de la plataforma, orden judicial) puede identificar objetivos de alto valor.

**Mitigación necesaria NO en el plan:**
- **Silent push + local fetch**: la notificación push solo despierta la app, que consulta al management server directamente (sin pasar datos por Firebase/APNs)
- **Frequency throttling**: máximo N notificaciones por hora para evitar perfilado temporal
- **WebSocket local**: modo LAN sin push (la app se conecta directamente al management server en red local)
- **Push deshabilitable**: que el usuario pueda elegir solo polling

---

### 1.3 Federated Learning — Filtración por Pesos de Modelo (MEDIO)

**Problema:** "Compartir pesos de modelo, nunca datos crudos" es una simplificación peligrosa. Técnicas de **model inversion** y **membership inference** permiten reconstruir datos de entrenamiento a partir de los pesos:

- Un Isolation Forest entrenado con procesos del usuario codifica qué procesos son "normales" → revela software instalado
- Un Autoencoder entrenado con tráfico de red codifica patrones de conexión → revela servicios usados
- **Gradient leakage**: en training distribuido, los gradientes compartidos pueden reconstruir batches de entrenamiento

**Impacto:** Un adversario que participa en el federated learning (o compromete el aggregator) puede extraer información sobre la actividad del endpoint.

**Mitigación necesaria NO en el plan:**
- **Differential Privacy (DP-SGD)**: añadir ruido calibrado a los gradientes antes de compartir (ε < 8)
- **Secure Aggregation**: los pesos se agregan sin que el servidor vea contribuciones individuales
- **Opt-in granular**: el usuario elige qué modelos participan en federated learning (ej: proceso sí, red no)
- **Entrenamiento 100% local por defecto**: federated desactivado, activación explícita

---

## 2. Integridad — Riesgos de Manipulación

### 2.1 Remote Shell — Puerta Trasera Potencial (CRÍTICO)

**Problema:** El plan propone "Shell read-only (auditado) para investigación". Incluso read-only:

- Un shell remoto es el vector de ataque más poderoso que existe
- "Read-only" es difícil de garantizar: `echo "payload" > /dev/shm/evil && chmod +x /dev/shm/evil && /dev/shm/evil` no requiere escritura en disco persistente
- Si el management server es comprometido, el atacante tiene shell en TODOS los agentes
- La auditoría solo sirve para forensic *después* del incidente

**Impacto:** Compromiso del management server = acceso shell a toda la flota. Es un risk multiplier extremo.

**Mitigación necesaria NO en el plan:**
- **Command whitelist estricta**: solo comandos predefinidos (`ps`, `netstat`, `ls`, `cat /proc/*`), nunca shell arbitrario
- **Just-In-Time (JIT) access**: el shell se habilita por tiempo limitado (máx 5 min) con aprobación de otro admin
- **Break-glass procedure**: el agente puede rechazar el shell si detecta anomalías en el management server
- **Read-only a nivel kernel**: usar seccomp/AppContainer para garantizar que el proceso del shell no puede ejecutar syscalls de escritura. El plan dice "read-only" pero no especifica cómo se garantiza.

---

### 2.2 EDR Playbooks — Automatización Peligrosa (CRÍTICO)

**Problema:** El playbook YAML de ejemplo (`ransomware-response`) ejecuta `isolate_host` automáticamente. Esto es una **denegación de servicio autoinfligida**:

- Un falso positivo en la regla `ransomware-file-encryption` aislaría el host legítimo
- No hay mecanismo de "human-in-the-loop" para acciones destructivas
- No hay rollback automático si el playbook fue disparado por error
- La acción `kill_process_tree` puede matar procesos críticos del sistema

**Impacto:** Un falso positivo del ML (recordar: el plan estima <5% FP = 50 de cada 1000 alertas son falsas) puede tumbar servidores de producción.

**Mitigación necesaria NO en el plan:**
- **Tiered response**: acciones se clasifican en tiers (T1: notificar, T2: requerir confirmación, T3: automático). Isolate/kill son T2 mínimo
- **Playbook simulation mode**: ejecutar en dry-run primero, mostrar qué pasaría
- **Blast radius limit**: máximo N hosts afectados por playbook automático en ventana de tiempo
- **Quorum requirement**: acciones T3 requieren confirmación de 2+ administradores
- **Dead man's switch**: si el agente no recibe heartbeat del management server en X minutos, revierte aislamiento

---

### 2.3 Plugin Marketplace — Supply Chain (CRÍTICO)

**Problema:** Plugins descargados de internet (GitHub Releases) que se ejecutan como procesos con capacidades de leer eventos y conectarse a red:

- Un plugin malicioso puede exfiltrar todos los eventos que lee (lee `event:read`)
- El "review process" descrito es vago: "Automated + manual para featured" — los no-featured no tienen revisión humana
- Si no hay revisión, el marketplace es un vector de ataque
- Los plugins se actualizan automáticamente (auto-update) → si un plugin legítimo es comprometido aguas arriba, todos los usuarios se actualizan al código malicioso

**Impacto:** Un plugin de notificación (Discord, Telegram) que es comprometido puede enviar todos los eventos del usuario al atacante. Un plugin de threat intel puede modificar scores de riesgo para ocultar actividad maliciosa.

**Mitigación necesaria NO en el plan:**
- **Sandboxing obligatorio por capability**: el plugin declara capacidades (`network:http`), el sandbox las enforce. El plan menciona capabilities pero no sandbox automático
- **Reproducible builds para plugins**: el hash del binario debe ser verificable desde el fuente
- **Transparency log (Rekor/Sigstore)**: cada release de plugin se registra en un log inmutable
- **Gradual rollout**: las actualizaciones se despliegan al 1% de usuarios primero, luego 10%, etc.
- **Plugin signing con hardware keys**: no solo SSH, sino HSMs/YubiKeys para developers

---

## 3. Privacidad — Datos Personales en el Pipeline

### 3.1 Fleet Queries — Acceso Ilimitado a Datos Personales (ALTO)

**Problema:** "Osquery-style SQL para consultar cualquier host en tiempo real" otorga al administrador del management server acceso a:

- `SELECT * FROM processes` → qué software ejecuta cada empleado, posible uso personal
- `SELECT * FROM network_connections` → hábitos de navegación, servicios usados
- `SELECT * FROM files WHERE path LIKE '/home/%'` → estructura de archivos personales
- `SELECT command_line FROM processes` → argumentos que pueden contener contraseñas, tokens, URLs personales

**Impacto:** Un administrador con acceso al management server puede realizar vigilancia masiva sobre los empleados. Esto viola GDPR (datos de empleados), leyes laborales europeas, y expectativas razonables de privacidad.

**Mitigación necesaria NO en el plan:**
- **Privacy-preserving queries**: no permitir SELECT sobre command_line, paths bajo /home, environment variables
- **Query audit log**: toda fleet query queda registrada con quién, qué, cuándo, y justificación
- **Differential Privacy en agregaciones**: `SELECT COUNT(*) FROM processes WHERE name='chrome'` devuelve count + ruido
- **Breakdown por host solo con consentimiento**: el detalle de un host específico requiere aprobación del usuario de ese host
- **Modo "personal" vs "enterprise"**: en modo personal (1-5 hosts del mismo dueño), fleet queries sin restricción. En modo enterprise, las restricciones aplican.

---

### 3.2 SIEM Connectors — Exfiltración Masiva (ALTO)

**Problema:** Los conectores SIEM envían eventos a Splunk, Elastic, Sentinel. Aunque el plan dice "opt-in":

- No hay granularidad: o envías todo o nada
- No hay transformación/anonymización antes de enviar
- El usuario pierde control sobre los datos una vez que salen (Splunk Cloud, Elastic Cloud)
- Los datos en un SIEM son accesibles por el equipo de seguridad, que puede no ser el usuario

**Impacto:** Los eventos de seguridad contienen PII indirecta: paths de usuario, IPs, software instalado, actividad horaria. Enviar esto a un SIEM externo puede violar GDPR si los datos salen de la UE, o regulaciones sectoriales (HIPAA, PCI).

**Mitigación necesaria NO en el plan:**
- **Transformer pipeline**: antes de enviar al SIEM, aplicar reglas de transformación (redactar home paths, user names → hashes)
- **Field whitelist por destino**: configurar qué campos se envían a cada SIEM
- **Data residency control**: forzar que el SIEM endpoint esté en la misma región geográfica
- **Auditoría de exfiltración**: registro de cuántos eventos y de qué tipo se enviaron a cada SIEM

---

## 4. Disponibilidad — Puntos Únicos de Fallo

### 4.1 Management Server como SPOF (CRÍTICO)

**Problema:** La arquitectura v2.0 es hub-and-spoke. Si el Management Server cae:

- Los agentes no pueden reportar eventos → el pipeline central de correlación se detiene
- Fleet queries no funcionan
- No se pueden aplicar políticas nuevas
- El dashboard multi-host queda ciego
- Si hay EDR actions pendientes de confirmación, quedan en limbo
- El Remote Shell no funciona
- Las mobile apps no reciben actualizaciones

**Impacto:** Toda la visibilidad y control centralizado depende de UN servidor. En un incidente de seguridad real, el atacante solo necesita tumbar el management server para cegar al equipo de seguridad.

**Mitigación necesaria NO en el plan:**
- **Modo autónomo del agente**: si el agente pierde conexión con el management server, sigue funcionando localmente (collectors, rules, risk, alerts locales)
- **Management server HA**: arquitectura active-passive o active-active con raft/paxos para el estado compartido
- **Local alerting fallback**: si el servidor central no responde, los agentes notifican directamente (Discord, Telegram) sin pasar por el hub
- **Agent buffer**: los agentes bufferean eventos localmente y los envían cuando el servidor vuelve (con backpressure para no saturar)
- **Health check independiente**: los agentes monitorean la salud del management server y cambian a modo autónomo automáticamente

---

### 4.2 mTLS — Dependencia de Infraestructura PKI (MEDIO)

**Problema:** Toda la comunicación agente↔servidor depende de mTLS con certificados x509. Esto requiere:

- Una CA interna (Vault, step-ca, cert-manager)
- Rotación de certificados
- Distribución de CRLs
- Manejo de certificados expirados
- Si la CA cae, no se pueden enrolar nuevos agentes ni rotar certificados existentes

**Impacto:** Una interrupción en la infraestructura PKI bloquea nuevas conexiones y eventualmente desconecta agentes existentes cuando sus certificados expiran.

**Mitigación necesaria NO en el plan:**
- **PSK como fallback**: el plan menciona "empezar con PSK" pero lo presenta como fase temporal. PSK debería ser una opción permanente para entornos pequeños
- **Certificado autofirmado con fingerprint pinning**: el agente acepta el certificado del servidor la primera vez (TOFU) y pinea el fingerprint
- **Grace period**: los agentes siguen funcionando N días con certificado expirado en modo degradado
- **Offline mode**: el agente funciona sin conexión al management server indefinidamente

---

## 5. Escalabilidad — Cuellos de Botella

### 5.1 StreamEvents Bidireccional — Buffer Explosion (ALTO)

**Problema:** Cada agente mantiene un stream gRPC bidireccional abierto con el management server. Con 1000 agentes:

- 1000 conexiones TCP persistentes al servidor
- 1000 goroutines/threads en el servidor
- Eventos fluyendo constantemente: 1000 agentes × ~50 eventos/segundo = 50,000 eventos/segundo
- El management server debe procesar, almacenar (PostgreSQL + TimescaleDB), correlacionar y reenviar
- PostgreSQL no está diseñado para 50k writes/segundo (requiere batching, partitioning, etc.)

**Impacto:** El management server se satura a partir de ~200-300 agentes si no hay optimización de escritura.

**Mitigación necesaria NO en el plan:**
- **Event batching en el agente**: enviar lotes de 100 eventos en vez de one-by-one
- **Sampling adaptativo**: en horas pico o alta carga, reducir sampling rate de eventos de baja severidad
- **Topic-based routing con NATS**: los eventos no van al servidor directamente, van a NATS topics; el servidor se suscribe
- **Escritura asíncrona con buffer**: usar WAL + write-ahead en PostgreSQL, o ClickHouse para eventos
- **Agregación local antes de enviar**: el agente pre-agrega eventos (counts por tipo) y envía agregados + raw events bajo demanda

### 5.2 Fleet Queries — Denegación de Servicio (MEDIO)

**Problema:** `SELECT * FROM processes` sobre 1000 hosts devuelve ~200,000 filas. Si un administrador ejecuta esto:

- El management server envía la query a todos los agentes
- Los agentes responden simultáneamente → thundering herd
- El servidor debe mergear y deduplicar 1000 respuestas
- La UI debe renderizar 200k filas

**Impacto:** Una fleet query mal construida puede saturar el management server y la red.

**Mitigación necesaria NO en el plan:**
- **Query timeout**: máximo 10 segundos por query
- **Row limit**: máximo 10,000 filas por query
- **Rate limiting por usuario**: máximo N fleet queries por minuto
- **Asynchronous queries**: la query se ejecuta en background y el resultado se notifica cuando está listo
- **Sampling**: `SELECT * FROM processes SAMPLE 10%` para queries exploratorias

---

## 6. Anonimato — Pérdida Total

**Problema:** El plan v2.0 no menciona el anonimato en absoluto. Cada feature lo erosiona:

| Feature | Impacto en anonimato |
|---|---|
| Agent registration (PSK/x509) | Cada host tiene identidad criptográfica persistente |
| Fleet dashboard | El administrador ve cada host individualmente con nombre, IP, health |
| Fleet queries | Acceso granular a procesos, archivos, conexiones por host |
| Audit log | Todas las acciones del administrador quedan registradas con timestamp + identidad |
| Mobile push | Token de dispositivo vinculado a identidad Google/Apple |
| Cloud Sync (threat intel compartida) | Los IOCs compartidos pueden incluir IP de origen, timestamps que revelan patrón de ataque |

**El anonimato simplemente no existe en la arquitectura v2.0.** Esto es aceptable para un producto enterprise, pero debe documentarse explícitamente: "v2.0 no es una herramienta anónima. Cada host, cada acción, cada evento es trazable a una identidad."

---

## 7. Cumplimiento Normativo — El Plan se Autosabotea

**Ironía:** El plan incluye compliance (CIS, GDPR, PCI-DSS) como feature, pero la arquitectura v2.0 **dificulta el cumplimiento**:

| Regulación | Problema |
|---|---|
| **GDPR Art. 25** (Data protection by design) | El plan no hace data minimization (envía eventos completos al servidor) |
| **GDPR Art. 32** (Security of processing) | Sin cifrado en reposo especificado para el management server |
| **GDPR Art. 44** (Transferencias internacionales) | Cloud Sync, SIEM connectors, y mobile push pueden transferir datos fuera de la UE |
| **PCI-DSS 3.4** (Render PAN unreadable) | Si eventos contienen datos de tarjeta (ej: command line de app de pago), no hay tokenización |
| **HIPAA** (si aplica) | Sin BAA con proveedores cloud (Firebase, APNs, Splunk Cloud), no se puede usar en healthcare |

---

## 8. Tabla Resumen de Riesgos

| # | Riesgo | Dimensión | Severidad | ¿Mitigado en el plan? |
|---|---|---|---|---|
| 1 | Concentración de datos en Management Server | Confidencialidad | CRÍTICO | No (solo mTLS) |
| 2 | Remote Shell como puerta trasera | Integridad | CRÍTICO | No (solo "auditado") |
| 3 | EDR playbooks automáticos sin human-in-the-loop | Integridad | CRÍTICO | No |
| 4 | Plugin marketplace supply chain | Integridad | CRÍTICO | Parcial (signing, no sandbox) |
| 5 | Management Server SPOF | Disponibilidad | CRÍTICO | No |
| 6 | Mobile push filtra metadatos | Privacidad | ALTO | No |
| 7 | Fleet queries acceso ilimitado | Privacidad | ALTO | No |
| 8 | SIEM connectors exfiltración masiva | Privacidad | ALTO | No (solo "opt-in") |
| 9 | Federated learning filtración | Confidencialidad | MEDIO | Parcial (differential privacy no especificada) |
| 10 | StreamEvents buffer explosion | Escalabilidad | ALTO | No |
| 11 | mTLS dependencia PKI | Disponibilidad | MEDIO | Parcial (PSK inicial) |
| 12 | Fleet queries DoS | Escalabilidad | MEDIO | No |
| 13 | Anonimato inexistente | Anonimato | ALTO | No mencionado |
| 14 | Cumplimiento normativo auto-contradictorio | Compliance | ALTO | No |
| 15 | Model inversion en ML | Confidencialidad | MEDIO | Parcial |

---

## 9. Recomendaciones Estructurales

### 9.1 Modo Dual: Local + Enterprise

La solución más importante: **Sentinel AI debe ofrecer dos modos de operación mutuamente excluyentes:**

| Modo | Descripción | Público |
|---|---|---|
| **Personal (v0.1.0-style)** | Local-first, sin management server, sin cloud. El pipeline original. | Usuarios individuales |
| **Enterprise (v2.0)** | Multi-host con management server, EDR, compliance. Con todas las mitigaciones de este documento. | Empresas |

El modo personal **debe mantenerse como producto independiente**, no como "v1.0 legacy". La UI debe tener un switch claro: "Estás en modo Personal. ¿Activar gestión centralizada?" — con explicación de implicaciones de privacidad.

### 9.2 Privacy Budget por Host

Cada host debe tener un **privacy budget** configurable que controle cuánta información comparte con el management server:

```yaml
privacy:
  share_command_lines: false
  share_file_paths: anonymized
  share_network_ips: anonymized
  share_user_names: hashed
  fleet_queries_require_approval: true
```

### 9.3 Agent Autonomy Guarantee

El agente debe ser **funcionalmente completo sin el management server**:

- Collectors, rules, correlation, risk, alertas → 100% local siempre
- Storage local con retention propia
- UI local (Tauri) funciona sin conexión al servidor
- El management server añade: fleet view, cross-host correlation, central policy, EDR commands

### 9.4 Threat Model Formal

Antes de implementar cualquier feature de v2.0, se debe escribir un documento de **threat model formal** (STRIDE o similar) que cubra:

- Adversario externo (compromete el management server)
- Adversario interno (administrador malicioso)
- Adversario supply chain (plugin malicioso)
- Adversario pasivo (metadatos de red, timing attacks)

---

## 10. Veredicto

El plan v2.0 es **técnicamente viable y valioso como producto enterprise**, pero:

1. **Traiciona la filosofía fundacional** sin reconocerlo. Necesita un modo "Personal" permanente.
2. **Subestima riesgos de seguridad críticos** (remote shell, playbooks automáticos, plugin supply chain) tratándolos como features sin las defensas correspondientes.
3. **No protege la privacidad del endpoint** en la arquitectura centralizada — asume que mTLS = privacidad, lo cual es falso.
4. **No es escalable a 1000 agentes** sin rediseño del pipeline de eventos y fleet queries.
5. **Carece de threat model** — los riesgos identificados en la sección de "Riesgos y Mitigaciones" del plan original son insuficientes (6 riesgos vs 15+ identificados aquí).
6. **Se auto-sabotea en compliance** — promete GDPR/CIS pero la arquitectura centralizada los viola.

**El plan no debe descartarse**, pero requiere un **rediseño de privacidad y seguridad** antes de comprometer recursos. Las 8 recomendaciones de mitigación por feature en este documento deben integrarse al plan como requisitos, no como "nice to have".

---

*Auditoría v1.0 — Para discusión y refinamiento del plan v2.0*
