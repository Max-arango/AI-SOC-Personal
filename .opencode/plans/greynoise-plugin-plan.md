# Plan de Implementación — GreyNoise Plugin

## Resumen

GreyNoise analiza IPs y las clasifica como **benign** (scanners legítimos — Shodan, Censys, etc.), **malicious** (atacantes reales), o **unknown** (sin datos). A diferencia de otros feeds de threat intel que solo marcan IPs como "maliciosas", GreyNoise permite **filtrar ruido**: reducir falsos positivos cuando una IP detectada es solo un scanner benigno.

## API Reference

### Endpoint
```
GET https://api.greynoise.io/v3/community/{ip}
```

### Headers
```
key: <API_KEY>
Accept: application/json
```

### Response (Community API - FREE)
```json
{
  "ip": "71.6.233.43",
  "noise": true,
  "riot": false,
  "classification": "benign",
  "name": "Shodan",
  "last_seen": "2024-01-15",
  "link": "https://viz.greynoise.io/ip/71.6.233.43"
}
```

### Classification Values
| Value | Meaning | Action |
|---|---|---|
| `benign` | Scanner, crawler, CDN — known good | **Reduce risk** (-20, add tag `grey_noise_benign`) |
| `malicious` | Known attacker, C2, malware | **Boost risk** (+25, add tag `grey_noise_malicious`) |
| `unknown` | No data available | No action |

### Rate Limits
- Community API: 1000 requests/day (free)
- Enterprise API: unlimited (paid)

---

## Diseño del Plugin

### Estructura de Archivos
```
plugins/greynoise/
├── Cargo.toml
└── src/
    └── lib.rs
```

### Cargo.toml
```toml
[package]
name = "sentinel-plugin-greynoise"
version = { workspace = true }
edition = "2021"
license = { workspace = true }
publish = false

[dependencies]
reqwest = { version = "0.12", features = ["json"] }
serde = { workspace = true, features = ["derive"] }
tokio = { workspace = true }
tracing = { workspace = true }
```

### API Pública (`lib.rs`)

```rust
// ── Tipos ──
pub struct GreyNoiseReport {
    pub ip: String,
    pub classification: String,   // "benign" | "malicious" | "unknown"
    pub name: String,             // e.g., "Shodan", "Censys", "Mirai"
    pub is_noise: bool,           // true = scanner/bot benigno
    pub is_riot: bool,            // true = IP de servicio empresarial (RIOT)
    pub risk_modifier: i32,       // +25 (malicious), -20 (benign), 0 (unknown)
    pub recommendation: String,   // "ignore_noise" | "investigate" | "no_data"
}

// ── Funciones ──
pub fn enabled() -> bool
pub async fn check_ip(ip: &str) -> Option<GreyNoiseReport>
```

### Lógica de Enriquecimiento

```
GreyNoise check_ip(remote_addr)
  │
  ├── classification == "benign" 
  │   → risk_score += -20 (reduce, min 0)
  │   → tags += ["grey_noise:benign", "grey_noise:{name}"]
  │   → recommendation = "ignore_noise"
  │
  ├── classification == "malicious"
  │   → risk_score += 25 (boost)
  │   → tags += ["grey_noise:malicious", "grey_noise:{name}"]
  │   → recommendation = "investigate"
  │
  └── classification == "unknown" o error
      → no modificación
      → recommendation = "no_data"
```

---

## Integración en el Pipeline

### Ubicación en `core-service/main.rs`

El GreyNoise lookup se añade al `tokio::join!` existente junto con AbuseIPDB, Shodan y OTX:

```rust
// Línea ~333 — Añadir una cuarta future al join!
let (abuse_result, shodan_result, otx_result, greynoise_result) = tokio::join!(
    async { if sentinel_plugin_abuseipdb::enabled() { ... } else { None } },
    async { if sentinel_plugin_shodan::enabled() { ... } else { None } },
    async { if sentinel_plugin_otx::enabled() { ... } else { None } },
    async { if sentinel_plugin_greynoise::enabled() { 
        sentinel_plugin_greynoise::check_ip(&ip).await 
    } else { None } },  // ← NUEVO
);
```

### Bloque de Enriquecimiento

Se añade después del bloque de OTX (línea ~415) y antes del bloque de GeoIP:

```rust
if let Some(report) = greynoise_result {
    if report.classification == "malicious" {
        enriched_event.risk_score = enriched_event.risk_score.saturating_add(25);
        enriched_event.tags.push("grey_noise:malicious".into());
    } else if report.classification == "benign" {
        enriched_event.risk_score = enriched_event.risk_score.saturating_sub(20);
        enriched_event.tags.push("grey_noise:benign".into());
    }
    if !report.name.is_empty() {
        enriched_event.tags.push(format!("grey_noise:{}", report.name.to_lowercase()));
    }
    info!("GreyNoise: {} → {} ({})", ip, report.classification, report.name);
}
```

### Dependencias a Añadir

1. `apps/sentinel-core-service/Cargo.toml`: añadir `sentinel-plugin-greynoise`
2. `plugins/greynoise/` — crear plugin completo

---

## Manejo de Errores

| Escenario | Comportamiento |
|---|---|
| API key no configurada | `enabled() → false`, no se llama |
| API no responde (timeout 10s) | `warn!()`, retorna `None`, evento sigue sin modificar |
| HTTP 429 (rate limit) | `warn!()`, retorna `None` |
| Respuesta malformed | `warn!()`, retorna `None` |
| IP inválida | No es necesario chequear (el network collector solo tiene IPs válidas) |

---

## Configuración

```bash
# Variable de entorno requerida
export SENTINEL_GREYNOISE_API_KEY="<free-community-key>"
```

Sin API key, el plugin se desactiva silenciosamente (`enabled() → false`).

---

## Plan de Ejecución (30 min)

| Paso | Minutos | Tarea |
|---|---|---|
| 1 | 5 | Crear `plugins/greynoise/Cargo.toml` + `src/lib.rs` |
| 2 | 5 | Añadir dep en `core-service/Cargo.toml` |
| 3 | 10 | Integrar `tokio::join!` + enrichment block en `main.rs` |
| 4 | 5 | Compilar + verificar |
| 5 | 5 | Commit + push |

---

## Beneficio

- **Reduce falsos positivos**: IPs de Shodan/Censys que disparan alertas de "port scan" se marcan como benignas y su riesgo se reduce
- **Prioriza amenazas reales**: IPs clasificadas como "malicious" reciben boost adicional
- **Sin costo**: Community API es gratis (1000 req/día)
- **Complementa AbuseIPDB**: AbuseIPDB dice "esta IP es mala", GreyNoise dice "esta IP es solo un scanner"
