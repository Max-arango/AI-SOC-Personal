# Plan de Dashboard de Visualizaciones — Sentinel AI

> Plan metodológico para las visualizaciones del dashboard. Cubre cada widget con sus requisitos de seguridad, privacidad, escalabilidad, integridad, disponibilidad y licencias open-source.

## Estado Actual

La UI tiene un Dashboard funcional con datos reales del backend (`invoke()` a Tauri), pero **solo en formato tabla/texto**. Las 7 páginas existen como placeholders. Faltan todas las visualizaciones gráficas.

## Widgets Planificados

### 1. Process Tree — `src/components/ProcessTree.tsx`
- Jerarquía de procesos (padre → hijo) desde `getProcesses()`
- `react-flow` v11 + `dagre` layout automático
- Seguridad: nombres sanitizados, PID no accionable sin confirmación
- Privacidad: detalle (path, cmdline) solo bajo click explícito
- Escalabilidad: virtualización, colapsa subárboles >50 hijos, límite 200 procesos

### 2. Network Map — `src/components/NetworkMap.tsx`
- Grafo de conexiones: nodos = IPs, aristas = conexiones, color por riesgo
- `react-flow` v11 + MaxMind GeoLite2 local
- Seguridad: IPs anonimizadas si PrivacyFilter activo, sin DNS inversa automática
- Privacidad: IPs locales como "Local", ocultables por usuario
- Escalabilidad: límite 200, agrupación /24 si >50 IPs

### 3. MITRE ATT&CK Heatmap — `src/components/MitreHeatmap.tsx`
- Matriz tácticas × severidad con colores (verde→rojo)
- `recharts` + Tailwind CSS
- Datos 100% agregados, sin IDs de eventos
- Pre-agregado en backend (~12 filas)

### 4. Risk Timeline — `src/components/RiskTimeline.tsx`
- Gráfico de líneas con risk score en el tiempo
- `recharts` LineChart + Tooltip + Brush
- Agregación DuckDB, máximo 1440 puntos
- Solo scores numéricos, sin nombres de reglas

### 5. Event Timeline (Virtual Scroll) — `src/components/EventTimeline.tsx`
- Lista infinita con scroll virtual
- `@tanstack/react-virtual` v3
- Paginación 100 eventos/página, solo ~20 filas en DOM
- Filtros avanzados en backend

## Dependencias Nuevas

| Paquete | Licencia | Uso | Tamaño |
|---|---|---|---|
| `reactflow` | MIT | Process Tree + Network Map | ~200KB |
| `recharts` | MIT | Risk Timeline + MITRE Heatmap | ~150KB |
| `@dagrejs/dagre` | MIT | Layout del process tree | ~20KB |
| `@tanstack/react-virtual` | MIT | Virtual scroll eventos | ~10KB |

## Timeline (3 semanas)

| Semana | Entregable |
|---|---|
| 1 | Process Tree + Risk Timeline. Backend `get_process_tree` + `get_risk_timeline`. |
| 2 | MITRE Heatmap + Event Timeline virtual scroll. Backend `get_mitre_heatmap`. |
| 3 | Network Map. Backend `get_network_graph`. Loading/Empty/Error states + responsive. |

## Dimensiones Garantizadas

- **Seguridad**: Backend sanitiza, frontend sin innerHTML, CSP en Tauri
- **Privacidad**: PrivacyFilter redacta antes de enviar a UI, datos agregados
- **Escalabilidad**: Virtual scroll + paginación + agregación backend, O(visible)
- **Open-source**: 100% librerías MIT/ISC/Apache 2.0
- **Confidencialidad**: Command lines, paths, IPs redactados vía PrivacyFilter
- **Integridad**: Badge stale, fallback SQLite si DuckDB no disponible
- **Disponibilidad**: Loading/empty/error states en todos los widgets
