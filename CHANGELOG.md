# Registro de cambios

Formato basado en [Keep a Changelog](https://keepachangelog.com/es/).

## [0.2.0] - En desarrollo

### Fase 4 — Dashboard, filtros e incidentes

- Gestión de incidentes (`/api/incidents`): creación manual y desde eventos, asignación, seguimiento y cierre.
- Máquina de estados: abierto → asignado → en_progreso → cerrado, con reglas de transición.
- Resolución obligatoria para cerrar, incidentes cerrados inmutables y prevención de duplicados.
- Endpoint de resumen para el dashboard (`/api/dashboard/resumen`).
- Dashboard web responsivo (HTML, CSS y JavaScript sin frameworks) con 4 vistas.
- Filtros por fecha, marca, equipo, severidad y sospechosos.
- Semáforo de equipos con ventana de mantenimiento.
- Protección contra XSS: todo texto proveniente de los logs se escapa antes de mostrarse.
- Indicador de conexión y actualización automática cada 15 segundos.
- Documentación: historias HU-11 a HU-15, pruebas de la Fase 4 y ciclo de vida de incidentes.

### Fase 3 — Recepción y clasificación Syslog

- Parser multimarca: RFC 3164, RFC 5424, Cisco IOS, Huawei VRP y Fortinet FortiOS.
- Cálculo de facility y severidad (0 a 7) a partir del PRI.
- Motor de ingesta con asociación al inventario por IP de origen.
- Deduplicación por huella SHA-256 con ventana de 60 segundos.
- Control de tormentas: máximo 120 eventos nuevos por origen por minuto.
- Detección de inyección de instrucciones dirigidas a agentes de IA, con alerta en auditoría.
- Limpieza de caracteres de control y límite de tamaño de los mensajes.
- Endpoints: `/api/syslog/parse`, `/ingest`, `/import`, `/simulate`, `/api/events` y `/api/events/stats`.
- Simulador de tráfico con los formatos reales de cada fabricante.
- Receptor Syslog UDP real (puerto 5514) con lista permitida de redes.
- Emisor UDP de prueba.
- Documentación: arquitectura y flujos, historias de usuario HU-06 a HU-10 y pruebas de la Fase 3.

### Fase 2 — Inventario de equipos

- CRUD de equipos: listar, consultar, crear, editar y eliminar (`/api/devices`).
- Filtros por marca, estado y texto de búsqueda.
- Validación de datos con esquemas Pydantic (IP, marca, estado, nombre).
- Regla de seguridad: los equipos simulados solo aceptan IP de documentación (RFC 5737).
- Protección contra nombres duplicados (409).
- Protección para no eliminar equipos con eventos o incidentes asociados.
- Registro de auditoría en cada creación, edición y eliminación.
- Endpoint de solo lectura para consultar la auditoría (`/api/audit`).
- Documentación: planteamiento, modelo de datos, historias de usuario y pruebas funcionales.

## [0.1.0] - 2026-09-26 — Versión alfa

### Fase 1 — Estructura y base de datos

- Estructura del proyecto, configuración y modelo de datos (SQLite + SQLAlchemy).
- Tablas: devices, syslog_events, incidents, action_proposals, audit_log.
- Carga de 4 equipos simulados con IP de documentación (RFC 5737).
- Servidor FastAPI con endpoint `/api/health`.
