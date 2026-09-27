# Registro de cambios

Formato basado en [Keep a Changelog](https://keepachangelog.com/es/).

## [0.2.0] - En desarrollo

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
