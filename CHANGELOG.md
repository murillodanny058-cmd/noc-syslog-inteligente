# Registro de cambios

Formato basado en [Keep a Changelog](https://keepachangelog.com/es/).

## [1.0.1] - 2026-10-24 — Calidad de código

- **Formato uniforme**: Python con `ruff format` (PEP 8, líneas de 110) y JavaScript, CSS y HTML con Prettier.
  Reglas guardadas en `pyproject.toml` y `.editorconfig` (4 espacios en Python, 2 en web, sin tabulaciones).
- **Análisis estático sin avisos**: `ruff check backend` → 0 problemas (antes 292). Se corrigieron una
  importación repetida, una sin usar, variables de una letra ambiguas y excepciones sin `from`.
- **Documentación del código**: 315 de 315 funciones y clases de Python con su descripción (antes 91 de 258)
  y las 64 funciones de JavaScript con un comentario de lo que hacen.
- **Funciones más simples**: `ejecutar_real` (consola) y `hallazgos_de` (auditor) se dividieron en partes
  pequeñas y con nombre propio; ninguna función queda en complejidad alta.
- `models.py`: las tablas de la Fase 12 usan el mismo estilo tipado (`Mapped`) que el resto.
- `styles.css`: se quitaron dos líneas duplicadas que dejaban una llave `}` de más.
- Sin cambios de funcionamiento: 31/31 pruebas automáticas OK y las 8 pestañas cargan sin errores.

## [1.0.0] - 2026-10-24 — Herramienta madura y marcha blanca

### Fase 12 — Agente auditor de usuarios con Hermes Agent
- Registro de la actividad de cada usuario (tabla `actividad`), incluidos los intentos sin permiso.
- Sesiones de LOGIN a LOGOUT con hallazgos por reglas (riesgo bajo, medio o alto).
- Informe redactado por **Hermes Agent (Nous Research)** por su API Server local; alternativas Claude o
  Gemini; modo por reglas si no hay IA. Pestaña "Auditoría IA" solo para el administrador.
- El agente solo lee y las instrucciones escondidas en los registros se le ocultan.

### Correcciones de la marcha blanca
- La consola real se reactiva sola cuando el equipo cierra la sesión por inactividad.
- El NOC reconoce la marca del equipo por el prompt y bloquea si no coincide con el equipo elegido.
- Aviso cuando no hay equipos reales registrados en lugar de elegir otro en silencio.
- "Proponer cambio" ya no permite doble envío.
- Eventos: no se permiten fechas futuras ni rango invertido (navegador y servidor).
- `.gitignore` limpio.

### Fase 11 — Cambios con aprobación humana
- Catálogo cerrado (envío de logs, descripción y estado de puerto), vista previa, separación de funciones,
  respaldo, ejecución por consola, rollback automático, verificación y deshacer. Alerta "cambio pendiente".

### Fase 10 — Puertos por evento
- Puerto de cada evento (botón 🔌), estado, VLAN, vecino CDP/LLDP y MAC; lectura por consola real.

### Fase 9 — Consola real por cable de consola
- Conexión por puerto COM sin IP, comandos de solo lectura, logs de la consola como eventos reales.
- Script `iniciar_noc.bat`.

### Fases 7 y 8
- PostgreSQL en la nube (Neon), usuarios con roles, sesiones seguras y bloqueo por fuerza bruta.
- Notificaciones por Telegram y correo con anti-saturación.

### Pruebas y operación
- `pruebas_v1`: 31 pruebas automáticas (funcionales, seguridad, carga y respaldo).
- `respaldo`: exportar y recuperar la base. Bitácora de marcha blanca, procedimiento de despliegue y
  rollback, manual técnico y guion de sustentación.

## [0.2.0] - 2026-09-28 — MVP

### Fase 6 — Política de defensa ante IA y cierre

- Flujo obligatorio de acciones: propuesta, revisión humana, aprobación, ejecución autorizada (simulada), verificación y auditoría (`/api/proposals`).
- Un agente de IA puede proponer, pero nunca aprobar; sus propuestas sospechosas se rechazan automáticamente.
- Suspensión automática de agentes de IA tras 3 acciones rechazadas en 10 minutos (`/api/policy/agent-status`).
- Script de prueba del control de tormentas.
- Documentación: política de defensa ante IA, manual de usuario, índice de evidencias, historias HU-20 y HU-21, pruebas de la Fase 6 y README definitivo.

### Fase 5 — Generador de configuraciones y consola simulada

- Generador de configuraciones Syslog comentadas para Cisco IOS, Fortinet FortiOS y Huawei VRP (`/api/config/generate`).
- Advertencias de buenas prácticas: UDP sin cifrar, falta de NTP, nivel debug, IP pública.
- Protección contra inyección de configuración con patrones de caracteres permitidos.
- Consola simulada de solo lectura (`/api/console/exec`) con lista permitida, lista bloqueada explicada, bloqueo de encadenamientos y denegación por defecto.
- Abreviaturas de comandos (`sh run`, `dis logbuffer`) y filtro `| include`.
- Auditoría de cada comando (CONSOLE_CMD y CONSOLE_BLOCKED) con el actor: operador o agente_ia.
- Pestañas web Configuraciones y Consola (estilo PuTTY, con historial y modo agente de IA).
- Documentación: historias HU-16 a HU-19, pruebas de la Fase 5 y política de la consola.

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
