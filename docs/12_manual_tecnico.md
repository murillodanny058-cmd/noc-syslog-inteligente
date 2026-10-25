# Manual técnico — NOC Syslog Inteligente v1.0.0

## 1. Arquitectura

```
Equipos de red ──UDP 514/5514──► Receptor Syslog ─┐
Equipos de red ──cable consola──► Consola real ────┼─► Motor de ingesta ─► Base de datos (Neon / SQLite)
                                                   │        (parser, severidad, deduplicación,
Navegador (dashboard) ◄──HTTP── FastAPI (API) ◄────┘         tormentas, detección de inyección)
                                   │
                                   ├─► Notificaciones (Telegram / correo) con anti-saturación
                                   └─► Agente auditor ─► Hermes Agent (API local 127.0.0.1:8642)
```

| Capa | Tecnología |
|---|---|
| API y servidor web | Python, FastAPI, Uvicorn |
| Datos | SQLAlchemy 2; PostgreSQL (Neon) o SQLite |
| Interfaz | HTML, CSS y JavaScript sin frameworks |
| Consola real | pyserial (puerto COM) |
| Agente de IA | Hermes Agent (Nous Research) por su API Server compatible con OpenAI |

## 2. Estructura del código

| Ruta | Contenido |
|---|---|
| `backend/app/main.py` | Arranque, routers, middleware de caché y de actividad |
| `backend/app/seguridad.py` | Contraseñas scrypt, sesiones, tabla de permisos por rol (denegar por defecto) |
| `backend/app/ingest.py` / `syslog_parser.py` | Recepción, parser multimarca, deduplicación, tormentas, inyección |
| `backend/app/consola_serial.py` | Consola real: lectura del COM, prompt, `--More--`, logs como eventos, marca por prompt, reactivación |
| `backend/app/puertos.py` | Interfaces: extracción del nombre, lectura de `show/display`, simulados |
| `backend/app/cambios.py` | Catálogo de cambios, validación, respaldo, aplicación, verificación |
| `backend/app/auditor.py` | Sesiones de usuario, hallazgos por reglas, informe con Hermes / Claude / Gemini / reglas |
| `backend/app/notificaciones.py` | Telegram, correo y WhatsApp con filtros |
| `backend/app/routers/` | Endpoints por tema |
| `backend/scripts/` | `init_db`, `crear_admin`, receptor UDP, pruebas, respaldo |
| `frontend/` | `index.html`, `app.js`, `herramientas.js`, `puertos.js`, `cambios.js`, `auditor.js`, `styles.css` |

## 3. Tablas principales

`devices`, `syslog_events`, `incidents`, `audit_log`, `users`, `user_sessions`, `notifications`,
`action_proposals`, `puertos` (Fase 10), `cambios_config` (Fase 11), `actividad` e
`informes_auditoria` (Fase 12). Todas las fechas se guardan en UTC.

## 4. Variables de entorno (`.env`, nunca en GitHub)

| Variable | Uso |
|---|---|
| `DATABASE_URL` | PostgreSQL (Neon). Vacía = SQLite en `data/` |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | Alertas por Telegram |
| `NOTIF_SEV_TELEGRAM`, `NOTIF_MAX_HORA_TELEGRAM`, `NOTIF_SILENCIO_MIN` | Anti-saturación (sev ≤ 2, 10 por hora, 30 min de silencio) |
| `HERMES_API_URL`, `HERMES_API_KEY`, `HERMES_MODELO` | Agente auditor con Hermes Agent |
| `ANTHROPIC_API_KEY` / `GEMINI_API_KEY`, `IA_MODELO` | Alternativas si no hay Hermes |

## 5. Seguridad (resumen)

| Control | Dónde |
|---|---|
| Sesión en cookie HttpOnly; solo el hash del token en la base | `seguridad.py` |
| Roles operador / aprobador / administrador; lo no listado solo lo hace el administrador | `seguridad.PERMISOS` |
| Bloqueo tras 5 fallos en 10 minutos | `routers/auth.py` |
| Logs = datos no confiables; detección de inyección para IA | `ingest.py` |
| Consola de solo lectura, lista permitida, `enable` y `show running-config` bloqueados | `consola_serial.py` |
| Cambios solo del catálogo, aprobados por otra persona, con respaldo y rollback; nunca `write memory` | `cambios.py` |
| El NOC no opera si la marca del prompt no coincide con el equipo elegido | `consola_serial._verificar_marca` |
| Agente auditor: solo lee; las inyecciones se le ocultan; Hermes solo en `127.0.0.1` con clave | `auditor.py` |
| Toda acción queda en `audit_log` con el usuario real; cada petición en `actividad` | `main.py` |

## 6. Agente auditor (Fase 12)

1. Un middleware guarda cada petición del usuario (método, ruta, filtros, código HTTP); no guarda cuerpos ni cookies.
2. `auditor.analizar()` une `actividad` + `audit_log` y corta en sesiones de LOGIN a LOGOUT
   (detecta sesiones sin cierre, vencidas e intentos fallidos).
3. Reglas fijas asignan riesgo bajo / medio / alto.
4. Hermes redacta el informe con un resumen ya saneado. Si Hermes no responde, el informe se hace por reglas.

## 7. Operación diaria

- Iniciar: `iniciar_noc.bat`. Hermes: `hermes gateway run` (o su tarea programada).
- Respaldo: `python -m backend.scripts.respaldo exportar`.
- Verificación: `python -m backend.scripts.pruebas_v1`.
- Despliegue y rollback: ver [11_despliegue_rollback.md](11_despliegue_rollback.md).
