"""
Servidor principal del NOC Syslog Inteligente.
  - /api/...      -> la API. Todo exige sesión, excepto /api/health y el login.
  - /api/serial/* -> consola real por cable de consola (Fase 9)
  - /docs         -> documentación interactiva (inicie sesión primero en el dashboard)
  - /login.html   -> página de inicio de sesión
  - /             -> el dashboard web
"""

import time

from fastapi import Depends, FastAPI, Query
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from . import auditor as auditor_mod
from . import models, vigilancia
from .config import APP_NAME, APP_VERSION, BASE_DIR
from .database import MOTOR, Base, SessionLocal, engine, get_db
from .routers import (
    alertas,
    auditor,
    auth,
    cambios,
    consola_real,
    dashboard,
    devices,
    herramientas,
    incidents,
    politica,
    puertos,
    syslog,
    usuarios,
)
from .seguridad import autorizar

# Crea las tablas que falten (incluye users, user_sessions y notifications)
Base.metadata.create_all(bind=engine)

# v1.1.0: vigilancia por ping de los equipos reales (solo si NOC_MONITOREO_PING=true en el .env)
vigilancia.iniciar_ping()

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description="NOC basado en Syslog con defensa frente a acciones de agentes de IA. "
    "Para usar esta página, inicie sesión primero en el dashboard.",
)

# Todas las rutas protegidas pasan por 'autorizar' (sesión + permiso del rol)
PROTEGIDO = [Depends(autorizar)]

# Códigos de respuesta documentados en /docs
RESPUESTAS = {
    401: {"description": "No ha iniciado sesión"},
    403: {"description": "Su rol no tiene permiso para esta acción"},
    404: {"description": "El recurso no existe"},
    409: {"description": "Conflicto con el estado actual (duplicado o estado no permitido)"},
}

app.include_router(auth.router, responses=RESPUESTAS)
for modulo in (
    dashboard,
    devices,
    syslog,
    incidents,
    herramientas,
    politica,
    usuarios,
    alertas,
    consola_real,
    puertos,
    cambios,
    auditor,
):
    app.include_router(modulo.router, dependencies=PROTEGIDO, responses=RESPUESTAS)


@app.get("/api/health", tags=["Sistema"], summary="Chequeo de salud (público)")
def health():
    """Si responde, el servidor y la BD están bien."""
    return {"status": "ok", "app": APP_NAME, "version": APP_VERSION, "base_datos": MOTOR}


@app.get(
    "/api/audit",
    tags=["Auditoría"],
    summary="Ver registro de auditoría (aprobador o administrador)",
    dependencies=PROTEGIDO,
    responses=RESPUESTAS,
)
def ver_auditoria(limite: int = Query(20, ge=1, le=200), db: Session = Depends(get_db)):
    """Últimos registros de auditoría, del más reciente al más antiguo."""
    registros = db.query(models.AuditLog).order_by(models.AuditLog.id.desc()).limit(limite).all()
    return [
        {
            "id": r.id,
            "fecha": r.timestamp,
            "actor": r.actor,
            "accion": r.action,
            "entidad": r.entity_type,
            "entidad_id": r.entity_id,
            "detalle": r.details,
        }
        for r in registros
    ]


# Fase 10: el navegador siempre revisa si hay una versión nueva del dashboard
# (evita que se quede con app.js o index.html viejos después de una actualización)
@app.middleware("http")
async def revisar_version_frontend(request, call_next):
    """Obliga al navegador a revisar si hay una versión nueva del dashboard (evita archivos viejos en
    caché).
    """
    respuesta = await call_next(request)
    if not request.url.path.startswith("/api"):
        respuesta.headers["Cache-Control"] = "no-cache"
    return respuesta


# Fase 12: registrar qué hace cada usuario (para el agente auditor).
# Se registra DESPUÉS de responder, con el usuario que 'autorizar' identificó
# (también los intentos sin permiso, código 403). No guarda cuerpos ni cookies.
@app.middleware("http")
async def registrar_actividad_usuario(request, call_next):
    """Después de cada petición, guarda en 'actividad' qué hizo el usuario (incluidos los intentos sin
    permiso).
    """
    inicio = time.monotonic()
    respuesta = await call_next(request)
    usuario = getattr(request.state, "usuario", None)
    if usuario and auditor_mod.debe_registrarse(request.method, request.url.path):

        def _guardar():
            """Escribe la actividad en la base en un hilo aparte; si falla, nunca afecta la respuesta al
            usuario.
            """
            db = SessionLocal()
            try:
                auditor_mod.registrar_actividad(
                    db,
                    usuario["username"],
                    request.method,
                    request.url.path,
                    request.url.query,
                    respuesta.status_code,
                    int((time.monotonic() - inicio) * 1000),
                )
            except Exception:
                db.rollback()  # la auditoría nunca debe tumbar la respuesta
            finally:
                db.close()

        await run_in_threadpool(_guardar)
    return respuesta


# Dashboard web. Se monta AL FINAL para que no tape las rutas /api y /docs.
app.mount("/", StaticFiles(directory=BASE_DIR / "frontend", html=True), name="frontend")

# --- FIN DEL ARCHIVO ---
