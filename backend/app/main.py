"""
Servidor principal del NOC Syslog Inteligente.
  - /api/...      -> la API. Todo exige sesión, excepto /api/health y el login.
  - /api/serial/* -> consola real por cable de consola (Fase 9)
  - /docs         -> documentación interactiva (inicie sesión primero en el dashboard)
  - /login.html   -> página de inicio de sesión
  - /             -> el dashboard web
"""
from fastapi import Depends, FastAPI, Query
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from . import models
from .config import APP_NAME, APP_VERSION, BASE_DIR
from .database import MOTOR, Base, engine, get_db
from .routers import (alertas, auth, consola_real, dashboard, devices, herramientas, incidents,
                      politica,puertos, syslog, usuarios)
from .seguridad import autorizar

# Crea las tablas que falten (incluye users, user_sessions y notifications)
Base.metadata.create_all(bind=engine)

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
for modulo in (dashboard, devices, syslog, incidents, herramientas, politica, usuarios, alertas,
               consola_real, puertos):
    app.include_router(modulo.router, dependencies=PROTEGIDO, responses=RESPUESTAS)


@app.get("/api/health", tags=["Sistema"], summary="Chequeo de salud (público)")
def health():
    """Si responde, el servidor y la BD están bien."""
    return {"status": "ok", "app": APP_NAME, "version": APP_VERSION, "base_datos": MOTOR}


@app.get("/api/audit", tags=["Auditoría"], summary="Ver registro de auditoría (aprobador o administrador)",
         dependencies=PROTEGIDO, responses=RESPUESTAS)
def ver_auditoria(limite: int = Query(20, ge=1, le=200), db: Session = Depends(get_db)):
    """Últimos registros de auditoría, del más reciente al más antiguo."""
    registros = (db.query(models.AuditLog)
                 .order_by(models.AuditLog.id.desc())
                 .limit(limite).all())
    return [
        {"id": r.id, "fecha": r.timestamp, "actor": r.actor, "accion": r.action,
         "entidad": r.entity_type, "entidad_id": r.entity_id, "detalle": r.details}
        for r in registros
    ]


# Dashboard web. Se monta AL FINAL para que no tape las rutas /api y /docs.
app.mount("/", StaticFiles(directory=BASE_DIR / "frontend", html=True), name="frontend")

# --- FIN DEL ARCHIVO ---