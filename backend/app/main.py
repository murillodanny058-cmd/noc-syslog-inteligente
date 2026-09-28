"""
Servidor principal del NOC Syslog Inteligente.
  - /api/...  -> la API (inventario, syslog, eventos, incidentes, dashboard,
                 herramientas y auditoría)
  - /docs     -> documentación interactiva de la API
  - /         -> el dashboard web (carpeta frontend/)
"""
from fastapi import Depends, FastAPI, Query
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from . import models
from .config import APP_NAME, APP_VERSION, BASE_DIR
from .database import Base, engine, get_db
from .routers import dashboard, devices, herramientas, incidents, syslog

# Crea las tablas si no existen
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description="NOC basado en Syslog con defensa frente a acciones de agentes de IA. "
                "**Todos los equipos y eventos son SIMULADOS.**",
)

# Módulos de la API
app.include_router(dashboard.router)
app.include_router(devices.router)
app.include_router(syslog.router)
app.include_router(incidents.router)
app.include_router(herramientas.router)


@app.get("/api/health", tags=["Sistema"], summary="Chequeo de salud")
def health():
    """Si responde, el servidor y la BD están bien."""
    return {"status": "ok", "app": APP_NAME, "version": APP_VERSION}


@app.get("/api/audit", tags=["Auditoría"], summary="Ver registro de auditoría (solo lectura)")
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