"""
Servidor FastAPI mínimo para verificar que todo arranca.
En la Fase 2 agregaremos aquí los endpoints del inventario.
"""
from fastapi import FastAPI
from .config import APP_NAME, APP_VERSION
from .database import Base, engine
from . import models  # noqa: F401  (importarlo registra las tablas en Base)

# Crea las tablas si no existen
Base.metadata.create_all(bind=engine)

app = FastAPI(title=APP_NAME, version=APP_VERSION)


@app.get("/api/health")
def health():
    """Chequeo de salud: si responde, el servidor y la BD están bien."""
    return {"status": "ok", "app": APP_NAME, "version": APP_VERSION}
