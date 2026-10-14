"""
Notificaciones (Fase 8).
  GET  /api/notifications          -> historial (aprobador o administrador)
  GET  /api/notifications/status   -> canales activos y filtros, SIN credenciales
  POST /api/notifications/test     -> mensaje de prueba (solo administrador)
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Notification
from ..notificaciones import enviar_prueba, estado_canales
from ..schemas import NotificationOut, NotificationTest

router = APIRouter(prefix="/api/notifications", tags=["Notificaciones"])


@router.get("", response_model=list[NotificationOut], summary="Historial de notificaciones")
def historial(limite: int = Query(50, ge=1, le=500), db: Session = Depends(get_db)):
    return db.query(Notification).order_by(Notification.id.desc()).limit(limite).all()


@router.get("/status", summary="Canales activos y filtros (sin credenciales)")
def estado():
    return estado_canales()


@router.post("/test", summary="Enviar un mensaje de prueba por un canal")
def prueba(datos: NotificationTest, db: Session = Depends(get_db)):
    return enviar_prueba(db, datos.canal)

# --- FIN DEL ARCHIVO ---
