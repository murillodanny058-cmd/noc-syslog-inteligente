"""
Resumen para el dashboard: todo lo que muestran las tarjetas en una sola consulta.
"""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import case, func
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Device, Incident, SyslogEvent
from ..schemas import EventOut
from .syslog import estadisticas

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


def _eventos(lista):
    """Convierte eventos de la BD al formato de la API (incluye severity_name)."""
    return [EventOut.model_validate(e).model_dump() for e in lista]


@router.get("/resumen", summary="Resumen para el dashboard")
def resumen(db: Session = Depends(get_db)):
    ahora = datetime.now(timezone.utc)
    hace_24h = ahora - timedelta(hours=24)

    # --- Equipos por estado ---
    por_estado = dict(db.query(Device.status, func.count(Device.id)).group_by(Device.status).all())

    # --- Salud de cada equipo en las últimas 24 horas ---
    actividad = {
        device_id: (total, criticos or 0, ultimo)
        for device_id, total, criticos, ultimo in (
            db.query(SyslogEvent.device_id,
                     func.count(SyslogEvent.id),
                     func.sum(case((SyslogEvent.severity <= 3, 1), else_=0)),
                     func.max(SyslogEvent.received_at))
            .filter(SyslogEvent.received_at >= hace_24h, SyslogEvent.device_id.isnot(None))
            .group_by(SyslogEvent.device_id).all())
    }
    equipos = []
    for d in db.query(Device).order_by(Device.name).all():
        total, criticos, ultimo = actividad.get(d.id, (0, 0, None))
        equipos.append({"id": d.id, "name": d.name, "ip_address": d.ip_address,
                        "vendor": d.vendor, "status": d.status, "eventos_24h": total,
                        "criticos_24h": criticos, "ultimo_evento": ultimo})

    # --- Incidentes por estado ---
    inc_estado = dict(db.query(Incident.status, func.count(Incident.id)).group_by(Incident.status).all())
    total_inc = sum(inc_estado.values())

    # --- Listas recientes ---
    criticos = (db.query(SyslogEvent).filter(SyslogEvent.severity <= 3)
                .order_by(SyslogEvent.id.desc()).limit(8).all())
    sospechosos = (db.query(SyslogEvent).filter(SyslogEvent.flagged_suspicious.is_(True))
                   .order_by(SyslogEvent.id.desc()).limit(5).all())
    ultima_hora = (db.query(func.count(SyslogEvent.id))
                   .filter(SyslogEvent.received_at >= ahora - timedelta(hours=1)).scalar())

    return {
        "generado": ahora,
        "equipos": {"total": sum(por_estado.values()), "por_estado": por_estado, "detalle": equipos},
        "eventos": {**estadisticas(db), "ultima_hora": ultima_hora},
        "incidentes": {"total": total_inc, "abiertos": total_inc - inc_estado.get("cerrado", 0),
                       "por_estado": inc_estado},
        "criticos_recientes": _eventos(criticos),
        "sospechosos_recientes": _eventos(sospechosos),
    }
