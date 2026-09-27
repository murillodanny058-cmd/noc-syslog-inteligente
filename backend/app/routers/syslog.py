"""
Endpoints de Syslog y eventos.
  POST /api/syslog/parse     -> analizar un mensaje SIN guardarlo (para aprender y probar)
  POST /api/syslog/ingest    -> recibir un mensaje y guardarlo como evento
  POST /api/syslog/import    -> importar un lote de mensajes
  POST /api/syslog/simulate  -> generar mensajes SIMULADOS
  GET  /api/events           -> consultar eventos con filtros
  GET  /api/events/stats     -> resumen por severidad
"""
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..database import get_db
from ..ingest import ingerir
from ..models import Device, SyslogEvent
from ..schemas import EventOut, IngestResult, SyslogImport, SyslogIn, SyslogTexto, Vendor
from ..simulador import generar_lote
from ..syslog_parser import FACILITIES, SEVERIDADES, parsear

router = APIRouter(tags=["Syslog y eventos"])


def _a_utc(fecha: Optional[datetime]) -> Optional[datetime]:
    """Si la fecha trae zona horaria, la convierte a UTC. Si no trae, se asume UTC."""
    if fecha is None or fecha.tzinfo is None:
        return fecha
    return fecha.astimezone(timezone.utc)


def _procesar_lote(db: Session, items) -> dict:
    """Ingiere varios mensajes y devuelve un resumen de lo que pasó."""
    resumen = {"total": len(items), "nuevo": 0, "duplicado": 0,
               "descartado_tormenta": 0, "rechazado": 0, "sospechosos": 0}
    for raw, ip, tipo in items:
        r = ingerir(db, raw, ip, tipo)
        resumen[r["resultado"]] += 1
        if r["resultado"] == "nuevo" and r.get("sospechoso"):
            resumen["sospechosos"] += 1
    return resumen


@router.post("/api/syslog/parse", summary="Analizar un mensaje (sin guardarlo)")
def analizar(datos: SyslogTexto):
    """Muestra cómo el parser 'entiende' un mensaje. No guarda nada."""
    r = parsear(datos.raw)
    r["severity_name"] = SEVERIDADES[r["severity"]]
    r["facility_name"] = FACILITIES.get(r["facility"], "?")
    return r


@router.post("/api/syslog/ingest", response_model=IngestResult, summary="Recibir un mensaje Syslog")
def recibir(datos: SyslogIn, db: Session = Depends(get_db)):
    return ingerir(db, datos.raw, datos.source_ip, datos.source_type)


@router.post("/api/syslog/import", summary="Importar un lote de mensajes")
def importar(lote: SyslogImport, db: Session = Depends(get_db)):
    return _procesar_lote(db, [(m.raw, m.source_ip, m.source_type) for m in lote.mensajes])


@router.post("/api/syslog/simulate", summary="Generar mensajes SIMULADOS de prueba")
def simular(
    cantidad: int = Query(30, ge=1, le=200, description="Cantidad de mensajes normales"),
    incluir_ataques: bool = Query(True, description="Agrega fuerza bruta e inyección de instrucciones"),
    db: Session = Depends(get_db),
):
    equipos = db.query(Device).filter(Device.is_simulated.is_(True)).all()
    if not equipos:
        raise HTTPException(status_code=400, detail="No hay equipos simulados en el inventario")
    return _procesar_lote(db, generar_lote(equipos, cantidad, incluir_ataques))


@router.get("/api/events", response_model=list[EventOut], summary="Consultar eventos con filtros")
def listar_eventos(
    desde: Optional[datetime] = Query(None, description="Fecha inicial en UTC. Ej: 2026-09-27T00:00:00"),
    hasta: Optional[datetime] = Query(None, description="Fecha final en UTC"),
    vendor: Optional[Vendor] = Query(None, description="Filtrar por marca"),
    device_id: Optional[int] = Query(None, description="Filtrar por equipo"),
    severidad: Optional[int] = Query(None, ge=0, le=7, description="Solo esta severidad exacta"),
    severidad_max: Optional[int] = Query(None, ge=0, le=7,
                                         description="Desde 0 hasta este valor. Ej: 3 = Error o más grave"),
    solo_sospechosos: bool = Query(False, description="Solo mensajes marcados como sospechosos"),
    limite: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db),
):
    consulta = db.query(SyslogEvent)
    if desde:
        consulta = consulta.filter(SyslogEvent.received_at >= _a_utc(desde))
    if hasta:
        consulta = consulta.filter(SyslogEvent.received_at <= _a_utc(hasta))
    if vendor:
        consulta = consulta.filter(SyslogEvent.vendor == vendor)
    if device_id is not None:
        consulta = consulta.filter(SyslogEvent.device_id == device_id)
    if severidad is not None:
        consulta = consulta.filter(SyslogEvent.severity == severidad)
    if severidad_max is not None:
        consulta = consulta.filter(SyslogEvent.severity <= severidad_max)
    if solo_sospechosos:
        consulta = consulta.filter(SyslogEvent.flagged_suspicious.is_(True))
    return consulta.order_by(SyslogEvent.id.desc()).limit(limite).all()


@router.get("/api/events/stats", summary="Resumen de eventos por severidad")
def estadisticas(db: Session = Depends(get_db)):
    filas = (db.query(SyslogEvent.severity, func.count(SyslogEvent.id), func.sum(SyslogEvent.repeat_count))
             .group_by(SyslogEvent.severity).all())
    conteo = {sev: (eventos, mensajes or 0) for sev, eventos, mensajes in filas}
    por_severidad = [
        {"severidad": s, "nombre": SEVERIDADES[s],
         "eventos": conteo.get(s, (0, 0))[0], "mensajes": conteo.get(s, (0, 0))[1]}
        for s in range(8)
    ]
    sospechosos = (db.query(func.count(SyslogEvent.id))
                   .filter(SyslogEvent.flagged_suspicious.is_(True)).scalar())
    return {
        "total_eventos": sum(f["eventos"] for f in por_severidad),
        "total_mensajes": sum(f["mensajes"] for f in por_severidad),
        "criticos_0_a_3": sum(f["eventos"] for f in por_severidad if f["severidad"] <= 3),
        "sospechosos": sospechosos,
        "por_severidad": por_severidad,
    }