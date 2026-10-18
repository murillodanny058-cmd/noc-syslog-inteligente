"""
Consola REAL por cable de consola (Fase 9):
  GET  /api/serial/puertos      -> puertos COM disponibles en el PC del NOC
  GET  /api/serial/estado       -> estado de la conexión y líneas nuevas de la consola
  GET  /api/serial/commands     -> comandos permitidos en equipos reales
  POST /api/serial/conectar     -> abrir la consola (aprobador o administrador)
  POST /api/serial/desconectar  -> cerrar la consola (aprobador o administrador)
  POST /api/serial/exec         -> ejecutar un comando de solo lectura en el equipo real
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..consola_serial import CONSOLA, NEGADOS_REAL, PERMITIDOS_REAL, disponible, ejecutar_real, listar_puertos
from ..console_sim import BLOQUEADOS
from ..database import get_db
from ..models import AuditLog, Device
from ..schemas import ConsoleResult, SerialConectar, SerialExec, VendorConfig

router = APIRouter(tags=["Consola real por cable (serial)"])


@router.get("/api/serial/puertos", summary="Puertos COM disponibles")
def puertos():
    if not disponible():
        raise HTTPException(status_code=503, detail="Falta la librería pyserial. Ejecute: pip install pyserial")
    return listar_puertos()


@router.get("/api/serial/estado", summary="Estado de la consola real y líneas nuevas")
def estado(desde: int = Query(0, ge=0, description="Número de la última línea que ya tiene el navegador")):
    return CONSOLA.estado(desde)


@router.get("/api/serial/commands", summary="Comandos permitidos en equipos reales")
def comandos(vendor: VendorConfig = Query(..., description="Fabricante")):
    return {
        "vendor": vendor,
        "permitidos": PERMITIDOS_REAL[vendor],
        "filtro": "<comando> | include <palabra>",
        "bloqueados": [{"ejemplos": e, "motivo": m} for _p, e, m in BLOQUEADOS]
        + [{"ejemplos": c, "motivo": m} for c, m in NEGADOS_REAL.items()],
        "politica": "Todo comando que no esté en la lista de permitidos se niega (denegar por defecto).",
    }


@router.post("/api/serial/conectar", summary="Abrir la consola real (cable de consola)")
def conectar(datos: SerialConectar, db: Session = Depends(get_db)):
    equipo = db.get(Device, datos.device_id)
    if equipo is None:
        raise HTTPException(status_code=404, detail=f"No existe un equipo con id {datos.device_id}")
    if equipo.is_simulated:
        raise HTTPException(status_code=409,
                            detail="Ese equipo es SIMULADO. Para la consola real registre el equipo del "
                                   "laboratorio en Inventario con Tipo de equipo: Real (laboratorio).")
    try:
        resultado = CONSOLA.conectar(datos.puerto, datos.velocidad, equipo)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
    db.add(AuditLog(actor="operador_local", action="SERIAL_CONNECT", entity_type="devices",
                    entity_id=equipo.id,
                    details=f"Consola real abierta en {datos.puerto} ({datos.velocidad} baudios) "
                            f"hacia {equipo.name}. Se quitó la paginación solo para esta sesión."))
    db.commit()
    return resultado


@router.post("/api/serial/desconectar", summary="Cerrar la consola real")
def desconectar(db: Session = Depends(get_db)):
    if not CONSOLA.conectado:
        return CONSOLA.estado()
    equipo = CONSOLA.equipo or {}
    puerto, capturados = CONSOLA.puerto, CONSOLA.eventos_capturados
    CONSOLA.desconectar()
    db.add(AuditLog(actor="operador_local", action="SERIAL_DISCONNECT", entity_type="devices",
                    entity_id=equipo.get("id"),
                    details=f"Consola real cerrada en {puerto}. Logs capturados: {capturados}."))
    db.commit()
    return CONSOLA.estado()


@router.post("/api/serial/exec", response_model=ConsoleResult,
             summary="Ejecutar un comando de solo lectura en el equipo real")
def ejecutar(datos: SerialExec, db: Session = Depends(get_db)):
    try:
        return ejecutar_real(db, datos.comando, datos.actor)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None

# --- FIN DEL ARCHIVO ---