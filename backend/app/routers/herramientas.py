"""
Herramientas del NOC:
  POST /api/config/generate   -> generar configuración Syslog comentada
  GET  /api/console/commands  -> comandos permitidos y bloqueados por fabricante
  POST /api/console/exec      -> ejecutar un comando en la consola simulada
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..config_generator import generar
from ..console_sim import BLOQUEADOS, PERMITIDOS, ejecutar
from ..database import get_db
from ..models import Device
from ..schemas import ConfigRequest, ConfigResult, ConsoleRequest, ConsoleResult, VendorConfig

router = APIRouter(tags=["Herramientas: configuraciones y consola"])


@router.post("/api/config/generate", response_model=ConfigResult,
             summary="Generar configuración Syslog comentada")
def generar_configuracion(datos: ConfigRequest):
    return generar(datos)


@router.get("/api/console/commands", summary="Comandos permitidos y bloqueados")
def listar_comandos(vendor: VendorConfig = Query(..., description="Fabricante")):
    return {
        "vendor": vendor,
        "permitidos": sorted(PERMITIDOS[vendor]),
        "filtro": "<comando> | include <palabra>",
        "bloqueados": [{"ejemplos": ejemplos, "motivo": motivo} for _p, ejemplos, motivo in BLOQUEADOS],
        "politica": "Todo comando que no esté en la lista de permitidos se niega (denegar por defecto).",
    }


@router.post("/api/console/exec", response_model=ConsoleResult,
             summary="Ejecutar un comando en la consola simulada (solo lectura)")
def ejecutar_comando(datos: ConsoleRequest, db: Session = Depends(get_db)):
    equipo = db.get(Device, datos.device_id)
    if equipo is None:
        raise HTTPException(status_code=404, detail=f"No existe un equipo con id {datos.device_id}")
    return ejecutar(db, equipo, datos.comando, datos.actor)

# --- FIN DEL ARCHIVO ---