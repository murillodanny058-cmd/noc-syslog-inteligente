"""
Puertos e interfaces (Fase 10):
  GET  /api/devices/{id}/ports          -> puertos de un equipo (estado, VLAN, vecino, MAC)
  POST /api/devices/{id}/ports/refresh  -> actualizar los puertos
                                           (SIM: simulados · REAL: por la consola real, solo lectura)
  GET  /api/events/{id}/port            -> en qué puerto pasó un evento y qué hay conectado ahí
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import or_
from sqlalchemy.orm import Session

from ..consola_serial import CONSOLA
from ..database import get_db
from ..models import AuditLog, Device, Port, SyslogEvent
from ..puertos import (COMANDOS_PUERTOS, clave_orden, combinar, extraer_interfaz, guardar_puertos,
                       nombre_corto, simular_puertos, todas_las_interfaces)
from ..schemas import PortOut, PuertoDeEvento

router = APIRouter(tags=["Puertos e interfaces"])


def _equipo(db: Session, device_id: int) -> Device:
    equipo = db.get(Device, device_id)
    if equipo is None:
        raise HTTPException(status_code=404, detail=f"No existe un equipo con id {device_id}")
    return equipo


def _asegurar_simulados(db: Session, equipo: Device):
    """Los equipos SIMULADOS reciben sus puertos simulados la primera vez que se consultan."""
    if equipo.is_simulated and not (db.query(Port)
                                    .filter(Port.device_id == equipo.id, Port.origen == "simulado").first()):
        guardar_puertos(db, equipo, simular_puertos(equipo), "simulado")


def _puertos(db: Session, equipo: Device) -> list:
    lista = db.query(Port).filter(Port.device_id == equipo.id).all()
    return sorted(lista, key=lambda p: clave_orden(p.interfaz))


@router.get("/api/devices/{device_id}/ports", response_model=list[PortOut],
            summary="Puertos de un equipo")
def listar_puertos(device_id: int, db: Session = Depends(get_db)):
    equipo = _equipo(db, device_id)
    _asegurar_simulados(db, equipo)
    return _puertos(db, equipo)


@router.post("/api/devices/{device_id}/ports/refresh", summary="Actualizar los puertos del equipo")
def actualizar_puertos(device_id: int, db: Session = Depends(get_db)):
    equipo = _equipo(db, device_id)

    if equipo.is_simulated:
        n = guardar_puertos(db, equipo, simular_puertos(equipo), "simulado")
        return {"equipo": equipo.name, "origen": "simulado", "puertos": n,
                "detalle": "Puertos simulados regenerados."}

    # Equipo REAL: se leen por la consola real (cable de consola), solo lectura
    if not CONSOLA.conectado or not CONSOLA.equipo or CONSOLA.equipo["id"] != equipo.id:
        raise HTTPException(status_code=409,
                            detail=f"Para leer los puertos de {equipo.name}, conéctelo primero en la "
                                   "pestaña Consola (modo Equipo REAL).")
    if CONSOLA.login_requerido:
        raise HTTPException(status_code=409, detail="El equipo está pidiendo usuario o contraseña.")
    comandos = COMANDOS_PUERTOS.get(equipo.vendor)
    if not comandos:
        raise HTTPException(status_code=409,
                            detail=f"La lectura de puertos está disponible para Cisco y Huawei, no para {equipo.vendor}.")

    salidas = []
    for tipo, comando in comandos:
        salida, _completo = CONSOLA._enviar_y_esperar(comando)
        salidas.append((tipo, salida))
        db.add(AuditLog(actor="operador_local", action="CONSOLE_CMD", entity_type="devices",
                        entity_id=equipo.id,
                        details=f"[PUERTOS · CONSOLA REAL {CONSOLA.puerto}] {equipo.name}> {comando}"))
    db.commit()
    puertos = combinar(salidas)
    n = guardar_puertos(db, equipo, puertos, "consola")
    return {"equipo": equipo.name, "origen": "consola", "puertos": n,
            "detalle": f"Leídos con {len(comandos)} comandos de solo lectura por la consola real."}


@router.get("/api/events/{event_id}/port", response_model=PuertoDeEvento,
            summary="Puerto donde ocurrió un evento")
def puerto_de_evento(event_id: int, db: Session = Depends(get_db)):
    evento = db.get(SyslogEvent, event_id)
    if evento is None:
        raise HTTPException(status_code=404, detail=f"No existe un evento con id {event_id}")
    interfaz = extraer_interfaz(evento.message)
    respuesta = {"evento_id": evento.id, "device_id": evento.device_id, "interfaz": interfaz,
                 "equipo": evento.device.name if evento.device else (evento.hostname or evento.source_ip)}
    if not interfaz:
        respuesta["nota"] = "El mensaje de este evento no menciona ningún puerto."
        return respuesta
    if evento.device is None:
        respuesta["nota"] = "El equipo que envió el evento no está registrado en el inventario."
        return respuesta

    equipo = evento.device
    _asegurar_simulados(db, equipo)
    respuesta["puerto"] = (db.query(Port)
                           .filter(Port.device_id == equipo.id, Port.interfaz == interfaz).first())
    if respuesta["puerto"] is None:
        respuesta["nota"] = ("Aún no hay datos de este puerto. Si el equipo es real, conéctelo en "
                             "Consola y use 'Actualizar puertos'.")
    # Otros eventos del mismo equipo que mencionan EXACTAMENTE este puerto
    # (se revisa en Python para que Gi1/0/1 no coincida con Gi1/0/10)
    corto = nombre_corto(interfaz)
    candidatos = (db.query(SyslogEvent)
                  .filter(SyslogEvent.device_id == equipo.id,
                          or_(SyslogEvent.message.contains(interfaz), SyslogEvent.message.contains(corto)))
                  .order_by(SyslogEvent.id.desc()).limit(300).all())
    respuesta["eventos_del_puerto"] = [e for e in candidatos
                                       if interfaz in todas_las_interfaces(e.message)][:10]
    return respuesta

# --- FIN DEL ARCHIVO ---