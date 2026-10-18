"""
Cambios de configuración con aprobación humana (Fase 11):
  GET  /api/changes/catalog        -> plantillas permitidas
  POST /api/changes/preview        -> ver los comandos EXACTOS sin guardar nada
  GET  /api/changes                -> listar cambios
  POST /api/changes                -> 1) proponer (humano o agente de IA)
  POST /api/changes/{id}/review    -> 2) aprobar o rechazar (aprobador HUMANO distinto de quien propuso)
  POST /api/changes/{id}/execute   -> 3) respaldo + ejecución por consola (rollback automático si falla)
  POST /api/changes/{id}/verify    -> 4) verificación automática
  POST /api/changes/{id}/rollback  -> 5) deshacer el cambio
"""
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from ..cambios import (CambioInvalido, a_json, a_texto, aplicar, catalogo, consola_lista_para, generar,
                       leer, verificar_salida)
from ..database import get_db
from ..ingest import es_sospechoso
from ..models import AuditLog, ConfigChange, Device, Incident
from ..notificaciones import encolar
from ..politica_ia import MOTIVO_SUSPENSION, agente_suspendido
from ..schemas import CambioCreate, CambioOut, CambioReview

router = APIRouter(tags=["Cambios con aprobación humana"])


def _ahora():
    return datetime.now(timezone.utc)


def _usuario(request: Request) -> str:
    return request.state.usuario["username"]


def _auditar(db: Session, actor: str, accion: str, cid, detalle: str):
    db.add(AuditLog(actor=actor, action=accion, entity_type="cambios_config", entity_id=cid,
                    details=detalle[:300]))


def _cambio(db: Session, cid: int) -> ConfigChange:
    c = db.get(ConfigChange, cid)
    if c is None:
        raise HTTPException(status_code=404, detail=f"No existe el cambio {cid}")
    return c


def _exigir(c: ConfigChange, estados: tuple, accion: str):
    if c.estado not in estados:
        raise HTTPException(status_code=409,
                            detail=f"Para {accion}, el cambio debe estar en: {', '.join(estados)} "
                                   f"(estado actual: '{c.estado}')")


def _generar(db: Session, datos: CambioCreate):
    equipo = db.get(Device, datos.device_id)
    if equipo is None:
        raise HTTPException(status_code=404, detail=f"No existe un equipo con id {datos.device_id}")
    try:
        return equipo, generar(datos.plantilla, equipo.vendor, datos.parametros)
    except CambioInvalido as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None


@router.get("/api/changes/catalog", summary="Plantillas de cambio permitidas")
def ver_catalogo():
    return catalogo()


@router.post("/api/changes/preview", summary="Vista previa: comandos exactos (no guarda nada)")
def vista_previa(datos: CambioCreate, db: Session = Depends(get_db)):
    equipo, plan = _generar(db, datos)
    return {"equipo": equipo.name, "resumen": plan["resumen"],
            "comandos": plan["comandos"], "rollback": plan["rollback"],
            "respaldo": plan["respaldo"], "verificacion": plan["verificacion"]}


@router.get("/api/changes", response_model=list[CambioOut], summary="Listar cambios")
def listar(db: Session = Depends(get_db)):
    return db.query(ConfigChange).order_by(ConfigChange.id.desc()).limit(50).all()


@router.post("/api/changes", response_model=CambioOut, status_code=status.HTTP_201_CREATED,
             summary="1) Proponer un cambio")
def proponer(datos: CambioCreate, request: Request, db: Session = Depends(get_db)):
    usuario = _usuario(request)
    actor = "agente_ia" if datos.origen == "agente_ia" else "operador_local"
    if datos.origen == "agente_ia" and agente_suspendido(db):
        raise HTTPException(status_code=403, detail=MOTIVO_SUSPENSION)
    texto = f"{datos.motivo} {' '.join(datos.parametros.values())}"
    if es_sospechoso(texto):
        _auditar(db, actor, "CHANGE_REJECTED_AUTO", None,
                 f"Propuesta de cambio sospechosa rechazada ({datos.origen}): {datos.motivo[:150]}")
        db.commit()
        raise HTTPException(status_code=422, detail="La propuesta contiene instrucciones o comandos "
                                                    "sospechosos y fue rechazada automáticamente.")
    if datos.incident_id is not None and db.get(Incident, datos.incident_id) is None:
        raise HTTPException(status_code=404, detail=f"No existe el incidente {datos.incident_id}")

    equipo, plan = _generar(db, datos)
    c = ConfigChange(device_id=equipo.id, incident_id=datos.incident_id, plantilla=datos.plantilla,
                     parametros=a_json(plan["parametros"]), motivo=datos.motivo,
                     comandos=a_texto(plan["comandos"]), rollback=a_texto(plan["rollback"]),
                     plan=a_json({k: plan.get(k) for k in ("respaldo", "verificacion", "esperado",
                                                            "linea_verificar", "resumen")}),
                     origen=datos.origen, propuesto_por=usuario, estado="propuesta",
                     simulado=bool(equipo.is_simulated))
    db.add(c)
    db.flush()
    _auditar(db, actor, "CHANGE_PROPOSE", c.id,
             f"{equipo.name}: {plan['resumen']} (propuso {usuario}, origen {datos.origen})")
    db.commit()
    db.refresh(c)
    encolar({"clave": f"cambio:{c.id}", "tipo": "cambio_pendiente", "severidad": 4, "siempre": True,
             "device_id": equipo.id, "titulo": f"Cambio #{c.id} pendiente de APROBACIÓN en {equipo.name}",
             "detalle": f"{plan['resumen']}. Propuso: {usuario}"
                        f"{' (agente de IA)' if datos.origen == 'agente_ia' else ''}. "
                        "Revíselo en la pestaña Cambios del NOC."})
    return c


@router.post("/api/changes/{cid}/review", response_model=CambioOut,
             summary="2) Revisión humana: aprobar o rechazar")
def revisar(cid: int, datos: CambioReview, request: Request, db: Session = Depends(get_db)):
    c = _cambio(db, cid)
    _exigir(c, ("propuesta",), "revisarlo")
    usuario = _usuario(request)
    if usuario == c.propuesto_por:
        _auditar(db, "operador_local", "CHANGE_REVIEW_DENIED", c.id,
                 "Intento de aprobar un cambio propio: se exige otra persona (separación de funciones)")
        db.commit()
        raise HTTPException(status_code=403,
                            detail="No puede revisar un cambio que usted mismo propuso: debe hacerlo "
                                   "otro aprobador (separación de funciones).")
    c.estado = datos.decision
    c.aprobado_por = usuario
    c.revisado = _ahora()
    c.nota_revision = datos.nota
    _auditar(db, "operador_local", "CHANGE_APPROVE" if datos.decision == "aprobada" else "CHANGE_REJECT",
             c.id, f"{datos.decision}: {c.comandos[:200]}")
    db.commit()
    db.refresh(c)
    return c


@router.post("/api/changes/{cid}/execute", response_model=CambioOut,
             summary="3) Respaldo + ejecución (rollback automático si falla)")
def ejecutar(cid: int, request: Request, db: Session = Depends(get_db)):
    c = _cambio(db, cid)
    _exigir(c, ("aprobada",), "ejecutarlo")
    equipo = db.get(Device, c.device_id)
    plan = json.loads(c.plan)
    c.ejecutado_por = _usuario(request)
    c.ejecutado = _ahora()

    if c.simulado:
        c.respaldo = "(equipo SIMULADO) " + ", ".join(plan["respaldo"])
        c.salida = "(equipo SIMULADO) comandos aplicados:\n" + c.comandos
        c.estado = "ejecutada"
        _auditar(db, "operador_local", "CHANGE_EXECUTE", c.id, f"{equipo.name} (SIMULADO): {c.comandos[:200]}")
        db.commit()
        db.refresh(c)
        return c

    motivo = consola_lista_para(equipo.id)
    if motivo:
        raise HTTPException(status_code=409, detail=motivo)

    c.respaldo = leer(plan["respaldo"])[:20000]  # 1) respaldo ANTES de tocar nada
    salida, error = aplicar(equipo.vendor, c.comandos.splitlines())  # 2) ejecución
    c.salida = salida[:20000]
    if error:
        reversa, _ = aplicar(equipo.vendor, c.rollback.splitlines())  # 3) rollback automático
        c.estado = "fallida"
        c.resultado = "El equipo rechazó un comando. Se aplicó el ROLLBACK automáticamente:\n" + reversa[:5000]
        _auditar(db, "operador_local", "CHANGE_FAILED_ROLLBACK", c.id, f"{equipo.name}: falló y se revirtió")
        encolar({"clave": f"cambio_fallido:{c.id}", "tipo": "cambio_fallido", "severidad": 3, "siempre": True,
                 "device_id": equipo.id, "titulo": f"Cambio #{c.id} FALLÓ en {equipo.name}",
                 "detalle": "El equipo rechazó un comando; el NOC aplicó el rollback automático."})
    else:
        c.estado = "ejecutada"
        _auditar(db, "operador_local", "CHANGE_EXECUTE", c.id, f"{equipo.name} (consola real): {c.comandos[:200]}")
    db.commit()
    db.refresh(c)
    return c


@router.post("/api/changes/{cid}/verify", response_model=CambioOut, summary="4) Verificación automática")
def verificar(cid: int, db: Session = Depends(get_db)):
    c = _cambio(db, cid)
    _exigir(c, ("ejecutada", "verificacion_fallida"), "verificarlo")
    equipo = db.get(Device, c.device_id)
    plan = json.loads(c.plan)
    if c.simulado:
        c.estado, c.resultado = "verificada", f"(equipo SIMULADO) verificación con '{plan['verificacion']}': OK"
    else:
        motivo = consola_lista_para(equipo.id)
        if motivo:
            raise HTTPException(status_code=409, detail=motivo)
        salida = leer([plan["verificacion"]])
        ok = verificar_salida(plan, salida)
        c.estado = "verificada" if ok else "verificacion_fallida"
        c.resultado = (("✔ El cambio quedó aplicado." if ok else
                        "✖ No se encontró el cambio en el equipo. Considere el rollback.")
                       + "\n\n" + salida[:15000])
    _auditar(db, "operador_local", "CHANGE_VERIFY", c.id, f"{equipo.name}: {c.estado}")
    db.commit()
    db.refresh(c)
    return c


@router.post("/api/changes/{cid}/rollback", response_model=CambioOut, summary="5) Deshacer el cambio")
def deshacer(cid: int, db: Session = Depends(get_db)):
    c = _cambio(db, cid)
    _exigir(c, ("ejecutada", "verificada", "verificacion_fallida"), "deshacerlo")
    equipo = db.get(Device, c.device_id)
    if c.simulado:
        reversa = "(equipo SIMULADO) rollback aplicado:\n" + c.rollback
    else:
        motivo = consola_lista_para(equipo.id)
        if motivo:
            raise HTTPException(status_code=409, detail=motivo)
        reversa, error = aplicar(equipo.vendor, c.rollback.splitlines())
        if error:
            reversa = "ATENCIÓN: el equipo rechazó parte del rollback. Revise manualmente.\n" + reversa
    c.estado = "revertida"
    c.resultado = reversa[:15000]
    _auditar(db, "operador_local", "CHANGE_ROLLBACK", c.id, f"{equipo.name}: {c.rollback[:200]}")
    db.commit()
    db.refresh(c)
    return c

# --- FIN DEL ARCHIVO ---