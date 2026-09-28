"""
Política de defensa ante IA: flujo obligatorio con aprobación humana.

  Evento -> Validación -> PROPUESTA -> REVISIÓN HUMANA -> APROBACIÓN
         -> EJECUCIÓN AUTORIZADA -> VERIFICACIÓN -> Auditoría

  GET  /api/policy/agent-status        -> ¿el agente de IA está suspendido?
  GET  /api/proposals                  -> listar propuestas
  POST /api/proposals                  -> proponer (humano o agente_ia)
  POST /api/proposals/{id}/review      -> revisión humana: aprobar o rechazar
  POST /api/proposals/{id}/execute     -> ejecución autorizada (SIMULADA)
  POST /api/proposals/{id}/verify      -> verificación
"""
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from ..database import get_db
from ..ingest import es_sospechoso
from ..models import ActionProposal, AuditLog, Incident
from ..politica_ia import (MAX_BLOQUEOS, MOTIVO_SUSPENSION, VENTANA,
                           agente_suspendido, bloqueos_recientes_agente)
from ..schemas import ProposalCreate, ProposalExecute, ProposalOut, ProposalReview, ProposalVerify

router = APIRouter(tags=["Política de IA y aprobaciones"])

# Nombres que NUNCA pueden firmar una aprobación (la revisión debe ser humana).
# En la v1.0.0 esto lo garantizará la autenticación con roles.
NOMBRES_NO_HUMANOS = {"agente_ia", "agente", "ia", "ai", "bot", "sistema"}


def auditar(db: Session, actor: str, accion: str, pid: Optional[int], detalle: str):
    db.add(AuditLog(actor=actor, action=accion, entity_type="action_proposals",
                    entity_id=pid, details=detalle[:300]))


def obtener_o_404(db: Session, pid: int) -> ActionProposal:
    p = db.get(ActionProposal, pid)
    if p is None:
        raise HTTPException(status_code=404, detail=f"No existe la propuesta {pid}")
    return p


def exigir_estado(p: ActionProposal, esperado: str, accion: str):
    if p.status != esperado:
        raise HTTPException(status_code=409,
                            detail=f"Para {accion}, la propuesta debe estar '{esperado}' "
                                   f"(estado actual: '{p.status}')")


@router.get("/api/policy/agent-status", summary="Estado del agente de IA")
def estado_agente(db: Session = Depends(get_db)):
    n = bloqueos_recientes_agente(db)
    return {"suspendido": n >= MAX_BLOQUEOS, "bloqueos_recientes": n,
            "limite": MAX_BLOQUEOS, "ventana_minutos": int(VENTANA.total_seconds() // 60)}


@router.get("/api/proposals", response_model=list[ProposalOut], summary="Listar propuestas")
def listar(incident_id: Optional[int] = Query(None), db: Session = Depends(get_db)):
    consulta = db.query(ActionProposal)
    if incident_id is not None:
        consulta = consulta.filter(ActionProposal.incident_id == incident_id)
    return consulta.order_by(ActionProposal.id.desc()).all()


@router.post("/api/proposals", response_model=ProposalOut, status_code=status.HTTP_201_CREATED,
             summary="1) Proponer una acción")
def proponer(datos: ProposalCreate, db: Session = Depends(get_db)):
    incidente = db.get(Incident, datos.incident_id)
    if incidente is None:
        raise HTTPException(status_code=404, detail=f"No existe el incidente {datos.incident_id}")
    if incidente.status == "cerrado":
        raise HTTPException(status_code=409, detail="No se proponen acciones sobre un incidente cerrado")

    actor = "agente_ia" if datos.proposed_by == "agente_ia" else "operador_local"
    if datos.proposed_by == "agente_ia":
        if agente_suspendido(db):
            raise HTTPException(status_code=403, detail=MOTIVO_SUSPENSION)
        if es_sospechoso(datos.action_text):
            auditar(db, actor, "PROPOSAL_REJECTED_AUTO", None,
                    f"Incidente #{incidente.id}: propuesta sospechosa rechazada: {datos.action_text[:150]}")
            db.commit()
            raise HTTPException(status_code=422,
                                detail="La propuesta del agente contiene instrucciones o comandos "
                                       "sospechosos y fue rechazada automáticamente.")

    p = ActionProposal(incident_id=incidente.id, action_text=datos.action_text,
                       proposed_by=datos.proposed_by, status="propuesta")
    db.add(p)
    db.flush()
    auditar(db, actor, "PROPOSE", p.id, f"Incidente #{incidente.id}: {datos.action_text[:200]}")
    db.commit()
    db.refresh(p)
    return p


@router.post("/api/proposals/{pid}/review", response_model=ProposalOut,
             summary="2) Revisión humana: aprobar o rechazar")
def revisar(pid: int, datos: ProposalReview, db: Session = Depends(get_db)):
    p = obtener_o_404(db, pid)
    exigir_estado(p, "propuesta", "revisarla")
    if datos.reviewed_by.strip().lower() in NOMBRES_NO_HUMANOS:
        auditar(db, "agente_ia", "REVIEW_DENIED", p.id,
                f"Intento de aprobación no humana firmado como '{datos.reviewed_by}'")
        db.commit()
        raise HTTPException(status_code=403,
                            detail="Un agente de IA no puede aprobar acciones: la revisión debe ser humana")

    p.status = datos.decision
    p.reviewed_by = datos.reviewed_by
    p.reviewed_at = datetime.now(timezone.utc)
    if datos.nota:
        p.verification_notes = f"Revisión: {datos.nota}"
    accion = "APPROVE" if datos.decision == "aprobada" else "REJECT"
    auditar(db, "operador_local", accion, p.id, f"{datos.reviewed_by} -> {datos.decision}: {p.action_text[:150]}")
    db.commit()
    db.refresh(p)
    return p


@router.post("/api/proposals/{pid}/execute", response_model=ProposalOut,
             summary="3) Ejecución autorizada (SIMULADA)")
def ejecutar(pid: int, datos: ProposalExecute, db: Session = Depends(get_db)):
    p = obtener_o_404(db, pid)
    exigir_estado(p, "aprobada", "ejecutarla")
    p.status = "ejecutada"
    auditar(db, "operador_local", "EXECUTE", p.id,
            f"Ejecución SIMULADA autorizada por {datos.ejecutado_por}: {p.action_text[:150]}")
    db.commit()
    db.refresh(p)
    return p


@router.post("/api/proposals/{pid}/verify", response_model=ProposalOut, summary="4) Verificación")
def verificar(pid: int, datos: ProposalVerify, db: Session = Depends(get_db)):
    p = obtener_o_404(db, pid)
    exigir_estado(p, "ejecutada", "verificarla")
    previo = f"{p.verification_notes} | " if p.verification_notes else ""
    p.verification_notes = f"{previo}Verificación: {datos.notas}"
    p.status = "verificada"
    auditar(db, "operador_local", "VERIFY", p.id, f"Verificada: {datos.notas[:150]}")
    db.commit()
    db.refresh(p)
    return p

# --- FIN DEL ARCHIVO ---