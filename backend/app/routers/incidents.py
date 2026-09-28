"""
Gestión de incidentes: creación, asignación, seguimiento y cierre.

Ciclo de vida:  abierto -> asignado -> en_progreso -> cerrado

Reglas:
  - Para asignar o iniciar el trabajo, el incidente debe tener un responsable.
  - Para cerrar, se exige una resolución (mínimo 10 caracteres).
  - Un incidente cerrado no se modifica ni se elimina (trazabilidad).
  - Un evento no puede tener dos incidentes abiertos al mismo tiempo.
  - Cada cambio queda registrado en la auditoría.
"""
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import AuditLog, Device, Incident, SyslogEvent
from ..schemas import IncidentCreate, IncidentOut, IncidentStatus, IncidentUpdate
from ..syslog_parser import SEVERIDADES

router = APIRouter(prefix="/api/incidents", tags=["Incidentes"])

ACTOR = "operador_local"  # en v1.0.0 vendrá del usuario autenticado

# Qué estados se pueden alcanzar desde cada estado
TRANSICIONES = {
    "abierto": {"asignado", "cerrado"},
    "asignado": {"en_progreso", "cerrado"},
    "en_progreso": {"cerrado"},
    "cerrado": set(),  # estado final
}


# ---------------------------------------------------------------------------
# Funciones de apoyo
# ---------------------------------------------------------------------------
def auditar(db: Session, accion: str, incidente_id: int, detalle: str):
    db.add(AuditLog(actor=ACTOR, action=accion, entity_type="incidents",
                    entity_id=incidente_id, details=detalle))


def obtener_o_404(db: Session, incidente_id: int) -> Incident:
    incidente = db.get(Incident, incidente_id)
    if incidente is None:
        raise HTTPException(status_code=404, detail=f"No existe el incidente {incidente_id}")
    return incidente


def validar_referencias(db: Session, device_id: Optional[int], event_id: Optional[int]):
    """El equipo y el evento indicados deben existir."""
    if device_id is not None and db.get(Device, device_id) is None:
        raise HTTPException(status_code=422, detail=f"No existe el equipo {device_id}")
    if event_id is not None and db.get(SyslogEvent, event_id) is None:
        raise HTTPException(status_code=422, detail=f"No existe el evento {event_id}")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@router.get("", response_model=list[IncidentOut], summary="Listar incidentes")
def listar_incidentes(
    estado: Optional[IncidentStatus] = Query(None, description="Filtrar por estado"),
    severidad_max: Optional[int] = Query(None, ge=0, le=7, description="Desde 0 hasta este valor"),
    limite: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    consulta = db.query(Incident)
    if estado:
        consulta = consulta.filter(Incident.status == estado)
    if severidad_max is not None:
        consulta = consulta.filter(Incident.severity <= severidad_max)
    # Primero los no cerrados, luego los más graves, luego los más recientes
    return (consulta.order_by(Incident.status == "cerrado", Incident.severity, Incident.id.desc())
            .limit(limite).all())


@router.get("/{incidente_id}", response_model=IncidentOut, summary="Ver un incidente")
def ver_incidente(incidente_id: int, db: Session = Depends(get_db)):
    return obtener_o_404(db, incidente_id)


@router.post("", response_model=IncidentOut, status_code=status.HTTP_201_CREATED,
             summary="Crear un incidente")
def crear_incidente(datos: IncidentCreate, db: Session = Depends(get_db)):
    validar_referencias(db, datos.device_id, datos.event_id)
    estado_inicial = "asignado" if datos.assigned_to else "abierto"
    incidente = Incident(**datos.model_dump(), status=estado_inicial)
    db.add(incidente)
    db.flush()
    auditar(db, "CREATE", incidente.id,
            f"Incidente creado ({estado_inicial}): {incidente.title[:100]}")
    db.commit()
    db.refresh(incidente)
    return incidente


@router.post("/from-event/{event_id}", response_model=IncidentOut,
             status_code=status.HTTP_201_CREATED, summary="Crear un incidente desde un evento")
def crear_desde_evento(event_id: int, db: Session = Depends(get_db)):
    evento = db.get(SyslogEvent, event_id)
    if evento is None:
        raise HTTPException(status_code=404, detail=f"No existe el evento {event_id}")

    abierto = (db.query(Incident)
               .filter(Incident.event_id == event_id, Incident.status != "cerrado").first())
    if abierto:
        raise HTTPException(status_code=409,
                            detail=f"El evento {event_id} ya tiene el incidente #{abierto.id} sin cerrar")

    origen = evento.hostname or evento.source_ip
    # El texto del log se copia como DATO (nunca se interpreta como instrucción)
    titulo = f"[{SEVERIDADES[evento.severity]}] {origen}: {evento.message}"[:200]
    descripcion = (f"Creado desde el evento #{evento.id}. Aplicación: {evento.app_name or '-'}. "
                   f"Repeticiones: {evento.repeat_count}. "
                   f"Sospechoso: {'sí' if evento.flagged_suspicious else 'no'}.")

    incidente = Incident(title=titulo, description=descripcion, severity=evento.severity,
                         status="abierto", device_id=evento.device_id, event_id=evento.id)
    db.add(incidente)
    db.flush()
    auditar(db, "CREATE", incidente.id, f"Incidente creado desde el evento #{evento.id}")
    db.commit()
    db.refresh(incidente)
    return incidente


@router.put("/{incidente_id}", response_model=IncidentOut,
            summary="Seguimiento: asignar, cambiar estado o cerrar")
def actualizar_incidente(incidente_id: int, datos: IncidentUpdate, db: Session = Depends(get_db)):
    incidente = obtener_o_404(db, incidente_id)

    if incidente.status == "cerrado":
        raise HTTPException(status_code=409, detail="El incidente está cerrado y no se puede modificar")

    cambios = datos.model_dump(exclude_unset=True, exclude_none=True)
    if not cambios:
        raise HTTPException(status_code=400, detail="No se envió ningún cambio")

    # Asignar un responsable a un incidente 'abierto' lo pasa a 'asignado' automáticamente
    if "assigned_to" in cambios and "status" not in cambios and incidente.status == "abierto":
        cambios["status"] = "asignado"

    nuevo_estado = cambios.get("status", incidente.status)
    responsable = cambios.get("assigned_to", incidente.assigned_to)
    resolucion = cambios.get("resolution", incidente.resolution)

    # Regla 1: solo transiciones permitidas
    if nuevo_estado != incidente.status and nuevo_estado not in TRANSICIONES[incidente.status]:
        permitidos = ", ".join(sorted(TRANSICIONES[incidente.status]))
        raise HTTPException(status_code=409,
                            detail=f"No se puede pasar de '{incidente.status}' a '{nuevo_estado}'. "
                                   f"Desde '{incidente.status}' se permite: {permitidos}")
    # Regla 2: asignado y en progreso requieren responsable
    if nuevo_estado in ("asignado", "en_progreso") and not responsable:
        raise HTTPException(status_code=422, detail="Debe indicar un responsable (assigned_to)")
    # Regla 3: cerrar requiere resolución
    if nuevo_estado == "cerrado" and not resolucion:
        raise HTTPException(status_code=422,
                            detail="Para cerrar debe escribir la resolución (mínimo 10 caracteres)")

    detalle = []
    for campo, valor in cambios.items():
        anterior = getattr(incidente, campo)
        if anterior != valor:
            detalle.append(f"{campo}: {str(anterior)[:60]} -> {str(valor)[:60]}")
            setattr(incidente, campo, valor)

    if incidente.status == "cerrado" and incidente.closed_at is None:
        incidente.closed_at = datetime.now(timezone.utc)

    if detalle:
        accion = "CLOSE" if incidente.status == "cerrado" else "UPDATE"
        auditar(db, accion, incidente.id, "; ".join(detalle))
        db.commit()
        db.refresh(incidente)
    return incidente