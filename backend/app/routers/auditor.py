"""
Agente auditor de usuarios (Fase 12) — SOLO ADMINISTRADOR:
  GET  /api/auditor/estado    -> qué motor de IA está activo (sin mostrar claves)
  GET  /api/auditor/usuarios  -> usuarios con actividad en los últimos días
  GET  /api/auditor/sesiones  -> sesiones de un usuario (de LOGIN a LOGOUT) con hallazgos por reglas
  POST /api/auditor/informe   -> el agente de IA revisa las sesiones y redacta el informe
  GET  /api/auditor/informes  -> informes generados antes
"""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..auditor import analizar, motor_ia, redactar_informe, usuarios_con_actividad
from ..database import get_db
from ..models import AuditLog, InformeAuditoria, User

router = APIRouter(prefix="/api/auditor", tags=["Agente auditor (administrador)"])
MAX_DIAS = 31


class PedidoInforme(BaseModel):
    """Datos para pedir un informe: usuario y periodo (por defecto, las últimas 24 horas)."""

    usuario: str = Field(..., min_length=1, max_length=100, pattern=r"^[A-Za-z0-9._\-]+$")
    desde: datetime | None = None
    hasta: datetime | None = None


def _utc(f: datetime | None) -> datetime | None:
    """Convierte una fecha a UTC (si no trae zona, se asume UTC)."""
    if f is None:
        return None
    return f.astimezone(UTC) if f.tzinfo else f.replace(tzinfo=UTC)


def _periodo(desde: datetime | None, hasta: datetime | None):
    """Valida el periodo pedido: sin fechas futuras, 'desde' antes que 'hasta' y máximo 31 días."""
    ahora = datetime.now(UTC)
    hasta = _utc(hasta) or ahora
    desde = _utc(desde) or hasta - timedelta(days=1)
    if hasta > ahora + timedelta(minutes=5) or desde > ahora + timedelta(minutes=5):
        raise HTTPException(status_code=422, detail="Las fechas no pueden estar en el futuro")
    if desde > hasta:
        raise HTTPException(status_code=422, detail="'Desde' no puede ser posterior a 'Hasta'")
    if hasta - desde > timedelta(days=MAX_DIAS):
        raise HTTPException(status_code=422, detail=f"El periodo máximo es de {MAX_DIAS} días")
    return desde, hasta


@router.get("/estado", summary="Motor de IA activo (sin claves)")
def estado():
    """Qué motor usa el agente (Hermes, Claude, Gemini o reglas), sin mostrar claves."""
    m = motor_ia()
    return {
        **m,
        "descripcion": {
            "hermes": "Hermes Agent (Nous Research)",
            "claude": "Claude (Anthropic)",
            "gemini": "Gemini (Google)",
            "reglas": "Sin IA: informe por reglas",
        }[m["motor"]],
    }


@router.get("/usuarios", summary="Usuarios con actividad")
def usuarios(dias: int = Query(7, ge=1, le=MAX_DIAS), db: Session = Depends(get_db)):
    """Usuarios registrados y si tuvieron actividad en los últimos días."""
    desde = datetime.now(UTC) - timedelta(days=dias)
    registrados = {u.username: u for u in db.query(User).all()}
    activos = usuarios_con_actividad(db, desde)
    nombres = sorted(set(registrados) | set(activos))
    return [
        {
            "usuario": n,
            "rol": registrados[n].role if n in registrados else None,
            "con_actividad": n in activos,
        }
        for n in nombres
    ]


@router.get("/sesiones", summary="Sesiones de un usuario, de LOGIN a LOGOUT")
def sesiones(
    usuario: str = Query(..., min_length=1, max_length=100, pattern=r"^[A-Za-z0-9._\-]+$"),
    desde: datetime | None = None,
    hasta: datetime | None = None,
    db: Session = Depends(get_db),
):
    """Sesiones de un usuario, de LOGIN a LOGOUT, con su línea de tiempo y hallazgos por reglas."""
    d, h = _periodo(desde, hasta)
    return analizar(db, usuario, d, h)


@router.post("/informe", summary="El agente de IA revisa las sesiones y redacta el informe")
def informe(pedido: PedidoInforme, request: Request, db: Session = Depends(get_db)):
    """El agente de IA revisa las sesiones y redacta el informe; se guarda y queda en la auditoría."""
    d, h = _periodo(pedido.desde, pedido.hasta)
    analisis = analizar(db, pedido.usuario, d, h)
    resultado = redactar_informe(analisis)
    pidio = request.state.usuario["username"]
    registro = InformeAuditoria(
        usuario_revisado=pedido.usuario,
        pedido_por=pidio,
        desde=d,
        hasta=h,
        motor=resultado["motor"],
        modelo=resultado["modelo"],
        riesgo=analisis["riesgo"],
        sesiones=analisis["total_sesiones"],
        contenido=resultado["contenido"],
        nota=resultado["nota"],
    )
    db.add(registro)
    db.flush()
    db.add(
        AuditLog(
            actor="operador_local",
            action="AUDIT_REPORT",
            entity_type="informes_auditoria",
            entity_id=registro.id,
            details=f"Informe de {pedido.usuario} ({analisis['total_sesiones']} sesiones, "
            f"riesgo {analisis['riesgo']}, motor {resultado['motor']})",
        )
    )
    db.commit()
    return {
        "id": registro.id,
        "usuario": pedido.usuario,
        "riesgo": analisis["riesgo"],
        "sesiones": analisis["total_sesiones"],
        "motor": resultado["motor"],
        "modelo": resultado["modelo"],
        "nota": resultado["nota"],
        "contenido": resultado["contenido"],
        "creado": registro.creado,
    }


@router.get("/informes", summary="Informes generados antes")
def informes(limite: int = Query(20, ge=1, le=100), db: Session = Depends(get_db)):
    """Informes generados antes, del más reciente al más antiguo."""
    filas = db.query(InformeAuditoria).order_by(InformeAuditoria.id.desc()).limit(limite).all()
    return [
        {
            "id": i.id,
            "usuario": i.usuario_revisado,
            "pedido_por": i.pedido_por,
            "desde": i.desde,
            "hasta": i.hasta,
            "motor": i.motor,
            "modelo": i.modelo,
            "riesgo": i.riesgo,
            "sesiones": i.sesiones,
            "nota": i.nota,
            "contenido": i.contenido,
            "creado": i.creado,
        }
        for i in filas
    ]


# --- FIN DEL ARCHIVO ---
