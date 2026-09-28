"""
Política de defensa frente a acciones de agentes de IA: reglas automáticas.

Suspensión ("disyuntor"): si un agente de IA acumula MAX_BLOQUEOS comandos
rechazados dentro de VENTANA, queda SUSPENDIDO: todo lo que pida se rechaza,
incluso los comandos permitidos. Cada intento durante la suspensión también
se audita, así que el agente sigue suspendido mientras siga insistiendo.
"""
from datetime import datetime, timedelta, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from .models import AuditLog

MAX_BLOQUEOS = 3
VENTANA = timedelta(minutes=10)
MOTIVO_SUSPENSION = (f"Agente de IA SUSPENDIDO: acumuló {MAX_BLOQUEOS} o más acciones rechazadas "
                     f"en {int(VENTANA.total_seconds() // 60)} minutos. Requiere revisión humana.")


def bloqueos_recientes_agente(db: Session) -> int:
    """Cuántos comandos del agente de IA se bloquearon dentro de la ventana."""
    desde = datetime.now(timezone.utc) - VENTANA
    return (db.query(func.count(AuditLog.id))
            .filter(AuditLog.actor == "agente_ia",
                    AuditLog.action == "CONSOLE_BLOCKED",
                    AuditLog.timestamp >= desde)
            .scalar())


def agente_suspendido(db: Session) -> bool:
    return bloqueos_recientes_agente(db) >= MAX_BLOQUEOS

# --- FIN DEL ARCHIVO ---