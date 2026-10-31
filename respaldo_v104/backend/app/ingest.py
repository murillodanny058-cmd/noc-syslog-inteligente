"""
Motor de ingesta: convierte un mensaje crudo en un evento clasificado.

Flujo seguro (en este orden):
  1. Parsear      -> extraer PRI, facility, severidad, host, app y mensaje.
  2. Asociar      -> buscar el equipo del inventario por su IP de origen.
  3. Inspeccionar -> ¿el texto intenta dar órdenes a una IA? Se MARCA, nunca se obedece.
  4. Deduplicar   -> si el mismo mensaje llegó hace poco, solo se suma al contador.
  5. Tormentas    -> se limita la cantidad de mensajes NUEVOS por origen por minuto.
  6. Guardar      -> se crea el evento (y una alerta de auditoría si es sospechoso).
  7. Avisar       -> se encola una notificación (Fase 8), sin frenar la ingesta.
"""

import hashlib
import re
from datetime import UTC, datetime, timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session

from .models import AuditLog, Device, SyslogEvent
from .notificaciones import SEV_MAX_GLOBAL, encolar
from .puertos import actualizar_por_evento
from .syslog_parser import SEVERIDADES, limpiar, parsear

VENTANA_DEDUP = timedelta(seconds=60)  # mismo mensaje dentro de 60 s = duplicado
LIMITE_POR_MINUTO = 120  # eventos NUEVOS por IP de origen por minuto

VENDOR_POR_FORMATO = {"Cisco IOS": "Cisco", "Huawei VRP": "Huawei", "Fortinet FortiOS": "Fortinet"}

# Textos típicos de "inyección de instrucciones" (prompt injection) y comandos destructivos.
PATRONES_SOSPECHOSOS = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"ignor(a|e|ar)\s+(las\s+|tus\s+|all\s+|previous\s+|the\s+)*(instrucciones|instructions)",
        r"olvida\s+(tus|las)\s+(instrucciones|reglas)",
        r"(system|sistema)\s*prompt",
        r"\b(act[uú]a|act)\s+(como|as)\b",
        r"\b(eres|you\s+are)\s+(ahora|now)\b",
        r"(ejecuta|execute|run)\s+(el\s+|the\s+)?(comando|command)",
        r"\b(rm\s+-rf|write\s+erase|erase\s+startup-config|format\s+flash)",
        r"<\s*script",
        r"\b(curl|wget)\s+https?://",
        r"\b(api[_-]?key|token|password)\s*[:=]",
    )
]


def es_sospechoso(texto: str) -> bool:
    """True si el texto coincide con algún patrón sospechoso."""
    return any(p.search(texto) for p in PATRONES_SOSPECHOSOS)


def huella(origen: str, severidad: int, mensaje: str) -> str:
    """Huella digital (SHA-256): mismo origen + severidad + texto = misma huella."""
    return hashlib.sha256(f"{origen}|{severidad}|{mensaje}".encode()).hexdigest()


def _resumen(resultado: str, evento: SyslogEvent) -> dict:
    """Resumen de lo que pasó con un mensaje (resultado, id del evento, severidad...)."""
    return {
        "resultado": resultado,
        "event_id": evento.id,
        "severity": evento.severity,
        "severity_name": SEVERIDADES[evento.severity],
        "facility": evento.facility,
        "repeat_count": evento.repeat_count,
        "sospechoso": evento.flagged_suspicious,
    }


def _avisar(evento: SyslogEvent):
    """Encola la notificación de un evento nuevo (los filtros se aplican en notificaciones.py)."""
    origen = evento.hostname or evento.source_ip
    if evento.flagged_suspicious:
        encolar(
            {
                "clave": f"sospechoso:{evento.source_ip}",
                "tipo": "sospechoso",
                "severidad": evento.severity,
                "siempre": True,
                "device_id": evento.device_id,
                "titulo": f"Posible inyección para IA desde {origen}",
                "detalle": f"Mensaje guardado como dato y NO ejecutado: {evento.message}",
            }
        )
    elif evento.severity <= SEV_MAX_GLOBAL:
        encolar(
            {
                "clave": evento.fingerprint,
                "tipo": "evento",
                "severidad": evento.severity,
                "siempre": False,
                "device_id": evento.device_id,
                "titulo": f"{origen} ({evento.vendor or 'sin marca'})",
                "detalle": f"{evento.app_name or '-'}: {evento.message}",
            }
        )


def ingerir(
    db: Session, raw: str, source_ip: str, source_type: str = "simulado", device_id: int | None = None
) -> dict:
    """Procesa UN mensaje Syslog y devuelve qué pasó con él.

    v1.0.3: si se conoce el equipo (consola por cable), se usa ese equipo en vez de buscarlo por IP."""
    ahora = datetime.now(UTC)

    # 1. Parsear
    datos = parsear(raw)
    if not datos["message"]:
        return {"resultado": "rechazado", "motivo": "El mensaje está vacío"}

    # 2. Asociar con el inventario
    equipo = db.get(Device, device_id) if device_id else None
    if equipo is None:
        equipo = db.query(Device).filter(Device.ip_address == source_ip).first()

    # 3. Inspeccionar (se revisa TODO el texto, no solo el mensaje)
    sospechoso = es_sospechoso(limpiar(raw))

    # 4. Deduplicación
    fp = huella(source_ip, datos["severity"], datos["message"])
    existente = (
        db.query(SyslogEvent)
        .filter(SyslogEvent.fingerprint == fp, SyslogEvent.received_at >= ahora - VENTANA_DEDUP)
        .order_by(SyslogEvent.id.desc())
        .first()
    )
    if existente:
        existente.repeat_count += 1
        db.commit()
        return _resumen("duplicado", existente)

    # 5. Control de tormentas
    recientes = (
        db.query(func.count(SyslogEvent.id))
        .filter(SyslogEvent.source_ip == source_ip, SyslogEvent.received_at >= ahora - timedelta(minutes=1))
        .scalar()
    )
    if recientes >= LIMITE_POR_MINUTO:
        encolar(
            {
                "clave": f"tormenta:{source_ip}",
                "tipo": "tormenta",
                "severidad": 1,
                "siempre": True,
                "device_id": equipo.id if equipo else None,
                "titulo": f"Tormenta de logs desde {source_ip}",
                "detalle": f"Más de {LIMITE_POR_MINUTO} eventos nuevos por minuto. "
                "Los excedentes se descartan para proteger el NOC.",
            }
        )
        return {
            "resultado": "descartado_tormenta",
            "motivo": f"Más de {LIMITE_POR_MINUTO} eventos nuevos por minuto desde {source_ip}",
        }

    # 6. Guardar el evento
    evento = SyslogEvent(
        received_at=ahora,
        event_time=datos["event_time"],
        device_id=equipo.id if equipo else None,
        source_ip=source_ip,
        hostname=(datos["hostname"] or (equipo.name if equipo else None) or "")[:255] or None,
        vendor=equipo.vendor if equipo else VENDOR_POR_FORMATO.get(datos["formato"]),
        facility=datos["facility"],
        severity=datos["severity"],
        app_name=(datos["app_name"] or "")[:100] or None,
        message=datos["message"],
        raw=raw[:4096],
        source_type=source_type,
        fingerprint=fp,
        repeat_count=1,
        flagged_suspicious=sospechoso,
    )
    db.add(evento)
    db.flush()

    # Fase 10: si el log dice que un puerto subió o cayó, se actualiza el estado de ese puerto
    try:
        actualizar_por_evento(db, evento)
    except Exception:
        pass  # el puerto es información extra: nunca debe impedir que se guarde el evento

    if sospechoso:
        db.add(
            AuditLog(
                actor="sistema",
                action="SUSPICIOUS_LOG",
                entity_type="syslog_events",
                entity_id=evento.id,
                details=f"Posible inyección de instrucciones desde {source_ip}. "
                f"El mensaje se guardó como dato y NO se ejecutó.",
            )
        )

    db.commit()
    db.refresh(evento)

    # 7. Avisar (en segundo plano)
    _avisar(evento)
    return _resumen("nuevo", evento)


# --- FIN DEL ARCHIVO ---
