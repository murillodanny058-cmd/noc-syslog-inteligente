"""
Modelo de datos del NOC Syslog Inteligente.
Cada clase = una tabla. Cada Column = una columna.
Las CheckConstraint obligan a la BD a rechazar datos inválidos
(ej. una severidad 9), aunque el código tenga un error.
"""
from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Boolean,
    ForeignKey, CheckConstraint, Index,
)
from sqlalchemy.orm import relationship
from .database import Base


def ahora_utc():
    """Guardamos todas las fechas en UTC para evitar líos de zona horaria."""
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# 1. INVENTARIO DE EQUIPOS
# ---------------------------------------------------------------------------
class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False)   # hostname
    ip_address = Column(String(45), nullable=False)           # 45 caracteres: cabe IPv6
    vendor = Column(String(30), nullable=False)               # marca
    model = Column(String(60))
    os_version = Column(String(60))
    location = Column(String(120))
    status = Column(String(20), nullable=False, default="activo")
    is_simulated = Column(Boolean, nullable=False, default=True)  # etiqueta obligatoria
    updated_at = Column(DateTime, default=ahora_utc, onupdate=ahora_utc)

    events = relationship("SyslogEvent", back_populates="device")
    incidents = relationship("Incident", back_populates="device")

    __table_args__ = (
        CheckConstraint("vendor IN ('Cisco','Fortinet','Huawei','Otro')", name="ck_device_vendor"),
        CheckConstraint("status IN ('activo','inactivo','mantenimiento','desconocido')",
                        name="ck_device_status"),
    )


# ---------------------------------------------------------------------------
# 2. EVENTOS SYSLOG  (¡DATOS NO CONFIABLES!)
# ---------------------------------------------------------------------------
class SyslogEvent(Base):
    __tablename__ = "syslog_events"

    id = Column(Integer, primary_key=True, index=True)
    received_at = Column(DateTime, default=ahora_utc, nullable=False)  # hora real de llegada al NOC
    event_time = Column(DateTime)             # hora que DICE el mensaje (puede ser falsa)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=True)  # null = equipo desconocido
    source_ip = Column(String(45), nullable=False)
    hostname = Column(String(255))
    vendor = Column(String(30))
    facility = Column(Integer, nullable=False)   # 0-23
    severity = Column(Integer, nullable=False)   # 0-7
    app_name = Column(String(100))               # ej. LINK, SYS, SEC_LOGIN

    # REGLA DE ORO: 'message' y 'raw' se guardan como TEXTO. Jamás se ejecutan
    # ni se pasan a una IA como instrucción.
    message = Column(Text, nullable=False)       # contenido ya separado del encabezado
    raw = Column(Text, nullable=False)           # mensaje original tal como llegó (evidencia)
    source_type = Column(String(20), nullable=False, default="simulado")

    # Defensa: deduplicación y control de tormentas
    fingerprint = Column(String(64), index=True)   # hash de (equipo + severidad + mensaje)
    repeat_count = Column(Integer, nullable=False, default=1)  # veces que se repitió
    flagged_suspicious = Column(Boolean, nullable=False, default=False)  # ej. texto tipo "prompt injection"

    device = relationship("Device", back_populates="events")

    __table_args__ = (
        CheckConstraint("severity BETWEEN 0 AND 7", name="ck_event_severity"),
        CheckConstraint("facility BETWEEN 0 AND 23", name="ck_event_facility"),
        CheckConstraint("source_type IN ('simulado','real','importado')", name="ck_event_source"),
        # Índice compuesto para que los filtros del dashboard sean rápidos
        Index("ix_events_filtros", "received_at", "severity", "vendor"),
    )


# ---------------------------------------------------------------------------
# 3. INCIDENTES
# ---------------------------------------------------------------------------
class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(200), nullable=False)
    description = Column(Text)
    severity = Column(Integer, nullable=False)
    status = Column(String(20), nullable=False, default="abierto")
    assigned_to = Column(String(100))            # técnico responsable
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=True)
    event_id = Column(Integer, ForeignKey("syslog_events.id"), nullable=True)  # evento que lo originó
    resolution = Column(Text)                    # qué se hizo para cerrarlo
    created_at = Column(DateTime, default=ahora_utc, nullable=False)
    updated_at = Column(DateTime, default=ahora_utc, onupdate=ahora_utc)
    closed_at = Column(DateTime)

    device = relationship("Device", back_populates="incidents")
    proposals = relationship("ActionProposal", back_populates="incident")

    __table_args__ = (
        CheckConstraint("severity BETWEEN 0 AND 7", name="ck_incident_severity"),
        CheckConstraint("status IN ('abierto','asignado','en_progreso','cerrado')",
                        name="ck_incident_status"),
    )


# ---------------------------------------------------------------------------
# 4. PROPUESTAS DE ACCIÓN  (flujo con aprobación humana obligatoria)
# Propuesta -> Revisión humana -> Aprobación -> Ejecución -> Verificación
# ---------------------------------------------------------------------------
class ActionProposal(Base):
    __tablename__ = "action_proposals"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    action_text = Column(Text, nullable=False)          # qué se propone hacer
    proposed_by = Column(String(20), nullable=False)    # 'humano' o 'agente_ia'
    status = Column(String(20), nullable=False, default="propuesta")
    reviewed_by = Column(String(100))                   # SIEMPRE un humano
    reviewed_at = Column(DateTime)
    verification_notes = Column(Text)
    created_at = Column(DateTime, default=ahora_utc, nullable=False)

    incident = relationship("Incident", back_populates="proposals")

    __table_args__ = (
        CheckConstraint("proposed_by IN ('humano','agente_ia')", name="ck_prop_origin"),
        CheckConstraint(
            "status IN ('propuesta','aprobada','rechazada','ejecutada','verificada')",
            name="ck_prop_status"),
    )


# ---------------------------------------------------------------------------
# 5. AUDITORÍA  (solo se agregan registros; nunca se editan ni se borran)
# ---------------------------------------------------------------------------
class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=ahora_utc, nullable=False)
    actor = Column(String(100), nullable=False)      # quién: usuario, 'sistema' o 'agente_ia'
    action = Column(String(50), nullable=False)      # qué: CREATE, UPDATE, APPROVE, SEED...
    entity_type = Column(String(50))                 # sobre qué tabla
    entity_id = Column(Integer)
    details = Column(Text)
    