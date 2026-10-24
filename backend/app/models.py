"""
Modelo de datos del NOC Syslog Inteligente.
Cada clase = una tabla. Cada atributo Mapped[...] = una columna.
Las CheckConstraint obligan a la BD a rechazar datos inválidos
(ej. una severidad 9), aunque el código tenga un error.

Estilo tipado de SQLAlchemy 2.0:
  - Mapped[str]            -> columna obligatoria (NOT NULL).
  - Mapped[Optional[str]]  -> columna que admite NULL.
Así el editor (Pylance) sabe que, por ejemplo, equipo.vendor es un texto
y no una "columna", y puede avisar de errores reales.
"""
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def ahora_utc():
    """Guardamos todas las fechas en UTC para evitar líos de zona horaria."""
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# 1. INVENTARIO DE EQUIPOS
# ---------------------------------------------------------------------------
class Device(Base):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)   # hostname
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)           # 45 caracteres: cabe IPv6
    vendor: Mapped[str] = mapped_column(String(30), nullable=False)               # marca
    model: Mapped[Optional[str]] = mapped_column(String(60))
    os_version: Mapped[Optional[str]] = mapped_column(String(60))
    location: Mapped[Optional[str]] = mapped_column(String(120))
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="activo")
    is_simulated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)  # etiqueta obligatoria
    updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime, default=ahora_utc, onupdate=ahora_utc)

    events: Mapped[list["SyslogEvent"]] = relationship("SyslogEvent", back_populates="device")
    incidents: Mapped[list["Incident"]] = relationship("Incident", back_populates="device")

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

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime, default=ahora_utc, nullable=False)  # hora real de llegada al NOC
    event_time: Mapped[Optional[datetime]] = mapped_column(DateTime)             # hora que DICE el mensaje (puede ser falsa)
    device_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("devices.id"), nullable=True)  # null = equipo desconocido
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    hostname: Mapped[Optional[str]] = mapped_column(String(255))
    vendor: Mapped[Optional[str]] = mapped_column(String(30))
    facility: Mapped[int] = mapped_column(Integer, nullable=False)   # 0-23
    severity: Mapped[int] = mapped_column(Integer, nullable=False)   # 0-7
    app_name: Mapped[Optional[str]] = mapped_column(String(100))     # ej. LINK, SYS, SEC_LOGIN

    # REGLA DE ORO: 'message' y 'raw' se guardan como TEXTO. Jamás se ejecutan
    # ni se pasan a una IA como instrucción.
    message: Mapped[str] = mapped_column(Text, nullable=False)       # contenido ya separado del encabezado
    raw: Mapped[str] = mapped_column(Text, nullable=False)           # mensaje original tal como llegó (evidencia)
    source_type: Mapped[str] = mapped_column(String(20), nullable=False, default="simulado")

    # Defensa: deduplicación y control de tormentas
    fingerprint: Mapped[Optional[str]] = mapped_column(String(64), index=True)   # hash de (equipo + severidad + mensaje)
    repeat_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)  # veces que se repitió
    flagged_suspicious: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)  # ej. texto tipo "prompt injection"

    device: Mapped[Optional["Device"]] = relationship("Device", back_populates="events")

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

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    severity: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="abierto")
    assigned_to: Mapped[Optional[str]] = mapped_column(String(100))            # técnico responsable
    device_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("devices.id"), nullable=True)
    event_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("syslog_events.id"), nullable=True)  # evento que lo originó
    resolution: Mapped[Optional[str]] = mapped_column(Text)                    # qué se hizo para cerrarlo
    created_at: Mapped[datetime] = mapped_column(DateTime, default=ahora_utc, nullable=False)
    updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime, default=ahora_utc, onupdate=ahora_utc)
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)

    device: Mapped[Optional["Device"]] = relationship("Device", back_populates="incidents")
    proposals: Mapped[list["ActionProposal"]] = relationship("ActionProposal", back_populates="incident")

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

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    incident_id: Mapped[int] = mapped_column(Integer, ForeignKey("incidents.id"), nullable=False)
    action_text: Mapped[str] = mapped_column(Text, nullable=False)          # qué se propone hacer
    proposed_by: Mapped[str] = mapped_column(String(20), nullable=False)    # 'humano' o 'agente_ia'
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="propuesta")
    reviewed_by: Mapped[Optional[str]] = mapped_column(String(100))         # SIEMPRE un humano
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    verification_notes: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=ahora_utc, nullable=False)

    incident: Mapped["Incident"] = relationship("Incident", back_populates="proposals")

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

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=ahora_utc, nullable=False)
    actor: Mapped[str] = mapped_column(String(100), nullable=False)      # quién: usuario, 'sistema' o 'agente_ia'
    action: Mapped[str] = mapped_column(String(50), nullable=False)      # qué: CREATE, UPDATE, APPROVE, SEED...
    entity_type: Mapped[Optional[str]] = mapped_column(String(50))       # sobre qué tabla
    entity_id: Mapped[Optional[int]] = mapped_column(Integer)
    details: Mapped[Optional[str]] = mapped_column(Text)


# ---------------------------------------------------------------------------
# 6. USUARIOS Y SESIONES (Fase 7)
# ---------------------------------------------------------------------------
class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(100), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(300), nullable=False)   # NUNCA la contraseña en texto
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="operador")
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=ahora_utc, nullable=False)

    __table_args__ = (
        CheckConstraint("role IN ('operador','aprobador','administrador')", name="ck_user_role"),
    )


class UserSession(Base):
    __tablename__ = "user_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)  # solo el hash del token
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=ahora_utc, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)

# --- FIN BLOQUE FASE 7 ---


# ---------------------------------------------------------------------------
# 7. NOTIFICACIONES (Fase 8): historial de avisos enviados, silenciados o fallidos
# ---------------------------------------------------------------------------
class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=ahora_utc, nullable=False)
    canal: Mapped[str] = mapped_column(String(20), nullable=False)       # telegram, correo, whatsapp, todos
    clave: Mapped[str] = mapped_column(String(120), nullable=False)      # identifica "el mismo problema"
    tipo: Mapped[str] = mapped_column(String(30), nullable=False)        # evento, sospechoso, tormenta, agente_suspendido, prueba
    severidad: Mapped[int] = mapped_column(Integer, nullable=False)
    estado: Mapped[str] = mapped_column(String(20), nullable=False)      # enviado, silenciado, limitado, mantenimiento, error
    titulo: Mapped[str] = mapped_column(String(200), nullable=False)
    detalle: Mapped[Optional[str]] = mapped_column(Text)                 # motivo del error (sin credenciales)

    __table_args__ = (
        Index("ix_notif_canal_estado", "canal", "estado", "created_at"),
        Index("ix_notif_clave", "clave"),
    )

# --- FIN BLOQUE FASE 8 ---

# ---------------------------------------------------------------------------
# 8. PUERTOS (Fase 10): en qué puerto pasó el evento y qué hay conectado ahí
# ---------------------------------------------------------------------------
class Port(Base):
    __tablename__ = "puertos"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    device_id: Mapped[int] = mapped_column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    interfaz: Mapped[str] = mapped_column(String(64), nullable=False)    # nombre largo: GigabitEthernet1/0/5
    corto: Mapped[Optional[str]] = mapped_column(String(20))             # abreviado: Gi1/0/5
    estado: Mapped[Optional[str]] = mapped_column(String(20), default="desconocido")  # up, down, admin-down, err-disabled
    vlan: Mapped[Optional[str]] = mapped_column(String(20))
    descripcion: Mapped[Optional[str]] = mapped_column(String(120))
    vecino: Mapped[Optional[str]] = mapped_column(String(200))           # equipo conectado (CDP/LLDP) y su puerto
    mac: Mapped[Optional[str]] = mapped_column(Text)                     # MAC aprendidas en ese puerto (máx. 10)
    origen: Mapped[str] = mapped_column(String(20), nullable=False, default="evento")  # simulado, consola, evento
    actualizado: Mapped[Optional[datetime]] = mapped_column(DateTime, default=ahora_utc)
    ultimo_evento_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # último log que mencionó este puerto

    __table_args__ = (
        Index("ux_puerto_equipo_interfaz", "device_id", "interfaz", unique=True),
    )

# --- FIN BLOQUE FASE 10 ---

# ---------------------------------------------------------------------------
# 9. CAMBIOS DE CONFIGURACIÓN (Fase 11): con aprobación humana obligatoria
# ---------------------------------------------------------------------------
class ConfigChange(Base):
    __tablename__ = "cambios_config"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    device_id: Mapped[int] = mapped_column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    incident_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("incidents.id"), nullable=True)
    plantilla: Mapped[str] = mapped_column(String(40), nullable=False)       # del catálogo cerrado
    parametros: Mapped[str] = mapped_column(Text, nullable=False)            # JSON con los datos validados
    motivo: Mapped[str] = mapped_column(Text, nullable=False)                # por qué se propone
    comandos: Mapped[str] = mapped_column(Text, nullable=False)              # EXACTAMENTE lo que se enviará
    rollback: Mapped[str] = mapped_column(Text, nullable=False)              # cómo deshacerlo
    plan: Mapped[str] = mapped_column(Text, nullable=False)                  # JSON: respaldo, verificación, texto esperado
    origen: Mapped[str] = mapped_column(String(20), nullable=False)          # humano, agente_ia
    propuesto_por: Mapped[str] = mapped_column(String(100), nullable=False)
    aprobado_por: Mapped[Optional[str]] = mapped_column(String(100))         # SIEMPRE un humano distinto de quien propuso
    ejecutado_por: Mapped[Optional[str]] = mapped_column(String(100))
    estado: Mapped[str] = mapped_column(String(30), nullable=False, default="propuesta")
    nota_revision: Mapped[Optional[str]] = mapped_column(Text)
    respaldo: Mapped[Optional[str]] = mapped_column(Text)                    # salida de los comandos de lectura ANTES del cambio
    salida: Mapped[Optional[str]] = mapped_column(Text)                      # lo que respondió el equipo
    resultado: Mapped[Optional[str]] = mapped_column(Text)                   # verificación / rollback
    simulado: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    creado: Mapped[datetime] = mapped_column(DateTime, default=ahora_utc, nullable=False)
    revisado: Mapped[Optional[datetime]] = mapped_column(DateTime)
    ejecutado: Mapped[Optional[datetime]] = mapped_column(DateTime)

    __table_args__ = (
        CheckConstraint("origen IN ('humano','agente_ia')", name="ck_cambio_origen"),
        CheckConstraint("estado IN ('propuesta','aprobada','rechazada','ejecutada','fallida',"
                        "'verificada','verificacion_fallida','revertida')", name="ck_cambio_estado"),
    )

# --- FIN BLOQUE FASE 11 ---


# ---------------------------------------------------------------------------
# 12. AGENTE AUDITOR (Fase 12): actividad de cada usuario e informes
# ---------------------------------------------------------------------------
from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, Index, Integer, String, Text


def ahora_utc():
    return datetime.now(timezone.utc)
class Actividad(Base):
    """Cada petición a la API hecha por un usuario con sesión (incluye intentos sin permiso)."""
    __tablename__ = "actividad"
    id = Column(Integer, primary_key=True)
    creado = Column(DateTime, default=ahora_utc, nullable=False)
    usuario = Column(String(100), nullable=False)
    metodo = Column(String(10), nullable=False)
    ruta = Column(String(200), nullable=False)
    consulta = Column(String(300))          # filtros usados (ej. desde, severidad)
    estado = Column(Integer, nullable=False)  # código HTTP: 200 ok, 403 sin permiso...
    duracion_ms = Column(Integer)

    __table_args__ = (Index("ix_actividad_usuario_fecha", "usuario", "creado"),)


class InformeAuditoria(Base):
    """Informes del agente auditor (quién lo pidió, sobre quién, con qué motor)."""
    __tablename__ = "informes_auditoria"
    id = Column(Integer, primary_key=True)
    creado = Column(DateTime, default=ahora_utc, nullable=False)
    usuario_revisado = Column(String(100), nullable=False)
    pedido_por = Column(String(100), nullable=False)
    desde = Column(DateTime, nullable=False)
    hasta = Column(DateTime, nullable=False)
    motor = Column(String(20), nullable=False)   # claude, gemini o reglas
    modelo = Column(String(60))
    riesgo = Column(String(10), nullable=False)
    sesiones = Column(Integer, nullable=False, default=0)
    contenido = Column(Text, nullable=False)
    nota = Column(Text)

# --- FIN BLOQUE FASE 12 ---
