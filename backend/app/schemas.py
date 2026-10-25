"""
Esquemas Pydantic: los "moldes" que validan los datos que entran y salen de la API.
Si alguien envía una IP mal escrita o una marca no permitida, FastAPI
responde automáticamente con error 422 y NUNCA llega a la base de datos.
"""

import ipaddress
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator

from .syslog_parser import SEVERIDADES

# Valores permitidos (los mismos que exige la base de datos en models.py)
Vendor = Literal["Cisco", "Fortinet", "Huawei", "Otro"]
DeviceStatus = Literal["activo", "inactivo", "mantenimiento", "desconocido"]

# El nombre solo puede tener letras, números, punto, guion y guion bajo.
# Así evitamos que se cuelen símbolos raros o código en el nombre.
PATRON_NOMBRE = r"^[A-Za-z0-9._-]+$"


def validar_ip(valor: str | None) -> str | None:
    """Comprueba que sea una IP válida (IPv4 o IPv6) y la normaliza."""
    if valor is None:
        return valor
    try:
        return str(ipaddress.ip_address(valor.strip()))
    except ValueError:
        raise ValueError("Dirección IP inválida. Ejemplo válido: 192.0.2.50") from None


class DeviceBase(BaseModel):
    """Campos comunes de un equipo."""

    name: str = Field(..., min_length=2, max_length=100, pattern=PATRON_NOMBRE, examples=["SIM-DIST-SW03"])
    ip_address: str = Field(..., examples=["192.0.2.50"])
    vendor: Vendor
    model: str | None = Field(None, max_length=60)
    os_version: str | None = Field(None, max_length=60)
    location: str | None = Field(None, max_length=120)
    status: DeviceStatus = "activo"
    is_simulated: bool = True

    @field_validator("ip_address")
    @classmethod
    def _ip_valida(cls, v):
        """Valida la IP (formato correcto y rangos permitidos)."""
        return validar_ip(v)


class DeviceCreate(DeviceBase):
    """Datos requeridos para CREAR un equipo."""

    pass


class DeviceUpdate(BaseModel):
    """Datos para EDITAR un equipo: todos opcionales (solo se cambia lo enviado)."""

    name: str | None = Field(None, min_length=2, max_length=100, pattern=PATRON_NOMBRE)
    ip_address: str | None = None
    vendor: Vendor | None = None
    model: str | None = Field(None, max_length=60)
    os_version: str | None = Field(None, max_length=60)
    location: str | None = Field(None, max_length=120)
    status: DeviceStatus | None = None
    is_simulated: bool | None = None

    @field_validator("ip_address")
    @classmethod
    def _ip_valida(cls, v):
        """Valida la IP (formato correcto y rangos permitidos)."""
        return validar_ip(v)


class DeviceOut(DeviceBase):
    """Lo que la API DEVUELVE: incluye el id y la fecha de actualización."""

    id: int
    updated_at: datetime | None = None

    # Permite construir este esquema directamente desde un objeto de SQLAlchemy
    model_config = ConfigDict(from_attributes=True)


# ===========================================================================
# FASE 3: Syslog y eventos
# ===========================================================================

SourceType = Literal["simulado", "real", "importado"]
EJEMPLO_SYSLOG = "<34>Oct 11 22:14:15 SIM-FW-EDGE01 sshd: Failed password for admin"


class SyslogTexto(BaseModel):
    """Un mensaje Syslog en texto crudo."""

    raw: str = Field(..., min_length=1, max_length=4096, examples=[EJEMPLO_SYSLOG])


class SyslogIn(SyslogTexto):
    """Mensaje + IP del equipo que lo envió."""

    source_ip: str = Field(..., examples=["192.0.2.20"])
    source_type: SourceType = "simulado"

    @field_validator("source_ip")
    @classmethod
    def _ip_valida(cls, v):
        """Valida la IP (formato correcto y rangos permitidos)."""
        return validar_ip(v)


class SyslogImport(BaseModel):
    """Lote de mensajes para importar (máximo 500 por envío)."""

    mensajes: list[SyslogIn] = Field(..., min_length=1, max_length=500)


class IngestResult(BaseModel):
    """Qué pasó con un mensaje recibido."""

    resultado: Literal["nuevo", "duplicado", "descartado_tormenta", "rechazado"]
    event_id: int | None = None
    severity: int | None = None
    severity_name: str | None = None
    facility: int | None = None
    repeat_count: int | None = None
    sospechoso: bool = False
    motivo: str | None = None


class EventOut(BaseModel):
    """Un evento tal como lo devuelve la API."""

    id: int
    received_at: datetime
    event_time: datetime | None = None
    device_id: int | None = None
    source_ip: str
    hostname: str | None = None
    vendor: str | None = None
    facility: int
    severity: int
    app_name: str | None = None
    message: str
    source_type: str
    repeat_count: int
    flagged_suspicious: bool

    model_config = ConfigDict(from_attributes=True)

    @computed_field
    @property
    def severity_name(self) -> str:
        """Nombre de la severidad (ej. 2 -> Critical), calculado automáticamente."""
        return SEVERIDADES.get(self.severity, "?")

    @computed_field
    @property
    def interfaz(self) -> str | None:
        """Fase 10: puerto mencionado en el mensaje (ej. GigabitEthernet1/0/5)."""
        from .puertos import extraer_interfaz  # import aquí para evitar import circular

        return extraer_interfaz(self.message)


# ===========================================================================
# FASE 4: Incidentes
# ===========================================================================
IncidentStatus = Literal["abierto", "asignado", "en_progreso", "cerrado"]

# Nombre de una persona: letras (con tildes), números, espacios, punto, guion
PATRON_PERSONA = r"^[A-Za-zÁÉÍÓÚáéíóúÑñÜü0-9 ._-]+$"


class IncidentCreate(BaseModel):
    """Datos para CREAR un incidente manualmente."""

    title: str = Field(..., min_length=3, max_length=200, examples=["Caída de enlace en SIM-CORE-SW01"])
    description: str | None = Field(None, max_length=2000)
    severity: int = Field(..., ge=0, le=7, examples=[3])
    device_id: int | None = None
    event_id: int | None = None
    assigned_to: str | None = Field(None, min_length=2, max_length=100, pattern=PATRON_PERSONA)


class IncidentUpdate(BaseModel):
    """Seguimiento: cambiar estado, responsable o escribir la resolución."""

    status: IncidentStatus | None = None
    assigned_to: str | None = Field(None, min_length=2, max_length=100, pattern=PATRON_PERSONA)
    resolution: str | None = Field(None, min_length=10, max_length=2000)


class IncidentOut(BaseModel):
    """Un incidente tal como lo devuelve la API."""

    id: int
    title: str
    description: str | None = None
    severity: int
    status: str
    assigned_to: str | None = None
    device_id: int | None = None
    event_id: int | None = None
    resolution: str | None = None
    created_at: datetime
    updated_at: datetime | None = None
    closed_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)

    @computed_field
    @property
    def severity_name(self) -> str:
        """Nombre de la severidad (ej. 3 -> Error)."""
        return SEVERIDADES.get(self.severity, "?")


# ===========================================================================
# FASE 5: Generador de configuraciones y consola simulada
# ===========================================================================
VendorConfig = Literal["Cisco", "Fortinet", "Huawei"]
FacilityLocal = Literal["local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7"]

# Formatos estrictos: impiden "colar" comandos extra en la configuración
PATRON_INTERFAZ = r"^[A-Za-z][A-Za-z0-9/.:-]{1,40}$"  # ej. Loopback0, GigabitEthernet0/1, port1
PATRON_ZONA = r"^[A-Z]{2,5}$"  # ej. COT, UTC


class ConfigRequest(BaseModel):
    """Parámetros para generar una configuración Syslog."""

    vendor: VendorConfig = Field(..., examples=["Cisco"])
    nombre_equipo: str | None = Field(
        None, min_length=2, max_length=60, pattern=PATRON_NOMBRE, examples=["SIM-CORE-SW01"]
    )
    servidor_ip: str = Field(..., examples=["192.0.2.100"])
    puerto: int = Field(514, ge=1, le=65535)
    protocolo: Literal["udp", "tcp"] = "udp"
    severidad_minima: int = Field(
        6, ge=0, le=7, description="Se envían los mensajes desde 0 hasta este nivel"
    )
    facility: FacilityLocal = "local7"
    interfaz_origen: str | None = Field(None, pattern=PATRON_INTERFAZ, examples=["Loopback0"])
    ntp_servidor: str | None = Field(None, examples=["192.0.2.123"])
    zona_horaria: str = Field("COT", pattern=PATRON_ZONA)
    desfase_horas: int = Field(-5, ge=-12, le=14)

    @field_validator("servidor_ip", "ntp_servidor")
    @classmethod
    def _ips_validas(cls, v):
        """Valida cada IP de la lista."""
        return validar_ip(v)


class ConfigResult(BaseModel):
    """Configuración generada, con advertencias y comandos de verificación."""

    vendor: str
    configuracion: str
    advertencias: list[str]
    verificacion: list[str]


class ConsoleRequest(BaseModel):
    """Un comando para la consola simulada."""

    device_id: int = Field(..., examples=[1])
    comando: str = Field(..., min_length=1, max_length=200, examples=["show logging"])
    actor: Literal["operador", "agente_ia"] = "operador"


class ConsoleResult(BaseModel):
    """Respuesta de la consola simulada."""

    prompt: str
    comando: str
    categoria: Literal["permitido", "bloqueado", "no_permitido", "invalido"]
    permitido: bool
    salida: str
    motivo: str | None = None


# --- FIN DEL BLOQUE FASE 5 ---


# ===========================================================================
# FASE 6: Propuestas de acción con aprobación humana
# ===========================================================================
class ProposalCreate(BaseModel):
    """Una acción propuesta para resolver un incidente."""

    incident_id: int = Field(..., examples=[3])
    action_text: str = Field(
        ...,
        min_length=10,
        max_length=500,
        examples=["Reemplazar la fuente de poder del slot 15 en SIM-AR-RTR01 (sim)"],
    )
    proposed_by: Literal["humano", "agente_ia"] = "humano"


class ProposalReview(BaseModel):
    """Revisión HUMANA: aprobar o rechazar."""

    decision: Literal["aprobada", "rechazada"]
    reviewed_by: str = Field(
        ..., min_length=2, max_length=100, pattern=PATRON_PERSONA, examples=["Dany Murillo"]
    )
    nota: str | None = Field(None, max_length=500)


class ProposalExecute(BaseModel):
    """Ejecución autorizada (SIMULADA)."""

    ejecutado_por: str = Field(
        ..., min_length=2, max_length=100, pattern=PATRON_PERSONA, examples=["Dany Murillo"]
    )


class ProposalVerify(BaseModel):
    """Verificación posterior a la ejecución."""

    notas: str = Field(
        ...,
        min_length=10,
        max_length=1000,
        examples=["La fuente quedó operativa y cesaron las alarmas (sim)"],
    )


class ProposalOut(BaseModel):
    """Respuesta con los datos de una propuesta de acción."""

    id: int
    incident_id: int
    action_text: str
    proposed_by: str
    status: str
    reviewed_by: str | None = None
    reviewed_at: datetime | None = None
    verification_notes: str | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# --- FIN DEL BLOQUE FASE 6 ---


# ===========================================================================
# FASE 7: Usuarios, roles y sesiones
# ===========================================================================
Rol = Literal["operador", "aprobador", "administrador"]
PATRON_USUARIO = r"^[a-z0-9._-]{3,50}$"  # minúsculas, números, punto, guion


class LoginIn(BaseModel):
    """Usuario y contraseña para iniciar sesión."""

    username: str = Field(..., min_length=3, max_length=50, examples=["admin"])
    password: str = Field(..., min_length=1, max_length=200)


class UserCreate(BaseModel):
    """Datos para crear un usuario (la contraseña se valida en el servidor)."""

    username: str = Field(..., pattern=PATRON_USUARIO, examples=["operador1"])
    full_name: str = Field(
        ..., min_length=3, max_length=100, pattern=PATRON_PERSONA, examples=["Operador de turno"]
    )
    role: Rol = "operador"
    password: str = Field(..., min_length=10, max_length=200)


class UserUpdate(BaseModel):
    """Datos para editar un usuario: solo se cambia lo que se envía."""

    full_name: str | None = Field(None, min_length=3, max_length=100, pattern=PATRON_PERSONA)
    role: Rol | None = None
    active: bool | None = None
    password: str | None = Field(None, min_length=10, max_length=200)


class UserOut(BaseModel):
    """Datos públicos de un usuario (nunca incluye la contraseña)."""

    id: int
    username: str
    full_name: str
    role: str
    active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# --- FIN BLOQUE FASE 7 ---


# ===========================================================================
# FASE 8: Notificaciones
# ===========================================================================
class NotificationTest(BaseModel):
    """Canal para el mensaje de prueba."""

    canal: Literal["telegram", "correo", "whatsapp"] = Field(..., examples=["telegram"])


class NotificationOut(BaseModel):
    """Un registro del historial de notificaciones."""

    id: int
    created_at: datetime
    canal: str
    clave: str
    tipo: str
    severidad: int
    estado: str
    titulo: str
    detalle: str | None = None

    model_config = ConfigDict(from_attributes=True)


# --- FIN BLOQUE FASE 8 ---
# ===========================================================================
# FASE 9: Consola REAL por cable de consola (puerto serial / COM)
# ===========================================================================
# Windows: COM1..COM256 · Linux: /dev/ttyUSB0, /dev/ttyACM0, /dev/ttyS0
PATRON_PUERTO = r"^(COM\d{1,3}|/dev/tty(USB|ACM|S)\d{1,3})$"


class SerialConectar(BaseModel):
    """Datos para abrir la consola real."""

    puerto: str = Field(..., pattern=PATRON_PUERTO, examples=["COM3"])
    velocidad: Literal[9600, 19200, 38400, 57600, 115200] = 9600
    device_id: int = Field(..., examples=[5])


class SerialExec(BaseModel):
    """Un comando de solo lectura para el equipo real."""

    comando: str = Field(..., min_length=1, max_length=200, examples=["show ip interface brief"])
    actor: Literal["operador", "agente_ia"] = "operador"


# --- FIN BLOQUE FASE 9 ---


# ===========================================================================
# FASE 10: Puertos e interfaces
# ===========================================================================
class PortOut(BaseModel):
    """Un puerto de un equipo."""

    id: int
    device_id: int
    interfaz: str
    corto: str | None = None
    estado: str | None = None
    vlan: str | None = None
    descripcion: str | None = None
    vecino: str | None = None
    mac: str | None = None
    origen: str
    actualizado: datetime | None = None
    ultimo_evento_id: int | None = None

    model_config = ConfigDict(from_attributes=True)


class PuertoDeEvento(BaseModel):
    """Respuesta de 'ver puerto' de un evento."""

    evento_id: int
    device_id: int | None = None
    equipo: str | None = None
    interfaz: str | None = None
    puerto: PortOut | None = None
    eventos_del_puerto: list[EventOut] = []
    nota: str | None = None


# --- FIN BLOQUE FASE 10 ---

# ===========================================================================
# FASE 11: Cambios de configuración con aprobación humana
# ===========================================================================
PlantillaCambio = Literal["syslog_servidor", "descripcion_puerto", "estado_puerto"]


class CambioCreate(BaseModel):
    """Propuesta de cambio: solo plantillas del catálogo, nunca comandos libres."""

    device_id: int = Field(..., examples=[5])
    plantilla: PlantillaCambio
    parametros: dict[str, str] = Field(
        ..., examples=[{"ip": "192.168.100.10", "puerto": "5514", "nivel": "informational"}]
    )
    motivo: str = Field(
        ..., min_length=10, max_length=300, examples=["El switch del laboratorio debe enviar sus logs al NOC"]
    )
    incident_id: int | None = None
    origen: Literal["humano", "agente_ia"] = "humano"


class CambioReview(BaseModel):
    """Revisión HUMANA del cambio."""

    decision: Literal["aprobada", "rechazada"]
    nota: str | None = Field(None, max_length=300)


class CambioOut(BaseModel):
    """Respuesta con todos los datos de un cambio de configuración."""

    id: int
    device_id: int
    incident_id: int | None = None
    plantilla: str
    parametros: str
    motivo: str
    comandos: str
    rollback: str
    origen: str
    propuesto_por: str
    aprobado_por: str | None = None
    ejecutado_por: str | None = None
    estado: str
    nota_revision: str | None = None
    respaldo: str | None = None
    salida: str | None = None
    resultado: str | None = None
    simulado: bool
    creado: datetime
    revisado: datetime | None = None
    ejecutado: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


# --- FIN BLOQUE FASE 11 ---
