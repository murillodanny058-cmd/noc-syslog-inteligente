"""
Esquemas Pydantic: los "moldes" que validan los datos que entran y salen de la API.
Si alguien envía una IP mal escrita o una marca no permitida, FastAPI
responde automáticamente con error 422 y NUNCA llega a la base de datos.
"""
import ipaddress
from datetime import datetime
from typing import Literal, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

# Valores permitidos (los mismos que exige la base de datos en models.py)
Vendor = Literal["Cisco", "Fortinet", "Huawei", "Otro"]
DeviceStatus = Literal["activo", "inactivo", "mantenimiento", "desconocido"]

# El nombre solo puede tener letras, números, punto, guion y guion bajo.
# Así evitamos que se cuelen símbolos raros o código en el nombre.
PATRON_NOMBRE = r"^[A-Za-z0-9._-]+$"


def validar_ip(valor: Optional[str]) -> Optional[str]:
    """Comprueba que sea una IP válida (IPv4 o IPv6) y la normaliza."""
    if valor is None:
        return valor
    try:
        return str(ipaddress.ip_address(valor.strip()))
    except ValueError:
        raise ValueError("Dirección IP inválida. Ejemplo válido: 192.0.2.50")


class DeviceBase(BaseModel):
    """Campos comunes de un equipo."""
    name: str = Field(..., min_length=2, max_length=100, pattern=PATRON_NOMBRE,
                      examples=["SIM-DIST-SW03"])
    ip_address: str = Field(..., examples=["192.0.2.50"])
    vendor: Vendor
    model: Optional[str] = Field(None, max_length=60)
    os_version: Optional[str] = Field(None, max_length=60)
    location: Optional[str] = Field(None, max_length=120)
    status: DeviceStatus = "activo"
    is_simulated: bool = True

    @field_validator("ip_address")
    @classmethod
    def _ip_valida(cls, v):
        return validar_ip(v)


class DeviceCreate(DeviceBase):
    """Datos requeridos para CREAR un equipo."""
    pass


class DeviceUpdate(BaseModel):
    """Datos para EDITAR un equipo: todos opcionales (solo se cambia lo enviado)."""
    name: Optional[str] = Field(None, min_length=2, max_length=100, pattern=PATRON_NOMBRE)
    ip_address: Optional[str] = None
    vendor: Optional[Vendor] = None
    model: Optional[str] = Field(None, max_length=60)
    os_version: Optional[str] = Field(None, max_length=60)
    location: Optional[str] = Field(None, max_length=120)
    status: Optional[DeviceStatus] = None
    is_simulated: Optional[bool] = None

    @field_validator("ip_address")
    @classmethod
    def _ip_valida(cls, v):
        return validar_ip(v)


class DeviceOut(DeviceBase):
    """Lo que la API DEVUELVE: incluye el id y la fecha de actualización."""
    id: int
    updated_at: Optional[datetime] = None

    # Permite construir este esquema directamente desde un objeto de SQLAlchemy
    model_config = ConfigDict(from_attributes=True)

    

# ===========================================================================
# FASE 3: Syslog y eventos
# ===========================================================================
from pydantic import computed_field
from .syslog_parser import SEVERIDADES

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
        return validar_ip(v)


class SyslogImport(BaseModel):
    """Lote de mensajes para importar (máximo 500 por envío)."""
    mensajes: list[SyslogIn] = Field(..., min_length=1, max_length=500)


class IngestResult(BaseModel):
    """Qué pasó con un mensaje recibido."""
    resultado: Literal["nuevo", "duplicado", "descartado_tormenta", "rechazado"]
    event_id: Optional[int] = None
    severity: Optional[int] = None
    severity_name: Optional[str] = None
    facility: Optional[int] = None
    repeat_count: Optional[int] = None
    sospechoso: bool = False
    motivo: Optional[str] = None


class EventOut(BaseModel):
    """Un evento tal como lo devuelve la API."""
    id: int
    received_at: datetime
    event_time: Optional[datetime] = None
    device_id: Optional[int] = None
    source_ip: str
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    facility: int
    severity: int
    app_name: Optional[str] = None
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



# ===========================================================================
# FASE 4: Incidentes
# ===========================================================================
IncidentStatus = Literal["abierto", "asignado", "en_progreso", "cerrado"]

# Nombre de una persona: letras (con tildes), números, espacios, punto, guion
PATRON_PERSONA = r"^[A-Za-zÁÉÍÓÚáéíóúÑñÜü0-9 ._-]+$"


class IncidentCreate(BaseModel):
    """Datos para CREAR un incidente manualmente."""
    title: str = Field(..., min_length=3, max_length=200,
                       examples=["Caída de enlace en SIM-CORE-SW01"])
    description: Optional[str] = Field(None, max_length=2000)
    severity: int = Field(..., ge=0, le=7, examples=[3])
    device_id: Optional[int] = None
    event_id: Optional[int] = None
    assigned_to: Optional[str] = Field(None, min_length=2, max_length=100, pattern=PATRON_PERSONA)


class IncidentUpdate(BaseModel):
    """Seguimiento: cambiar estado, responsable o escribir la resolución."""
    status: Optional[IncidentStatus] = None
    assigned_to: Optional[str] = Field(None, min_length=2, max_length=100, pattern=PATRON_PERSONA)
    resolution: Optional[str] = Field(None, min_length=10, max_length=2000)


class IncidentOut(BaseModel):
    """Un incidente tal como lo devuelve la API."""
    id: int
    title: str
    description: Optional[str] = None
    severity: int
    status: str
    assigned_to: Optional[str] = None
    device_id: Optional[int] = None
    event_id: Optional[int] = None
    resolution: Optional[str] = None
    created_at: datetime
    updated_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)

    @computed_field
    @property
    def severity_name(self) -> str:
        return SEVERIDADES.get(self.severity, "?")

    

# ===========================================================================
# FASE 5: Generador de configuraciones y consola simulada
# ===========================================================================
VendorConfig = Literal["Cisco", "Fortinet", "Huawei"]
FacilityLocal = Literal["local0", "local1", "local2", "local3",
                        "local4", "local5", "local6", "local7"]

# Formatos estrictos: impiden "colar" comandos extra en la configuración
PATRON_INTERFAZ = r"^[A-Za-z][A-Za-z0-9/.:-]{1,40}$"  # ej. Loopback0, GigabitEthernet0/1, port1
PATRON_ZONA = r"^[A-Z]{2,5}$"                          # ej. COT, UTC


class ConfigRequest(BaseModel):
    """Parámetros para generar una configuración Syslog."""
    vendor: VendorConfig = Field(..., examples=["Cisco"])
    nombre_equipo: Optional[str] = Field(None, min_length=2, max_length=60,
                                         pattern=PATRON_NOMBRE, examples=["SIM-CORE-SW01"])
    servidor_ip: str = Field(..., examples=["192.0.2.100"])
    puerto: int = Field(514, ge=1, le=65535)
    protocolo: Literal["udp", "tcp"] = "udp"
    severidad_minima: int = Field(6, ge=0, le=7,
                                  description="Se envían los mensajes desde 0 hasta este nivel")
    facility: FacilityLocal = "local7"
    interfaz_origen: Optional[str] = Field(None, pattern=PATRON_INTERFAZ, examples=["Loopback0"])
    ntp_servidor: Optional[str] = Field(None, examples=["192.0.2.123"])
    zona_horaria: str = Field("COT", pattern=PATRON_ZONA)
    desfase_horas: int = Field(-5, ge=-12, le=14)

    @field_validator("servidor_ip", "ntp_servidor")
    @classmethod
    def _ips_validas(cls, v):
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
    motivo: Optional[str] = None

# --- FIN DEL BLOQUE FASE 5 ---