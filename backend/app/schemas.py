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
