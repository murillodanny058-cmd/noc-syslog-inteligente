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
    