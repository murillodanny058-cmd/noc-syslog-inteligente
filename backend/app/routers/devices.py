"""
Endpoints CRUD del inventario de equipos.
  GET    /api/devices        -> listar (con filtros)
  GET    /api/devices/{id}   -> ver uno
  POST   /api/devices        -> crear
  PUT    /api/devices/{id}   -> editar
  DELETE /api/devices/{id}   -> eliminar
Cada cambio queda registrado en audit_log (quién, qué y cuándo).
"""
import ipaddress
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import AuditLog, Device
from ..schemas import DeviceCreate, DeviceOut, DeviceStatus, DeviceUpdate, Vendor

router = APIRouter(prefix="/api/devices", tags=["Inventario de equipos"])

# Rangos reservados para documentación (RFC 5737 para IPv4, RFC 3849 para IPv6).
# Un equipo SIMULADO debe usar una IP de estos rangos: así nunca se confunde
# con un equipo real de producción.
RANGOS_DOCUMENTACION = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
]

# Por ahora no hay inicio de sesión; en v1.0.0 este valor vendrá del usuario autenticado.
ACTOR = "operador_local"


# ---------------------------------------------------------------------------
# Funciones de apoyo
# ---------------------------------------------------------------------------
def registrar_auditoria(db: Session, accion: str, device_id: int, detalle: str):
    """Agrega un registro al audit_log (se guarda con el mismo commit del cambio)."""
    db.add(AuditLog(actor=ACTOR, action=accion, entity_type="devices",
                    entity_id=device_id, details=detalle))


def validar_ip_simulada(ip: str, es_simulado: bool):
    """Si el equipo es simulado, su IP DEBE estar en un rango de documentación."""
    ip_obj = ipaddress.ip_address(ip)
    if es_simulado and not any(ip_obj in red for red in RANGOS_DOCUMENTACION):
        raise HTTPException(
            status_code=422,
            detail="Un equipo simulado debe usar una IP de documentación (RFC 5737): "
                   "192.0.2.x, 198.51.100.x o 203.0.113.x",
        )


def obtener_o_404(db: Session, device_id: int) -> Device:
    """Busca el equipo por id; si no existe responde 404."""
    equipo = db.get(Device, device_id)
    if equipo is None:
        raise HTTPException(status_code=404, detail=f"No existe un equipo con id {device_id}")
    return equipo


def nombre_duplicado(db: Session, nombre: str, excluir_id: Optional[int] = None) -> bool:
    """True si ya existe otro equipo con ese nombre."""
    consulta = db.query(Device).filter(Device.name == nombre)
    if excluir_id is not None:
        consulta = consulta.filter(Device.id != excluir_id)
    return consulta.first() is not None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@router.get("", response_model=List[DeviceOut], summary="Listar equipos")
def listar_equipos(
    vendor: Optional[Vendor] = Query(None, description="Filtrar por marca"),
    estado: Optional[DeviceStatus] = Query(None, description="Filtrar por estado"),
    buscar: Optional[str] = Query(None, max_length=50,
                                  description="Texto a buscar en nombre, IP o ubicación"),
    db: Session = Depends(get_db),
):
    consulta = db.query(Device)
    if vendor:
        consulta = consulta.filter(Device.vendor == vendor)
    if estado:
        consulta = consulta.filter(Device.status == estado)
    if buscar:
        patron = f"%{buscar}%"
        consulta = consulta.filter(
            Device.name.ilike(patron) | Device.ip_address.ilike(patron) | Device.location.ilike(patron)
        )
    return consulta.order_by(Device.name).all()


@router.get("/{device_id}", response_model=DeviceOut, summary="Ver un equipo")
def ver_equipo(device_id: int, db: Session = Depends(get_db)):
    return obtener_o_404(db, device_id)


@router.post("", response_model=DeviceOut, status_code=status.HTTP_201_CREATED,
             summary="Crear un equipo")
def crear_equipo(datos: DeviceCreate, db: Session = Depends(get_db)):
    if nombre_duplicado(db, datos.name):
        raise HTTPException(status_code=409, detail=f"Ya existe un equipo llamado '{datos.name}'")
    validar_ip_simulada(datos.ip_address, datos.is_simulated)

    equipo = Device(**datos.model_dump())
    db.add(equipo)
    db.flush()  # asigna el id sin confirmar todavía, para usarlo en la auditoría
    registrar_auditoria(db, "CREATE", equipo.id,
                        f"Equipo creado: {equipo.name} ({equipo.ip_address}, {equipo.vendor})")
    db.commit()  # guarda el equipo y su auditoría JUNTOS (todo o nada)
    db.refresh(equipo)
    return equipo


@router.put("/{device_id}", response_model=DeviceOut, summary="Editar un equipo")
def editar_equipo(device_id: int, datos: DeviceUpdate, db: Session = Depends(get_db)):
    equipo = obtener_o_404(db, device_id)

    # Solo los campos que el usuario realmente envió
    cambios = datos.model_dump(exclude_unset=True, exclude_none=True)
    if not cambios:
        raise HTTPException(status_code=400, detail="No se envió ningún campo para actualizar")

    if "name" in cambios and nombre_duplicado(db, cambios["name"], excluir_id=device_id):
        raise HTTPException(status_code=409, detail=f"Ya existe un equipo llamado '{cambios['name']}'")

    # Validamos con los valores FINALES (los nuevos o, si no cambian, los actuales)
    validar_ip_simulada(cambios.get("ip_address", equipo.ip_address),
                        cambios.get("is_simulated", equipo.is_simulated))

    detalle = []
    for campo, valor_nuevo in cambios.items():
        valor_anterior = getattr(equipo, campo)
        if valor_anterior != valor_nuevo:
            detalle.append(f"{campo}: {valor_anterior} -> {valor_nuevo}")
            setattr(equipo, campo, valor_nuevo)

    if detalle:  # solo auditamos si algo cambió de verdad
        registrar_auditoria(db, "UPDATE", equipo.id, "; ".join(detalle))
        db.commit()
        db.refresh(equipo)
    return equipo


@router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT,
               summary="Eliminar un equipo")
def eliminar_equipo(device_id: int, db: Session = Depends(get_db)):
    equipo = obtener_o_404(db, device_id)

    # Protección: no se borra la historia. Si tiene eventos o incidentes,
    # se debe marcar como 'inactivo' en lugar de eliminarlo.
    if equipo.events or equipo.incidents:
        raise HTTPException(
            status_code=409,
            detail="El equipo tiene eventos o incidentes asociados. "
                   "Cámbielo a estado 'inactivo' en vez de eliminarlo.",
        )

    registrar_auditoria(db, "DELETE", equipo.id,
                        f"Equipo eliminado: {equipo.name} ({equipo.ip_address})")
    db.delete(equipo)
    db.commit()