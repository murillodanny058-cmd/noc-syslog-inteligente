"""
Gestión de usuarios (solo administrador).
  GET  /api/users        -> listar
  POST /api/users        -> crear
  PUT  /api/users/{id}   -> editar nombre, rol, estado o contraseña
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import AuditLog, User, UserSession
from ..schemas import UserCreate, UserOut, UserUpdate
from ..seguridad import hash_password, validar_fortaleza

router = APIRouter(prefix="/api/users", tags=["Usuarios (administrador)"])


def auditar(db: Session, accion: str, uid: int, detalle: str):
    # 'operador_local' se reemplaza automáticamente por el usuario que inició sesión
    """Registra en la auditoría una acción sobre un usuario."""
    db.add(
        AuditLog(
            actor="operador_local", action=accion, entity_type="users", entity_id=uid, details=detalle[:300]
        )
    )


@router.get("", response_model=list[UserOut], summary="Listar usuarios")
def listar(db: Session = Depends(get_db)):
    """Lista los usuarios (sin contraseñas)."""
    return db.query(User).order_by(User.username).all()


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED, summary="Crear usuario")
def crear(datos: UserCreate, db: Session = Depends(get_db)):
    """Crea un usuario con contraseña fuerte (se guarda solo el hash)."""
    if db.query(User).filter(User.username == datos.username).first():
        raise HTTPException(status_code=409, detail=f"Ya existe el usuario '{datos.username}'")
    error = validar_fortaleza(datos.password)
    if error:
        raise HTTPException(status_code=422, detail=error)
    u = User(
        username=datos.username,
        full_name=datos.full_name,
        role=datos.role,
        password_hash=hash_password(datos.password),
    )
    db.add(u)
    db.flush()
    auditar(db, "USER_CREATE", u.id, f"Usuario creado: {u.username} ({u.role})")
    db.commit()
    db.refresh(u)
    return u


@router.put("/{uid}", response_model=UserOut, summary="Editar usuario")
def editar(uid: int, datos: UserUpdate, request: Request, db: Session = Depends(get_db)):
    """Cambia nombre, rol, estado o contraseña; cierra sus sesiones si cambian permisos o contraseña."""
    u = db.get(User, uid)
    if u is None:
        raise HTTPException(status_code=404, detail=f"No existe el usuario {uid}")
    cambios = datos.model_dump(exclude_unset=True, exclude_none=True)
    if not cambios:
        raise HTTPException(status_code=400, detail="No se envió ningún cambio")

    # Protección: el administrador no puede bloquearse a sí mismo
    actual = request.state.usuario
    if u.id == actual["id"] and (
        cambios.get("active") is False or cambios.get("role", u.role) != "administrador"
    ):
        raise HTTPException(
            status_code=409, detail="No puede desactivarse ni quitarse el rol de administrador a sí mismo"
        )

    detalle = []
    cerrar_sesiones = False
    if "password" in cambios:
        error = validar_fortaleza(cambios["password"])
        if error:
            raise HTTPException(status_code=422, detail=error)
        u.password_hash = hash_password(cambios.pop("password"))
        detalle.append("contraseña cambiada")
        cerrar_sesiones = True
    for campo, valor in cambios.items():
        if getattr(u, campo) != valor:
            detalle.append(f"{campo}: {getattr(u, campo)} -> {valor}")
            setattr(u, campo, valor)
            if campo in ("role", "active"):
                cerrar_sesiones = True

    if cerrar_sesiones:  # el usuario debe volver a iniciar sesión con sus nuevos permisos
        db.query(UserSession).filter(UserSession.user_id == u.id).delete()
    if detalle:
        auditar(db, "USER_UPDATE", u.id, f"{u.username}: " + "; ".join(detalle))
        db.commit()
        db.refresh(u)
    return u


# --- FIN DEL ARCHIVO ---
