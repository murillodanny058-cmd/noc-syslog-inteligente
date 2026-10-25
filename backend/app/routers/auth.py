"""
Inicio y cierre de sesión.
  POST /api/auth/login   -> valida usuario y contraseña; entrega la cookie de sesión
  GET  /api/auth/me      -> quién está conectado
  POST /api/auth/logout  -> cierra la sesión
"""

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import AuditLog, User, UserSession
from ..schemas import LoginIn
from ..seguridad import (
    COOKIE,
    DURACION_SESION,
    HASH_FICTICIO,
    MAX_FALLOS,
    VENTANA_FALLOS,
    autorizar,
    crear_sesion,
    hash_token,
    verificar_password,
)

router = APIRouter(prefix="/api/auth", tags=["Autenticación"])


@router.post("/login", summary="Iniciar sesión")
def login(datos: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
    """Valida usuario y contraseña, bloquea tras 5 fallos en 10 minutos y entrega la cookie de sesión
    (HttpOnly).
    """
    nombre = datos.username.strip().lower()

    # Bloqueo por fuerza bruta: 5 fallos en 10 minutos
    desde = datetime.now(UTC) - VENTANA_FALLOS
    fallos = (
        db.query(func.count(AuditLog.id))
        .filter(
            AuditLog.action == "LOGIN_FAILED",
            AuditLog.details == f"usuario={nombre}",
            AuditLog.timestamp >= desde,
        )
        .scalar()
    )
    if fallos >= MAX_FALLOS:
        raise HTTPException(status_code=429, detail="Demasiados intentos fallidos. Espere 10 minutos.")

    usuario = db.query(User).filter(User.username == nombre).first()
    if usuario is None:
        verificar_password(datos.password, HASH_FICTICIO)  # mismo tiempo de respuesta
        valido = False
    else:
        valido = usuario.active and verificar_password(datos.password, usuario.password_hash)

    if not valido:
        db.add(
            AuditLog(
                actor="sistema",
                action="LOGIN_FAILED",
                entity_type="users",
                entity_id=usuario.id if usuario else None,
                details=f"usuario={nombre}",
            )
        )
        db.commit()
        # Mismo mensaje si el usuario no existe o la contraseña es incorrecta
        raise HTTPException(status_code=401, detail="Usuario o contraseña incorrectos")

    token = crear_sesion(db, usuario)
    db.add(
        AuditLog(
            actor=usuario.username,
            action="LOGIN",
            entity_type="users",
            entity_id=usuario.id,
            details="Inicio de sesión",
        )
    )
    db.commit()

    response.set_cookie(
        COOKIE,
        token,
        httponly=True,
        samesite="strict",
        secure=request.url.scheme == "https",
        max_age=int(DURACION_SESION.total_seconds()),
    )
    return {"username": usuario.username, "full_name": usuario.full_name, "role": usuario.role}


@router.get("/me", summary="Usuario conectado")
def yo(usuario: dict = Depends(autorizar)):
    """Datos del usuario que inició sesión (nombre y rol)."""
    return usuario


@router.post("/logout", summary="Cerrar sesión")
def salir(
    request: Request, response: Response, usuario: dict = Depends(autorizar), db: Session = Depends(get_db)
):
    """Cierra la sesión: borra el token de la base y la cookie del navegador."""
    token = request.cookies.get(COOKIE)
    if token:
        db.query(UserSession).filter(UserSession.token_hash == hash_token(token)).delete()
    db.add(
        AuditLog(
            actor=usuario["username"],
            action="LOGOUT",
            entity_type="users",
            entity_id=usuario["id"],
            details="Cierre de sesión",
        )
    )
    db.commit()
    response.delete_cookie(COOKIE, httponly=True, samesite="strict")
    return {"mensaje": "Sesión cerrada"}


# --- FIN DEL ARCHIVO ---
