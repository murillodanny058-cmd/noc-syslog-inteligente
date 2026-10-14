"""
Autenticación y autorización (Fase 7).

- Contraseñas: scrypt (biblioteca estándar de Python) con sal aleatoria.
  Nunca se guardan en texto.
- Sesiones: token aleatorio en una cookie HttpOnly (JavaScript no puede leerla).
  En la base de datos solo se guarda el HASH del token.
- Autorización: tabla central de permisos por rol. Lo que no está en la tabla,
  solo lo puede hacer el administrador (denegar por defecto).
- Auditoría: las acciones quedan a nombre del usuario que inició sesión.
"""
import hashlib
import hmac
import re
import secrets
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, Request
from sqlalchemy import event
from starlette.concurrency import run_in_threadpool

from .database import SessionLocal
from .models import AuditLog, User, UserSession

COOKIE = "noc_sesion"
DURACION_SESION = timedelta(hours=8)
MAX_FALLOS = 5
VENTANA_FALLOS = timedelta(minutes=10)

TODOS = {"operador", "aprobador", "administrador"}
APROBADORES = {"aprobador", "administrador"}
ADMIN = {"administrador"}

# Usuario de la petición actual (para que la auditoría registre quién hizo cada acción)
USUARIO_CTX: ContextVar = ContextVar("usuario_noc", default=None)


# ---------------------------------------------------------------------------
# Contraseñas
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    sal = secrets.token_bytes(16)
    clave = hashlib.scrypt(password.encode("utf-8"), salt=sal, n=2**14, r=8, p=1)
    return f"scrypt${sal.hex()}${clave.hex()}"


def verificar_password(password: str, guardado: str) -> bool:
    try:
        _algoritmo, sal_hex, clave_hex = guardado.split("$")
        clave = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(sal_hex), n=2**14, r=8, p=1)
        return hmac.compare_digest(clave.hex(), clave_hex)  # comparación en tiempo constante
    except (ValueError, AttributeError):
        return False


def validar_fortaleza(password: str):
    """Devuelve un mensaje de error, o None si la contraseña es aceptable."""
    if len(password) < 10:
        return "La contraseña debe tener al menos 10 caracteres"
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        return "La contraseña debe combinar letras y números"
    return None


# Hash ficticio: se usa cuando el usuario no existe, para que la respuesta tarde
# lo mismo y un atacante no pueda adivinar qué usuarios existen.
HASH_FICTICIO = hash_password("usuario-inexistente-123")


# ---------------------------------------------------------------------------
# Sesiones
# ---------------------------------------------------------------------------
def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def crear_sesion(db, usuario: User) -> str:
    token = secrets.token_urlsafe(32)
    db.add(UserSession(token_hash=hash_token(token), user_id=usuario.id,
                       expires_at=datetime.now(timezone.utc) + DURACION_SESION))
    return token


def _usuario_por_token(token):
    if not token:
        return None
    db = SessionLocal()
    try:
        sesion = (db.query(UserSession)
                  .filter(UserSession.token_hash == hash_token(token),
                          UserSession.expires_at > datetime.now(timezone.utc))
                  .first())
        if sesion is None:
            return None
        u = db.get(User, sesion.user_id)
        if u is None or not u.active:
            return None
        return {"id": u.id, "username": u.username, "full_name": u.full_name, "role": u.role}
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Autorización: tabla central de permisos (método, ruta, roles)
# La primera regla que coincide es la que se aplica.
# ---------------------------------------------------------------------------
PERMISOS = [
    ("GET",  r"/api/audit",                                  APROBADORES),
    ("GET",  r"/api/users.*",                                ADMIN),
    ("GET",  r"/api/.*",                                     TODOS),
    ("POST", r"/api/auth/logout",                            TODOS),
    ("POST", r"/api/syslog/(parse|ingest|import|simulate)",  TODOS),
    ("POST", r"/api/incidents(/from-event/\d+)?",            TODOS),
    ("PUT",  r"/api/incidents/\d+",                          TODOS),
    ("POST", r"/api/config/generate",                        TODOS),
    ("POST", r"/api/console/exec",                           TODOS),
    ("POST", r"/api/proposals",                              TODOS),
    ("POST", r"/api/proposals/\d+/(review|execute|verify)",  APROBADORES),
]
# Lo que no esté aquí (crear, editar o borrar equipos; gestionar usuarios...)
# solo lo puede hacer el administrador: DENEGAR POR DEFECTO.


def roles_permitidos(metodo: str, ruta: str) -> set:
    for m, patron, roles in PERMISOS:
        if m == metodo and re.fullmatch(patron, ruta):
            return roles
    return ADMIN


async def autorizar(request: Request) -> dict:
    """Dependencia de FastAPI: exige sesión y revisa el permiso del rol."""
    usuario = await run_in_threadpool(_usuario_por_token, request.cookies.get(COOKIE))
    if usuario is None:
        raise HTTPException(status_code=401, detail="Debe iniciar sesión")
    if usuario["role"] not in roles_permitidos(request.method, request.url.path):
        raise HTTPException(status_code=403,
                            detail=f"Su rol ({usuario['role']}) no tiene permiso para esta acción")
    USUARIO_CTX.set(usuario["username"])
    request.state.usuario = usuario
    return usuario


# ---------------------------------------------------------------------------
# Auditoría con el usuario real
# ---------------------------------------------------------------------------
@event.listens_for(AuditLog, "before_insert")
def _registrar_usuario_real(_mapper, _conexion, registro):
    """Las acciones que el código marca como 'operador_local' quedan a nombre
    del usuario que inició sesión. Las del agente de IA conservan 'agente_ia'."""
    usuario = USUARIO_CTX.get()
    if usuario and registro.actor == "operador_local":
        registro.actor = usuario


# --- FIN DEL ARCHIVO ---