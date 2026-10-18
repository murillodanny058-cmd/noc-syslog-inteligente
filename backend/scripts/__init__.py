"""
Servidor principal del NOC Syslog Inteligente.

Rutas expuestas:
    - /api/...      -> API REST. Todas las rutas exigen sesión, excepto
                       /api/health y las rutas de autenticación (login).
    - /docs         -> Documentación interactiva (Swagger UI). Requiere haber
                       iniciado sesión previamente en el dashboard.
    - /login.html   -> Página de inicio de sesión.
    - /             -> Dashboard web (archivos estáticos del frontend).
"""

# =============================================================================
# Importaciones
# =============================================================================

# --- Biblioteca estándar -----------------------------------------------------
from typing import Any, Final

# --- Terceros ----------------------------------------------------------------
from fastapi import Depends, FastAPI, Query
from fastapi.params import Depends as DependsParam
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

# --- Módulos locales del proyecto --------------------------------------------
from . import models
from .config import APP_NAME, APP_VERSION, BASE_DIR
from .database import MOTOR, Base, engine, get_db
from .routers import (
    alertas,
    auth,
    dashboard,
    devices,
    herramientas,
    incidents,
    politica,
    syslog,
    usuarios,
)
from .seguridad import autorizar


# =============================================================================
# Constantes de configuración
# =============================================================================

# Descripción que se muestra en la cabecera de /docs.
DESCRIPCION_API: Final[str] = (
    "NOC basado en Syslog con defensa frente a acciones de agentes de IA. "
    "Para usar esta página, inicie sesión primero en el dashboard."
)

# Dependencias aplicadas a toda ruta protegida: verifican que exista una
# sesión válida y que el rol del usuario tenga permiso para la acción.
PROTEGIDO: Final[list[DependsParam]] = [Depends(autorizar)]

# Códigos de respuesta comunes que se documentan en /docs para cada ruta.
RESPUESTAS: Final[dict[int | str, dict[str, Any]]] = {
    401: {"description": "No ha iniciado sesión"},
    403: {"description": "Su rol no tiene permiso para esta acción"},
    404: {"description": "El recurso no existe"},
    409: {"description": "Conflicto con el estado actual (duplicado o estado no permitido)"},
}

# Routers que requieren sesión y permisos. El router 'auth' queda fuera
# a propósito, porque el login debe ser accesible sin sesión.
ROUTERS_PROTEGIDOS: Final[tuple] = (
    dashboard,
    devices,
    syslog,
    incidents,
    herramientas,
    politica,
    usuarios,
    alertas,
)

# Límites del parámetro de paginación del registro de auditoría.
AUDITORIA_LIMITE_DEFECTO: Final[int] = 20
AUDITORIA_LIMITE_MIN: Final[int] = 1
AUDITORIA_LIMITE_MAX: Final[int] = 200

# Directorio con los archivos estáticos del dashboard web.
DIRECTORIO_FRONTEND: Final = BASE_DIR / "frontend"


# =============================================================================
# Inicialización de la base de datos
# =============================================================================

# Crea las tablas que aún no existan (incluye users, user_sessions y
# notifications). No modifica tablas existentes; para cambios de esquema
# se recomienda usar migraciones (p. ej. Alembic).
Base.metadata.create_all(bind=engine)


# =============================================================================
# Aplicación FastAPI
# =============================================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=DESCRIPCION_API,
)


# =============================================================================
# Registro de routers
# =============================================================================

# Router de autenticación: público (no lleva la dependencia 'autorizar').
app.include_router(auth.router, responses=RESPUESTAS)

# Resto de routers: todos protegidos por sesión y permisos de rol.
for modulo in ROUTERS_PROTEGIDOS:
    app.include_router(
        modulo.router,
        dependencies=PROTEGIDO,
        responses=RESPUESTAS,
    )


# =============================================================================
# Rutas del sistema
# =============================================================================

@app.get(
    "/api/health",
    tags=["Sistema"],
    summary="Chequeo de salud (público)",
)
def health() -> dict[str, str]:
    """
    Indica que el servidor está en funcionamiento.

    Ruta pública, pensada para monitores externos y balanceadores de carga.

    Returns:
        Diccionario con el estado, el nombre y versión de la aplicación
        y el motor de base de datos configurado.
    """
    return {
        "status": "ok",
        "app": APP_NAME,
        "version": APP_VERSION,
        "base_datos": MOTOR,
    }


# =============================================================================
# Rutas de auditoría
# =============================================================================

def _serializar_auditoria(registro: models.AuditLog) -> dict[str, Any]:
    """
    Convierte un registro de auditoría del ORM en un diccionario para la API.

    Args:
        registro: Instancia de AuditLog obtenida de la base de datos.

    Returns:
        Diccionario con los campos expuestos públicamente, con nombres en español.
    """
    return {
        "id": registro.id,
        "fecha": registro.timestamp,
        "actor": registro.actor,
        "accion": registro.action,
        "entidad": registro.entity_type,
        "entidad_id": registro.entity_id,
        "detalle": registro.details,
    }


@app.get(
    "/api/audit",
    tags=["Auditoría"],
    summary="Ver registro de auditoría (aprobador o administrador)",
    dependencies=PROTEGIDO,
    responses=RESPUESTAS,
)
def ver_auditoria(
    limite: int = Query(
        AUDITORIA_LIMITE_DEFECTO,
        ge=AUDITORIA_LIMITE_MIN,
        le=AUDITORIA_LIMITE_MAX,
        description="Cantidad máxima de registros a devolver.",
    ),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    """
    Devuelve los últimos registros de auditoría.

    Los resultados se ordenan del más reciente al más antiguo.

    Args:
        limite: Número máximo de registros a devolver (entre 1 y 200).
        db: Sesión de base de datos inyectada por FastAPI.

    Returns:
        Lista de registros de auditoría serializados.
    """
    # Consulta los registros más recientes primero, limitando la cantidad.
    registros = (
        db.query(models.AuditLog)
        .order_by(models.AuditLog.id.desc())
        .limit(limite)
        .all()
    )

    # Transforma cada registro del ORM en un diccionario serializable.
    return [_serializar_auditoria(registro) for registro in registros]


# =============================================================================
# Frontend estático
# =============================================================================

# El dashboard web se monta AL FINAL: al estar en la raíz "/", si se montara
# antes interceptaría las peticiones dirigidas a /api y /docs.
# html=True permite servir index.html automáticamente en "/".
app.mount(
    "/",
    StaticFiles(directory=DIRECTORIO_FRONTEND, html=True),
    name="frontend",
)

# =============================================================================
# FIN DEL ARCHIVO
# =============================================================================