"""
Configuración central del proyecto.
Toda la configuración sensible viene de variables de entorno (.env),
nunca escrita directamente en el código.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

# Raíz del proyecto: este archivo está en backend/app/, así que subimos 2 niveles
BASE_DIR = Path(__file__).resolve().parents[2]
load_dotenv(BASE_DIR / ".env")

# Base local SQLite: se usa si no hay DATABASE_URL (plan B) y como respaldo
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
SQLITE_URL = f"sqlite:///{(DATA_DIR / 'noc_syslog.db').as_posix()}"


def _normalizar(url: str) -> str:
    """Neon entrega 'postgresql://' o 'postgres://'. SQLAlchemy necesita que se
    indique el controlador: 'postgresql+psycopg://'."""
    for prefijo in ("postgres://", "postgresql://"):
        if url.startswith(prefijo):
            return "postgresql+psycopg://" + url[len(prefijo) :]
    return url


# Si existe DATABASE_URL en .env se usa PostgreSQL; si no, SQLite local
DATABASE_URL = _normalizar(os.getenv("DATABASE_URL", "").strip()) or SQLITE_URL

APP_NAME = "NOC Syslog Inteligente"
APP_VERSION = "1.1.0"

# --- FIN DEL ARCHIVO ---
