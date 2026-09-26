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

# Carpeta donde vive el archivo SQLite
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

# Si existe DATABASE_URL en .env la usamos; si no, SQLite local
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    f"sqlite:///{(DATA_DIR / 'noc_syslog.db').as_posix()}",
)

APP_NAME = "NOC Syslog Inteligente"
APP_VERSION = "0.2.0"
