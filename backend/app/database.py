"""
Conexión a la base de datos con SQLAlchemy.
- engine: el "cable" hacia la BD.
- SessionLocal: fábrica de sesiones (cada petición abre y cierra una).
- Base: clase madre de todos los modelos (tablas).
"""
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, declarative_base
from .config import DATABASE_URL

ES_SQLITE = DATABASE_URL.startswith("sqlite")

# SQLite por defecto no permite usar la conexión desde varios hilos;
# FastAPI sí usa varios hilos, por eso desactivamos esa verificación.
connect_args = {"check_same_thread": False} if ES_SQLITE else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)

if ES_SQLITE:
    # SQLite NO valida llaves foráneas a menos que se lo pidamos explícitamente
    @event.listens_for(engine, "connect")
    def _activar_llaves_foraneas(dbapi_conn, _):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()


def get_db():
    """Entrega una sesión de BD y garantiza que se cierre (lo usaremos en Fase 2)."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        