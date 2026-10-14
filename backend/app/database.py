"""
Conexión a la base de datos con SQLAlchemy.
- PostgreSQL (Neon) si hay DATABASE_URL en .env.
- SQLite local si no la hay (plan B).
"""
from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker

from .config import DATABASE_URL

ES_SQLITE = DATABASE_URL.startswith("sqlite")
MOTOR = "sqlite" if ES_SQLITE else "postgresql"

if ES_SQLITE:
    # SQLite no permite por defecto usar la conexión desde varios hilos (FastAPI sí lo hace)
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

    @event.listens_for(engine, "connect")
    def _activar_llaves_foraneas(dbapi_conn, _):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")  # SQLite no valida llaves foráneas por defecto
        cursor.close()
else:
    # PostgreSQL en la nube.
    # pool_pre_ping: revisa que la conexión siga viva antes de usarla, porque
    # Neon "duerme" la base de datos tras 5 minutos sin uso.
    engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_recycle=300,
                           pool_size=5, max_overflow=5)

    @event.listens_for(engine, "connect")
    def _zona_horaria_utc(dbapi_conn, _):
        cursor = dbapi_conn.cursor()
        cursor.execute("SET TIME ZONE 'UTC'")  # todas las fechas del NOC están en UTC
        cursor.close()
        dbapi_conn.commit()

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()


def get_db():
    """Entrega una sesión de BD y garantiza que se cierre."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- FIN DEL ARCHIVO ---