"""
Copia TODOS los datos de la base local SQLite a PostgreSQL (Neon).

Uso (una sola vez), con la DATABASE_URL de Neon ya guardada en .env:
    python -m backend.scripts.migrar_a_postgres

No borra nada de SQLite: el archivo data/noc_syslog.db queda como respaldo.
Si una tabla del destino ya tiene datos, se salta (no duplica).
"""

import sys

from sqlalchemy import create_engine, func, select, text

from backend.app import models  # noqa: F401  (registra las tablas)
from backend.app.config import SQLITE_URL
from backend.app.database import ES_SQLITE, Base
from backend.app.database import engine as destino

# Orden obligatorio: primero las tablas de las que dependen las demás
ORDEN = ["devices", "syslog_events", "incidents", "action_proposals", "audit_log"]


def main():
    """Copia los datos de la base SQLite local a PostgreSQL (Neon)."""
    if ES_SQLITE:
        print("[ERROR] DATABASE_URL no apunta a PostgreSQL. Revise el archivo .env.")
        sys.exit(1)

    origen = create_engine(SQLITE_URL)
    Base.metadata.create_all(bind=destino)  # crea las 5 tablas en PostgreSQL

    with origen.connect() as o, destino.begin() as d:
        for nombre in ORDEN:
            tabla = Base.metadata.tables[nombre]
            existentes = d.execute(select(func.count()).select_from(tabla)).scalar()
            if existentes:
                print(f"[SALTADO] {nombre}: el destino ya tiene {existentes} filas")
                continue

            filas = [dict(f._mapping) for f in o.execute(select(tabla))]
            if filas:
                d.execute(tabla.insert(), filas)

            # Ajusta el contador de ids para que los nuevos registros sigan la numeración
            d.execute(
                text(
                    f"SELECT setval(pg_get_serial_sequence('{nombre}', 'id'), "
                    f"COALESCE((SELECT MAX(id) FROM {nombre}), 0) + 1, false)"
                )
            )
            print(f"[OK] {nombre}: {len(filas)} filas copiadas")

    print("\nMigración terminada. SQLite queda intacto como respaldo en data/noc_syslog.db")


if __name__ == "__main__":
    main()

# --- FIN DEL ARCHIVO ---
