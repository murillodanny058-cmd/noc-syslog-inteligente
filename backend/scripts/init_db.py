"""
Crea las tablas y carga equipos SIMULADOS.
Las IP usan rangos reservados para documentación (RFC 5737):
192.0.2.0/24, 198.51.100.0/24 y 203.0.113.0/24. NO existen en internet,
así cumplimos la regla de no usar IP reales de producción.

Ejecutar desde la raíz del proyecto:  python -m backend.scripts.init_db
"""
from sqlalchemy import inspect
from backend.app.database import Base, engine, SessionLocal
from backend.app.models import Device, AuditLog

EQUIPOS_SIMULADOS = [
    dict(name="SIM-CORE-SW01", ip_address="192.0.2.10", vendor="Cisco",
         model="Catalyst 9300 (sim)", os_version="IOS-XE 17.x (sim)",
         location="Datacenter - Rack A1 (sim)"),
    dict(name="SIM-FW-EDGE01", ip_address="192.0.2.20", vendor="Fortinet",
         model="FortiGate 100F (sim)", os_version="FortiOS 7.x (sim)",
         location="Perímetro (sim)"),
    dict(name="SIM-AR-RTR01", ip_address="198.51.100.30", vendor="Huawei",
         model="AR6120 (sim)", os_version="VRP V300 (sim)",
         location="Sede Norte (sim)"),
    dict(name="SIM-ACC-SW02", ip_address="203.0.113.40", vendor="Cisco",
         model="Catalyst 2960 (sim)", os_version="IOS 15.x (sim)",
         location="Piso 2 (sim)", status="mantenimiento"),
]


def main():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if db.query(Device).count() == 0:
            for equipo in EQUIPOS_SIMULADOS:
                db.add(Device(**equipo, is_simulated=True))
            db.add(AuditLog(actor="sistema", action="SEED", entity_type="devices",
                            details=f"{len(EQUIPOS_SIMULADOS)} equipos SIMULADOS cargados"))
            db.commit()
            print(f"[OK] {len(EQUIPOS_SIMULADOS)} equipos simulados cargados.")
        else:
            print("[INFO] Ya existen equipos; no se volvieron a cargar.")

        print("[OK] Tablas en la BD:", inspect(engine).get_table_names())
        for d in db.query(Device).all():
            print(f"   - {d.name:15} {d.ip_address:15} {d.vendor:9} {d.status}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
    