"""
Respaldo y recuperación de la base de datos del NOC (v1.0.0).

  python -m backend.scripts.respaldo exportar
      Copia TODAS las tablas (excepto las sesiones abiertas) a un archivo JSON en data/respaldos/.
      Funciona igual con PostgreSQL (Neon) o con SQLite.

  python -m backend.scripts.respaldo restaurar data/respaldos/noc_AAAAMMDD_HHMMSS.json
      Prueba de RECUPERACIÓN: carga el respaldo en una base SQLite NUEVA
      (data/restaurado_AAAAMMDD_HHMMSS.db), sin tocar la base en uso,
      y compara cuántas filas hay en cada tabla.

SEGURIDAD:
  - El respaldo contiene los HASH de las contraseñas (nunca las contraseñas) y datos internos:
    se guarda en data/, que está en .gitignore. NUNCA lo suba a GitHub.
  - No se respaldan las sesiones abiertas (user_sessions): tras recuperar, cada usuario
    vuelve a iniciar sesión.
"""
import json
import sys
from datetime import date, datetime
from pathlib import Path

from sqlalchemy import create_engine, select

from backend.app import models  # noqa: F401  (registra todas las tablas)
from backend.app.config import DATA_DIR
from backend.app.database import MOTOR, Base, engine

OMITIDAS = {"user_sessions"}
CARPETA = DATA_DIR / "respaldos"


def _a_json(valor):
    if isinstance(valor, (datetime, date)):
        return {"__fecha__": valor.isoformat()}
    return valor


def _de_json(valor):
    if isinstance(valor, dict) and "__fecha__" in valor:
        return datetime.fromisoformat(valor["__fecha__"])
    return valor


def exportar() -> Path:
    CARPETA.mkdir(parents=True, exist_ok=True)
    marca = datetime.now().strftime("%Y%m%d_%H%M%S")
    datos = {"creado": datetime.now().isoformat(), "motor_origen": MOTOR, "tablas": {}}
    with engine.connect() as con:
        for tabla in Base.metadata.sorted_tables:
            if tabla.name in OMITIDAS:
                continue
            filas = con.execute(select(tabla)).mappings().all()
            datos["tablas"][tabla.name] = [{k: _a_json(v) for k, v in f.items()} for f in filas]
    archivo = CARPETA / f"noc_{marca}.json"
    archivo.write_text(json.dumps(datos, ensure_ascii=False), encoding="utf-8")
    print(f"[OK] Respaldo creado: {archivo}")
    for nombre, filas in datos["tablas"].items():
        print(f"     {nombre:<22} {len(filas):>6} filas")
    print("     (No lo suba a GitHub: contiene datos internos y hash de contraseñas)")
    return archivo


def restaurar(ruta: str) -> bool:
    archivo = Path(ruta)
    datos = json.loads(archivo.read_text(encoding="utf-8"))
    marca = datetime.now().strftime("%Y%m%d_%H%M%S")
    destino = DATA_DIR / f"restaurado_{marca}.db"
    motor = create_engine(f"sqlite:///{destino.as_posix()}")
    Base.metadata.create_all(bind=motor)
    ok = True
    with motor.begin() as con:
        for tabla in Base.metadata.sorted_tables:  # orden correcto por llaves foráneas
            filas = datos["tablas"].get(tabla.name, [])
            if filas:
                con.execute(tabla.insert(), [{k: _de_json(v) for k, v in f.items()} for f in filas])
    print(f"[OK] Respaldo cargado en una base NUEVA: {destino}")
    print(f"     {'tabla':<22} {'respaldo':>9} {'recuperado':>11}")
    with motor.connect() as con:
        for tabla in Base.metadata.sorted_tables:
            if tabla.name in OMITIDAS:
                continue
            esperado = len(datos["tablas"].get(tabla.name, []))
            obtenido = len(con.execute(select(tabla)).all())
            estado = "OK" if esperado == obtenido else "DIFERENTE"
            ok &= esperado == obtenido
            print(f"     {tabla.name:<22} {esperado:>9} {obtenido:>11}  {estado}")
    motor.dispose()
    print("[OK] Recuperación verificada: todas las tablas coinciden." if ok
          else "[ERROR] Hay tablas que no coinciden.")
    return ok


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "exportar":
        exportar()
    elif len(sys.argv) >= 3 and sys.argv[1] == "restaurar":
        sys.exit(0 if restaurar(sys.argv[2]) else 1)
    else:
        print(__doc__)

# --- FIN DEL ARCHIVO ---
