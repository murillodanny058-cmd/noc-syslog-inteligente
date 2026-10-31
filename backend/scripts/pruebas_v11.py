"""
Pruebas automáticas de la versión 1.1.0 (hallazgos 3 y 2: equipo apagado y notificaciones rápidas).

    python -m backend.scripts.pruebas_v11

- Usa una base SQLite TEMPORAL (data/pruebas_v11.db): NO toca la base real (Neon).
- No envía nada a Telegram ni al correo: los envíos se reemplazan por funciones de prueba.
- El "equipo" es un switch FALSO en memoria que se puede apagar y encender (no hace falta cable).
- Tarda alrededor de 1 minuto (espera el latido de la consola).
- Al final escribe el informe en docs/evidencias/resultados_pruebas_v11.md
"""

import os
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
BASE_PRUEBAS = RAIZ / "data" / "pruebas_v11.db"
BASE_PRUEBAS.parent.mkdir(exist_ok=True)
BASE_PRUEBAS.unlink(missing_ok=True)

# Antes de importar la app: base temporal, latido rápido y canales externos con datos falsos
os.environ.update(
    DATABASE_URL=f"sqlite:///{BASE_PRUEBAS.as_posix()}",
    NOC_LATIDO_SEG="10",
    NOC_LATIDO_FALLOS="2",
    NOC_MONITOREO_PING="false",
    TELEGRAM_BOT_TOKEN="prueba",
    TELEGRAM_CHAT_ID="prueba",
    SMTP_USER="prueba",
    SMTP_PASSWORD="prueba",
    ALERT_EMAIL_TO="prueba",
    WHATSAPP_PHONE="",
    WHATSAPP_APIKEY="",
)

from backend.app import consola_serial, notificaciones, vigilancia  # noqa: E402
from backend.app.config import APP_VERSION  # noqa: E402
from backend.app.database import Base, SessionLocal, engine  # noqa: E402
from backend.app.models import AuditLog, Device, Incident, Notification, SyslogEvent  # noqa: E402

RESULTADOS = []
ENVIADOS = []  # (canal, segundos desde el inicio, texto)
INICIO = time.monotonic()


def prueba(codigo, que, esperado, obtenido, ok):
    """Registra el resultado de una prueba y lo muestra en pantalla."""
    RESULTADOS.append((codigo, que, str(esperado), str(obtenido), "OK" if ok else "FALLA"))
    print(f"  [{'OK' if ok else 'FALLA'}] {codigo} {que} -> {obtenido}")


# --- Canales falsos: Telegram instantáneo, correo LENTO (4 s, como un SMTP real lento) ---
def _telegram_falso(texto, _asunto):
    """Simula Telegram (instantáneo)."""
    ENVIADOS.append(("telegram", time.monotonic() - INICIO, texto))


def _correo_falso(texto, _asunto):
    """Simula un correo lento."""
    time.sleep(4)
    ENVIADOS.append(("correo", time.monotonic() - INICIO, texto))


notificaciones.ENVIAR.update(telegram=_telegram_falso, correo=_correo_falso)


class EquipoFalso:
    """Imita un puerto serial con un switch Cisco detrás. 'apagado' = no contesta nada."""

    def __init__(self):
        """Switch encendido, sin nada pendiente por leer."""
        self.apagado = False
        self.desconectado = False
        self._salida = b""
        self._candado = threading.Lock()
        self.is_open = True

    @property
    def in_waiting(self):
        """Bytes pendientes por leer."""
        return len(self._salida)

    def write(self, datos):
        """El NOC escribe: si está encendido, contesta con el prompt."""
        if self.desconectado:
            raise OSError("dispositivo desconectado")
        if not self.apagado and b"\r" in datos:
            with self._candado:
                self._salida += b"\r\nLAB-SW01#"
        return len(datos)

    def flush(self):
        """Nada que hacer."""

    def read(self, _n):
        """El NOC lee lo que contestó el equipo."""
        if self.desconectado:
            raise OSError("device reports readiness to read but returned no data")
        with self._candado:
            datos, self._salida = self._salida, b""
        if not datos:
            time.sleep(0.2)
        return datos

    def encender(self):
        """El equipo arranca e imprime sus mensajes de inicio."""
        self.apagado = False
        with self._candado:
            self._salida += b"\r\n*Mar  1 00:00:30: %SYS-5-RESTART: System restarted --\r\nPress RETURN to get started!\r\n"

    def close(self):
        """Cierra el puerto."""
        self.is_open = False


def esperar(condicion, maximo):
    """Espera hasta 'maximo' segundos a que la condición se cumpla."""
    limite = time.monotonic() + maximo
    while time.monotonic() < limite:
        if condicion():
            return True
        time.sleep(0.3)
    return condicion()


def main():
    """Ejecuta las pruebas y escribe el informe."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    equipo = Device(
        name="LAB-SW01", ip_address="10.0.0.11", vendor="Cisco", status="activo", is_simulated=False
    )
    mant = Device(
        name="LAB-MANT", ip_address="10.0.0.12", vendor="Huawei", status="mantenimiento", is_simulated=False
    )
    db.add_all([equipo, mant])
    db.commit()
    db.refresh(equipo)
    db.refresh(mant)
    id_equipo, id_mant = equipo.id, mant.id

    falso = EquipoFalso()
    consola_serial.serial.serial_for_url = lambda *a, **k: falso
    consola = consola_serial.ConsolaSerial()

    print(f"\nPruebas v1.1.0 — NOC Syslog Inteligente {APP_VERSION}\n")
    estado = consola.conectar("PRUEBA", 9600, equipo)
    prueba(
        "V01",
        "La consola se conecta y ve el prompt",
        "LAB-SW01#",
        estado["prompt"],
        estado["prompt"] == "LAB-SW01#",
    )

    # --- Hallazgo 3: el equipo se apaga ---
    falso.apagado = True
    t0 = time.monotonic()
    detectado = esperar(lambda: consola.caido_desde, 45)
    demora = time.monotonic() - t0
    prueba("V02", "Equipo apagado: el latido lo detecta", "en menos de 45 s", f"{demora:.0f} s", detectado)

    time.sleep(1.5)
    db = SessionLocal()
    evento = db.query(SyslogEvent).filter(SyslogEvent.message.like("%EQUIPO_SIN_RESPUESTA%")).first()
    prueba(
        "V03",
        "Se guarda un evento de severidad 1 a nombre del equipo",
        "sev 1, LAB-SW01",
        f"sev {evento.severity}, {evento.device.name}" if evento else "sin evento",
        bool(evento and evento.severity == 1 and evento.device_id == id_equipo),
    )
    incidente = db.query(Incident).filter(Incident.device_id == id_equipo).first()
    prueba(
        "V04",
        "Se abre un incidente automático",
        "abierto",
        f"#{incidente.id} {incidente.status}" if incidente else "sin incidente",
        bool(incidente and incidente.status == "abierto"),
    )
    estado_eq = db.get(Device, id_equipo).status
    prueba(
        "V05", "El equipo pasa a 'inactivo' en el Inventario", "inactivo", estado_eq, estado_eq == "inactivo"
    )
    aviso = esperar(lambda: any("NO RESPONDE" in t for c, _, t in ENVIADOS if c == "telegram"), 3)
    prueba("V06", "Llega el aviso 'NO RESPONDE' por Telegram", "enviado", "enviado" if aviso else "no", aviso)
    auditado = db.query(AuditLog).filter(AuditLog.action == "DEVICE_DOWN").count()
    prueba("V07", "La caída queda en la auditoría", "DEVICE_DOWN", f"{auditado} registro(s)", auditado == 1)

    # --- El equipo vuelve ---
    falso.encender()
    volvio = esperar(lambda: not consola.caido_desde, 5)
    time.sleep(1.5)
    db = SessionLocal()
    recuperado = db.query(SyslogEvent).filter(SyslogEvent.message.like("%EQUIPO_RECUPERADO%")).first()
    prueba(
        "V08",
        "Al volver: evento de recuperación con el tiempo caído",
        "EQUIPO_RECUPERADO ... tras N s",
        recuperado.message[-40:] if recuperado else "sin evento",
        bool(volvio and recuperado and "tras" in recuperado.message),
    )
    estado_eq = db.get(Device, id_equipo).status
    prueba("V09", "El equipo vuelve a 'activo'", "activo", estado_eq, estado_eq == "activo")
    aviso = esperar(lambda: any("recuperado" in t for c, _, t in ENVIADOS if c == "telegram"), 3)
    prueba("V10", "Llega el aviso 'recuperado' por Telegram", "enviado", "enviado" if aviso else "no", aviso)

    # --- Mantenimiento: apagado planeado, no avisa ---
    def avisos_mant():
        """Avisos por Telegram que mencionan al equipo en mantenimiento."""
        return sum(1 for c, _, t in ENVIADOS if c == "telegram" and "LAB-MANT" in t)

    vigilancia.marcar_caido(id_mant, "ping", "(prueba)")
    time.sleep(1)
    db = SessionLocal()
    guardado = db.query(SyslogEvent).filter(SyslogEvent.device_id == id_mant).count()
    prueba(
        "V11",
        "Equipo en mantenimiento: guarda el evento pero NO avisa",
        "1 evento, 0 avisos",
        f"{guardado} evento, {avisos_mant()} avisos",
        guardado == 1 and avisos_mant() == 0,
    )
    vigilancia.marcar_recuperado(id_mant)

    # --- Hallazgo 2: Telegram no espera al correo ---
    t0 = time.monotonic() - INICIO
    for i in range(3):
        notificaciones.encolar(
            {
                "clave": f"prueba:{i}",
                "tipo": "evento",
                "severidad": 1,
                "titulo": f"Prueba {i}",
                "detalle": "x",
            }
        )
    esperar(lambda: sum(1 for c, s, _ in ENVIADOS if c == "telegram" and s >= t0) >= 3, 5)
    tiempos = [s - t0 for c, s, _ in ENVIADOS if c == "telegram" and s >= t0]
    prueba(
        "V12",
        "3 alertas con correo lento (4 s c/u): Telegram no espera",
        "las 3 por Telegram en < 2 s",
        f"{len(tiempos)} en {max(tiempos, default=99):.1f} s",
        len(tiempos) == 3 and max(tiempos) < 2,
    )
    db = SessionLocal()
    medido = db.query(Notification).filter(Notification.detalle.like("Entregado en%")).first()
    prueba(
        "V13",
        "Se mide cuánto tardó cada aviso",
        "Entregado en X s",
        medido.detalle if medido else "sin medida",
        medido is not None,
    )

    # --- Cable de consola desconectado ---
    falso.desconectado = True
    esperar(lambda: not consola.conectado, 3)
    time.sleep(1.5)
    db = SessionLocal()
    perdido = db.query(SyslogEvent).filter(SyslogEvent.message.like("%CONSOLA_PERDIDA%")).first()
    prueba(
        "V14",
        "Cable USB de consola desconectado: evento de severidad 2",
        "CONSOLA_PERDIDA sev 2",
        f"sev {perdido.severity}" if perdido else "sin evento",
        bool(perdido and perdido.severity == 2),
    )

    # --- Seguridad del ping ---
    casos = {"10.0.0.1": True, "192.0.2.20": False, "127.0.0.1": False, "10.0.0.1 & del *": False}
    ok = all(vigilancia._ip_valida(ip) == esperado for ip, esperado in casos.items())
    prueba(
        "V15",
        "Ping: solo IPs válidas (sin inyección, sin IPs de documentación)",
        "rechaza 192.0.2.x, 127.0.0.1 y '& del *'",
        "correcto" if ok else "incorrecto",
        ok,
    )

    # --- Informe ---
    total_ok = sum(1 for r in RESULTADOS if r[4] == "OK")
    print(f"\nResultado: {total_ok} de {len(RESULTADOS)} pruebas OK")
    lineas = [
        "# Resultados de las pruebas v1.1.0 (equipo apagado y notificaciones)",
        "",
        f"- Fecha: {datetime.now():%Y-%m-%d %H:%M}",
        f"- Versión: {APP_VERSION}",
        "- Base: SQLite temporal · equipo: switch falso en memoria · canales: simulados",
        f"- **Resultado: {total_ok} de {len(RESULTADOS)} OK**",
        "",
        "| Código | Prueba | Esperado | Obtenido | Resultado |",
        "|---|---|---|---|---|",
    ]
    lineas += [f"| {c} | {q} | {e} | {o} | {r} |" for c, q, e, o, r in RESULTADOS]
    salida = RAIZ / "docs" / "evidencias" / "resultados_pruebas_v11.md"
    salida.parent.mkdir(parents=True, exist_ok=True)
    salida.write_text("\n".join(lineas) + "\n", encoding="utf-8")
    print(f"Informe: {salida}")
    engine.dispose()
    BASE_PRUEBAS.unlink(missing_ok=True)
    return total_ok == len(RESULTADOS)
       try:
           BASE_PRUEBAS.unlink(missing_ok=True)
       except PermissionError:
           pass  # en Windows los hilos de la consola pueden tenerla abierta: se borra en la próxima prueba

if __name__ == "__main__":
    sys.exit(0 if main() else 1)

# --- FIN DEL ARCHIVO ---
