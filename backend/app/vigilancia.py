"""
Vigilancia de equipos caídos (v1.1.0 — hallazgo 3: "si un equipo se apaga no muestra ningún evento").

Un equipo apagado NO puede enviar un log diciendo "me apagué": el silencio es la señal.
Por eso el NOC pregunta activamente si el equipo sigue vivo, por dos caminos:

  1. Consola por cable (consola_serial.py): si el equipo deja de contestar al Enter
     del "latido", se genera el evento %NOC-1-EQUIPO_SIN_RESPUESTA.
  2. Ping (opcional, este archivo): a los equipos REALES y activos con IP se les hace
     ping cada cierto tiempo. Se activa en el .env con NOC_MONITOREO_PING=true.

Cuando un equipo cae:
  - se guarda un evento de severidad 1 (Alerta) -> llega a Telegram y correo,
  - se abre un incidente automático (queda en la pestaña Incidentes),
  - el equipo pasa a estado 'inactivo' en el Inventario (si estaba 'activo'),
  - todo queda en la auditoría.
Cuando vuelve a responder: evento %NOC-5-EQUIPO_RECUPERADO, aviso "recuperado"
con el tiempo que estuvo caído, nota en el incidente y el equipo vuelve a 'activo'.

Un equipo en 'mantenimiento' no avisa (apagado planeado), pero el evento sí se guarda.
"""

import ipaddress
import os
import platform
import subprocess
import threading
import time
from datetime import UTC, datetime, timedelta, timezone

from .database import SessionLocal
from .ingest import ingerir
from .models import AuditLog, Device, Incident
from .notificaciones import encolar


def _env(nombre, defecto=""):
    """Lee una variable del .env sin espacios sobrantes."""
    return os.getenv(nombre, defecto).strip()


ZONA = timezone(timedelta(hours=int(_env("NOC_UTC_OFFSET", "-5"))))  # hora de Colombia
FACILITY_NOC = 23  # local7
PING_ACTIVO = _env("NOC_MONITOREO_PING", "false").lower() in ("1", "true", "si", "sí", "yes")
PING_SEG = max(15, int(_env("NOC_PING_SEG", "60")))  # cada cuánto se hace ping
PING_FALLOS = max(1, int(_env("NOC_PING_FALLOS", "3")))  # pings fallidos seguidos para declararlo caído

# Estado compartido: equipos caídos ahora mismo  {device_id: {"desde": datetime, "via": str, ...}}
CAIDOS: dict[int, dict] = {}
_candado = threading.Lock()


def _hora(fecha: datetime) -> str:
    """Hora local legible (HH:MM:SS)."""
    return fecha.astimezone(ZONA).strftime("%H:%M:%S")


def _duracion(segundos: float) -> str:
    """Duración legible: '45 s', '3 min', '1 h 12 min'."""
    segundos = int(segundos)
    if segundos < 60:
        return f"{segundos} s"
    minutos = segundos // 60
    if minutos < 60:
        return f"{minutos} min"
    return f"{minutos // 60} h {minutos % 60} min"


def _evento(db, equipo: Device, severidad: int, mnemonico: str, texto: str):
    """Guarda un evento generado por el NOC (no por el equipo) usando el motor de ingesta normal,
    así pasa por deduplicación, notificaciones y aparece en la pestaña Eventos."""
    raw = f"<{FACILITY_NOC * 8 + severidad}>%NOC-{severidad}-{mnemonico}: {texto}"
    # avisar=False: el aviso lo envía este archivo, saltando el límite por hora (es crítico)
    return ingerir(db, raw, equipo.ip_address, "real", device_id=equipo.id, avisar=False)


def _avisar(equipo: Device, clave: str, tipo: str, severidad: int, titulo: str, texto: str):
    """Aviso directo por Telegram/correo. 'siempre' salta el límite por hora y la severidad mínima
    del canal; los equipos en mantenimiento (apagado planeado) no avisan."""
    if equipo.status == "mantenimiento":
        return
    encolar(
        {
            "clave": clave,
            "tipo": tipo,
            "severidad": severidad,
            "siempre": True,
            "device_id": equipo.id,
            "titulo": titulo,
            "detalle": texto,
        }
    )


def marcar_caido(device_id: int, via: str, detalle: str = "", desde: datetime | None = None) -> bool:
    """El equipo dejó de responder (desde: última vez que se supo de él). True si es una caída NUEVA."""
    ahora = desde or datetime.now(UTC)
    with _candado:
        if device_id in CAIDOS:
            return False
        CAIDOS[device_id] = {"desde": ahora, "via": via}
    db = SessionLocal()
    try:
        equipo = db.get(Device, device_id)
        if equipo is None:
            CAIDOS.pop(device_id, None)
            return False
        medio = "por la consola" if via == "consola" else "al ping"
        texto = f"El equipo {equipo.name} no responde {medio} desde las {_hora(ahora)}. {detalle}".strip()
        r = _evento(db, equipo, 1, "EQUIPO_SIN_RESPUESTA", texto)
        _avisar(
            equipo,
            f"caido:{equipo.id}:{int(ahora.timestamp())}",
            "caido",
            1,
            f"🔴 {equipo.name} NO RESPONDE",
            texto,
        )

        # Incidente automático (uno solo por caída: si ya hay uno abierto del mismo equipo, no se repite)
        abierto = (
            db.query(Incident)
            .filter(
                Incident.device_id == equipo.id,
                Incident.status != "cerrado",
                Incident.title.like("Equipo sin respuesta:%"),
            )
            .first()
        )
        if abierto is None:
            incidente = Incident(
                title=f"Equipo sin respuesta: {equipo.name}"[:200],
                description=texto + "\nIncidente creado automáticamente por la vigilancia del NOC.",
                severity=1,
                status="abierto",
                device_id=equipo.id,
                event_id=r.get("event_id"),
            )
            db.add(incidente)
            db.flush()
            CAIDOS[device_id]["incidente"] = incidente.id

        cambio_estado = equipo.status == "activo"
        if cambio_estado:
            equipo.status = "inactivo"
        CAIDOS[device_id]["cambio_estado"] = cambio_estado
        db.add(
            AuditLog(
                actor="sistema",
                action="DEVICE_DOWN",
                entity_type="devices",
                entity_id=equipo.id,
                details=texto,
            )
        )
        db.commit()
        return True
    except Exception as exc:
        db.rollback()
        print(f"[VIGILANCIA] No se pudo registrar la caída: {exc}")
        return True
    finally:
        db.close()


def marcar_recuperado(device_id: int) -> bool:
    """El equipo volvió a responder. Devuelve True si estaba caído."""
    with _candado:
        info = CAIDOS.pop(device_id, None)
    if info is None:
        return False
    ahora = datetime.now(UTC)
    duracion = _duracion((ahora - info["desde"]).total_seconds())
    db = SessionLocal()
    try:
        equipo = db.get(Device, device_id)
        if equipo is None:
            return True
        texto = (
            f"El equipo {equipo.name} volvió a responder a las {_hora(ahora)} tras {duracion} sin respuesta."
        )
        _evento(db, equipo, 5, "EQUIPO_RECUPERADO", texto)
        if info.get("incidente"):
            incidente = db.get(Incident, info["incidente"])
            if incidente and incidente.status != "cerrado":
                incidente.description = (
                    (incidente.description or "")
                    + "\n"
                    + texto
                    + (" Revise la causa (corte de energía, reinicio, cable) y cierre el incidente.")
                )
        if info.get("cambio_estado") and equipo.status == "inactivo":
            equipo.status = "activo"
        db.add(
            AuditLog(
                actor="sistema",
                action="DEVICE_UP",
                entity_type="devices",
                entity_id=equipo.id,
                details=texto,
            )
        )
        db.commit()
        _avisar(
            equipo,
            f"recuperado:{equipo.id}:{int(ahora.timestamp())}",
            "recuperado",
            5,
            f"✅ {equipo.name} recuperado",
            texto,
        )
        return True
    except Exception as exc:
        db.rollback()
        print(f"[VIGILANCIA] No se pudo registrar la recuperación: {exc}")
        return True
    finally:
        db.close()


def estado() -> dict:
    """Equipos caídos ahora mismo y configuración de la vigilancia (para el dashboard)."""
    ahora = datetime.now(UTC)
    with _candado:
        caidos = [
            {
                "device_id": dev,
                "desde": info["desde"].isoformat(),
                "via": info["via"],
                "duracion": _duracion((ahora - info["desde"]).total_seconds()),
                "incidente": info.get("incidente"),
            }
            for dev, info in CAIDOS.items()
        ]
    return {
        "caidos": caidos,
        "ping": {"activo": PING_ACTIVO, "cada_seg": PING_SEG, "fallos": PING_FALLOS},
    }


# ---------------------------------------------------------------------------
# Ping (opcional)
# ---------------------------------------------------------------------------
def _ip_valida(ip: str) -> bool:
    """Solo IPs reales: se descartan las de documentación (192.0.2.x, etc.), loopback y no válidas."""
    try:
        direccion = ipaddress.ip_address(ip)
    except ValueError:
        return False
    documentacion = ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
    if any(direccion in ipaddress.ip_network(red) for red in documentacion):
        return False
    return not (direccion.is_loopback or direccion.is_unspecified or direccion.is_multicast)


def hacer_ping(ip: str) -> bool:
    """Un ping (1 paquete, 1 segundo). La IP se valida antes y se pasa como argumento
    (nunca dentro de un texto de comando), así no se puede inyectar nada."""
    if not _ip_valida(ip):
        return False
    if platform.system() == "Windows":
        comando = ["ping", "-n", "1", "-w", "1000", ip]
    else:
        comando = ["ping", "-c", "1", "-W", "1", ip]
    try:
        r = subprocess.run(comando, capture_output=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    # En Windows, "Destination host unreachable" devuelve 0: se exige "TTL=" en la respuesta
    return r.returncode == 0 and b"ttl=" in r.stdout.lower()


def _vigilar_ping():
    """Hilo: hace ping a los equipos reales activos (o caídos por ping) y avisa caídas y recuperaciones."""
    fallos: dict[int, int] = {}
    while True:
        db = SessionLocal()
        try:
            equipos = [
                (d.id, d.ip_address)
                for d in db.query(Device).filter(Device.is_simulated.is_(False)).all()
                if (d.status == "activo" or CAIDOS.get(d.id, {}).get("via") == "ping")
                and _ip_valida(d.ip_address)
            ]
        except Exception as exc:
            print(f"[VIGILANCIA] No se pudo leer el inventario: {exc}")
            equipos = []
        finally:
            db.close()
        for device_id, ip in equipos:
            if hacer_ping(ip):
                fallos[device_id] = 0
                if CAIDOS.get(device_id, {}).get("via") == "ping":
                    marcar_recuperado(device_id)
            else:
                fallos[device_id] = fallos.get(device_id, 0) + 1
                if fallos[device_id] == PING_FALLOS:
                    marcar_caido(device_id, "ping", f"({PING_FALLOS} pings seguidos sin respuesta a {ip})")
        time.sleep(PING_SEG)


_hilo_ping = None


def iniciar_ping():
    """Arranca el hilo del ping si NOC_MONITOREO_PING=true en el .env (una sola vez)."""
    global _hilo_ping
    if not PING_ACTIVO or (_hilo_ping and _hilo_ping.is_alive()):
        return
    _hilo_ping = threading.Thread(target=_vigilar_ping, name="vigilancia-ping", daemon=True)
    _hilo_ping.start()
    print(f"[VIGILANCIA] Ping activo: cada {PING_SEG} s, caído tras {PING_FALLOS} fallos seguidos.")


# --- FIN DEL ARCHIVO ---
