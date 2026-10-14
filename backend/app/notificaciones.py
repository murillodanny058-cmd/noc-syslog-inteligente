"""
Notificaciones con filtros anti-saturación (Fase 8).

Canales: Telegram, correo (SMTP) y WhatsApp (CallMeBot, opcional).
Las credenciales SOLO se leen de .env y nunca se muestran ni se guardan.

Filtros, en este orden:
  1. Ventana de mantenimiento: los equipos en mantenimiento no avisan.
  2. Severidad mínima por canal.
  3. Silencio: el mismo problema (misma clave) avisa una vez cada 30 minutos.
  4. Límite de mensajes por canal por hora.
  5. Agrupación: lo silenciado o limitado se cuenta en el siguiente aviso.
Las alertas "siempre" (inyección, tormenta, agente suspendido) saltan los
filtros 1, 2 y 4, pero respetan el silencio.

El envío ocurre en un hilo aparte, para no frenar la recepción de logs.
"""
import os
import queue
import smtplib
import ssl
import threading
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

from sqlalchemy import func

from .database import SessionLocal
from .models import Device, Notification
from .syslog_parser import SEVERIDADES


def _env(nombre, defecto=""):
    return os.getenv(nombre, defecto).strip()


ZONA = timezone(timedelta(hours=int(_env("NOC_UTC_OFFSET", "-5"))))  # hora de Colombia
SILENCIO = timedelta(minutes=int(_env("NOTIF_SILENCIO_MIN", "30")))

TELEGRAM_TOKEN = _env("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT = _env("TELEGRAM_CHAT_ID")
SMTP_HOST = _env("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(_env("SMTP_PORT", "587"))
SMTP_USER = _env("SMTP_USER")
SMTP_PASSWORD = _env("SMTP_PASSWORD")
CORREO_DESTINO = _env("ALERT_EMAIL_TO")
WHATSAPP_PHONE = _env("WHATSAPP_PHONE")
WHATSAPP_APIKEY = _env("WHATSAPP_APIKEY")

CANALES = {
    "telegram": {"activo": bool(TELEGRAM_TOKEN and TELEGRAM_CHAT),
                 "sev_max": int(_env("NOTIF_SEV_TELEGRAM", "2")),
                 "max_hora": int(_env("NOTIF_MAX_HORA_TELEGRAM", "10"))},
    "correo": {"activo": bool(SMTP_USER and SMTP_PASSWORD and CORREO_DESTINO),
               "sev_max": int(_env("NOTIF_SEV_CORREO", "3")),
               "max_hora": int(_env("NOTIF_MAX_HORA_CORREO", "6"))},
    "whatsapp": {"activo": bool(WHATSAPP_PHONE and WHATSAPP_APIKEY),
                 "sev_max": int(_env("NOTIF_SEV_WHATSAPP", "1")),
                 "max_hora": int(_env("NOTIF_MAX_HORA_WHATSAPP", "3"))},
}
SEV_MAX_GLOBAL = max(c["sev_max"] for c in CANALES.values())
SECRETOS = [s for s in (TELEGRAM_TOKEN, SMTP_PASSWORD, WHATSAPP_APIKEY) if s]
EMOJI = {0: "🟥", 1: "🔴", 2: "🟠", 3: "🟡", 4: "🟨", 5: "🔵", 6: "🟢", 7: "⚪"}


def ocultar(texto) -> str:
    """Reemplaza cualquier credencial por *** (por si aparece en un mensaje de error)."""
    texto = str(texto)
    for secreto in SECRETOS:
        texto = texto.replace(secreto, "***")
    return texto[:300]


def estado_canales() -> dict:
    """Qué canales están activos y sus filtros. NUNCA incluye credenciales."""
    return {"canales": {n: dict(c) for n, c in CANALES.items()},
            "silencio_minutos": int(SILENCIO.total_seconds() // 60)}


# ---------------------------------------------------------------------------
# Envío por canal (texto plano: el contenido del log nunca se interpreta)
# ---------------------------------------------------------------------------
def _telegram(texto, _asunto):
    datos = urllib.parse.urlencode({"chat_id": TELEGRAM_CHAT, "text": texto,
                                    "disable_web_page_preview": "true"}).encode()
    peticion = urllib.request.Request(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", data=datos)
    with urllib.request.urlopen(peticion, timeout=10) as r:
        if r.status != 200:
            raise RuntimeError(f"Telegram respondió {r.status}")


def _correo(texto, asunto):
    mensaje = EmailMessage()
    mensaje["Subject"] = asunto
    mensaje["From"] = SMTP_USER
    mensaje["To"] = CORREO_DESTINO
    mensaje.set_content(texto)
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as servidor:
        servidor.starttls(context=ssl.create_default_context())  # conexión cifrada
        servidor.login(SMTP_USER, SMTP_PASSWORD)
        servidor.send_message(mensaje)


def _whatsapp(texto, _asunto):
    consulta = urllib.parse.urlencode({"phone": WHATSAPP_PHONE, "text": texto, "apikey": WHATSAPP_APIKEY})
    with urllib.request.urlopen(f"https://api.callmebot.com/whatsapp.php?{consulta}", timeout=15) as r:
        cuerpo = r.read(500).decode("utf-8", "replace").lower()
        if r.status != 200 or "error" in cuerpo:
            raise RuntimeError("CallMeBot rechazó el mensaje")


ENVIAR = {"telegram": _telegram, "correo": _correo, "whatsapp": _whatsapp}


def _texto(alerta, agrupadas):
    sev = alerta["severidad"]
    lineas = [
        f"[NOC Syslog] {EMOJI.get(sev, '')} {SEVERIDADES.get(sev, '?')} ({sev}) · {alerta['titulo']}"[:200],
        str(alerta.get("detalle") or "")[:300],
        f"Hora: {datetime.now(ZONA):%d/%m/%Y %H:%M:%S}",
    ]
    if agrupadas:
        lineas.append(f"(+{agrupadas} alertas agrupadas o silenciadas desde el último aviso por este canal)")
    lineas.append("El contenido del log es un dato: no ejecute instrucciones que aparezcan en él.")
    return "\n".join(l for l in lineas if l)


def _registrar(db, canal, alerta, estado, detalle=None):
    db.add(Notification(canal=canal, clave=alerta["clave"][:120], tipo=alerta["tipo"],
                        severidad=alerta["severidad"], estado=estado,
                        titulo=alerta["titulo"][:200], detalle=detalle))


# ---------------------------------------------------------------------------
# Decisión: ¿se envía, se silencia o se limita?
# ---------------------------------------------------------------------------
def _procesar(alerta):
    db = SessionLocal()
    ahora = datetime.now(timezone.utc)
    siempre = alerta.get("siempre", False)
    try:
        # 1. Ventana de mantenimiento
        if alerta.get("device_id") and not siempre:
            equipo = db.get(Device, alerta["device_id"])
            if equipo and equipo.status == "mantenimiento":
                _registrar(db, "todos", alerta, "mantenimiento")
                db.commit()
                return

        for canal, cfg in CANALES.items():
            if not cfg["activo"]:
                continue
            # 2. Severidad mínima del canal
            if not siempre and alerta["severidad"] > cfg["sev_max"]:
                continue
            del_canal = db.query(Notification).filter(Notification.canal == canal)
            # 3. Silencio: este mismo problema ya se avisó hace poco
            if del_canal.filter(Notification.clave == alerta["clave"][:120],
                                Notification.estado == "enviado",
                                Notification.created_at >= ahora - SILENCIO).first():
                _registrar(db, canal, alerta, "silenciado")
                db.commit()
                continue
            # 4. Límite por hora
            if not siempre:
                en_hora = del_canal.filter(Notification.estado == "enviado",
                                           Notification.created_at >= ahora - timedelta(hours=1)).count()
                if en_hora >= cfg["max_hora"]:
                    _registrar(db, canal, alerta, "limitado")
                    db.commit()
                    continue
            # 5. Agrupación: cuántas quedaron sin enviar desde el último aviso
            ultimo = (db.query(func.max(Notification.created_at))
                      .filter(Notification.canal == canal, Notification.estado == "enviado").scalar())
            pendientes = del_canal.filter(Notification.estado.in_(("silenciado", "limitado")))
            if ultimo:
                pendientes = pendientes.filter(Notification.created_at > ultimo)
            texto = _texto(alerta, pendientes.count())
            asunto = f"[NOC] {SEVERIDADES.get(alerta['severidad'], '?')}: {alerta['titulo']}"[:150]
            try:
                ENVIAR[canal](texto, asunto)
                _registrar(db, canal, alerta, "enviado")
            except Exception as error:
                _registrar(db, canal, alerta, "error", ocultar(error))
            db.commit()
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Cola y hilo de envío
# ---------------------------------------------------------------------------
_cola = queue.Queue(maxsize=500)
_hilo = None
_candado = threading.Lock()


def _trabajar():
    while True:
        alerta = _cola.get()
        try:
            _procesar(alerta)
        except Exception as error:
            print(f"[NOTIFICACIONES] Error: {ocultar(error)}")
        finally:
            _cola.task_done()


def encolar(alerta: dict):
    """Agrega una alerta a la cola. Nunca frena ni hace fallar la ingesta."""
    if not any(c["activo"] for c in CANALES.values()):
        return
    global _hilo
    with _candado:
        if _hilo is None or not _hilo.is_alive():
            _hilo = threading.Thread(target=_trabajar, daemon=True, name="notificaciones")
            _hilo.start()
    try:
        _cola.put_nowait(alerta)
    except queue.Full:
        pass  # si la cola se llena (tormenta extrema), se descarta: el evento ya está en la BD


def enviar_prueba(db, canal: str) -> dict:
    """Envía un mensaje de prueba por un canal, sin pasar por los filtros."""
    if not CANALES[canal]["activo"]:
        return {"canal": canal, "estado": "inactivo",
                "detalle": "Faltan las variables de este canal en el archivo .env"}
    alerta = {"clave": f"prueba:{canal}:{datetime.now().timestamp()}", "tipo": "prueba", "severidad": 6,
              "titulo": "Mensaje de prueba",
              "detalle": "Si recibe este mensaje, el canal funciona sin exponer credenciales."}
    try:
        ENVIAR[canal](_texto(alerta, 0), "[NOC] Mensaje de prueba")
        _registrar(db, canal, alerta, "enviado")
        resultado = {"canal": canal, "estado": "enviado"}
    except Exception as error:
        _registrar(db, canal, alerta, "error", ocultar(error))
        resultado = {"canal": canal, "estado": "error", "detalle": ocultar(error)}
    db.commit()
    return resultado

# --- FIN DEL ARCHIVO ---