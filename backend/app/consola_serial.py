"""
Consola REAL por cable de consola (puerto serial / COM) — Fase 9.

El equipo se conecta con el cable de consola al PC del NOC y el dashboard
habla con él directamente. NO necesita dirección IP.

Hace dos cosas:
  1. Comandos de SOLO LECTURA desde el dashboard, con la misma política que la
     consola simulada (denegar por defecto, lista de permitidos, bloqueados,
     auditoría y suspensión del agente de IA).
  2. Captura de logs: los mensajes que el equipo imprime en la consola
     (por ejemplo %LINK-3-UPDOWN) se envían al motor de ingesta como eventos
     REALES del equipo elegido, igual que si hubieran llegado por Syslog UDP.

SEGURIDAD:
  - Al equipo NUNCA se le envía el texto que escribió el usuario: se envía la
    versión CANÓNICA de un comando de la lista permitida (ej. "sh ip int br"
    se envía como "show ip interface brief").
  - Lo que responde el equipo es un DATO NO CONFIABLE: se limpia y nunca se
    ejecuta ni se obedece.
  - No se permite "show running-config" en equipos reales: contiene secretos.
  - Solo un usuario a la vez puede tener abierto el puerto (igual que PuTTY).
"""

import os
import re
import threading
import time
from collections import deque
from datetime import UTC, datetime, timedelta

from . import vigilancia  # v1.1.0: equipos caídos
from .console_sim import ALIAS, BLOQUEADOS, CARACTERES_PROHIBIDOS, PATRON_FILTRO
from .database import SessionLocal
from .ingest import ingerir
from .models import AuditLog, Device
from .notificaciones import encolar
from .politica_ia import MAX_BLOQUEOS, MOTIVO_SUSPENSION, agente_suspendido, bloqueos_recientes_agente
from .syslog_parser import limpiar

try:  # pyserial es opcional: sin él, el NOC funciona igual con la consola simulada
    import serial
    from serial.tools import list_ports
except ImportError:  # pragma: no cover
    serial = None
    list_ports = None

VELOCIDADES = (9600, 19200, 38400, 57600, 115200)
TIEMPO_COMANDO = 12  # segundos máximos esperando la respuesta de un comando
MAX_SALIDA = 30000  # caracteres máximos que se devuelven por comando
FACILITY_CONSOLA = 23  # local7, la que usan por defecto Cisco y Huawei
# v1.1.0 (hallazgo 3): "latido". Si la consola lleva LATIDO_SEG segundos en silencio, el NOC envía
# un Enter; si el equipo no contesta LATIDO_FALLOS veces seguidas, se declara CAÍDO.
LATIDO_SEG = max(10, int(os.getenv("NOC_LATIDO_SEG", "20")))
LATIDO_FALLOS = max(1, int(os.getenv("NOC_LATIDO_FALLOS", "2")))
LATIDO_ESPERA = 5  # segundos que se espera la respuesta a cada Enter

# Comandos de SOLO LECTURA permitidos en equipos REALES
PERMITIDOS_REAL = {
    "Cisco": [
        "show version",
        "show clock",
        "show logging",
        "show ip interface brief",
        "show interfaces status",
        "show vlan brief",
        "show mac address-table",
        "show cdp neighbors",
        "show lldp neighbors",
        "show ntp status",
        "show inventory",
        "show users",
        "help",
    ],
    "Huawei": [
        "display version",
        "display clock",
        "display logbuffer",
        "display ip interface brief",
        "display interface brief",
        "display vlan",
        "display mac-address",
        "display lldp neighbor brief",
        "display info-center",
        "display users",
        "help",
    ],
    "Fortinet": [
        "get system status",
        "get system interface",
        "get log syslogd setting",
        "get system arp",
        "help",
    ],
}

# Comandos de lectura que se niegan en equipos reales, con su motivo
NEGADOS_REAL = {
    "show running-config": "Contiene contraseñas y secretos del equipo real: no se muestra en el NOC.",
    "show startup-config": "Contiene contraseñas y secretos del equipo real: no se muestra en el NOC.",
    "display current-configuration": "Contiene contraseñas y secretos del equipo real: no se muestra.",
    "show full-configuration": "Contiene contraseñas y secretos del equipo real: no se muestra.",
}

# Cómo quitar la paginación (--More--) SOLO en esta sesión. No cambia la configuración.
SIN_PAGINACION = {"Cisco": "terminal length 0", "Huawei": "screen-length 0 temporary"}
# Cómo salir del modo configuración si alguien dejó el equipo ahí (no cambia nada)
SALIR_CONFIG = {"Cisco": "end", "Huawei": "return", "Fortinet": "end"}

# --- Reconocimiento de lo que imprime la consola ---
RE_PROMPT = re.compile(
    r"(?:^|\n)\s*("
    r"[A-Za-z0-9][\w.\-/]*(?:\([\w.\-/ ]*\))?[#>]"  # Cisco: Switch>  Switch#  Switch(config)#
    r"|<(?!cr>)[^<>\r\n]{1,64}>"  # Huawei: <HUAWEI>
    r"|\[[~*]?[^\[\]\r\n]{1,64}\]"  # Huawei system-view: [HUAWEI]
    r"|[\w.\-]+ (?:\([\w.\-]+\) )?[#$]"  # Fortinet: FGT60E #
    r")\s?$"
)
RE_LOGIN = re.compile(r"(?i)(user ?name|login|password|contrase\w*)\s*:\s*$")
RE_MORE = re.compile(r"\s*-+ ?\(?more\)?[^\n]*?-+\s*|\s*--More--\s*", re.IGNORECASE)
RE_LOG_CISCO = re.compile(r"%([A-Z0-9_]+)-([0-7])-([A-Z0-9_]+):")
# v1.0.3: también los traps sin "%%" (ej. "IFNET/1/IF_LINKDOWN:OID ...", severidad 1)
RE_LOG_HUAWEI = re.compile(
    r"(?:%%\d*|(?<=\s))([A-Z][A-Z0-9_]+)/([0-7])/([A-Z][A-Z0-9_]+)(?:\([^)]*\))?(?:\[\d+\])?:"
)
RE_CTRL_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
RE_BORRADO = re.compile(r"\x08+ *\x08*")
# v1.0.0: el equipo cerró la sesión de consola por inactividad (exec-timeout)
RE_SESION_CERRADA = re.compile(r"press return to get started|con0 is now available", re.IGNORECASE)


def _ahora():
    """Fecha y hora actual en UTC."""
    return datetime.now(UTC)


def marca_por_prompt(prompt: str):
    """v1.0.0: reconoce la marca por el prompt.
    <HUAWEI> o [HUAWEI] = Huawei · 'FGT60E #' = Fortinet · Switch> o Switch# = Cisco."""
    p = (prompt or "").strip()
    if p.startswith(("<", "[")):
        return "Huawei"
    if re.search(r"\s[#$]$", p):
        return "Fortinet"
    if re.fullmatch(r"[A-Za-z0-9][\w.\-/]*(?:\([\w.\-/ ]*\))?[#>]", p):
        return "Cisco"
    return None


def disponible() -> bool:
    """True si la librería pyserial está instalada (necesaria para la consola real)."""
    return serial is not None


def listar_puertos() -> list:
    """Puertos COM que ve el sistema operativo (ej. COM3 = 'USB Serial Port')."""
    if list_ports is None:
        return []
    return [
        {"puerto": p.device, "descripcion": p.description or ""}
        for p in sorted(list_ports.comports(), key=lambda x: x.device)
    ]


def severidad_de_log(linea: str):
    """Si la línea es un log de Cisco o Huawei devuelve su severidad (0-7); si no, None."""
    m = RE_LOG_CISCO.search(linea) or RE_LOG_HUAWEI.search(linea)
    return int(m.group(2)) if m else None


class ConsolaSerial:
    """Una conexión serial a la vez (como PuTTY). Un hilo lee todo lo que llega."""

    def __init__(self):
        """Prepara la consola sin conexión: buffer de líneas, candados y estado inicial."""
        self._lock = threading.RLock()
        self._lock_cmd = threading.Lock()
        self._puerto_obj = None
        self._hilo = None
        self._activo = False
        self._parcial = ""
        self._captura = None  # lista de líneas mientras se ejecuta un comando
        self._listo = threading.Event()  # se activa cuando vuelve a aparecer el prompt
        self.lineas = deque(maxlen=400)  # lo último que imprimió la consola
        self.contador = 0
        self.puerto = None
        self.velocidad = None
        self.equipo = None  # dict con id, name, vendor, ip_address
        self.prompt = None
        self.login_requerido = False
        self.eventos_capturados = 0
        self.conectado_desde = None
        self.ultimo_error = None
        self._ultimo_dato = 0.0  # v1.1.0: cuándo llegó el último byte del equipo (time.monotonic)
        self._ultimo_latido = 0.0
        self._fallos_latido = 0
        self._en_latido = False
        self.caido_desde = None  # v1.1.0: hora en que el equipo dejó de responder

    # ------------------------------------------------------------------ estado
    @property
    def conectado(self) -> bool:
        """True si hay un puerto COM abierto y el hilo de lectura está activo."""
        return bool(self._activo and self._puerto_obj and self._puerto_obj.is_open)

    def estado(self, desde: int = 0) -> dict:
        """Estado de la consola para el navegador: conexión, equipo, prompt, contador de logs y líneas
        nuevas.
        """
        with self._lock:
            nuevas = [linea for linea in self.lineas if linea["n"] > desde]
            return {
                "disponible": disponible(),
                "conectado": self.conectado,
                "puerto": self.puerto,
                "velocidad": self.velocidad,
                "equipo": self.equipo,
                "prompt": self.prompt,
                "login_requerido": self.login_requerido,
                "eventos_capturados": self.eventos_capturados,
                "conectado_desde": self.conectado_desde,
                "ultimo_error": self.ultimo_error,
                "marca_detectada": getattr(self, "marca_detectada", None),
                "incompatible": getattr(self, "incompatible", None),
                "caido_desde": self.caido_desde,  # v1.1.0
                "latido_seg": LATIDO_SEG,
                "ultimo": self.contador,
                "lineas": nuevas[-200:],
            }

    def _agregar(self, texto: str, tipo: str):
        """Agrega una línea a la pantalla de la consola (máximo 2000 líneas en memoria)."""
        with self._lock:
            self.contador += 1
            self.lineas.append({"n": self.contador, "tipo": tipo, "texto": texto})

    # ------------------------------------------------------------ conectar
    def conectar(self, puerto: str, velocidad: int, equipo: Device):
        """Abre el puerto COM, despierta la consola, revisa la marca del equipo y prepara la sesión (sin
        paginación).
        """
        if serial is None:
            raise RuntimeError("Falta la librería pyserial. Ejecute: pip install pyserial")
        with self._lock:
            if self.conectado:
                raise RuntimeError(f"Ya hay una consola abierta en {self.puerto}. Desconéctela primero.")
            try:
                self._puerto_obj = serial.serial_for_url(
                    puerto,
                    baudrate=velocidad,
                    bytesize=8,
                    parity="N",
                    stopbits=1,
                    timeout=0.2,
                    write_timeout=2,
                )
            except Exception as exc:  # puerto ocupado, inexistente, sin permisos...
                self._puerto_obj = None
                texto = str(exc)
                if "PermissionError" in texto or "Access is denied" in texto or "Acceso denegado" in texto:
                    texto = f"El puerto {puerto} está ocupado. Cierre PuTTY u otro programa que lo use."
                raise RuntimeError(f"No se pudo abrir {puerto}: {texto}") from None

            self.puerto, self.velocidad = puerto, velocidad
            self.equipo = {
                "id": equipo.id,
                "name": equipo.name,
                "vendor": equipo.vendor,
                "ip_address": equipo.ip_address,
            }
            self.lineas.clear()
            self._parcial = ""
            self.prompt = None
            self.login_requerido = False
            self.eventos_capturados = 0
            self.ultimo_error = None
            self.dormida = False  # v1.0.0
            self.incompatible = None  # v1.0.0
            self.marca_detectada = None  # v1.0.0
            self.conectado_desde = _ahora().isoformat()
            # v1.1.0: si el equipo ya estaba caído (de una conexión anterior), se recuerda
            caido = vigilancia.CAIDOS.get(equipo.id)
            self.caido_desde = caido["desde"].isoformat() if caido else None
            self._ultimo_dato = self._ultimo_latido = time.monotonic()
            self._fallos_latido = 0
            self._activo = True
            self._hilo = threading.Thread(target=self._leer, name="consola-serial", daemon=True)
            self._hilo.start()
            threading.Thread(target=self._vigia, name="consola-latido", daemon=True).start()

        self._agregar(
            f"*** Consola REAL abierta en {puerto} a {velocidad} baudios · "
            f"equipo {equipo.name} ({equipo.vendor}) ***",
            "info",
        )
        # Despertar la consola y esperar el prompt
        try:
            self._listo.clear()
            self._escribir("\r")
            self._listo.wait(3)
            if not self.prompt and not self.login_requerido:
                self._listo.clear()
                self._escribir("\r")
                self._listo.wait(3)
        except Exception:
            self.desconectar()
            raise RuntimeError(
                f"El puerto {puerto} no responde. ¿Es el puerto del cable de consola? "
                "Los puertos 'Bluetooth' no sirven. Revise también la velocidad (9600)."
            ) from None
        if not self.prompt and not self.login_requerido:
            self._agregar(
                "⚠ El equipo no respondió. Revise que el COM sea el del cable de consola "
                "(no Bluetooth), que el equipo esté encendido y que la velocidad sea 9600.",
                "error",
            )
            return self.estado()
        self._verificar_marca()  # v1.0.0: ¿el equipo del cable es el que se eligió?
        if self.incompatible:
            return self.estado()
        self._preparar_sesion()
        return self.estado()

    def _preparar_sesion(self):
        """Sale del modo configuración si quedó abierto y quita la paginación (solo esta sesión)."""
        if not self.prompt or self.login_requerido:
            return
        vendor = self.equipo["vendor"]
        if "(config" in self.prompt or self.prompt.startswith("["):
            self._enviar_y_esperar(SALIR_CONFIG.get(vendor, "end"), 4)
            self._agregar(
                "(El equipo estaba en modo configuración: se salió con "
                f"'{SALIR_CONFIG.get(vendor, 'end')}', sin cambiar nada)",
                "info",
            )
        if vendor in SIN_PAGINACION:
            self._enviar_y_esperar(SIN_PAGINACION[vendor], 4)

    def desconectar(self):
        """Cierra el puerto COM y detiene el hilo de lectura."""
        with self._lock:
            self._activo = False
            obj, self._puerto_obj = self._puerto_obj, None
        if obj is not None:
            try:
                obj.close()
            except Exception:
                pass
        if self._hilo and self._hilo is not threading.current_thread():
            self._hilo.join(timeout=2)
        self._agregar("*** Consola cerrada ***", "info")
        self.prompt = None

    # -------------------------------------------------------------- lectura
    def _escribir(self, texto: str):
        """Envía texto al equipo por el puerto COM. Si el equipo no responde, lanza RuntimeError con un
        mensaje claro.
        """
        obj = self._puerto_obj
        if obj is None:
            raise RuntimeError("La consola no está conectada")
        try:
            obj.write(texto.encode("ascii", errors="ignore"))
            obj.flush()
        except Exception as exc:
            raise RuntimeError(
                f"No se pudo escribir en {self.puerto}: el equipo no responde ({exc.__class__.__name__})."
            ) from None

    def _leer(self):
        """Hilo de lectura: recibe todo lo que imprime el equipo y lo pasa a _procesar()."""
        while self._activo:
            obj = self._puerto_obj
            try:
                if obj is None:
                    break
                datos = obj.read(obj.in_waiting or 1)
            except Exception as exc:  # cable desconectado, puerto cerrado...
                if self._activo:
                    self.ultimo_error = f"Se perdió la conexión con {self.puerto}: {exc}"
                    self._agregar(self.ultimo_error, "error")
                    self._activo = False
                    self._listo.set()
                    threading.Thread(target=self._cable_perdido, daemon=True).start()  # v1.1.0
                break
            if datos:
                self._ultimo_dato = time.monotonic()  # v1.1.0: el equipo está vivo
                if self.caido_desde:
                    self._recuperado()
                self._procesar(datos.decode("utf-8", errors="replace"))

    # ------------------------------------------------- v1.1.0: equipo caído
    def _vigia(self):
        """Hilo del latido: si la consola está en silencio, envía un Enter y espera respuesta.
        Un equipo apagado no contesta: tras LATIDO_FALLOS intentos se declara caído."""
        while self._activo:
            time.sleep(1)
            ahora = time.monotonic()
            if (
                not self._activo
                or getattr(self, "incompatible", None)
                or self.login_requerido  # en "Password:" un Enter sería un intento de login fallido
                or ahora - self._ultimo_dato < LATIDO_SEG
                or ahora - self._ultimo_latido < LATIDO_SEG
            ):
                continue
            if not self._lock_cmd.acquire(blocking=False):
                continue  # hay un comando en curso: no se interrumpe
            try:
                antes = self._ultimo_dato
                self._ultimo_latido = time.monotonic()
                self._en_latido = True
                try:
                    self._escribir("\r")
                except RuntimeError:
                    pass
                limite = time.monotonic() + LATIDO_ESPERA
                while self._activo and self._ultimo_dato == antes and time.monotonic() < limite:
                    time.sleep(0.2)
                respondio = self._ultimo_dato != antes
                time.sleep(0.3)  # deja terminar de llegar el prompt
                self._en_latido = False
            finally:
                self._lock_cmd.release()
            if respondio:
                self._fallos_latido = 0
                continue
            self._fallos_latido += 1
            if self._fallos_latido >= LATIDO_FALLOS and not self.caido_desde and self._activo:
                self._caido()

    def _caido(self):
        """El equipo no contesta por la consola: evento crítico, incidente y aviso (vigilancia.py)."""
        # Desde cuándo: la última vez que el equipo envió algo
        desde = _ahora() - timedelta(seconds=time.monotonic() - self._ultimo_dato)
        self.caido_desde = desde.isoformat()
        espera = LATIDO_SEG * LATIDO_FALLOS
        self._agregar(
            f"🔴 El equipo {self.equipo['name']} NO RESPONDE por la consola (sin respuesta en ~{espera} s). "
            "¿Se apagó o se reinició? Se generó un evento crítico, un incidente y el aviso por Telegram.",
            "error",
        )
        vigilancia.marcar_caido(
            self.equipo["id"], "consola", "Revise la energía del equipo y el cable de consola.", desde
        )

    def _recuperado(self):
        """Llegaron datos de un equipo que estaba caído: se registra la recuperación en otro hilo."""
        self.caido_desde = None
        self._fallos_latido = 0
        self._agregar(f"🟢 El equipo {self.equipo['name']} volvió a responder.", "info")
        threading.Thread(target=vigilancia.marcar_recuperado, args=(self.equipo["id"],), daemon=True).start()

    def _cable_perdido(self):
        """El puerto COM desapareció (adaptador USB desconectado): evento de severidad 2 (Crítico)."""
        if not self.equipo:
            return
        db = SessionLocal()
        try:
            texto = (
                f"Se perdió la conexión de consola ({self.puerto}) con {self.equipo['name']}: "
                "se desconectó el cable USB de consola o el adaptador."
            )
            raw = f"<{FACILITY_CONSOLA * 8 + 2}>%NOC-2-CONSOLA_PERDIDA: {texto}"
            ingerir(db, raw, self.equipo["ip_address"], "real", device_id=self.equipo["id"])
        except Exception as exc:
            self.ultimo_error = f"No se pudo registrar la pérdida de la consola: {exc}"
        finally:
            db.close()

    def _procesar(self, texto: str):
        """Limpia lo recibido (colores, retrocesos, --More--), lo corta en líneas y detecta el prompt o una
        pregunta de login.
        """
        texto = RE_CTRL_ANSI.sub("", texto)
        texto = RE_BORRADO.sub("", texto)  # el equipo "borra" el --More-- con retrocesos y espacios
        # Paginación: si aparece --More--, se pide la siguiente página con un espacio
        if RE_MORE.search(self._parcial + texto):
            texto = RE_MORE.sub("\n", self._parcial + texto)
            self._parcial = ""
            try:
                self._escribir(" ")
            except Exception:
                pass
        texto = texto.replace("\x08", "").replace("\r\n", "\n").replace("\r", "\n")
        bloque = self._parcial + texto
        *completas, self._parcial = bloque.split("\n")
        for linea in completas:
            self._linea(limpiar(linea).rstrip())

        # ¿Lo que quedó sin salto de línea es un prompt o una pregunta de login?
        resto = limpiar(self._parcial).strip()
        if resto:
            if RE_LOGIN.search(resto):
                self.login_requerido = True
                self.prompt = None
                self._agregar(resto, "consola")
                self._parcial = ""
                self._listo.set()
            elif RE_PROMPT.search("\n" + resto):
                self.prompt = RE_PROMPT.search("\n" + resto).group(1)
                self.login_requerido = False
                # v1.0.4: si al conectar el equipo no mostró el prompt, se revisa la marca ahora
                if self.equipo and not getattr(self, "marca_detectada", None):
                    self._verificar_marca()
                self._listo.set()

    def _revisar_marca_log(self, linea: str):
        """v1.0.4: los logs también delatan la marca (Cisco: %LINK-3-UPDOWN; Huawei: IFNET/1/...).
        Si no coincide con el equipo elegido, se bloquea igual que con el prompt."""
        if getattr(self, "incompatible", None) or not self.equipo:
            return
        marca = "Cisco" if RE_LOG_CISCO.search(linea) else "Huawei"
        elegida = self.equipo["vendor"]
        if elegida in ("Cisco", "Huawei") and marca != elegida:
            self.marca_detectada = marca
            self.incompatible = (
                f"Los logs que llegan son de un equipo {marca}, pero eligió {self.equipo['name']} "
                f"({elegida}). Desconecte y elija el equipo correcto; si no aparece, regístrelo en "
                "Inventario con Tipo: Real. Mientras tanto no se envían comandos ni se guardan logs."
            )
            self._agregar("⚠ " + self.incompatible, "error")

    def _linea(self, linea: str):
        """Procesa una línea completa: detecta logs (%FAC-SEV-MNEM), sesión cerrada por inactividad y el
        prompt.
        """
        if not linea:
            if self._captura is not None:
                self._captura.append("")
            return
        if self._en_latido and self.prompt and linea.strip() == self.prompt.strip():
            return  # v1.1.0: el prompt que devuelve el latido no se repite en pantalla
        if RE_SESION_CERRADA.search(linea):  # v1.0.0: el equipo cerró la sesión
            self.dormida = True
        sev = severidad_de_log(linea)
        if sev is not None:
            self._revisar_marca_log(linea)  # v1.0.4
            self._ingerir_log(linea, sev)
        if self._captura is not None and sev is None:
            if len(self._captura) < 4000:
                self._captura.append(linea)
            return
        self._agregar(linea, "log" if sev is not None else "consola")
        m = RE_PROMPT.search("\n" + linea)
        if m and m.end() == len(linea) + 1:
            self.prompt = m.group(1)

    def _ingerir_log(self, linea: str, severidad: int):
        """Envía el log de la consola al motor de ingesta como evento REAL del equipo."""
        if not self.equipo:
            return
        if getattr(self, "incompatible", None):
            return  # v1.0.0: no se guardan logs a nombre de otro equipo
        raw = f"<{FACILITY_CONSOLA * 8 + severidad}>{linea.lstrip()}"
        db = SessionLocal()
        try:
            r = ingerir(db, raw, self.equipo["ip_address"], "real", device_id=self.equipo["id"])  # v1.0.3
            if r.get("resultado") == "nuevo":
                self.eventos_capturados += 1
        except Exception as exc:
            self.ultimo_error = f"No se pudo guardar un log de la consola: {exc}"
        finally:
            db.close()

    # ------------------------------------------------------------ comandos
    def _verificar_marca(self):
        """v1.0.0: compara la marca que muestra el prompt con la del equipo elegido."""
        self.marca_detectada = marca_por_prompt(self.prompt) if self.prompt else None
        elegida = self.equipo["vendor"] if self.equipo else None
        if self.marca_detectada and elegida and self.marca_detectada != elegida:
            self.incompatible = (
                f"El equipo conectado parece {self.marca_detectada} (prompt {self.prompt.strip()}), pero "
                f"eligió {self.equipo['name']} ({elegida}). Desconecte y elija el equipo correcto; si no "
                "aparece, regístrelo en Inventario con Tipo: Real. Mientras tanto no se envían comandos "
                "ni se guardan logs, para no mezclar equipos."
            )
            self._agregar("⚠ " + self.incompatible, "error")

    def _despertar(self):
        """v1.0.0: el equipo cerró la sesión por inactividad ('Press RETURN to get started')."""
        self.dormida = False
        with self._lock_cmd:
            self._listo.clear()
            self._escribir("\r")
            self._listo.wait(3)
        self._agregar(
            "(La consola estaba inactiva: el NOC la reactivó con Enter. Si el prompt "
            "volvió a '>', los cambios necesitan modo '#')",
            "info",
        )
        vendor = self.equipo["vendor"] if self.equipo else None
        if vendor in SIN_PAGINACION:
            self._enviar_una_vez(SIN_PAGINACION[vendor], 4)

    def _enviar_y_esperar(self, comando: str, espera: float = TIEMPO_COMANDO):
        """Envía UN comando ya validado y devuelve (salida, completo).
        v1.0.0: si la consola se 'durmió', la reactiva y reintenta UNA vez."""
        if getattr(self, "incompatible", None):
            return "⚠ " + self.incompatible, False
        if getattr(self, "dormida", False):
            self._despertar()
        salida, completo = self._enviar_una_vez(comando, espera)
        if not completo and not salida.strip() and self._activo:
            self._despertar()
            salida, completo = self._enviar_una_vez(comando, espera)
        return salida, completo

    def _enviar_una_vez(self, comando: str, espera: float = TIEMPO_COMANDO):
        """Envía UN comando ya validado y devuelve (salida, completo)."""
        with self._lock_cmd:
            self._captura = []
            self._listo.clear()
            try:
                self._escribir(comando + "\r")
            except RuntimeError:
                self._captura = None
                raise
            inicio = time.monotonic()
            completo = False
            while time.monotonic() - inicio < espera:
                if self._listo.wait(0.3):
                    # Pequeña pausa por si el equipo sigue enviando texto
                    time.sleep(0.15)
                    completo = True
                    break
                if not self._activo:
                    break
            lineas, self._captura = self._captura or [], None
        # Quitar el eco del comando (la primera línea suele ser "Switch#show version")
        if lineas and comando.split()[0] in lineas[0] and lineas[0].rstrip().endswith(comando.strip()):
            lineas = lineas[1:]
        while lineas and not lineas[0].strip():
            lineas.pop(0)
        salida = "\n".join(lineas).rstrip()
        return salida[:MAX_SALIDA], completo


CONSOLA = ConsolaSerial()


# ---------------------------------------------------------------------------
# Política para la consola REAL (misma idea que la simulada)
# ---------------------------------------------------------------------------
def _auditar(db, equipo: dict, comando: str, actor: str, permitido: bool, motivo=None):
    """Registra en la auditoría cada comando de la consola real, permitido o rechazado."""
    detalle = f"[CONSOLA REAL {CONSOLA.puerto}] {equipo['name']}> {comando[:120]}"
    if not permitido:
        detalle += f" | RECHAZADO: {motivo}"
    db.add(
        AuditLog(
            actor="agente_ia" if actor == "agente_ia" else "operador_local",
            action="CONSOLE_CMD" if permitido else "CONSOLE_BLOCKED",
            entity_type="devices",
            entity_id=equipo["id"],
            details=detalle[:300],
        )
    )
    db.commit()


def ayuda(vendor: str) -> str:
    """Texto de ayuda con los comandos permitidos para la marca indicada."""
    lista = "\n".join(f"  - {c}" for c in PERMITIDOS_REAL.get(vendor, []))
    return (
        f"Comandos permitidos en el equipo REAL {vendor} (solo lectura):\n{lista}\n\n"
        "Filtro permitido:  <comando> | include <palabra>\n"
        "Los logs que el equipo imprima en la consola llegan solos al NOC como eventos reales."
    )


def _avisar_suspension(db, eq: dict, comando: str, actor: str, permitido: bool):
    """Si con este rechazo el agente de IA llega al límite, avisa por Telegram que quedó suspendido."""
    if actor == "agente_ia" and not permitido and bloqueos_recientes_agente(db) == MAX_BLOQUEOS:
        encolar(
            {
                "clave": "agente_suspendido",
                "tipo": "agente_suspendido",
                "severidad": 1,
                "siempre": True,
                "titulo": "Agente de IA SUSPENDIDO",
                "detalle": f"Acumuló {MAX_BLOQUEOS} comandos bloqueados. Último intento en "
                f"el equipo REAL {eq['name']}: {comando[:80]}. Requiere revisión humana.",
            }
        )


def _validar_comando(comando_original: str, comando: str, vendor: str):
    """Revisa un comando contra la política de la consola real, en orden:
    caracteres prohibidos -> filtro '| include' -> lista bloqueada -> lista permitida.

    Devuelve (canonico, filtro, None) si se permite, o (None, None, (categoria, motivo, salida))
    si se rechaza o se responde sin ir al equipo (como 'help')."""
    # 1. Caracteres prohibidos: no se puede encadenar ni redirigir comandos
    if CARACTERES_PROHIBIDOS.search(comando_original):
        motivo = "Caracteres no permitidos (; & ` $ < > \\ ||): no se puede encadenar ni redirigir comandos."
        return None, None, ("invalido", motivo, "")
    texto = comando.lower()

    # 2. Filtro "| include <palabra>" (se aplica en el NOC, no en el equipo)
    filtro = None
    if "|" in texto:
        m = PATRON_FILTRO.fullmatch(texto)
        if not m:
            return None, None, ("invalido", "Solo se permite un filtro de la forma: | include <palabra>", "")
        texto, filtro = m.group(1).strip(), m.group(2)

    # 3. Lista bloqueada
    for patron, _ejemplos, motivo in BLOQUEADOS:
        if re.match(patron, texto):
            return None, None, ("bloqueado", motivo, "")

    # 4. Lista permitida: se pasa a la forma completa ("sh ver" -> "show version")
    alias = ALIAS.get(vendor, {})
    canonico = " ".join(alias.get(t, t) for t in texto.split())
    if canonico in NEGADOS_REAL:
        return None, None, ("bloqueado", NEGADOS_REAL[canonico], "")
    if canonico == "help":
        return None, None, ("permitido", None, ayuda(vendor))
    if canonico not in PERMITIDOS_REAL[vendor]:
        motivo = (
            f"'{comando}' no está en la lista de comandos permitidos del equipo real. "
            "Escriba 'help' para verlos."
        )
        return None, None, ("no_permitido", motivo, "")
    return canonico, filtro, None


def _salida_con_notas(salida: str, completo: bool, filtro) -> str:
    """Aplica el filtro '| include' y agrega notas útiles (respuesta incompleta, comando no reconocido)."""
    if filtro:
        salida = "\n".join(linea for linea in salida.splitlines() if filtro in linea.lower())
    if not completo:
        salida += "\n(El equipo no terminó de responder a tiempo: la salida puede estar incompleta)"
    if "% invalid input" in salida.lower() or "% incomplete" in salida.lower():
        salida += (
            "\n(Nota: el equipo no reconoció el comando. Si el prompt termina en '>', "
            "algunos 'show' requieren modo privilegiado '#'.)"
        )
    return salida or "(sin resultados)"


def ejecutar_real(db, comando_original: str, actor: str) -> dict:
    """Valida el comando con la política y, si se permite, lo envía al equipo real.

    Todo intento (permitido o no) queda en la auditoría. Al equipo se le envía siempre
    la versión CANÓNICA del comando, nunca el texto que escribió el usuario."""
    if not CONSOLA.conectado or not CONSOLA.equipo:
        raise RuntimeError("La consola real no está conectada. Elija el puerto COM y presione Conectar.")
    eq = CONSOLA.equipo
    comando = " ".join(comando_original.strip().split())

    def responder(categoria, salida="", motivo=None):
        """Arma la respuesta estándar de la consola real (categoría, salida y motivo)."""
        permitido = categoria == "permitido"
        _auditar(db, eq, comando, actor, permitido, motivo)
        _avisar_suspension(db, eq, comando, actor, permitido)
        return {
            "prompt": CONSOLA.prompt or f"{eq['name']}#",
            "comando": comando,
            "categoria": categoria,
            "permitido": permitido,
            "salida": salida,
            "motivo": motivo,
        }

    # 0. Agente de IA suspendido o marca sin consola real
    if actor == "agente_ia" and agente_suspendido(db):
        return responder("bloqueado", motivo=MOTIVO_SUSPENSION)
    vendor = eq["vendor"]
    if vendor not in PERMITIDOS_REAL:
        return responder(
            "no_permitido", motivo="La consola real solo está disponible para Cisco, Fortinet y Huawei."
        )

    # 1 a 4. Política del comando
    canonico, filtro, rechazo = _validar_comando(comando_original, comando, vendor)
    if rechazo:
        categoria, motivo, salida = rechazo
        return responder(categoria, salida=salida, motivo=motivo)

    # El NOC no guarda credenciales: si el equipo pide login, no se envía nada
    if CONSOLA.login_requerido:
        return responder(
            "no_permitido",
            motivo="El equipo está pidiendo usuario o contraseña. El NOC no guarda credenciales: "
            "inicie sesión una vez con PuTTY, cierre PuTTY y vuelva a conectar aquí.",
        )

    # 5. Enviar al equipo la versión CANÓNICA (nunca el texto del usuario)
    salida, completo = CONSOLA._enviar_y_esperar(canonico)
    return responder("permitido", salida=_salida_con_notas(salida, completo, filtro))


# --- FIN DEL ARCHIVO ---
