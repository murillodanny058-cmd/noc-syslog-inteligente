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
import re
import threading
import time
from collections import deque
from datetime import datetime, timezone

from .database import SessionLocal
from .models import AuditLog, Device
from .notificaciones import encolar
from .politica_ia import MAX_BLOQUEOS, MOTIVO_SUSPENSION, agente_suspendido, bloqueos_recientes_agente
from .console_sim import ALIAS, BLOQUEADOS, CARACTERES_PROHIBIDOS, PATRON_FILTRO
from .ingest import ingerir
from .syslog_parser import limpiar

try:  # pyserial es opcional: sin él, el NOC funciona igual con la consola simulada
    import serial
    from serial.tools import list_ports
except ImportError:  # pragma: no cover
    serial = None
    list_ports = None

VELOCIDADES = (9600, 19200, 38400, 57600, 115200)
TIEMPO_COMANDO = 12          # segundos máximos esperando la respuesta de un comando
MAX_SALIDA = 30000           # caracteres máximos que se devuelven por comando
FACILITY_CONSOLA = 23        # local7, la que usan por defecto Cisco y Huawei

# Comandos de SOLO LECTURA permitidos en equipos REALES
PERMITIDOS_REAL = {
    "Cisco": [
        "show version", "show clock", "show logging", "show ip interface brief",
        "show interfaces status", "show vlan brief", "show mac address-table",
        "show cdp neighbors", "show lldp neighbors", "show ntp status",
        "show inventory", "show users", "help",
    ],
    "Huawei": [
        "display version", "display clock", "display logbuffer", "display ip interface brief",
        "display interface brief", "display vlan", "display mac-address",
        "display lldp neighbor brief", "display info-center", "display users", "help",
    ],
    "Fortinet": [
        "get system status", "get system interface", "get log syslogd setting",
        "get system arp", "help",
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
    r"[A-Za-z0-9][\w.\-/]*(?:\([\w.\-/ ]*\))?[#>]"   # Cisco: Switch>  Switch#  Switch(config)#
    r"|<(?!cr>)[^<>\r\n]{1,64}>"                        # Huawei: <HUAWEI>
    r"|\[[~*]?[^\[\]\r\n]{1,64}\]"                  # Huawei system-view: [HUAWEI]
    r"|[\w.\-]+ (?:\([\w.\-]+\) )?[#$]"              # Fortinet: FGT60E #
    r")\s?$")
RE_LOGIN = re.compile(r"(?i)(user ?name|login|password|contrase\w*)\s*:\s*$")
RE_MORE = re.compile(r"\s*-+ ?\(?more\)?[^\n]*?-+\s*|\s*--More--\s*", re.IGNORECASE)
RE_LOG_CISCO = re.compile(r"%([A-Z0-9_]+)-([0-7])-([A-Z0-9_]+):")
RE_LOG_HUAWEI = re.compile(r"%%\d*([A-Z0-9_]+)/([0-7])/([A-Z0-9_]+)")
RE_CTRL_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
RE_BORRADO = re.compile(r"\x08+ *\x08*")


def _ahora():
    return datetime.now(timezone.utc)


def disponible() -> bool:
    return serial is not None


def listar_puertos() -> list:
    """Puertos COM que ve el sistema operativo (ej. COM3 = 'USB Serial Port')."""
    if list_ports is None:
        return []
    return [{"puerto": p.device, "descripcion": p.description or ""}
            for p in sorted(list_ports.comports(), key=lambda x: x.device)]


def severidad_de_log(linea: str):
    """Si la línea es un log de Cisco o Huawei devuelve su severidad (0-7); si no, None."""
    m = RE_LOG_CISCO.search(linea) or RE_LOG_HUAWEI.search(linea)
    return int(m.group(2)) if m else None


class ConsolaSerial:
    """Una conexión serial a la vez (como PuTTY). Un hilo lee todo lo que llega."""

    def __init__(self):
        self._lock = threading.RLock()
        self._lock_cmd = threading.Lock()
        self._puerto_obj = None
        self._hilo = None
        self._activo = False
        self._parcial = ""
        self._captura = None              # lista de líneas mientras se ejecuta un comando
        self._listo = threading.Event()   # se activa cuando vuelve a aparecer el prompt
        self.lineas = deque(maxlen=400)   # lo último que imprimió la consola
        self.contador = 0
        self.puerto = None
        self.velocidad = None
        self.equipo = None                # dict con id, name, vendor, ip_address
        self.prompt = None
        self.login_requerido = False
        self.eventos_capturados = 0
        self.conectado_desde = None
        self.ultimo_error = None

    # ------------------------------------------------------------------ estado
    @property
    def conectado(self) -> bool:
        return bool(self._activo and self._puerto_obj and self._puerto_obj.is_open)

    def estado(self, desde: int = 0) -> dict:
        with self._lock:
            nuevas = [l for l in self.lineas if l["n"] > desde]
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
                "ultimo": self.contador,
                "lineas": nuevas[-200:],
            }

    def _agregar(self, texto: str, tipo: str):
        with self._lock:
            self.contador += 1
            self.lineas.append({"n": self.contador, "tipo": tipo, "texto": texto})

    # ------------------------------------------------------------ conectar
    def conectar(self, puerto: str, velocidad: int, equipo: Device):
        if serial is None:
            raise RuntimeError("Falta la librería pyserial. Ejecute: pip install pyserial")
        with self._lock:
            if self.conectado:
                raise RuntimeError(f"Ya hay una consola abierta en {self.puerto}. Desconéctela primero.")
            try:
                self._puerto_obj = serial.serial_for_url(
                    puerto, baudrate=velocidad, bytesize=8, parity="N", stopbits=1,
                    timeout=0.2, write_timeout=2)
            except Exception as exc:  # puerto ocupado, inexistente, sin permisos...
                self._puerto_obj = None
                texto = str(exc)
                if "PermissionError" in texto or "Access is denied" in texto or "Acceso denegado" in texto:
                    texto = f"El puerto {puerto} está ocupado. Cierre PuTTY u otro programa que lo use."
                raise RuntimeError(f"No se pudo abrir {puerto}: {texto}") from None

            self.puerto, self.velocidad = puerto, velocidad
            self.equipo = {"id": equipo.id, "name": equipo.name, "vendor": equipo.vendor,
                           "ip_address": equipo.ip_address}
            self.lineas.clear()
            self._parcial = ""
            self.prompt = None
            self.login_requerido = False
            self.eventos_capturados = 0
            self.ultimo_error = None
            self.conectado_desde = _ahora().isoformat()
            self._activo = True
            self._hilo = threading.Thread(target=self._leer, name="consola-serial", daemon=True)
            self._hilo.start()

        self._agregar(f"*** Consola REAL abierta en {puerto} a {velocidad} baudios · "
                      f"equipo {equipo.name} ({equipo.vendor}) ***", "info")
        # Despertar la consola y esperar el prompt
        self._listo.clear()
        self._escribir("\r")
        self._listo.wait(3)
        if not self.prompt and not self.login_requerido:
            self._listo.clear()
            self._escribir("\r")
            self._listo.wait(3)
        self._preparar_sesion()
        return self.estado()

    def _preparar_sesion(self):
        """Sale del modo configuración si quedó abierto y quita la paginación (solo esta sesión)."""
        if not self.prompt or self.login_requerido:
            return
        vendor = self.equipo["vendor"]
        if "(config" in self.prompt or self.prompt.startswith("["):
            self._enviar_y_esperar(SALIR_CONFIG.get(vendor, "end"), 4)
            self._agregar("(El equipo estaba en modo configuración: se salió con "
                          f"'{SALIR_CONFIG.get(vendor, 'end')}', sin cambiar nada)", "info")
        if vendor in SIN_PAGINACION:
            self._enviar_y_esperar(SIN_PAGINACION[vendor], 4)

    def desconectar(self):
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
        obj = self._puerto_obj
        if obj is None:
            raise RuntimeError("La consola no está conectada")
        obj.write(texto.encode("ascii", errors="ignore"))
        obj.flush()

    def _leer(self):
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
                break
            if datos:
                self._procesar(datos.decode("utf-8", errors="replace"))

    def _procesar(self, texto: str):
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
                self._listo.set()

    def _linea(self, linea: str):
        if not linea:
            if self._captura is not None:
                self._captura.append("")
            return
        sev = severidad_de_log(linea)
        if sev is not None:
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
        raw = f"<{FACILITY_CONSOLA * 8 + severidad}>{linea.lstrip()}"
        db = SessionLocal()
        try:
            r = ingerir(db, raw, self.equipo["ip_address"], "real")
            if r.get("resultado") == "nuevo":
                self.eventos_capturados += 1
        except Exception as exc:
            self.ultimo_error = f"No se pudo guardar un log de la consola: {exc}"
        finally:
            db.close()

    # ------------------------------------------------------------ comandos
    def _enviar_y_esperar(self, comando: str, espera: float = TIEMPO_COMANDO):
        """Envía UN comando ya validado y devuelve (salida, completo)."""
        with self._lock_cmd:
            self._captura = []
            self._listo.clear()
            self._escribir(comando + "\r")
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
    detalle = f"[CONSOLA REAL {CONSOLA.puerto}] {equipo['name']}> {comando[:120]}"
    if not permitido:
        detalle += f" | RECHAZADO: {motivo}"
    db.add(AuditLog(actor="agente_ia" if actor == "agente_ia" else "operador_local",
                    action="CONSOLE_CMD" if permitido else "CONSOLE_BLOCKED",
                    entity_type="devices", entity_id=equipo["id"], details=detalle[:300]))
    db.commit()


def ayuda(vendor: str) -> str:
    lista = "\n".join(f"  - {c}" for c in PERMITIDOS_REAL.get(vendor, []))
    return (f"Comandos permitidos en el equipo REAL {vendor} (solo lectura):\n{lista}\n\n"
            "Filtro permitido:  <comando> | include <palabra>\n"
            "Los logs que el equipo imprima en la consola llegan solos al NOC como eventos reales.")


def ejecutar_real(db, comando_original: str, actor: str) -> dict:
    """Valida el comando con la política y, si se permite, lo envía al equipo real."""
    if not CONSOLA.conectado or not CONSOLA.equipo:
        raise RuntimeError("La consola real no está conectada. Elija el puerto COM y presione Conectar.")
    eq = CONSOLA.equipo
    comando = " ".join(comando_original.strip().split())

    def responder(categoria, salida="", motivo=None):
        permitido = categoria == "permitido"
        _auditar(db, eq, comando, actor, permitido, motivo)
        if actor == "agente_ia" and not permitido and bloqueos_recientes_agente(db) == MAX_BLOQUEOS:
            encolar({"clave": "agente_suspendido", "tipo": "agente_suspendido", "severidad": 1,
                     "siempre": True, "titulo": "Agente de IA SUSPENDIDO",
                     "detalle": f"Acumuló {MAX_BLOQUEOS} comandos bloqueados. Último intento en "
                                f"el equipo REAL {eq['name']}: {comando[:80]}. Requiere revisión humana."})
        return {"prompt": CONSOLA.prompt or f"{eq['name']}#", "comando": comando,
                "categoria": categoria, "permitido": permitido, "salida": salida, "motivo": motivo}

    # 0. Agente de IA suspendido
    if actor == "agente_ia" and agente_suspendido(db):
        return responder("bloqueado", motivo=MOTIVO_SUSPENSION)
    vendor = eq["vendor"]
    if vendor not in PERMITIDOS_REAL:
        return responder("no_permitido", motivo="La consola real solo está disponible para Cisco, Fortinet y Huawei.")

    # 1. Caracteres prohibidos
    if CARACTERES_PROHIBIDOS.search(comando_original):
        return responder("invalido", motivo="Caracteres no permitidos (; & ` $ < > \\ ||): "
                                            "no se puede encadenar ni redirigir comandos.")
    texto = comando.lower()

    # 2. Filtro "| include <palabra>" (se aplica en el NOC, no en el equipo)
    filtro = None
    if "|" in texto:
        m = PATRON_FILTRO.fullmatch(texto)
        if not m:
            return responder("invalido", motivo="Solo se permite un filtro de la forma: | include <palabra>")
        texto, filtro = m.group(1).strip(), m.group(2)

    # 3. Lista bloqueada
    for patron, _ejemplos, motivo in BLOQUEADOS:
        if re.match(patron, texto):
            return responder("bloqueado", motivo=motivo)

    # 4. Lista permitida (con abreviaturas)
    alias = ALIAS.get(vendor, {})
    canonico = " ".join(alias.get(t, t) for t in texto.split())
    if canonico in NEGADOS_REAL:
        return responder("bloqueado", motivo=NEGADOS_REAL[canonico])
    if canonico == "help":
        return responder("permitido", salida=ayuda(vendor))
    if canonico not in PERMITIDOS_REAL[vendor]:
        return responder("no_permitido",
                         motivo=f"'{comando}' no está en la lista de comandos permitidos del equipo real. "
                                "Escriba 'help' para verlos.")

    # Estado del equipo antes de enviar
    if CONSOLA.login_requerido:
        return responder("no_permitido",
                         motivo="El equipo está pidiendo usuario o contraseña. El NOC no guarda credenciales: "
                                "inicie sesión una vez con PuTTY, cierre PuTTY y vuelva a conectar aquí.")

    # 5. Enviar al equipo la versión CANÓNICA (nunca el texto del usuario)
    salida, completo = CONSOLA._enviar_y_esperar(canonico)
    if filtro:
        salida = "\n".join(l for l in salida.splitlines() if filtro in l.lower())
    if not completo:
        salida += "\n(El equipo no terminó de responder a tiempo: la salida puede estar incompleta)"
    if "% invalid input" in salida.lower() or "% incomplete" in salida.lower():
        salida += ("\n(Nota: el equipo no reconoció el comando. Si el prompt termina en '>', "
                   "algunos 'show' requieren modo privilegiado '#'.)")
    return responder("permitido", salida=salida or "(sin resultados)")

# --- FIN DEL ARCHIVO ---