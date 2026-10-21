"""
Consola SIMULADA de solo lectura (tipo PuTTY).

Política de comandos, evaluada en este orden:
  0. Agente de IA suspendido -> se rechaza todo (política de IA, Fase 6).
  1. Caracteres prohibidos   -> no se permite encadenar ni redirigir (; & ` $ < > \\ ||).
  2. Filtro                  -> solo se acepta "| include <palabra>".
  3. Lista BLOQUEADA         -> comandos peligrosos conocidos, con su explicación.
  4. Lista PERMITIDA         -> solo estos comandos responden.
  5. Todo lo demás           -> se niega ("denegar por defecto").

Cada intento, permitido o no, queda en la auditoría con su actor
(operador humano o agente de IA). Si el agente de IA queda suspendido,
se envía una notificación (Fase 8).

NUNCA se conecta a un equipo real: las respuestas se construyen con los datos
simulados de la base de datos.

Este módulo también lo reutiliza la consola serial real (consola_serial.py),
que importa ALIAS, BLOQUEADOS, CARACTERES_PROHIBIDOS y PATRON_FILTRO para
aplicar exactamente la misma política.
"""
# ---------------------------------------------------------------------------
# Importaciones
# ---------------------------------------------------------------------------
import re
from datetime import datetime, timezone
from typing import Callable, Optional

from sqlalchemy.orm import Session

from .config_generator import generar
from .models import AuditLog, Device, SyslogEvent
from .notificaciones import encolar
from .politica_ia import (
    MAX_BLOQUEOS,
    MOTIVO_SUSPENSION,
    agente_suspendido,
    bloqueos_recientes_agente,
)
from .schemas import ConfigRequest
from .syslog_parser import SEVERIDADES

# ---------------------------------------------------------------------------
# Constantes generales
# ---------------------------------------------------------------------------
# Direcciones de documentación (RFC 5737): nunca apuntan a equipos reales.
SERVIDOR_NOC_SIM = "192.0.2.100"   # servidor NOC simulado
NTP_SIM = "192.0.2.123"            # servidor NTP simulado

# Valores que se usan para identificar al actor en la auditoría.
ACTOR_IA = "agente_ia"
ACTOR_OPERADOR = "operador_local"

# Límites de longitud para no guardar textos enormes en la auditoría
# ni en las notificaciones.
MAX_COMANDO_AUDITORIA = 120
MAX_DETALLE_AUDITORIA = 300
MAX_COMANDO_NOTIFICACION = 80

# Cantidad de eventos que muestra "show logging" / "display logbuffer".
MAX_EVENTOS_LOG = 15

# Marcas soportadas por la consola simulada.
MARCAS_SOPORTADAS = ("Cisco", "Fortinet", "Huawei")

# Texto que se agrega a las salidas para dejar claro que no son de un equipo real.
AVISO_SIMULADO = "*** EQUIPO SIMULADO: salida generada por el NOC ***"

# ---------------------------------------------------------------------------
# Reglas de la política de comandos
# ---------------------------------------------------------------------------
# Caracteres que permitirían encadenar o redirigir comandos:
# ; & ` $ < > \ salto de línea, retorno de carro y el operador ||
CARACTERES_PROHIBIDOS = re.compile(r"[;&`$<>\\\n\r]|\|\|")

# Único filtro aceptado: "<comando> | include <palabra>" (también "inc" o "i").
#   grupo 1 -> el comando
#   grupo 2 -> la palabra que se busca en la salida
PATRON_FILTRO = re.compile(r"(.+?)\s*\|\s*(?:include|inc|i)\s+([\w./:-]+)")

# Comandos peligrosos conocidos: (patrón, ejemplos, motivo).
# No son la barrera de seguridad (esa es "denegar por defecto"): sirven para
# EXPLICAR al usuario por qué su comando se rechaza.
BLOQUEADOS: list[tuple[str, str, str]] = [
    (r"^(conf|config|configure)\b",
     "configure terminal, conf t, config system",
     "Entrar a modo configuración está prohibido: la consola es de solo lectura."),
    (r"^system-view\b",
     "system-view",
     "system-view abre el modo configuración de Huawei: prohibido en solo lectura."),
    (r"^(write|wr|copy|save)\b",
     "write memory, copy run start, save",
     "Guardar o copiar configuraciones modifica el equipo."),
    (r"^(erase|delete|del|format|rmdir)\b",
     "write erase, erase startup-config, delete flash:",
     "Comando destructivo: borraría archivos o la configuración."),
    (r"^(reload|reboot|reset|restart)\b",
     "reload, reboot",
     "Reiniciar el equipo cortaría el servicio de la red."),
    (r"^execute\b",
     "execute reboot, execute factoryreset",
     "En FortiOS, 'execute' realiza acciones: reinicio, restauración de fábrica o respaldos."),
    (r"^(clear|purge)\b",
     "clear logging, clear counters",
     "Borraría logs o contadores: sería destruir evidencia."),
    (r"^(debug|undebug|diagnose|diag)\b",
     "debug all, diagnose debug",
     "La depuración puede saturar la CPU del equipo."),
    (r"^(shutdown|no|undo)\b",
     "shutdown, no logging, undo info-center",
     "Apagar interfaces o negar comandos modifica la configuración."),
    (r"^(set|unset|edit|end|next|append)\b",
     "set, edit, end",
     "Comandos de edición de FortiOS: prohibidos en solo lectura."),
    (r"^(ssh|telnet|connect)\b",
     "ssh, telnet",
     "Saltar desde la consola a otro equipo no está permitido."),
    (r"^(enable|username|password|secret|crypto)\b",
     "enable, username admin",
     "Cambiar privilegios o credenciales no está permitido."),
]

# Abreviaturas comunes que usan los administradores, por marca.
# Se expanden palabra por palabra antes de buscar en la lista permitida.
ALIAS: dict[str, dict[str, str]] = {
    "Cisco": {
        "sh": "show", "run": "running-config", "log": "logging", "ver": "version",
        "int": "interface", "br": "brief", "clo": "clock", "?": "help",
    },
    "Huawei": {
        "dis": "display", "disp": "display", "cur": "current-configuration",
        "ver": "version", "int": "interface", "br": "brief", "clo": "clock", "?": "help",
    },
    "Fortinet": {
        "?": "help",
    },
}

# Formato del prompt de cada marca; {n} se reemplaza por el nombre del equipo.
PROMPTS: dict[str, str] = {
    "Cisco": "{n}#",
    "Fortinet": "{n} #",
    "Huawei": "<{n}>",
}
PROMPT_POR_DEFECTO = "{n}>"


# ---------------------------------------------------------------------------
# Respuestas simuladas
# Todas reciben (db, eq) para tener la misma firma, aunque no todas usen db.
# ---------------------------------------------------------------------------
def _ahora() -> datetime:
    """Fecha y hora actual en UTC."""
    return datetime.now(timezone.utc)


def _version(db: Session, eq: Device) -> str:
    """Salida de 'show version' / 'get system status' / 'display version'."""
    if eq.vendor == "Cisco":
        return (
            f"Cisco IOS XE Software, Version {eq.os_version}\n"
            f"{eq.name} uptime is 12 days, 3 hours, 41 minutes\n"
            f"cisco {eq.model} processor\n"
            f"Processor board ID SIM-{eq.id:04d}\n"
            f"{AVISO_SIMULADO}"
        )
    if eq.vendor == "Fortinet":
        return (
            f"Version: {eq.model} {eq.os_version}\n"
            f"Serial-Number: FGT-SIM-{eq.id:04d}\n"
            f"Hostname: {eq.name}\n"
            "Operation Mode: NAT\n"
            f"System time: {_ahora():%a %b %d %H:%M:%S %Y}\n"
            f"{AVISO_SIMULADO}"
        )
    # Huawei
    return (
        "Huawei Versatile Routing Platform Software\n"
        f"VRP (R) software, {eq.os_version}\n"
        f"{eq.model} uptime is 12 days, 3 hours, 41 minutes\n"
        f"{AVISO_SIMULADO}"
    )


def _reloj(db: Session, eq: Device) -> str:
    """Salida de 'show clock' / 'display clock'."""
    t = _ahora()
    if eq.vendor == "Huawei":
        return f"{t:%Y-%m-%d %H:%M:%S} UTC\n{t:%A}\nTime Zone(UTC) : UTC"
    # Cisco: hora con milisegundos
    return f"{t:%H:%M:%S}.{t.microsecond // 1000:03d} UTC {t:%a %b %d %Y}"


def _logs(db: Session, eq: Device) -> str:
    """Salida de 'show logging' / 'display logbuffer' con los últimos eventos del equipo."""
    # Últimos eventos registrados en el NOC para este equipo (del más nuevo al más viejo)
    eventos = (
        db.query(SyslogEvent)
        .filter(SyslogEvent.device_id == eq.id)
        .order_by(SyslogEvent.id.desc())
        .limit(MAX_EVENTOS_LOG)
        .all()
    )

    # Encabezado con el estado del logging
    lineas = [
        "Syslog logging: enabled",
        "    Trap logging: level informational",
        f"    Logging to {SERVIDOR_NOC_SIM} (udp port 514)",
        "",
        f"Log Buffer (últimos {len(eventos)} eventos registrados en el NOC):",
    ]

    # Se muestran en orden cronológico (del más viejo al más nuevo), como en un equipo real
    for e in reversed(eventos):
        repeticiones = f" (x{e.repeat_count})" if e.repeat_count > 1 else ""
        lineas.append(
            f"{e.received_at:%b %d %H:%M:%S}: [{e.severity} {SEVERIDADES[e.severity]}] "
            f"{e.app_name or '-'}: {e.message}{repeticiones}"
        )
    return "\n".join(lineas)


def _configuracion(db: Session, eq: Device) -> str:
    """Configuración 'actual' del equipo: la arma el propio generador, sin sus comentarios."""
    # model_validate valida igual que ConfigRequest(...) y completa los valores
    # por defecto (puerto, severidad, zona horaria...) sin que el editor los exija.
    datos = generar(ConfigRequest.model_validate({
        "vendor": eq.vendor,
        "nombre_equipo": eq.name,
        "servidor_ip": SERVIDOR_NOC_SIM,
        "ntp_servidor": NTP_SIM,
    }))
    # Se quitan las líneas de comentario del generador ("! " en Cisco/Huawei, "# " en Fortinet)
    lineas = [
        linea for linea in datos["configuracion"].splitlines()
        if not linea.startswith(("! ", "# "))
    ]
    return f"! Configuración simulada de {eq.name}\n" + "\n".join(lineas)


def _interfaces(db: Session, eq: Device) -> str:
    """Resumen de interfaces con la IP de gestión del equipo."""
    if eq.vendor == "Fortinet":
        return (
            f"== [ port1 ]\nname: port1   mode: static   ip: {eq.ip_address} 255.255.255.0   status: up\n"
            "== [ port2 ]\nname: port2   mode: static   ip: 0.0.0.0 0.0.0.0   status: down"
        )
    if eq.vendor == "Huawei":
        return (
            "Interface                    IP Address/Mask      Physical   Protocol\n"
            f"LoopBack0                    {eq.ip_address}/32     up         up(s)\n"
            "GigabitEthernet0/0/1         unassigned           up         up\n"
            "GigabitEthernet0/0/2         unassigned           down       down"
        )
    # Cisco
    return (
        "Interface              IP-Address      OK? Method Status                Protocol\n"
        f"Loopback0              {eq.ip_address:<15} YES NVRAM  up                    up\n"
        "GigabitEthernet1/0/1   unassigned      YES unset  up                    up\n"
        "GigabitEthernet1/0/2   unassigned      YES unset  down                  down"
    )


def _ntp(db: Session, eq: Device) -> str:
    """Salida de 'show ntp status'."""
    return f"Clock is synchronized, stratum 3, reference is {NTP_SIM} (sim)"


def _syslog_estado(db: Session, eq: Device) -> str:
    """Estado del envío de Syslog hacia el servidor NOC."""
    if eq.vendor == "Fortinet":
        return (
            f"status              : enable\n"
            f"server              : {SERVIDOR_NOC_SIM}\n"
            "mode                : udp\n"
            "port                : 514\n"
            "facility            : local7\n"
            "format              : default"
        )
    # Huawei ('display info-center')
    return (
        "Information Center:enabled\n"
        "Log host:\n"
        f"    {SERVIDOR_NOC_SIM}, channel number 2, channel name loghost,\n"
        "    language english, host facility local7, port 514, transport udp"
    )


def _ayuda(db: Session, eq: Device) -> str:
    """Lista los comandos permitidos para la marca del equipo."""
    permitidos = "\n".join(f"  - {c}" for c in sorted(PERMITIDOS[eq.vendor]))
    return (
        f"Comandos permitidos en {eq.vendor} (solo lectura):\n{permitidos}\n\n"
        "Filtro permitido:  <comando> | include <palabra>\n\n"
        "Ejemplos de comandos bloqueados: configure terminal, reload, write erase,\n"
        "execute factoryreset, system-view, debug all, clear logging"
    )


# Tipo de las funciones que generan una respuesta simulada.
Respuesta = Callable[[Session, Device], str]

# Lista PERMITIDA por marca: comando completo (ya sin abreviaturas) -> función que responde.
PERMITIDOS: dict[str, dict[str, Respuesta]] = {
    "Cisco": {
        "show version": _version,
        "show clock": _reloj,
        "show logging": _logs,
        "show running-config": _configuracion,
        "show ip interface brief": _interfaces,
        "show ntp status": _ntp,
        "help": _ayuda,
    },
    "Fortinet": {
        "get system status": _version,
        "get log syslogd setting": _syslog_estado,
        "show log syslogd setting": _configuracion,
        "get system interface": _interfaces,
        "help": _ayuda,
    },
    "Huawei": {
        "display version": _version,
        "display clock": _reloj,
        "display logbuffer": _logs,
        "display info-center": _syslog_estado,
        "display current-configuration": _configuracion,
        "display ip interface brief": _interfaces,
        "help": _ayuda,
    },
}


# ---------------------------------------------------------------------------
# Ejecución con política y auditoría
# ---------------------------------------------------------------------------
def _auditar(db: Session, eq: Device, comando: str, actor: str,
             permitido: bool, motivo: Optional[str]) -> None:
    """Registra el intento en la auditoría (permitido o rechazado)."""
    detalle = f"{eq.name}> {comando[:MAX_COMANDO_AUDITORIA]}"
    if not permitido:
        detalle += f" | RECHAZADO: {motivo}"

    db.add(AuditLog(
        # Cualquier actor que no sea el agente de IA se registra como operador local
        actor=ACTOR_IA if actor == ACTOR_IA else ACTOR_OPERADOR,
        action="CONSOLE_CMD" if permitido else "CONSOLE_BLOCKED",
        entity_type="devices",
        entity_id=eq.id,
        details=detalle[:MAX_DETALLE_AUDITORIA],
    ))
    db.commit()


def _avisar_si_se_suspende(db: Session, eq: Device, comando: str) -> None:
    """Fase 8: notifica en el momento exacto en que el agente de IA queda suspendido."""
    if bloqueos_recientes_agente(db) != MAX_BLOQUEOS:
        return
    encolar({
        "clave": "agente_suspendido",
        "tipo": "agente_suspendido",
        "severidad": 1,
        "siempre": True,
        "titulo": "Agente de IA SUSPENDIDO",
        "detalle": (
            f"Acumuló {MAX_BLOQUEOS} comandos bloqueados. Último intento en "
            f"{eq.name}: {comando[:MAX_COMANDO_NOTIFICACION]}. Requiere revisión humana."
        ),
    })


def ejecutar(db: Session, eq: Device, comando_original: str, actor: str) -> dict:
    """
    Aplica la política de comandos y devuelve la respuesta de la consola simulada.

    Parámetros:
        db: sesión de base de datos (para leer eventos y auditar).
        eq: equipo sobre el que se ejecuta el comando.
        comando_original: texto tal como lo escribió el usuario o el agente.
        actor: "agente_ia" para el agente; cualquier otro valor es un operador.

    Devuelve un diccionario con: prompt, comando, categoria
    ("permitido", "bloqueado", "no_permitido" o "invalido"), permitido,
    salida y motivo (este último solo cuando se rechaza).
    """
    # Normaliza los espacios: "show   version " -> "show version"
    comando = " ".join(comando_original.strip().split())
    prompt = PROMPTS.get(eq.vendor, PROMPT_POR_DEFECTO).format(n=eq.name)

    def responder(categoria: str, salida: str = "", motivo: Optional[str] = None) -> dict:
        """Audita el intento, avisa si corresponde y arma la respuesta."""
        permitido = categoria == "permitido"
        _auditar(db, eq, comando, actor, permitido, motivo)
        if actor == ACTOR_IA and not permitido:
            _avisar_si_se_suspende(db, eq, comando)
        return {
            "prompt": prompt,
            "comando": comando,
            "categoria": categoria,
            "permitido": permitido,
            "salida": salida,
            "motivo": motivo,
        }

    # 0. Política de IA: un agente suspendido no puede ejecutar nada
    if actor == ACTOR_IA and agente_suspendido(db):
        return responder("bloqueado", motivo=MOTIVO_SUSPENSION)

    # Solo hay respuestas simuladas para las marcas soportadas
    if eq.vendor not in PERMITIDOS:
        return responder(
            "no_permitido",
            motivo=f"La consola solo está disponible para {', '.join(MARCAS_SOPORTADAS[:-1])} "
                   f"y {MARCAS_SOPORTADAS[-1]}.",
        )

    # 1. Caracteres prohibidos (encadenar o redirigir comandos).
    #    Se revisa el texto ORIGINAL para no perder saltos de línea al normalizar.
    if CARACTERES_PROHIBIDOS.search(comando_original):
        return responder(
            "invalido",
            motivo="Caracteres no permitidos (; & ` $ < > \\ ||): "
                   "no se puede encadenar ni redirigir comandos.",
        )

    texto = comando.lower()

    # 2. Filtro "| include <palabra>": se separa el comando de la palabra a buscar
    filtro: Optional[str] = None
    if "|" in texto:
        coincidencia = PATRON_FILTRO.fullmatch(texto)
        if not coincidencia:
            return responder(
                "invalido",
                motivo="Solo se permite un filtro de la forma: | include <palabra>",
            )
        texto, filtro = coincidencia.group(1).strip(), coincidencia.group(2)

    # 3. Lista bloqueada: si coincide, se explica el motivo del rechazo
    for patron, _ejemplos, motivo in BLOQUEADOS:
        if re.match(patron, texto):
            return responder("bloqueado", motivo=motivo)

    # 4. Lista permitida: se expanden las abreviaturas palabra por palabra
    alias = ALIAS.get(eq.vendor, {})
    canonico = " ".join(alias.get(palabra, palabra) for palabra in texto.split())
    funcion = PERMITIDOS[eq.vendor].get(canonico)

    # 5. Denegar por defecto: lo que no está permitido explícitamente, se niega
    if funcion is None:
        return responder(
            "no_permitido",
            motivo=f"'{comando}' no está en la lista de comandos permitidos. "
                   "Escriba 'help' para verlos.",
        )

    # Comando permitido: se genera la salida y se aplica el filtro si lo hay
    salida = funcion(db, eq)
    if filtro:
        salida = "\n".join(linea for linea in salida.splitlines() if filtro in linea.lower())
    return responder("permitido", salida=salida)

# --- FIN DEL ARCHIVO ---
