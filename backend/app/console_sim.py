"""
Consola SIMULADA de solo lectura (tipo PuTTY).

Política de comandos, en este orden:
  0. Agente de IA suspendido -> se rechaza todo (política de IA, Fase 6).
  1. Caracteres prohibidos  -> no se permite encadenar ni redirigir (; & ` $ < > \\ ||).
  2. Filtro                 -> solo se acepta "| include <palabra>".
  3. Lista BLOQUEADA        -> comandos peligrosos conocidos, con su explicación.
  4. Lista PERMITIDA        -> solo estos comandos responden.
  5. Todo lo demás          -> se niega ("denegar por defecto").

Cada intento, permitido o no, queda en la auditoría con su actor
(operador humano o agente de IA).

NUNCA se conecta a un equipo real: las respuestas se construyen con los datos
simulados de la base de datos.
"""
import re
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from .config_generator import generar
from .models import AuditLog, Device, SyslogEvent
from .politica_ia import MOTIVO_SUSPENSION, agente_suspendido
from .schemas import ConfigRequest
from .syslog_parser import SEVERIDADES

SERVIDOR_NOC_SIM = "192.0.2.100"   # servidor NOC simulado (RFC 5737)
NTP_SIM = "192.0.2.123"

CARACTERES_PROHIBIDOS = re.compile(r"[;&`$<>\\\n\r]|\|\|")
PATRON_FILTRO = re.compile(r"(.+?)\s*\|\s*(?:include|inc|i)\s+([\w./:-]+)")

# (patrón, ejemplos, motivo). Sirven para EXPLICAR por qué se bloquean.
BLOQUEADOS = [
    (r"^(conf|config|configure)\b", "configure terminal, conf t, config system",
     "Entrar a modo configuración está prohibido: la consola es de solo lectura."),
    (r"^system-view\b", "system-view",
     "system-view abre el modo configuración de Huawei: prohibido en solo lectura."),
    (r"^(write|wr|copy|save)\b", "write memory, copy run start, save",
     "Guardar o copiar configuraciones modifica el equipo."),
    (r"^(erase|delete|del|format|rmdir)\b", "write erase, erase startup-config, delete flash:",
     "Comando destructivo: borraría archivos o la configuración."),
    (r"^(reload|reboot|reset|restart)\b", "reload, reboot",
     "Reiniciar el equipo cortaría el servicio de la red."),
    (r"^execute\b", "execute reboot, execute factoryreset",
     "En FortiOS, 'execute' realiza acciones: reinicio, restauración de fábrica o respaldos."),
    (r"^(clear|purge)\b", "clear logging, clear counters",
     "Borraría logs o contadores: sería destruir evidencia."),
    (r"^(debug|undebug|diagnose|diag)\b", "debug all, diagnose debug",
     "La depuración puede saturar la CPU del equipo."),
    (r"^(shutdown|no|undo)\b", "shutdown, no logging, undo info-center",
     "Apagar interfaces o negar comandos modifica la configuración."),
    (r"^(set|unset|edit|end|next|append)\b", "set, edit, end",
     "Comandos de edición de FortiOS: prohibidos en solo lectura."),
    (r"^(ssh|telnet|connect)\b", "ssh, telnet",
     "Saltar desde la consola a otro equipo no está permitido."),
    (r"^(enable|username|password|secret|crypto)\b", "enable, username admin",
     "Cambiar privilegios o credenciales no está permitido."),
]

# Abreviaturas comunes que usan los administradores
ALIAS = {
    "Cisco": {"sh": "show", "run": "running-config", "log": "logging", "ver": "version",
              "int": "interface", "br": "brief", "clo": "clock", "?": "help"},
    "Huawei": {"dis": "display", "disp": "display", "cur": "current-configuration",
               "ver": "version", "int": "interface", "br": "brief", "clo": "clock", "?": "help"},
    "Fortinet": {"?": "help"},
}

PROMPTS = {"Cisco": "{n}#", "Fortinet": "{n} #", "Huawei": "<{n}>"}


# ---------------------------------------------------------------------------
# Respuestas simuladas
# ---------------------------------------------------------------------------
def _ahora():
    return datetime.now(timezone.utc)


def _version(db, eq):
    if eq.vendor == "Cisco":
        return (f"Cisco IOS XE Software, Version {eq.os_version}\n"
                f"{eq.name} uptime is 12 days, 3 hours, 41 minutes\n"
                f"cisco {eq.model} processor\n"
                f"Processor board ID SIM-{eq.id:04d}\n"
                "*** EQUIPO SIMULADO: salida generada por el NOC ***")
    if eq.vendor == "Fortinet":
        return (f"Version: {eq.model} {eq.os_version}\n"
                f"Serial-Number: FGT-SIM-{eq.id:04d}\n"
                f"Hostname: {eq.name}\n"
                "Operation Mode: NAT\n"
                f"System time: {_ahora():%a %b %d %H:%M:%S %Y}\n"
                "*** EQUIPO SIMULADO: salida generada por el NOC ***")
    return (f"Huawei Versatile Routing Platform Software\n"
            f"VRP (R) software, {eq.os_version}\n"
            f"{eq.model} uptime is 12 days, 3 hours, 41 minutes\n"
            "*** EQUIPO SIMULADO: salida generada por el NOC ***")


def _reloj(db, eq):
    t = _ahora()
    if eq.vendor == "Huawei":
        return f"{t:%Y-%m-%d %H:%M:%S} UTC\n{t:%A}\nTime Zone(UTC) : UTC"
    return f"{t:%H:%M:%S}.{t.microsecond // 1000:03d} UTC {t:%a %b %d %Y}"


def _logs(db, eq):
    eventos = (db.query(SyslogEvent).filter(SyslogEvent.device_id == eq.id)
               .order_by(SyslogEvent.id.desc()).limit(15).all())
    lineas = ["Syslog logging: enabled",
              "    Trap logging: level informational",
              f"    Logging to {SERVIDOR_NOC_SIM} (udp port 514)",
              "",
              f"Log Buffer (últimos {len(eventos)} eventos registrados en el NOC):"]
    for e in reversed(eventos):
        repeticiones = f" (x{e.repeat_count})" if e.repeat_count > 1 else ""
        lineas.append(f"{e.received_at:%b %d %H:%M:%S}: [{e.severity} {SEVERIDADES[e.severity]}] "
                      f"{e.app_name or '-'}: {e.message}{repeticiones}")
    return "\n".join(lineas)


def _configuracion(db, eq):
    """Configuración 'actual' del equipo: la genera el propio generador (sin comentarios)."""
    datos = generar(ConfigRequest(vendor=eq.vendor, nombre_equipo=eq.name,
                                  servidor_ip=SERVIDOR_NOC_SIM, ntp_servidor=NTP_SIM))
    lineas = [l for l in datos["configuracion"].splitlines()
              if not l.startswith("! ") and not l.startswith("# ")]
    return f"! Configuración simulada de {eq.name}\n" + "\n".join(lineas)


def _interfaces(db, eq):
    if eq.vendor == "Fortinet":
        return (f"== [ port1 ]\nname: port1   mode: static   ip: {eq.ip_address} 255.255.255.0   status: up\n"
                "== [ port2 ]\nname: port2   mode: static   ip: 0.0.0.0 0.0.0.0   status: down")
    if eq.vendor == "Huawei":
        return ("Interface                    IP Address/Mask      Physical   Protocol\n"
                f"LoopBack0                    {eq.ip_address}/32     up         up(s)\n"
                "GigabitEthernet0/0/1         unassigned           up         up\n"
                "GigabitEthernet0/0/2         unassigned           down       down")
    return ("Interface              IP-Address      OK? Method Status                Protocol\n"
            f"Loopback0              {eq.ip_address:<15} YES NVRAM  up                    up\n"
            "GigabitEthernet1/0/1   unassigned      YES unset  up                    up\n"
            "GigabitEthernet1/0/2   unassigned      YES unset  down                  down")


def _ntp(db, eq):
    return f"Clock is synchronized, stratum 3, reference is {NTP_SIM} (sim)"


def _syslog_estado(db, eq):
    if eq.vendor == "Fortinet":
        return (f"status              : enable\nserver              : {SERVIDOR_NOC_SIM}\n"
                "mode                : udp\nport                : 514\n"
                "facility            : local7\nformat              : default")
    return ("Information Center:enabled\nLog host:\n"
            f"    {SERVIDOR_NOC_SIM}, channel number 2, channel name loghost,\n"
            "    language english, host facility local7, port 514, transport udp")


def _ayuda(db, eq):
    permitidos = "\n".join(f"  - {c}" for c in sorted(PERMITIDOS[eq.vendor]))
    return (f"Comandos permitidos en {eq.vendor} (solo lectura):\n{permitidos}\n\n"
            "Filtro permitido:  <comando> | include <palabra>\n\n"
            "Ejemplos de comandos bloqueados: configure terminal, reload, write erase,\n"
            "execute factoryreset, system-view, debug all, clear logging")


PERMITIDOS = {
    "Cisco": {"show version": _version, "show clock": _reloj, "show logging": _logs,
              "show running-config": _configuracion, "show ip interface brief": _interfaces,
              "show ntp status": _ntp, "help": _ayuda},
    "Fortinet": {"get system status": _version, "get log syslogd setting": _syslog_estado,
                 "show log syslogd setting": _configuracion, "get system interface": _interfaces,
                 "help": _ayuda},
    "Huawei": {"display version": _version, "display clock": _reloj, "display logbuffer": _logs,
               "display info-center": _syslog_estado,
               "display current-configuration": _configuracion,
               "display ip interface brief": _interfaces, "help": _ayuda},
}


# ---------------------------------------------------------------------------
# Ejecución con política y auditoría
# ---------------------------------------------------------------------------
def _auditar(db: Session, eq: Device, comando: str, actor: str, permitido: bool, motivo):
    detalle = f"{eq.name}> {comando[:120]}"
    if not permitido:
        detalle += f" | RECHAZADO: {motivo}"
    db.add(AuditLog(actor="agente_ia" if actor == "agente_ia" else "operador_local",
                    action="CONSOLE_CMD" if permitido else "CONSOLE_BLOCKED",
                    entity_type="devices", entity_id=eq.id, details=detalle[:300]))
    db.commit()


def ejecutar(db: Session, eq: Device, comando_original: str, actor: str) -> dict:
    """Aplica la política y devuelve la respuesta de la consola simulada."""
    comando = " ".join(comando_original.strip().split())  # normaliza los espacios
    prompt = PROMPTS.get(eq.vendor, "{n}>").format(n=eq.name)

    def responder(categoria, salida="", motivo=None):
        permitido = categoria == "permitido"
        _auditar(db, eq, comando, actor, permitido, motivo)
        return {"prompt": prompt, "comando": comando, "categoria": categoria,
                "permitido": permitido, "salida": salida, "motivo": motivo}

    # 0. Política de IA: un agente suspendido no puede ejecutar nada
    if actor == "agente_ia" and agente_suspendido(db):
        return responder("bloqueado", motivo=MOTIVO_SUSPENSION)

    if eq.vendor not in PERMITIDOS:
        return responder("no_permitido", motivo="La consola solo está disponible para Cisco, Fortinet y Huawei.")

    # 1. Caracteres prohibidos (encadenar o redirigir comandos)
    if CARACTERES_PROHIBIDOS.search(comando_original):
        return responder("invalido", motivo="Caracteres no permitidos (; & ` $ < > \\ ||): "
                                            "no se puede encadenar ni redirigir comandos.")

    texto = comando.lower()

    # 2. Filtro "| include <palabra>"
    filtro = None
    if "|" in texto:
        m = PATRON_FILTRO.fullmatch(texto)
        if not m:
            return responder("invalido", motivo="Solo se permite un filtro de la forma: | include <palabra>")
        texto, filtro = m.group(1).strip(), m.group(2)

    # 3. Lista bloqueada (explica el motivo)
    for patron, _ejemplos, motivo in BLOQUEADOS:
        if re.match(patron, texto):
            return responder("bloqueado", motivo=motivo)

    # 4. Lista permitida (con abreviaturas)
    alias = ALIAS.get(eq.vendor, {})
    canonico = " ".join(alias.get(t, t) for t in texto.split())
    funcion = PERMITIDOS[eq.vendor].get(canonico)

    # 5. Denegar por defecto
    if funcion is None:
        return responder("no_permitido",
                         motivo=f"'{comando}' no está en la lista de comandos permitidos. "
                                "Escriba 'help' para verlos.")

    salida = funcion(db, eq)
    if filtro:
        salida = "\n".join(l for l in salida.splitlines() if filtro in l.lower())
    return responder("permitido", salida=salida)

# --- FIN DEL ARCHIVO ---
