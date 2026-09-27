"""
Parser (analizador) de mensajes Syslog.

Formatos soportados:
  - RFC 5424 (moderno): <PRI>1 2026-09-27T18:40:00Z HOST APP PROCID MSGID - MENSAJE
  - RFC 3164 (clásico): <PRI>Sep 27 18:40:00 HOST app: MENSAJE
  - Cisco IOS:          <PRI>34: *Sep 27 18:40:00.123: %LINK-3-UPDOWN: MENSAJE
  - Huawei VRP:         <PRI>Sep 27 2026 18:40:00 HOST %%01IFNET/3/LINK_STATE(l)[0]:MENSAJE
  - Fortinet FortiOS:   <PRI>date=2026-09-27 time=18:40:00 devname="HOST" ... msg="MENSAJE"

REGLA DE ORO: este módulo SOLO extrae datos del texto. Nunca ejecuta,
evalúa ni obedece el contenido del mensaje: los logs son datos NO confiables.
"""
import re
from datetime import datetime, timezone

# Niveles de severidad (0 = lo más grave, 7 = lo menos grave)
SEVERIDADES = {
    0: "Emergency", 1: "Alert", 2: "Critical", 3: "Error",
    4: "Warning", 5: "Notice", 6: "Informational", 7: "Debug",
}

# Facilities: qué parte del sistema generó el mensaje
FACILITIES = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon", 4: "auth", 5: "syslog",
    6: "lpr", 7: "news", 8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
    12: "ntp", 13: "security", 14: "console", 15: "solaris-cron",
    16: "local0", 17: "local1", 18: "local2", 19: "local3",
    20: "local4", 21: "local5", 22: "local6", 23: "local7",
}

LARGO_MAXIMO = 2048  # caracteres; un mensaje más largo se recorta

# --- Expresiones regulares: "moldes" de texto para reconocer cada formato ---
RE_PRI = re.compile(r"^<(\d{1,3})>")
RE_RFC5424 = re.compile(r"^1 (\S+) (\S+) (\S+) (\S+) (\S+) (-|(?:\[[^\]]*\])+) ?(.*)$", re.S)
RE_CISCO = re.compile(
    r"^(?:\d+: )?[*.]?"                                              # secuencia y marca '*'
    r"([A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2})(?:\.\d+)?(?: [A-Z]{2,5})?: "  # fecha
    r"%([A-Z0-9_]+)-(\d)-([A-Z0-9_]+): ?(.*)$", re.S)                # %FACILITY-SEV-MNEMONICO
RE_HUAWEI = re.compile(
    r"^([A-Z][a-z]{2} +\d{1,2} \d{4} \d{2}:\d{2}:\d{2})(?:[+-]\d{2}:\d{2})? (\S+) "
    r"%%\d*([A-Z0-9_]+)/(\d)/([A-Z0-9_]+)(?:\([^)]*\))?(?:\[\d+\])?: ?(.*)$", re.S)
RE_RFC3164 = re.compile(
    r"^([A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}) (\S+) ([^:\[\s]+)(?:\[\d+\])?: ?(.*)$", re.S)
RE_CLAVE_VALOR = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')  # formato Fortinet: clave=valor


def limpiar(texto: str) -> str:
    """Quita caracteres de control (saltos de línea, etc.) y recorta el largo.
    Evita que un atacante 'falsifique' líneas extra dentro de un solo log."""
    texto = "".join(c for c in texto if c == "\t" or c.isprintable())
    return texto[:LARGO_MAXIMO]


def _fecha(texto, formato):
    """Convierte texto a fecha UTC. Si no se puede, devuelve None (nunca falla)."""
    try:
        return datetime.strptime(" ".join(texto.split()), formato).replace(tzinfo=timezone.utc)
    except (ValueError, TypeError, AttributeError):
        return None


def _fecha_iso(texto):
    """Fecha en formato ISO (RFC 5424), ej. 2026-09-27T18:40:00Z."""
    if not texto or texto == "-":
        return None
    try:
        fecha = datetime.fromisoformat(texto.replace("Z", "+00:00"))
        return fecha.astimezone(timezone.utc) if fecha.tzinfo else fecha.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _valor(texto):
    """En RFC 5424 un guion '-' significa 'sin valor'."""
    return None if texto == "-" else texto


def parsear(raw: str) -> dict:
    """Analiza un mensaje Syslog y devuelve sus partes. Nunca lanza excepción."""
    texto = limpiar(raw.strip())

    # Valores por defecto: si no hay PRI se asume 13 (user.notice), según el RFC 3164
    r = {"formato": "desconocido", "pri_valido": False, "facility": 1, "severity": 5,
         "hostname": None, "app_name": None, "event_time": None, "message": texto}

    # 1) PRI: PRI = facility * 8 + severidad  ->  facility = PRI // 8, severidad = PRI % 8
    m = RE_PRI.match(texto)
    if m and int(m.group(1)) <= 191:  # 191 = 23 * 8 + 7, el valor máximo posible
        pri = int(m.group(1))
        r.update(pri_valido=True, facility=pri // 8, severity=pri % 8)
        cuerpo = texto[m.end():]
    else:
        cuerpo = texto

    anio = datetime.now(timezone.utc).year  # RFC 3164 y Cisco no incluyen el año

    # 2) Reconocer el formato y extraer sus partes
    if (g := RE_RFC5424.match(cuerpo)):
        fecha, host, app, _proc, _msgid, _sd, msg = g.groups()
        r.update(formato="RFC 5424", event_time=_fecha_iso(fecha),
                 hostname=_valor(host), app_name=_valor(app), message=msg)

    elif (g := RE_CISCO.match(cuerpo)):
        fecha, fac, sev, mnem, msg = g.groups()
        r.update(formato="Cisco IOS", event_time=_fecha(f"{anio} {fecha}", "%Y %b %d %H:%M:%S"),
                 app_name=f"{fac}-{sev}-{mnem}", message=msg)
        if not r["pri_valido"]:
            r["severity"] = int(sev)  # Cisco también trae la severidad en el texto

    elif (g := RE_HUAWEI.match(cuerpo)):
        fecha, host, modulo, sev, mnem, msg = g.groups()
        r.update(formato="Huawei VRP", event_time=_fecha(fecha, "%b %d %Y %H:%M:%S"),
                 hostname=host, app_name=f"{modulo}/{sev}/{mnem}", message=msg)
        if not r["pri_valido"]:
            r["severity"] = int(sev)

    elif "devname=" in cuerpo:
        campos = {k: (a if a else b) for k, a, b in RE_CLAVE_VALOR.findall(cuerpo)}
        r.update(formato="Fortinet FortiOS",
                 event_time=_fecha(f"{campos.get('date', '')} {campos.get('time', '')}",
                                   "%Y-%m-%d %H:%M:%S"),
                 hostname=campos.get("devname"),
                 app_name=campos.get("subtype") or campos.get("type"),
                 message=campos.get("msg") or campos.get("logdesc") or cuerpo)

    elif (g := RE_RFC3164.match(cuerpo)):
        fecha, host, app, msg = g.groups()
        r.update(formato="RFC 3164", event_time=_fecha(f"{anio} {fecha}", "%Y %b %d %H:%M:%S"),
                 hostname=host, app_name=app, message=msg)

    else:
        r["message"] = cuerpo  # formato no reconocido: se guarda el texto tal cual

    r["message"] = r["message"].strip()
    return r
