"""
Cambios de configuración con APROBACIÓN HUMANA — Fase 11.

Flujo obligatorio (cada paso queda en la auditoría):

  PROPUESTA (humano o agente de IA)
     -> REVISIÓN por un aprobador HUMANO distinto de quien propuso
     -> RESPALDO del estado actual (comandos de solo lectura)
     -> EJECUCIÓN por la consola real (o simulada si el equipo es SIM)
     -> VERIFICACIÓN automática
     -> ROLLBACK si algo falla (automático) o si el aprobador lo pide

SEGURIDAD:
  - Nadie escribe comandos libres: solo se usan PLANTILLAS de un catálogo
    cerrado, y cada dato se valida (IP, interfaz, texto, nivel).
  - El NOC genera los comandos de configuración Y los de rollback ANTES de
    aprobar, para que el aprobador vea exactamente qué se va a enviar.
  - Los cambios quedan solo en la configuración en uso (running-config):
    el NOC NUNCA guarda en la memoria del equipo (write memory / save).
    Si algo sale mal, un reinicio del equipo también lo deshace.
"""
import ipaddress
import json
import re

from .consola_serial import CONSOLA
from .puertos import RE_INTERFAZ, extraer_interfaz, nombre_corto

NIVELES = {"errors": 3, "warnings": 4, "notifications": 5, "informational": 6}
RE_TEXTO = re.compile(r"^[A-Za-z0-9 _.\-]{1,60}$")   # descripciones: sin símbolos raros
RE_ERROR_EQUIPO = re.compile(r"%\s*(invalid|incomplete|ambiguous|unknown)|^\s*error:|unrecognized command",
                             re.IGNORECASE | re.MULTILINE)


class CambioInvalido(ValueError):
    """Los datos del cambio no pasaron la validación."""


# ---------------------------------------------------------------------------
# Validaciones de los parámetros
# ---------------------------------------------------------------------------
def _ip(valor) -> str:
    try:
        ip = ipaddress.IPv4Address(str(valor).strip())
    except ValueError:
        raise CambioInvalido("La IP del servidor no es válida (ej. 192.168.100.10)") from None
    if ip.is_multicast or ip.is_unspecified or ip.is_loopback:
        raise CambioInvalido("Esa IP no puede ser un servidor Syslog")
    return str(ip)


def _puerto_udp(valor) -> int:
    try:
        n = int(valor)
    except (TypeError, ValueError):
        raise CambioInvalido("El puerto UDP debe ser un número") from None
    if not 1 <= n <= 65535:
        raise CambioInvalido("El puerto UDP debe estar entre 1 y 65535")
    return n


def _interfaz(valor) -> str:
    texto = str(valor or "").strip()
    if not RE_INTERFAZ.fullmatch(texto):
        raise CambioInvalido("Interfaz no válida. Ejemplos: Fa0/1, Gi1/0/5, GigabitEthernet0/0/1")
    return extraer_interfaz(texto)


def _texto(valor) -> str:
    texto = str(valor or "").strip()
    if not RE_TEXTO.fullmatch(texto):
        raise CambioInvalido("La descripción solo admite letras, números, espacio, punto, guion y "
                             "guion bajo (máximo 60 caracteres)")
    return texto


# ---------------------------------------------------------------------------
# Catálogo de plantillas (Cisco IOS y Huawei VRP)
# Cada plantilla devuelve: comandos, rollback, respaldo, verificación y texto esperado.
# ---------------------------------------------------------------------------
def _syslog(vendor, p):
    ip, puerto = _ip(p.get("ip")), _puerto_udp(p.get("puerto", 5514))
    nivel = p.get("nivel", "informational")
    if nivel not in NIVELES:
        raise CambioInvalido(f"Nivel no válido. Use: {', '.join(NIVELES)}")
    if vendor == "Huawei":
        return {"comandos": [f"info-center loghost {ip}", "info-center enable"],
                "rollback": [f"undo info-center loghost {ip}"],
                "respaldo": ["display info-center"],
                "verificacion": "display info-center", "esperado": ip,
                "resumen": f"Enviar los logs al NOC {ip}"}
    return {"comandos": [f"logging host {ip} transport udp port {puerto}", f"logging trap {nivel}"],
            "rollback": [f"no logging host {ip}"],
            "respaldo": ["show logging"],
            "verificacion": "show logging", "esperado": ip,
            "resumen": f"Enviar los logs al NOC {ip}:{puerto} (nivel {nivel})"}


def _descripcion(vendor, p):
    interfaz, texto = _interfaz(p.get("interfaz")), _texto(p.get("descripcion"))
    quitar = "undo description" if vendor == "Huawei" else "no description"
    if vendor == "Huawei":
        respaldo, verificacion = ["display interface description"], "display interface description"
    else:
        respaldo, verificacion = ["show interfaces status"], "show interfaces status"
    return {"comandos": [f"interface {interfaz}", f"description {texto}"],
            "rollback": [f"interface {interfaz}", quitar],
            "respaldo": respaldo, "verificacion": verificacion, "esperado": texto[:15],
            "resumen": f"Describir {nombre_corto(interfaz)} como '{texto}'"}


def _estado_puerto(vendor, p):
    interfaz = _interfaz(p.get("interfaz"))
    accion = p.get("accion")
    if accion not in ("apagar", "encender"):
        raise CambioInvalido("Acción no válida: use 'apagar' o 'encender'")
    encender = "undo shutdown" if vendor == "Huawei" else "no shutdown"
    on, off = (encender, "shutdown")
    comando, inverso = (off, on) if accion == "apagar" else (on, off)
    if vendor == "Huawei":
        respaldo, verificacion = ["display interface brief"], "display interface brief"
        esperado = "*down" if accion == "apagar" else ""
    else:
        respaldo, verificacion = ["show interfaces status"], "show interfaces status"
        esperado = "disabled" if accion == "apagar" else ""
    return {"comandos": [f"interface {interfaz}", comando],
            "rollback": [f"interface {interfaz}", inverso],
            "respaldo": respaldo, "verificacion": verificacion, "esperado": esperado,
            "linea_verificar": nombre_corto(interfaz) if vendor != "Huawei" else interfaz,
            "resumen": f"{accion.capitalize()} el puerto {nombre_corto(interfaz)}"}


PLANTILLAS = {
    "syslog_servidor": {"nombre": "Configurar envío de logs al NOC", "funcion": _syslog,
                        "parametros": ["ip", "puerto", "nivel"]},
    "descripcion_puerto": {"nombre": "Poner descripción a un puerto", "funcion": _descripcion,
                           "parametros": ["interfaz", "descripcion"]},
    "estado_puerto": {"nombre": "Apagar o encender un puerto", "funcion": _estado_puerto,
                      "parametros": ["interfaz", "accion"]},
}


def generar(plantilla: str, vendor: str, parametros: dict) -> dict:
    """Valida los datos y genera los comandos EXACTOS que se enviarían al equipo."""
    if plantilla not in PLANTILLAS:
        raise CambioInvalido("Plantilla desconocida: solo se permiten cambios del catálogo")
    if vendor not in ("Cisco", "Huawei"):
        raise CambioInvalido("Los cambios por consola están disponibles para Cisco y Huawei")
    datos = PLANTILLAS[plantilla]["funcion"](vendor, parametros or {})
    datos["parametros"] = {k: parametros.get(k) for k in PLANTILLAS[plantilla]["parametros"]
                           if parametros.get(k) not in (None, "")}
    return datos


def catalogo() -> list:
    return [{"clave": k, "nombre": v["nombre"], "parametros": v["parametros"]}
            for k, v in PLANTILLAS.items()]


# ---------------------------------------------------------------------------
# Ejecución por la consola real
# ---------------------------------------------------------------------------
ENTRAR = {"Cisco": "configure terminal", "Huawei": "system-view"}
SALIR = {"Cisco": "end", "Huawei": "return"}


def consola_lista_para(device_id: int):
    """Devuelve un motivo (texto) si la consola real NO está lista para ese equipo; None si está lista."""
    if not CONSOLA.conectado or not CONSOLA.equipo or CONSOLA.equipo["id"] != device_id:
        return "Conecte primero este equipo en la pestaña Consola (modo Equipo REAL)."
    if getattr(CONSOLA, "incompatible", None):  # v1.0.0
        return CONSOLA.incompatible
    if CONSOLA.login_requerido:
        return "El equipo está pidiendo usuario o contraseña."
    if CONSOLA.prompt and CONSOLA.prompt.rstrip().endswith(">") and not CONSOLA.prompt.startswith("<"):
        return "El equipo está en modo usuario (>). Se necesita modo privilegiado (#) para configurar."
    return None


def leer(comandos: list) -> str:
    """Ejecuta comandos de SOLO LECTURA (respaldo y verificación)."""
    partes = []
    for c in comandos:
        salida, _ = CONSOLA._enviar_y_esperar(c)
        partes.append(f"### {c}\n{salida}")
    return "\n\n".join(partes)


def aplicar(vendor: str, lineas: list) -> tuple:
    """Entra al modo configuración, envía las líneas y sale. Devuelve (salida, hubo_error)."""
    registro, error = [], False
    for linea in [ENTRAR[vendor], *lineas]:
        salida, completo = CONSOLA._enviar_y_esperar(linea, 8)
        registro.append(f"{linea}\n{salida}".rstrip())
        if not completo or RE_ERROR_EQUIPO.search(salida):
            error = True
            break
    salida, _ = CONSOLA._enviar_y_esperar(SALIR[vendor], 8)  # siempre se sale del modo configuración
    registro.append(f"{SALIR[vendor]}\n{salida}".rstrip())
    return "\n".join(registro), error


def verificar_salida(datos: dict, salida: str) -> bool:
    """¿La salida del comando de verificación muestra que el cambio quedó aplicado?"""
    esperado = datos.get("esperado", "")
    linea_clave = datos.get("linea_verificar")
    if linea_clave:  # apagar/encender: se revisa SOLO la línea de ese puerto
        lineas = [l for l in salida.splitlines()
                  if l.split() and l.split()[0].lower() == linea_clave.lower()]  # Fa0/1 ≠ Fa0/10
        if not lineas:
            return False
        if esperado:
            return esperado in lineas[0]
        return "disabled" not in lineas[0] and "*down" not in lineas[0]
    return bool(esperado) and esperado.lower() in salida.lower()


def a_texto(lista: list) -> str:
    return "\n".join(lista)


def a_json(d: dict) -> str:
    return json.dumps(d, ensure_ascii=False)

# --- FIN DEL ARCHIVO ---