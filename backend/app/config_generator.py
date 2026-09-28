"""
Generador de configuraciones Syslog COMENTADAS para:
  - Cisco IOS / IOS-XE
  - Fortinet FortiOS
  - Huawei VRP

SEGURIDAD: todos los parámetros llegan ya validados por el esquema ConfigRequest
(formatos estrictos). Así nadie puede "colar" comandos extra en la configuración
(inyección de configuración), por ejemplo escribiendo un salto de línea seguido
de 'reload' en el nombre de la interfaz.

AVISO: la sintaxis puede variar según la versión del sistema operativo de cada
equipo. Revise siempre con la documentación oficial antes de aplicar.
"""
import ipaddress

from .syslog_parser import SEVERIDADES

# Nombre de cada nivel de severidad (0 a 7) en el idioma de cada fabricante
NIVELES = {
    "Cisco": ["emergencies", "alerts", "critical", "errors",
              "warnings", "notifications", "informational", "debugging"],
    "Fortinet": ["emergency", "alert", "critical", "error",
                 "warning", "notification", "information", "debug"],
    "Huawei": ["emergencies", "alert", "critical", "error",
               "warning", "notification", "informational", "debugging"],
}

INTERFAZ_POR_DEFECTO = {"Cisco": "Loopback0", "Fortinet": "port1", "Huawei": "LoopBack0"}

VERIFICACION = {
    "Cisco": ["show logging", "show running-config | include logging", "show clock", "show ntp status"],
    "Fortinet": ["get log syslogd setting", "get system status"],
    "Huawei": ["display info-center", "display clock", "display current-configuration | include info-center"],
}

AVISO_VERSION = ("La sintaxis puede variar según la versión del sistema operativo. "
                 "Verifique con la documentación oficial del fabricante antes de aplicar.")


def _advertencias(p) -> list[str]:
    """Buenas prácticas: avisa sobre decisiones riesgosas."""
    avisos = []
    if not ipaddress.ip_address(p.servidor_ip).is_private:
        avisos.append("La IP del servidor NOC parece pública: los logs viajarían por internet sin cifrar.")
    if p.protocolo == "udp":
        avisos.append("UDP no garantiza la entrega ni cifra los mensajes. "
                      "En producción considere TCP con TLS (RFC 5425).")
    if p.severidad_minima == 7:
        avisos.append("El nivel 7 (Debug) genera muchísimo tráfico y puede saturar el NOC.")
    if p.severidad_minima <= 2:
        avisos.append(f"Con el nivel {p.severidad_minima} solo se enviarán eventos muy graves: "
                      "se perderán errores y advertencias.")
    if not p.ntp_servidor:
        avisos.append("Sin servidor NTP las fechas de los logs pueden ser incorrectas "
                      "(en Cisco aparece un '*' antes de la hora).")
    if p.puerto != 514:
        avisos.append(f"Puerto {p.puerto}: el receptor del NOC debe escuchar en ese mismo puerto.")
    avisos.append(AVISO_VERSION)
    return avisos


def _cisco(p, nombre, interfaz):
    nivel = NIVELES["Cisco"][p.severidad_minima]
    lineas = [
        "! =====================================================================",
        f"! Configuración Syslog para Cisco IOS / IOS-XE - equipo {nombre}",
        f"! Servidor NOC: {p.servidor_ip}  puerto {p.puerto}/{p.protocolo.upper()}",
        "! Generada por NOC Syslog Inteligente. Las líneas con '!' son comentarios.",
        "! =====================================================================",
        "configure terminal",
        "!",
        "! 1) Zona horaria y NTP: sin hora sincronizada los logs muestran '*'",
        f"clock timezone {p.zona_horaria} {p.desfase_horas} 0",
    ]
    if p.ntp_servidor:
        lineas.append(f"ntp server {p.ntp_servidor}")
    else:
        lineas.append("! (sin servidor NTP: configure uno para tener fechas confiables)")
    lineas += [
        "!",
        "! 2) Fecha con milisegundos y zona horaria en cada mensaje",
        "service timestamps log datetime msec localtime show-timezone",
        "service sequence-numbers",
        "!",
        "! 3) Incluir el nombre del equipo en cada mensaje",
        "logging origin-id hostname",
        "!",
        f"! 4) Enviar los logs al servidor del NOC por {p.protocolo.upper()}",
        f"logging host {p.servidor_ip} transport {p.protocolo} port {p.puerto}",
        "!",
        f"! 5) Nivel mínimo: {p.severidad_minima} ({SEVERIDADES[p.severidad_minima]}) "
        f"-> se envían los niveles 0 a {p.severidad_minima}",
        f"logging trap {nivel}",
        "!",
        f"! 6) Facility {p.facility} (la estándar de Cisco es local7)",
        f"logging facility {p.facility}",
        "!",
        "! 7) Interfaz de origen fija: el NOC reconoce al equipo por esta IP",
        f"logging source-interface {interfaz}",
        "!",
        "! 8) Copia local en memoria para diagnóstico",
        "logging buffered 64000 informational",
        "!",
        "end",
        "! 9) Guardar la configuración (solo después de verificar)",
        "write memory",
    ]
    return lineas


def _fortinet(p, nombre, interfaz):
    nivel = NIVELES["Fortinet"][p.severidad_minima]
    modo = "udp" if p.protocolo == "udp" else "reliable"
    lineas = [
        "# =====================================================================",
        f"# Configuración Syslog para Fortinet FortiOS - equipo {nombre}",
        f"# Servidor NOC: {p.servidor_ip}  puerto {p.puerto}/{p.protocolo.upper()}",
        "# Generada por NOC Syslog Inteligente. Las líneas con '#' son comentarios.",
        "# =====================================================================",
        "#",
    ]
    if p.ntp_servidor:
        lineas += [
            "# 1) Hora sincronizada con NTP",
            "config system ntp",
            "    set ntpsync enable",
            "    set type custom",
            "    config ntpserver",
            "        edit 1",
            f'            set server "{p.ntp_servidor}"',
            "        next",
            "    end",
            "end",
        ]
    else:
        lineas.append("# 1) (sin servidor NTP: configure uno para tener fechas confiables)")
    lineas += [
        "#",
        "# 2) Servidor Syslog del NOC",
    ]
    if modo == "reliable":
        lineas.append("#    'reliable' significa Syslog sobre TCP (RFC 6587)")
    lineas += [
        "config log syslogd setting",
        "    set status enable",
        f'    set server "{p.servidor_ip}"',
        f"    set mode {modo}",
        f"    set port {p.puerto}",
        f"    set facility {p.facility}",
        "    set format default",
        "    set interface-select-method specify",
        f'    set interface "{interfaz}"',
        "end",
        "#",
        f"# 3) Nivel mínimo: {p.severidad_minima} ({SEVERIDADES[p.severidad_minima]}) "
        f"-> se envían los niveles 0 a {p.severidad_minima}",
        "config log syslogd filter",
        f"    set severity {nivel}",
        "end",
    ]
    return lineas


def _huawei(p, nombre, interfaz):
    nivel = NIVELES["Huawei"][p.severidad_minima]
    signo = "minus" if p.desfase_horas < 0 else "add"
    lineas = [
        "# =====================================================================",
        f"# Configuración Syslog para Huawei VRP - equipo {nombre}",
        f"# Servidor NOC: {p.servidor_ip}  puerto {p.puerto}/{p.protocolo.upper()}",
        "# Generada por NOC Syslog Inteligente. Las líneas con '#' son comentarios.",
        "# =====================================================================",
        "system-view",
        "#",
        "# 1) Zona horaria y NTP",
        f"clock timezone {p.zona_horaria} {signo} {abs(p.desfase_horas):02d}:00:00",
    ]
    if p.ntp_servidor:
        lineas.append(f"ntp-service unicast-server {p.ntp_servidor}")
    else:
        lineas.append("# (sin servidor NTP: configure uno para tener fechas confiables)")
    lineas += [
        "#",
        "# 2) Activar el centro de información (el sistema de logs de Huawei)",
        "info-center enable",
        "#",
        "# 3) Interfaz de origen fija: el NOC reconoce al equipo por esta IP",
        f"info-center loghost source {interfaz}",
        "#",
        f"# 4) Servidor Syslog del NOC ({p.protocolo.upper()}, puerto {p.puerto})",
        f"info-center loghost {p.servidor_ip} facility {p.facility} "
        f"port {p.puerto} transport {p.protocolo}",
        "#",
        f"# 5) Nivel mínimo: {p.severidad_minima} ({SEVERIDADES[p.severidad_minima]}) "
        f"-> se envían los niveles 0 a {p.severidad_minima}",
        f"info-center source default channel loghost log level {nivel}",
        "#",
        "# 6) Salir y guardar (solo después de verificar)",
        "return",
        "save",
    ]
    return lineas


CONSTRUCTORES = {"Cisco": _cisco, "Fortinet": _fortinet, "Huawei": _huawei}


def generar(p) -> dict:
    """Devuelve la configuración comentada, sus advertencias y cómo verificarla."""
    nombre = p.nombre_equipo or "EQUIPO-NOC"
    interfaz = p.interfaz_origen or INTERFAZ_POR_DEFECTO[p.vendor]
    lineas = CONSTRUCTORES[p.vendor](p, nombre, interfaz)
    return {
        "vendor": p.vendor,
        "configuracion": "\n".join(lineas),
        "advertencias": _advertencias(p),
        "verificacion": VERIFICACION[p.vendor],
    }

# --- FIN DEL ARCHIVO ---