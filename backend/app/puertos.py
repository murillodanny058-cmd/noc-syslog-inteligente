"""
Puertos e interfaces de los equipos — Fase 10.

Responde a la pregunta del NOC: "¿en qué PUERTO pasó este evento y qué hay
conectado ahí?".

  1. extraer_interfaz(): lee el mensaje del log y encuentra la interfaz
     (ej. "Interface GigabitEthernet1/0/5" -> GigabitEthernet1/0/5).
  2. Tabla de puertos por equipo: estado, VLAN, descripción, vecino conectado
     (CDP/LLDP) y direcciones MAC aprendidas.
       - Equipos SIMULADOS: los puertos se generan de forma simulada.
       - Equipos REALES: se leen por la consola real con comandos de solo
         lectura (show interfaces status, show cdp neighbors, show mac address-table).
  3. actualizar_por_evento(): cuando llega un log "changed state to down/up",
     el estado del puerto se actualiza solo.

REGLA DE ORO: todo lo que viene del equipo o del log es DATO NO CONFIABLE.
Solo se extrae texto con expresiones regulares; nunca se ejecuta nada.
"""
import random
import re
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from .models import Device, Port

# ---------------------------------------------------------------------------
# 1. Reconocer interfaces en el texto
# ---------------------------------------------------------------------------
# Nombre largo -> abreviatura (la que usan "show interfaces status" y la gente)
TIPOS = [
    ("TwentyFiveGigE", "Twe"), ("TenGigabitEthernet", "Te"), ("GigabitEthernet", "Gi"),
    ("FastEthernet", "Fa"), ("Ethernet", "Eth"), ("Port-channel", "Po"),
    ("XGigabitEthernet", "XGE"), ("Eth-Trunk", "Eth-Trunk"), ("Vlanif", "Vlanif"),
    ("Vlan", "Vlan"), ("Loopback", "Lo"),
]
# Abreviatura -> nombre largo (incluye variantes comunes)
ABREVIATURAS = {
    "gi": "GigabitEthernet", "ge": "GigabitEthernet", "fa": "FastEthernet",
    "te": "TenGigabitEthernet", "xge": "XGigabitEthernet", "twe": "TwentyFiveGigE",
    "eth": "Ethernet", "et": "Ethernet", "po": "Port-channel", "lo": "Loopback",
    # Estas tres pueden llevar un espacio: "Gig 0/1" (así las muestra show cdp neighbors)
    "gig": "GigabitEthernet", "fas": "FastEthernet", "ten": "TenGigabitEthernet",
}
CON_ESPACIO = ("gig", "fas", "ten")
_LARGOS = "|".join(sorted((re.escape(l) for l, _ in TIPOS), key=len, reverse=True))
_CORTOS = "|".join(sorted((a for a in ABREVIATURAS if a not in CON_ESPACIO), key=len, reverse=True))
_NUM = r"\d+(?:/\d+){0,3}(?:\.\d+)?"
RE_INTERFAZ = re.compile(
    rf"\b(?:(?P<largo>{_LARGOS})(?P<n1>{_NUM})"            # GigabitEthernet1/0/5 (sin espacio)
    rf"|(?P<esp>{'|'.join(CON_ESPACIO)}) ?(?P<n2>{_NUM})"    # Gig 1/0/5
    rf"|(?P<corto>{_CORTOS})(?P<n3>{_NUM}))\b"             # Gi1/0/5, Fa0/1, Po1
    r"|\b(?P<forti>port\d{1,3}|wan\d|internal\d?|dmz)\b",  # Fortinet: port1, wan1
    re.IGNORECASE,
)


def _canonico(tipo: str) -> str:
    """Normaliza mayúsculas: 'gigabitethernet' -> 'GigabitEthernet'."""
    for largo, _ in TIPOS:
        if largo.lower() == tipo.lower():
            return largo
    return tipo


def extraer_interfaz(texto: str):
    """Devuelve la PRIMERA interfaz que aparece en el texto (nombre largo) o None."""
    if not texto:
        return None
    m = RE_INTERFAZ.search(texto)
    if not m:
        return None
    if m.group("forti"):
        return m.group("forti").lower()
    if m.group("largo"):
        return f"{_canonico(m.group('largo'))}{m.group('n1')}"
    if m.group("esp"):
        return f"{ABREVIATURAS[m.group('esp').lower()]}{m.group('n2')}"
    return f"{ABREVIATURAS[m.group('corto').lower()]}{m.group('n3')}"


def todas_las_interfaces(texto: str) -> set:
    """Todas las interfaces que menciona un texto (ej. un MAC flap menciona dos puertos)."""
    encontradas = set()
    for m in RE_INTERFAZ.finditer(texto or ""):
        encontradas.add(extraer_interfaz(m.group(0)))
    return encontradas


def nombre_corto(interfaz: str) -> str:
    """GigabitEthernet1/0/5 -> Gi1/0/5 (como lo muestra 'show interfaces status')."""
    for largo, corto in TIPOS:
        if interfaz.startswith(largo) and interfaz[len(largo):len(largo) + 1].isdigit():
            return corto + interfaz[len(largo):]
    return interfaz


def normalizar(nombre: str) -> str:
    """Cualquier forma ('Gi1/0/5', 'Gig 1/0/5', 'GigabitEthernet1/0/5') -> nombre largo."""
    return extraer_interfaz(nombre) or nombre.strip()


def clave_orden(interfaz: str):
    """Orden natural: Gi1/0/2 antes que Gi1/0/10."""
    return [int(t) if t.isdigit() else t.lower() for t in re.split(r"(\d+)", interfaz)]


# ---------------------------------------------------------------------------
# 2. Leer la salida de los comandos de solo lectura (Cisco y Huawei)
# ---------------------------------------------------------------------------
RE_ESTADO_CISCO = re.compile(
    r"^(?P<port>\S+)\s+(?P<desc>.*?)\s*(?P<estado>connected|notconnect|disabled|err-disabled|"
    r"inactive|monitoring|suspended|sfpAbsent)\s+(?P<vlan>\S+)\s+\S+\s+\S+(?:\s+(?P<tipo>.*))?$")
RE_MAC_CISCO = re.compile(
    r"^\s*(?P<vlan>\d+|All)\s+(?P<mac>[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+\S+\s+(?P<port>\S+)",
    re.IGNORECASE)
RE_MAC_HUAWEI = re.compile(
    r"^\s*(?P<mac>[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4})\s+(?P<vlan>\d+)\S*\s+(?:\S+\s+)?(?P<port>\S*\d+/\d+\S*)",
    re.IGNORECASE)
RE_BRIEF_HUAWEI = re.compile(
    r"^(?P<port>(?:XGigabitEthernet|GigabitEthernet|Ethernet|Eth-Trunk)\S+)\s+(?P<fis>\*?\^?(?:up|down)\S*)\s+"
    r"(?P<prot>\S+)", re.IGNORECASE)
ESTADOS_CISCO = {"connected": "up", "notconnect": "down", "disabled": "admin-down",
                 "err-disabled": "err-disabled", "inactive": "down", "suspended": "down",
                 "monitoring": "up", "sfpAbsent": "down"}


def leer_status_cisco(salida: str) -> dict:
    """'show interfaces status' -> {interfaz: {estado, vlan, descripcion}}."""
    puertos = {}
    for linea in salida.splitlines():
        m = RE_ESTADO_CISCO.match(linea.rstrip())
        if not m or m.group("port").lower() == "port":
            continue
        nombre = normalizar(m.group("port"))
        puertos[nombre] = {"estado": ESTADOS_CISCO.get(m.group("estado"), m.group("estado")),
                           "vlan": m.group("vlan")[:20],
                           "descripcion": m.group("desc").strip()[:120] or None}
    return puertos


def leer_vecinos(salida: str) -> dict:
    """Vecinos conectados -> {interfaz_local: 'EQUIPO (puerto remoto)'}.
    Entiende 'show cdp neighbors' / 'show lldp neighbors' (Cisco: el vecino va primero)
    y 'display lldp neighbor brief' (Huawei: la interfaz local va primero)."""
    vecinos, pendiente = {}, None
    for linea in salida.splitlines():
        texto = linea.rstrip()
        bajo = texto.lower().strip()
        if not bajo or bajo.startswith(("capability", "device id", "device-id", "total", "local intf")):
            continue
        partes = texto.split()
        primero = RE_INTERFAZ.fullmatch(partes[0]) if partes else None
        if primero and len(partes) >= 2:
            # Huawei: GE0/0/1  SW2  GE0/0/2  100
            local, vecino = primero, partes[1]
            resto = texto[texto.index(partes[1]) + len(partes[1]):]
        else:
            # Cisco: SW2  Gig 1/0/1  120  S I  WS-C2960  Gig 0/1
            # (si el nombre del vecino es largo, queda solo en una línea y el resto en la siguiente)
            if len(partes) == 1:
                pendiente = partes[0]
                continue
            inicio = 0 if pendiente else len(texto) - len(texto.lstrip()) + len(partes[0])
            local = RE_INTERFAZ.search(texto, inicio)
            if not local:
                pendiente = None
                continue
            vecino = pendiente or partes[0]
            resto = texto[local.end():]
        remoto = RE_INTERFAZ.search(resto)
        nombre_local = normalizar(local.group(0))
        vecinos[nombre_local] = (f"{vecino} ({nombre_corto(normalizar(remoto.group(0)))})"
                                 if remoto else vecino)[:200]
        pendiente = None
    return vecinos


def leer_macs(salida: str) -> dict:
    """'show mac address-table' (Cisco) o 'display mac-address' (Huawei) -> {interfaz: [mac, ...]}."""
    macs = {}
    for linea in salida.splitlines():
        m = RE_MAC_CISCO.match(linea) or RE_MAC_HUAWEI.match(linea)
        if not m:
            continue
        puerto = m.group("port")
        if puerto.upper() in ("CPU", "DROP") or not RE_INTERFAZ.search(puerto):
            continue
        macs.setdefault(normalizar(puerto), []).append(m.group("mac").lower())
    return macs


def leer_brief_huawei(salida: str) -> dict:
    """'display interface brief' -> {interfaz: {estado}}."""
    puertos = {}
    for linea in salida.splitlines():
        m = RE_BRIEF_HUAWEI.match(linea.strip())
        if m:
            fis = m.group("fis").lower()
            estado = "admin-down" if fis.startswith("*") else ("up" if "up" in fis else "down")
            puertos[normalizar(m.group("port"))] = {"estado": estado}
    return puertos


# Comandos de SOLO LECTURA que se usan para leer los puertos de un equipo real
COMANDOS_PUERTOS = {
    "Cisco": [("estado", "show interfaces status"), ("vecinos", "show cdp neighbors"),
              ("vecinos", "show lldp neighbors"), ("macs", "show mac address-table")],
    "Huawei": [("estado_hw", "display interface brief"), ("vecinos", "display lldp neighbor brief"),
               ("macs", "display mac-address")],
}


def combinar(salidas: dict) -> dict:
    """Une lo leído por cada comando en un solo diccionario por interfaz."""
    puertos = {}
    for tipo, texto in salidas:
        if tipo == "estado":
            datos = leer_status_cisco(texto)
        elif tipo == "estado_hw":
            datos = leer_brief_huawei(texto)
        elif tipo == "vecinos":
            datos = {k: {"vecino": v} for k, v in leer_vecinos(texto).items()}
        else:
            datos = {k: {"mac": ", ".join(v[:10])} for k, v in leer_macs(texto).items()}
        for nombre, valores in datos.items():
            puertos.setdefault(nombre, {}).update(valores)
    return puertos


# ---------------------------------------------------------------------------
# 3. Puertos SIMULADOS (para los equipos SIM del inventario)
# ---------------------------------------------------------------------------
def simular_puertos(equipo: Device) -> dict:
    """Genera puertos coherentes con los mensajes del simulador. Siempre iguales para el mismo equipo."""
    azar = random.Random(equipo.id * 7919)
    if equipo.vendor == "Fortinet":
        nombres = [f"port{i}" for i in range(1, 11)]
    elif equipo.vendor == "Huawei":
        nombres = [f"GigabitEthernet0/0/{i}" for i in range(1, 25)]
    else:
        nombres = [f"GigabitEthernet1/0/{i}" for i in range(1, 25)]
    vecinos = ["SIM-ACC-SW02", "SIM-AP-PISO2", "SIM-SRV-WEB01", "SIM-IMPRESORA-01", "SIM-PC-ADMIN"]
    puertos = {}
    for i, nombre in enumerate(nombres, start=1):
        uplink = i == 1  # el primer puerto es el enlace hacia el núcleo: siempre conectado
        arriba = uplink or azar.random() < 0.6
        datos = {"estado": "up" if arriba else "down",
                 "vlan": "trunk" if uplink else str(azar.choice([10, 20, 30])),
                 "descripcion": "UPLINK (sim)" if uplink else None}
        if arriba:
            datos["mac"] = f"0011.22{equipo.id:02x}.{i:04x}"
            if uplink:
                datos["vecino"] = "SIM-NUCLEO-01 (Gi0/1)"
            elif azar.random() < 0.5:
                datos["vecino"] = f"{azar.choice(vecinos)} (eth0)"
        puertos[nombre] = datos
    return puertos


# ---------------------------------------------------------------------------
# 4. Guardar en la base de datos
# ---------------------------------------------------------------------------
def _ahora():
    return datetime.now(timezone.utc)


def guardar_puertos(db: Session, equipo: Device, puertos: dict, origen: str) -> int:
    """Crea o actualiza los puertos del equipo. Devuelve cuántos se guardaron."""
    existentes = {p.interfaz: p for p in db.query(Port).filter(Port.device_id == equipo.id)}
    for nombre, datos in puertos.items():
        nombre = nombre[:64]
        p = existentes.get(nombre)
        if p is None:
            p = Port(device_id=equipo.id, interfaz=nombre)
            db.add(p)
        p.corto = nombre_corto(nombre)[:20]
        for campo in ("estado", "vlan", "descripcion", "vecino", "mac"):
            # Un dato simulado nunca pisa el estado que informó un log real del puerto
            if campo == "estado" and origen == "simulado" and p.ultimo_evento_id:
                continue
            if campo in datos:
                setattr(p, campo, datos[campo])
        if not (origen == "simulado" and p.ultimo_evento_id):
            p.origen = origen
        p.actualizado = _ahora()
    db.commit()
    return len(puertos)


RE_CAMBIO = re.compile(r"changed state to (?P<e>up|down|administratively down)|"
                       r"entered the (?P<h>UP|DOWN) state|link status is (?P<f>up|down)", re.IGNORECASE)


def actualizar_por_evento(db: Session, evento) -> None:
    """Si el log dice que una interfaz subió o cayó, actualiza ese puerto (sin hacer commit)."""
    if not evento.device_id:
        return
    interfaz = extraer_interfaz(evento.message)
    if not interfaz:
        return
    p = (db.query(Port).filter(Port.device_id == evento.device_id, Port.interfaz == interfaz).first())
    cambio = RE_CAMBIO.search(evento.message)
    if p is None:
        if not cambio:
            return  # solo se crean puertos nuevos cuando el log informa su estado
        p = Port(device_id=evento.device_id, interfaz=interfaz[:64], corto=nombre_corto(interfaz)[:20],
                 origen="evento")
        db.add(p)
    if cambio:
        valor = (cambio.group("e") or cambio.group("h") or cambio.group("f")).lower()
        p.estado = "admin-down" if valor.startswith("admin") else valor
    p.ultimo_evento_id = evento.id
    p.actualizado = _ahora()

# --- FIN DEL ARCHIVO ---