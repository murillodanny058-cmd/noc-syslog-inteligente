"""
Receptor Syslog REAL por red (UDP).
Escucha mensajes Syslog en un puerto UDP y los procesa con el mismo motor de ingesta.

Uso (desde la raíz del proyecto, con el venv activo):
    python -m backend.scripts.syslog_udp_listener
    python -m backend.scripts.syslog_udp_listener --puerto 5514 --tipo real

Medidas de seguridad:
  - Por defecto escucha SOLO en 127.0.0.1 (este mismo computador).
  - Lista permitida: solo acepta mensajes de redes autorizadas.
  - Tamaño máximo por paquete: 4096 bytes.
  - Los mensajes pasan por el motor de ingesta: deduplicación, control de
    tormentas y detección de inyección de instrucciones.
"""
import argparse
import ipaddress
import socket
from datetime import datetime

from backend.app.database import SessionLocal
from backend.app.ingest import ingerir

# Redes permitidas: este PC + rangos de documentación (RFC 5737)
REDES_PERMITIDAS = "127.0.0.1/32,192.0.2.0/24,198.51.100.0/24,203.0.113.0/24"
TAMANO_MAXIMO = 4096


def main():
    parser = argparse.ArgumentParser(description="Receptor Syslog UDP del NOC")
    parser.add_argument("--host", default="127.0.0.1",
                        help="IP donde escuchar (0.0.0.0 = todas las interfaces)")
    parser.add_argument("--puerto", type=int, default=5514, help="Puerto UDP")
    parser.add_argument("--tipo", choices=["simulado", "real"], default="simulado",
                        help="Cómo etiquetar los mensajes recibidos")
    parser.add_argument("--permitidas", default=REDES_PERMITIDAS,
                        help="Redes autorizadas separadas por coma")
    args = parser.parse_args()

    redes = [ipaddress.ip_network(r.strip()) for r in args.permitidas.split(",")]

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP
    sock.bind((args.host, args.puerto))
    sock.settimeout(1.0)  # revisa cada segundo si se presionó Ctrl + C

    print("=" * 70)
    print(f" Receptor Syslog escuchando en UDP {args.host}:{args.puerto}")
    print(f" Etiqueta de los mensajes: {args.tipo}")
    print(f" Redes permitidas: {', '.join(str(r) for r in redes)}")
    print(" Presione Ctrl + C para detener")
    print("=" * 70)

    conteo = {"recibidos": 0, "bloqueados": 0, "nuevo": 0, "duplicado": 0,
              "descartado_tormenta": 0, "rechazado": 0, "sospechosos": 0}
    try:
        while True:
            try:
                datos, (ip_origen, _puerto) = sock.recvfrom(TAMANO_MAXIMO)
            except socket.timeout:
                continue  # no llegó nada en este segundo; seguimos esperando

            conteo["recibidos"] += 1
            hora = datetime.now().strftime("%H:%M:%S")

            # Defensa 1: lista permitida
            if not any(ipaddress.ip_address(ip_origen) in red for red in redes):
                conteo["bloqueados"] += 1
                print(f"[{hora}] {ip_origen:15} BLOQUEADO: origen fuera de la lista permitida")
                continue

            # Defensa 2: el motor de ingesta (el texto se trata como DATO, nunca como orden)
            texto = datos.decode("utf-8", errors="replace")
            db = SessionLocal()
            try:
                r = ingerir(db, texto, ip_origen, args.tipo)
            except Exception as error:
                print(f"[{hora}] {ip_origen:15} ERROR al procesar: {error}")
                continue
            finally:
                db.close()

            conteo[r["resultado"]] += 1
            alerta = ""
            if r["resultado"] == "nuevo" and r.get("sospechoso"):
                conteo["sospechosos"] += 1
                alerta = "  [!] SOSPECHOSO"
            print(f"[{hora}] {ip_origen:15} {r['resultado']:12} "
                  f"sev={r.get('severity')} {r.get('severity_name') or ''}"
                  f" x{r.get('repeat_count') or 0}{alerta}")
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()
        print("\nReceptor detenido. Resumen:")
        for clave, valor in conteo.items():
            print(f"   {clave:20} {valor}")


if __name__ == "__main__":
    main()