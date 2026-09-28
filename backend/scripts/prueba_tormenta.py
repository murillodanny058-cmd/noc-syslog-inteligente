"""
Prueba del CONTROL DE TORMENTAS (pendiente desde la Fase 3).
Envía 150 mensajes DISTINTOS por UDP en pocos segundos. Con el límite de
120 eventos nuevos por minuto por origen, el receptor debe guardar cerca
de 120 y descartar el resto como 'descartado_tormenta'.

Uso (con el receptor encendido en otra terminal):
    python -m backend.scripts.prueba_tormenta
"""
import argparse
import socket
import time
from datetime import datetime, timezone


def main():
    parser = argparse.ArgumentParser(description="Prueba de tormenta de logs")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--puerto", type=int, default=5514)
    parser.add_argument("--cantidad", type=int, default=150)
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ahora = datetime.now(timezone.utc)
    print(f"Enviando {args.cantidad} mensajes DISTINTOS (tormenta simulada) a {args.host}:{args.puerto}...")
    for i in range(1, args.cantidad + 1):
        mensaje = (f"<187>{i}: *{ahora:%b %d %H:%M:%S}.000: %LINK-3-UPDOWN: "
                   f"Interface GigabitEthernet1/0/{i}, changed state to down (tormenta sim)")
        sock.sendto(mensaje.encode("utf-8"), (args.host, args.puerto))
        time.sleep(0.01)
    sock.close()
    print("Listo. Detenga el receptor con Ctrl + C y revise el resumen.")


if __name__ == "__main__":
    main()

# --- FIN DEL ARCHIVO ---