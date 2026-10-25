"""
Diagnóstico de Telegram. NO muestra el token.
Uso: python -m backend.scripts.diagnostico_telegram
"""

import json
import os
import urllib.error
import urllib.parse
import urllib.request

from backend.app import config  # noqa: F401  (carga el archivo .env)

token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
chat = os.getenv("TELEGRAM_CHAT_ID", "").strip()
base = "https://api.telegram.org/bot" + token


def llamar(metodo, datos=None):
    """Llama a un método de la API de Telegram y devuelve la respuesta, sin mostrar el token."""
    try:
        cuerpo = urllib.parse.urlencode(datos).encode() if datos else None
        with urllib.request.urlopen(base + "/" + metodo, data=cuerpo, timeout=10) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        return json.load(e)


print("1) Token cargado:", "SÍ" if token else "NO", "| tiene ':' ->", ":" in token)
print("2) Chat ID leído:", repr(chat))

r = llamar("getMe")
print(
    "3) ¿El token es válido?:", "SÍ, bot @" + r["result"]["username"] if r.get("ok") else r.get("description")
)

r = llamar("getUpdates")
quienes = {
    (u["message"]["chat"]["id"], u["message"]["chat"].get("first_name"))
    for u in r.get("result", [])
    if "message" in u
}
print("4) Quién le ha escrito al bot:", quienes or "NADIE todavía")

r = llamar("sendMessage", {"chat_id": chat, "text": "Prueba de diagnóstico del NOC"})
print("5) Envío de prueba:", "✅ ENVIADO" if r.get("ok") else "❌ " + str(r.get("description")))

# --- FIN DEL ARCHIVO ---
