# Procedimiento de despliegue y rollback — v1.0.0

## 1. Requisitos

- Windows 10/11, Python 3.12 o superior, Git.
- Base de datos: PostgreSQL en Neon (`DATABASE_URL` en `.env`) o, si no hay, SQLite local automática.
- Opcional: cable de consola USB–RJ45 (consola real) y Hermes Agent (agente auditor con IA).

## 2. Instalación nueva

```powershell
git clone https://github.com/murillodanny058-cmd/noc-syslog-inteligente.git
cd noc-syslog-inteligente
git checkout v1.0.0
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env        # y llenar los valores reales SOLO en .env
python -m backend.scripts.init_db
python -m backend.scripts.crear_admin
```

Iniciar: doble clic en `iniciar_noc.bat` (abre el servidor en `0.0.0.0:8000` y el navegador).

## 3. Agente auditor con Hermes Agent (opcional)

1. Instalar Hermes (PowerShell **normal**, no administrador): `iex (irm https://hermes-agent.nousresearch.com/install.ps1)`.
2. `hermes setup model` → proveedor (por ejemplo, Nous Portal, plan gratuito).
3. En `%LOCALAPPDATA%\hermes\.env`: `API_SERVER_ENABLED=true` y `API_SERVER_KEY=<clave aleatoria>`.
4. `hermes -p default gateway restart` y comprobar `curl.exe http://127.0.0.1:8642/health`.
5. `hermes tools`: desactivar terminal, archivos, web y navegador para la plataforma API server.
6. En el `.env` del NOC: `HERMES_API_URL=http://127.0.0.1:8642` y `HERMES_API_KEY=<la misma clave>`.

Sin Hermes, el agente auditor funciona en modo **reglas** (sin IA).

## 4. Actualizar a una versión nueva

```powershell
python -m backend.scripts.respaldo exportar      # 1. respaldo ANTES de actualizar
git fetch --tags
git checkout v1.0.0                              # 2. versión nueva
pip install -r requirements.txt                  # 3. dependencias
# 4. iniciar el NOC: las tablas nuevas se crean solas al arrancar
python -m backend.scripts.pruebas_v1             # 5. verificar (base temporal)
```

## 5. Rollback (volver a la versión anterior)

Usar si después de actualizar algo no funciona:

```powershell
# 1. Cerrar la ventana del NOC
git checkout v0.2.0                              # 2. código de la versión anterior
pip install -r requirements.txt
# 3. Iniciar el NOC con iniciar_noc.bat
```

- Las tablas nuevas de la v1.0.0 (`actividad`, `informes_auditoria`, `puertos`, `cambios_config`) no
  molestan a la versión anterior: simplemente no las usa.
- Si los **datos** se dañaron, restaurar el respaldo del paso 4.1 en una base nueva
  (`python -m backend.scripts.respaldo restaurar ...`) y apuntar `DATABASE_URL` a ella mientras se revisa.

## 6. Rollback de un cambio en un equipo

Los cambios del NOC solo quedan en la configuración en uso (running-config) y nunca se guardan en memoria:
1. Pestaña **Cambios** → **Deshacer (rollback)**.
2. Si el NOC no responde: aplicar a mano los comandos de rollback que muestra la tarjeta del cambio.
3. Último recurso: reiniciar el equipo (vuelve a su configuración guardada).

## 7. Checklist de salida a producción

- [ ] `git status` sin `.env`, `data/` ni `lab_muestras/`
- [ ] `python -m backend.scripts.pruebas_v1` con todas las pruebas OK
- [ ] Respaldo reciente en `data/respaldos/`
- [ ] Usuario administrador y al menos un aprobador distinto
- [ ] Telegram probado (`POST /api/notifications/test`)
- [ ] Hermes respondiendo en `127.0.0.1:8642/health` (si se usa)
