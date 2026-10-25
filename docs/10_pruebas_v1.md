# Pruebas de la versión 1.0.0

Tres niveles de prueba: **automáticas** (se repiten con un comando), **con equipo real** (marcha blanca)
y **de recuperación** (respaldo y restauración).

## 1. Pruebas automáticas

```powershell
python -m backend.scripts.pruebas_v1
```

- Usa una base SQLite **temporal** (`data/pruebas_v1.db`): no toca la base real.
- No envía nada a Telegram, correo ni a la IA.
- Escribe el resultado en [`evidencias/resultados_pruebas_v1.md`](evidencias/resultados_pruebas_v1.md).

| Tipo | Códigos | Qué se comprueba |
|---|---|---|
| Funcionales | F01–F14 | Salud, inventario, recepción y clasificación, agrupación de repetidos, filtros, puerto del evento, incidentes, fechas futuras rechazadas, consola simulada, generador, ciclo completo de un cambio y agente auditor |
| Seguridad | S01–S13 | Separación de funciones, roles (401/403), contraseña débil, fuerza bruta (429), inyección en logs, consola bloqueada, suspensión del agente de IA, propuesta maliciosa, validación de IP, inyección oculta al agente auditor |
| Carga | C01–C03 | 500 logs en un lote, control de tormentas (120 nuevos por minuto por equipo) y agrupación de 300 repeticiones |
| Respaldo | R01 | Exportar la base y recuperarla en una base nueva con las mismas filas |

## 2. Pruebas con equipo real (marcha blanca)

Registradas en la [bitácora de marcha blanca](09_bitacora_marcha_blanca.md): conexión por consola sin IP,
captura de logs, bloqueos (`enable`, `show running-config`), lectura de puertos, cambio con aprobación
y rollback automático.

## 3. Prueba de carga por red (UDP)

```powershell
# Terminal A: receptor
python -m backend.scripts.syslog_udp_listener --host 127.0.0.1 --puerto 5514
# Terminal B: 150 mensajes distintos en ráfaga
python -m backend.scripts.prueba_tormenta --cantidad 150
```
Resultado esperado: se guardan 120 eventos nuevos en el minuto y el resto se descarta, con una alerta de tormenta.

## 4. Respaldo y recuperación de la base real

```powershell
python -m backend.scripts.respaldo exportar
python -m backend.scripts.respaldo restaurar data\respaldos\noc_AAAAMMDD_HHMMSS.json
```
La restauración se hace en una base SQLite **nueva** y compara las filas de cada tabla, así se prueba
la recuperación sin arriesgar la base en uso. El respaldo queda en `data/` (ignorada por Git) porque
contiene hash de contraseñas.
