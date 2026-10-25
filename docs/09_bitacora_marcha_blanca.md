# Bitácora de marcha blanca — v1.0.0

Operación controlada del NOC con equipos **reales** del laboratorio, sin cambiar su configuración
salvo autorización del docente y siempre con rollback. Las IP reales del laboratorio no se publican.

- **Equipo principal:** Cisco Catalyst WS-C2960+24TC-L, IOS 15.0(2)SE8, registrado como `LAB-SW01` (Real).
- **Conexión:** cable de consola USB–RJ45 (puerto `COM15`, 9600 baudios). Sin IP: el switch estaba con
  configuración de fábrica y sin red de gestión.
- **NOC:** PC del estudiante (Windows), FastAPI + PostgreSQL (Neon), iniciado con `iniciar_noc.bat`.

## Sesión 1 — miércoles 21 de octubre de 2026 (laboratorio)

| Hora (aprox.) | Prueba | Resultado | Evidencia | Observaciones |
|---|---|---|---|---|
| 18:16 | Conexión a la consola real por COM15 (USB), no Bluetooth | OK | Captura "Conectado a COM15" | El switch se estaba reiniciando: el primer comando salió incompleto (hallazgo H5) |
| 18:16 | Logs del arranque capturados como eventos reales, sin IP | OK (4 logs) | Captura consola + Eventos | `%LINEPROTO-5-UPDOWN`, `%SYS-5-CONFIG_I`, `%SYS-5-RESTART` |
| 18:19 | `show version` completo tras reconectar | OK | Captura | Modelo, serie e IOS 15.0(2)SE8 |
| 18:19 | Intento de `enable` desde el NOC | BLOQUEADO (correcto) | Captura | Política: cambiar privilegios no está permitido |
| 18:23 | Cable conectado en Fa0/23: `%LINK-3-UPDOWN` llega al NOC | OK | Captura | Contador "logs capturados" sube a 1 |
| 18:24 | Botón 🔌 del evento: puerto Fa0/23 con sus eventos | OK | Captura | Error 3 (link up) y Notice 5 (protocolo up) |
| 18:30 | `show running-config` | BLOQUEADO (correcto) | Captura | Contiene secretos del equipo real |
| 18:37 | Actualizar puertos (primer intento) | FALLÓ | Captura | La consola se había "dormido" por inactividad (hallazgo H1) |
| 19:04 | `show interfaces status` y `show mac address-table` tras reconectar | OK | Capturas | Paginación `--More--` manejada por el NOC |
| 19:06 | Actualizar puertos por consola real | OK | Captura | 27 interfaces; Fa0/23 conectado con su MAC; MAC de CPU ignoradas |
| 19:11 | Propuesta con IP `127.0.0.1` | RECHAZADA (correcto) | Captura | Validación: loopback no puede ser servidor Syslog |
| 19:20 | Propuestas #3 y #4 (IP mal digitada, enviadas dos veces) | Duplicado | Captura | Doble clic en Proponer (hallazgo H4) |
| 19:28 | #5 con la IP correcta | Pendiente | Captura | Quedó sin ejecutar por fin del tiempo de laboratorio |
| 19:42 | #4 rechazado por `aprobador.lab` | OK | Captura | Revisión humana detecta el error |
| 19:43 | #3 aprobado y ejecutado | FALLÓ → ROLLBACK AUTOMÁTICO | Captura | El equipo no aceptó/no respondió; el NOC revirtió solo |
| 21:46 | Filtro de fechas en Eventos | OK | Capturas | El navegador no deja elegir fechas futuras |

## Sesión 2 — viernes 23 y sábado 24 de octubre de 2026

| Prueba | Resultado | Evidencia | Observaciones |
|---|---|---|---|
| Hermes Agent (Nous Research) instalado; API Server en `127.0.0.1:8642` | OK | `curl /health` → `{"status":"ok"}` | Clave en `.env`, solo escucha en el propio PC |
| Agente auditor: informe de sesiones de `deduardo` redactado por Hermes | OK | Captura del Informe #1 | Detectó la sesión sin cerrar y la conexión a LAB-SW01 |
| Conexión de un Huawei físico | Hallazgo | Captura | Aparecía la política de Cisco (hallazgo H6) |
| Pruebas automáticas `pruebas_v1` | 31/31 OK | `docs/evidencias/resultados_pruebas_v1.md` | Funcionales, seguridad, carga y respaldo |

## Hallazgos y correcciones

| # | Hallazgo | Impacto | Corrección en v1.0.0 |
|---|---|---|---|
| H1 | El switch cierra la sesión de consola tras ~10 min sin uso ("Press RETURN to get started") y el NOC no la reactivaba | Comandos y lectura de puertos sin respuesta | El NOC detecta el mensaje, envía Enter, vuelve a quitar la paginación y reintenta el comando una vez |
| H2 | El NOC bloquea `enable` (correcto); para cambios se hizo `enable` en PuTTY y se cerró PuTTY | Procedimiento manual | Documentado en el manual; el NOC avisa si el prompt está en `>` |
| H3 | El switch no tiene NTP (reloj en 1993) | Hora del equipo no confiable | El NOC guarda la hora de **recepción**; se recomienda NTP (el generador de configuración ya lo incluye) |
| H4 | Doble clic en "Proponer" creó dos cambios iguales | Propuestas duplicadas | El botón se bloquea mientras se envía |
| H5 | Al conectar con el switch arrancando, el primer comando salió incompleto | Salida parcial | Se documenta: esperar el arranque o reconectar; la reactivación de H1 también ayuda |
| H6 | Con un Huawei físico en el cable y "LAB-SW01 (Cisco)" elegido, el NOC mostró la política de Cisco y habría guardado los logs a nombre del Cisco | Mezcla de equipos | El NOC reconoce la marca por el prompt (`<HUAWEI>` vs `Switch>`); si no coincide, avisa, no envía comandos, no guarda logs y bloquea cambios y lectura de puertos. En modo REAL avisa si no hay equipos reales registrados |
| H7 | El límite de fechas del calendario quedaba fijo en la hora en que se abrió la pestaña | No dejaba elegir la hora actual | Se recalcula al abrir el calendario, con 5 min de tolerancia como el servidor |

## Conclusión

El NOC operó con un equipo real sin necesitar IP, capturó sus logs, leyó sus puertos, bloqueó todo lo
peligroso y aplicó el rollback automático cuando un cambio falló. Los 7 hallazgos quedaron corregidos o
documentados en la versión 1.0.0.
