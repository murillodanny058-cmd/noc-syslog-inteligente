# Resultados de pruebas automáticas — v1.0.0

Ejecutado: 2026-10-24 23:08 con `python -m backend.scripts.pruebas_v1` (base SQLite temporal, sin enviar nada a Telegram ni a la IA).

**Resultado: 31 de 31 pruebas OK.**

| Código | Tipo | Prueba | Esperado | Obtenido | Resultado |
|---|---|---|---|---|---|
| F01 | Funcional | Chequeo de salud del servidor | 200 | 200 | OK |
| F02 | Funcional | Administrador registra un equipo | 201 | 201 | OK |
| F03 | Funcional | Recepción y clasificación de un log (severidad 3) | nuevo / sev 3 | nuevo / sev 3 | OK |
| F04 | Funcional | El mismo log repetido se agrupa (no inunda) | duplicado | duplicado | OK |
| F05 | Funcional | Filtro de eventos por severidad | >=1 evento | 1 | OK |
| F06 | Funcional | Detección del puerto del evento | GigabitEthernet1/0/5 | GigabitEthernet1/0/5 | OK |
| F07 | Funcional | Detalle del puerto del evento (Fase 10) | 200 | 200 | OK |
| F08 | Funcional | Crear incidente desde un evento | 201 | 201 | OK |
| F09 | Funcional | Filtro con fecha futura se rechaza | 422 | 422 | OK |
| F10 | Funcional | Consola simulada: comando permitido | permitido | permitido | OK |
| F11 | Funcional | Generador de configuración Syslog | 200 | 200 | OK |
| F12 | Funcional | Proponer un cambio del catálogo | 201 | 201 | OK |
| S01 | Seguridad | Quien propone NO puede aprobar su cambio | 403 | 403 | OK |
| S02 | Seguridad | Un operador no puede aprobar cambios | 403 | 403 | OK |
| F13 | Funcional | Aprobar → ejecutar → verificar → rollback | aprobada→ejecutada→verificada→revertida | aprobada→ejecutada→verificada→revertida | OK |
| S03 | Seguridad | Sin sesión no se ve nada | 401 | 401 | OK |
| S04 | Seguridad | Un operador no puede crear usuarios | 403 | 403 | OK |
| S05 | Seguridad | Solo el administrador usa el agente auditor | 403 | 403 | OK |
| S06 | Seguridad | Se rechaza una contraseña débil | 422 | 422 | OK |
| S07 | Seguridad | Bloqueo por fuerza bruta (6 intentos fallidos) | 401 x5 y luego 429 | [401, 401, 401, 401, 401, 429] | OK |
| S08 | Seguridad | Log con inyección para IA se marca sospechoso | True | True | OK |
| S09 | Seguridad | Consola: entrar a configuración está bloqueado | bloqueado | bloqueado | OK |
| S10 | Seguridad | Agente de IA suspendido tras 3 bloqueos | no permitido | False | OK |
| S11 | Seguridad | Propuesta de cambio con inyección se rechaza sola | 422 | 422 | OK |
| S12 | Seguridad | Validación: 127.0.0.1 no es un servidor Syslog válido | 422 | 422 | OK |
| S13 | Seguridad | Agente auditor: la inyección se oculta a la IA | texto omitido | omitido | OK |
| F14 | Funcional | Agente auditor: informe de sesiones (modo reglas) | 200 | 200 · 2 sesiones · riesgo alto | OK |
| C01 | Carga | 500 logs distintos de 5 equipos en un lote | 500 nuevos | 500 nuevos en 3.7 s (135 logs/s) | OK |
| C02 | Carga | Tormenta: 300 logs distintos de un equipo en 1 minuto | 120 guardados, 180 descartados | 120 guardados, 180 descartados | OK |
| C03 | Carga | 300 veces el mismo log | 1 evento, 299 agrupados | 1 evento, 299 agrupados | OK |
| R01 | Respaldo | Exportar respaldo y recuperarlo en una base nueva | tablas iguales | tablas iguales | OK |
