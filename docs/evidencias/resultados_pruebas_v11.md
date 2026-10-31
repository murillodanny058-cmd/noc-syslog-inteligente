# Resultados de las pruebas v1.1.0 (equipo apagado y notificaciones)

- Fecha: 2026-10-30 21:37
- Versión: 1.1.0
- Base: SQLite temporal · equipo: switch falso en memoria · canales: simulados
- **Resultado: 15 de 15 OK**

| Código | Prueba | Esperado | Obtenido | Resultado |
|---|---|---|---|---|
| V01 | La consola se conecta y ve el prompt | LAB-SW01# | LAB-SW01# | OK |
| V02 | Equipo apagado: el latido lo detecta | en menos de 45 s | 26 s | OK |
| V03 | Se guarda un evento de severidad 1 a nombre del equipo | sev 1, LAB-SW01 | sev 1, LAB-SW01 | OK |
| V04 | Se abre un incidente automático | abierto | #1 abierto | OK |
| V05 | El equipo pasa a 'inactivo' en el Inventario | inactivo | inactivo | OK |
| V06 | Llega el aviso 'NO RESPONDE' por Telegram | enviado | enviado | OK |
| V07 | La caída queda en la auditoría | DEVICE_DOWN | 1 registro(s) | OK |
| V08 | Al volver: evento de recuperación con el tiempo caído | EQUIPO_RECUPERADO ... tras N s |  a las 21:37:09 tras 28 s sin respuesta. | OK |
| V09 | El equipo vuelve a 'activo' | activo | activo | OK |
| V10 | Llega el aviso 'recuperado' por Telegram | enviado | enviado | OK |
| V11 | Equipo en mantenimiento: guarda el evento pero NO avisa | 1 evento, 0 avisos | 1 evento, 0 avisos | OK |
| V12 | 3 alertas con correo lento (4 s c/u): Telegram no espera | las 3 por Telegram en < 2 s | 3 en 0.0 s | OK |
| V13 | Se mide cuánto tardó cada aviso | Entregado en X s | Entregado en 0.0 s | OK |
| V14 | Cable USB de consola desconectado: evento de severidad 2 | CONSOLA_PERDIDA sev 2 | sev 2 | OK |
| V15 | Ping: solo IPs válidas (sin inyección, sin IPs de documentación) | rechaza 192.0.2.x, 127.0.0.1 y '& del *' | correcto | OK |
