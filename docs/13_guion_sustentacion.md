# Guion de sustentación — Corte 3 (v1.0.0)

Duración sugerida: 12 a 15 minutos. Antes de empezar: NOC y Hermes encendidos, sesión de `deduardo`
abierta, otra ventana en incógnito con un operador, y el `.env` **cerrado**.

| Min | Qué decir | Qué mostrar |
|---|---|---|
| 0–1 | Problema y objetivo: un NOC basado en Syslog que no se deja manipular por una IA | README y Resumen |
| 1–2 | Evolución del MVP v0.2.0 a v1.0.0: base en la nube, roles, Telegram, consola real, puertos, cambios con aprobación y agente auditor | CHANGELOG |
| 2–4 | **Consola real sin IP**: el equipo se conecta por cable y sus logs llegan solos | Consola → Equipo REAL; captura de `%LINK-3-UPDOWN Fa0/23` |
| 4–5 | **Puertos por evento**: en qué puerto pasó y qué hay conectado | Eventos → botón 🔌 → Puertos de LAB-SW01 |
| 5–7 | **Cambios con aprobación humana**: quien propone no aprueba; respaldo, verificación y rollback | Cambios: #4 rechazado, #3 con rollback automático |
| 7–9 | **Agente auditor con Hermes Agent**: qué hizo cada usuario desde que entró hasta que salió | Auditoría IA → Ver sesiones → Generar informe |
| 9–10 | Seguridad del agente: solo lee, las inyecciones se le ocultan, Hermes solo local y con clave; la IA redacta pero un humano revisa | Hallazgo "texto omitido" y política de la consola |
| 10–11 | **Notificaciones sin inundar**: agrupación, silencio de 30 min, máximo por hora | Telegram en el celular |
| 11–13 | **Marcha blanca**: 7 hallazgos reales y cómo se corrigieron | `09_bitacora_marcha_blanca.md` |
| 13–14 | **Pruebas**: 31 automáticas OK; carga, tormenta, respaldo y recuperación | `resultados_pruebas_v1.md` |
| 14–15 | Limitaciones y siguientes pasos: acceso remoto por VPN (Tailscale), dashboard en la nube con agente local de consola, retención y búsqueda de logs | — |

## Preguntas probables

- **¿Por qué no por IP?** Los equipos del laboratorio no tenían red de gestión; el cable de consola no la necesita y es como trabaja un técnico en sitio.
- **¿Y si la IA se equivoca?** Solo redacta; los hallazgos los marcan reglas fijas y el informe lo revisa un humano. En el informe #1, Hermes interpretó mal "0 logs capturados"; por eso la revisión humana es obligatoria.
- **¿Y si alguien mete una orden en un log?** Se marca como sospechoso, nunca se ejecuta y no llega al agente.
- **¿Qué pasa si un cambio sale mal?** Rollback automático (se vio en el #3) y nunca se guarda en memoria.
