# Historias de usuario — NOC Syslog Inteligente

Formato: _Como [rol], quiero [acción], para [beneficio]._
Criterios de aceptación: _Dado [contexto], cuando [acción], entonces [resultado]._

Rol principal: **operador del NOC**, persona que supervisa la red.

---

## Módulo 1: Inventario de equipos (Fase 2)

### HU-01 · Consultar el inventario

**Como** operador del NOC, **quiero** ver la lista de equipos de la red,
**para** conocer qué dispositivos estoy supervisando.

**Criterios de aceptación:**

1. Dado que existen equipos registrados, cuando consulto el inventario,
   entonces veo nombre, IP, marca, modelo, versión, ubicación, estado y fecha
   de actualización de cada uno.
2. Dado que filtro por marca y/o estado, cuando consulto, entonces solo veo
   los equipos que cumplen todos los filtros.
3. Dado que consulto un id que no existe, entonces recibo el error 404.

### HU-02 · Registrar un equipo

**Como** operador del NOC, **quiero** agregar un equipo nuevo al inventario,
**para** empezar a supervisar sus eventos.

\*\*Criter

---

## Módulo 2: Recepción y clasificación Syslog (Fase 3)

**Rol nuevo — Analista de seguridad:** revisa eventos sospechosos e intentos
de manipulación del sistema.

### HU-06 — Recibir mensajes Syslog por la red

**Como** operador NOC, **quiero** que el sistema reciba los logs que envían los
equipos por UDP, **para** centralizarlos sin intervención manual.

**Criterios de aceptación**

1. **Dado** que el receptor está activo, **cuando** un equipo envía un mensaje
   Syslog por UDP, **entonces** el mensaje se procesa y se guarda como evento.
2. **Dado** que el origen no está en la lista permitida, **cuando** llega un
   mensaje, **entonces** se bloquea y no se guarda.
3. **Dado** que se inicia el receptor, **cuando** se elige la etiqueta,
   **entonces** los eventos quedan identificados como simulados o reales.

**Pruebas:** PF-F3-13, PF-F3-14, PF-F3-15, PF-F3-16

### HU-07 — Clasificar los eventos

**Como** operador NOC, **quiero** que cada mensaje se clasifique por equipo,
fabricante, fecha, facility y severidad, **para** priorizar mi atención.

**Criterios de aceptación**

1. **Dado** un mensaje con PRI, **cuando** se procesa, **entonces** se calculan
   facility (PRI ÷ 8) y severidad (residuo), del 0 al 7.
2. **Dado** un mensaje en formato Cisco, Huawei, Fortinet, RFC 3164 o RFC 5424,
   **cuando** se procesa, **entonces** se extraen su aplicación y su mensaje.
3. **Dado** que la IP de origen está en el inventario, **cuando** se guarda el
   evento, **entonces** queda asociado al equipo y a su marca.
4. **Dado** que se consultan las estadísticas, **cuando** se muestran,
   **entonces** aparecen los 8 niveles de severidad con su conteo.

**Pruebas:** PF-F3-01, PF-F3-02, PF-F3-03, PF-F3-10

### HU-08 — Evitar la saturación por mensajes repetidos

**Como** operador NOC, **quiero** que los mensajes repetidos se agrupen,
**para** no perder los eventos importantes entre miles de copias.

**Criterios de aceptación**

1. **Dado** que llega un mensaje idéntico a otro de hace menos de 60 segundos,
   **cuando** se procesa, **entonces** no se crea un evento nuevo y su contador
   aumenta en 1.
2. **Dado** que un origen supera 120 eventos nuevos por minuto, **cuando** llegan
   más mensajes distintos, **entonces** se descartan por control de tormentas.

**Pruebas:** PF-F3-04, PF-F3-06, PF-F3-14

### HU-09 — Detectar logs que intentan manipular a una IA

**Como** analista de seguridad, **quiero** que se marquen los mensajes que
contienen instrucciones dirigidas a una IA, **para** detectar intentos de
manipulación sin que nada se ejecute.

**Criterios de aceptación**

1. **Dado** un mensaje con frases como "ignora tus instrucciones" o comandos
   destructivos, **cuando** se procesa, **entonces** se marca como sospechoso.
2. **Dado** un mensaje sospechoso, **cuando** se guarda, **entonces** se trata
   solo como dato y nunca se ejecuta.
3. **Dado** un mensaje sospechoso, **cuando** se guarda, **entonces** se registra
   una alerta `SUSPICIOUS_LOG` en la auditoría.

**Pruebas:** PF-F3-05, PF-F3-09, PF-F3-12, PF-F3-14

### HU-10 — Consultar eventos con filtros

**Como** operador NOC, **quiero** filtrar los eventos por fecha, marca, equipo,
severidad y sospecha, **para** encontrar rápidamente lo que necesito.

**Criterios de aceptación**

1. **Dado** que filtro por severidad máxima, **cuando** consulto, **entonces**
   solo veo eventos de ese nivel o más graves.
2. **Dado** que filtro por marca, **cuando** consulto, **entonces** solo veo
   eventos de esa marca.
3. **Dado** que activo "solo sospechosos", **cuando** consulto, **entonces** solo
   veo los eventos marcados.

**Pruebas:** PF-F3-07, PF-F3-08, PF-F3-09
