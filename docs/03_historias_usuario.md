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

---

## Módulo 3: Dashboard y filtros (Fase 4)

### HU-11 — Ver el estado general del NOC

**Como** operador NOC, **quiero** un tablero con el resumen de la red,
**para** saber de un vistazo qué requiere atención.

**Criterios de aceptación**

1. **Dado** que abro el dashboard, **cuando** carga, **entonces** veo tarjetas
   con equipos, eventos, críticos (0 a 3), sospechosos e incidentes abiertos.
2. **Dado** que hay eventos, **cuando** veo el resumen, **entonces** un gráfico
   muestra la cantidad por cada nivel de severidad, del 0 al 7.
3. **Dado** que un equipo activo tiene eventos críticos en las últimas 24 horas,
   **cuando** veo el semáforo, **entonces** aparece en rojo; si está en
   mantenimiento, aparece en gris.
4. **Dado** que el dashboard está abierto, **cuando** pasan 15 segundos,
   **entonces** los datos se actualizan solos.
5. **Dado** que abro el dashboard en un celular, **cuando** carga, **entonces**
   el contenido se reorganiza en una sola columna.

**Pruebas:** PF-F4-10, PF-F4-12, PF-F4-13, PF-F4-19

### HU-12 — Filtrar eventos desde la interfaz

**Como** operador NOC, **quiero** filtrar los eventos con controles visuales,
**para** encontrar lo que busco sin escribir consultas.

**Criterios de aceptación**

1. **Dado** que elijo fecha, marca, equipo, severidad o "solo sospechosos",
   **cuando** presiono Filtrar, **entonces** la tabla muestra solo los eventos
   que cumplen todos los filtros.
2. **Dado** que la API guarda las fechas en UTC, **cuando** se muestran,
   **entonces** aparecen en la hora local del operador.
3. **Dado** que un mensaje contiene código HTML o JavaScript, **cuando** se
   muestra, **entonces** aparece como texto y nunca se ejecuta.

**Pruebas:** PF-F4-14, PF-F4-18

---

## Módulo 4: Gestión de incidentes (Fase 4)

### HU-13 — Crear incidentes

**Como** operador NOC, **quiero** crear un incidente desde un evento o de forma
manual, **para** registrar los problemas que alguien debe atender.

**Criterios de aceptación**

1. **Dado** un evento, **cuando** presiono "Crear incidente", **entonces** se crea
   un incidente abierto con título, severidad y equipo tomados del evento.
2. **Dado** que el evento ya tiene un incidente sin cerrar, **cuando** intento
   crear otro, **entonces** se rechaza con el código 409.
3. **Dado** que creo un incidente manual con responsable, **cuando** se guarda,
   **entonces** nace en estado "asignado".

**Pruebas:** PF-F4-01, PF-F4-02, PF-F4-09, PF-F4-15

### HU-14 — Asignar y dar seguimiento

**Como** operador NOC, **quiero** asignar incidentes y cambiar su estado,
**para** que siempre se sepa quién atiende cada problema y en qué va.

**Criterios de aceptación**

1. **Dado** un incidente abierto, **cuando** le asigno un responsable,
   **entonces** pasa automáticamente a "asignado".
2. **Dado** un incidente abierto, **cuando** intento pasarlo a "en progreso",
   **entonces** se rechaza con el código 409 y se indican los estados permitidos.
3. **Dado** un incidente, **cuando** lo veo en el dashboard, **entonces** solo
   aparecen los botones de las acciones permitidas en su estado.

**Pruebas:** PF-F4-03, PF-F4-04, PF-F4-05, PF-F4-16

### HU-15 — Cerrar incidentes

**Como** operador NOC, **quiero** cerrar los incidentes documentando la solución,
**para** conservar el conocimiento y medir los tiempos de respuesta.

**Criterios de aceptación**

1. **Dado** un incidente, **cuando** intento cerrarlo sin resolución (mínimo 10
   caracteres), **entonces** se rechaza.
2. **Dado** un incidente, **cuando** lo cierro con resolución, **entonces** se
   registra la fecha de cierre y la acción CLOSE en la auditoría.
3. **Dado** un incidente cerrado, **cuando** intento modificarlo, **entonces** se
   rechaza con el código 409.

**Pruebas:** PF-F4-06, PF-F4-07, PF-F4-08, PF-F4-11, PF-F4-16

<!-- FIN FASE 4 -->
