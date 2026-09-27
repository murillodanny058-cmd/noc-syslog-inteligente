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
