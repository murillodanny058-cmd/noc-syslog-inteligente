# Planteamiento del proyecto — NOC Syslog Inteligente

> Proyecto académico · Administración y Gestión de Redes · 2026-2
> Autor: Dany Murillo · Docente: Ing. John Harold Pérez Calderón

## 1. Problema

En una red empresarial, cada equipo (switch, router, firewall) genera sus
propios mensajes de eventos: interfaces caídas, inicios de sesión fallidos,
cambios de configuración. Cuando esos mensajes se quedan dentro de cada equipo,
el administrador debe revisarlos uno por uno, y los problemas se detectan tarde
o nunca.

A esto se suma un riesgo nuevo: los agentes de inteligencia artificial que
automatizan tareas de red. Un agente de IA podría ejecutar acciones sin
supervisión, o ser manipulado por un texto malicioso escondido dentro de un log
(inyección de instrucciones o _prompt injection_).

**Pregunta problema:** ¿cómo centralizar y clasificar los eventos de una red
multimarca para detectar incidentes a tiempo, garantizando que ninguna acción
sugerida por un agente de IA se ejecute sin aprobación humana?

## 2. Objetivos

### Objetivo general

Desarrollar un sistema NOC basado en Syslog que centralice, clasifique y
visualice los eventos de equipos Cisco, Fortinet y Huawei, e incorpore controles
de defensa frente a acciones de agentes de IA.

### Objetivos específicos

1. Mantener un inventario editable de los equipos de red.
2. Recibir o importar mensajes Syslog y clasificarlos por equipo, fabricante,
   fecha, facility y severidad (0 a 7).
3. Presentar un dashboard con el estado de los equipos, los eventos recientes,
   los críticos y los incidentes.
4. Gestionar incidentes: creación, asignación, seguimiento y cierre.
5. Generar configuraciones Syslog comentadas para Cisco, Fortinet y Huawei.
6. Ofrecer una consola simulada de solo lectura con comandos permitidos y
   bloqueados.
7. Definir una política de defensa frente a acciones de agentes de IA, con
   aprobación humana obligatoria y auditoría.

## 3. Alcance

### Incluye (v0.2.0 MVP)

- Aplicación web con backend en Python (FastAPI) y base de datos SQLite.
- Equipos y mensajes **simulados**, claramente identificados como tales.
- Direcciones IP de documentación (RFC 5737), nunca IP reales de producción.
- Registro de auditoría de todas las acciones sobre los datos.

### No incluye (queda para v1.0.0 o fuera del proyecto)

- Conexión a equipos reales en producción.
- Ejecución real de comandos sobre los equipos (la consola es simulada).
- Autenticación de usuarios con roles (se plantea para v1.0.0).
- Despliegue en internet (se realiza en el Corte 3).

## 4. Requisitos

### Requisitos funcionales

| ID    | Requisito                                                                                   |
| ----- | ------------------------------------------------------------------------------------------- |
| RF-01 | Crear, consultar, editar y eliminar equipos del inventario.                                 |
| RF-02 | Recibir o importar mensajes Syslog, identificando si son simulados o reales.                |
| RF-03 | Clasificar cada evento por equipo, fabricante, fecha, facility y severidad (0-7).           |
| RF-04 | Mostrar un dashboard con equipos, eventos recientes, críticos e incidentes.                 |
| RF-05 | Filtrar eventos por fecha, marca, equipo y severidad.                                       |
| RF-06 | Crear, asignar, dar seguimiento y cerrar incidentes.                                        |
| RF-07 | Generar configuraciones Syslog comentadas para Cisco, Fortinet y Huawei.                    |
| RF-08 | Ofrecer una consola simulada de solo lectura con lista de comandos permitidos y bloqueados. |
| RF-09 | Exigir aprobación humana para toda acción propuesta, y registrarla en auditoría.            |

### Requisitos no funcionales

| ID     | Requisito                                                                                |
| ------ | ---------------------------------------------------------------------------------------- |
| RNF-01 | **Seguridad:** los logs se tratan como datos no confiables, nunca como instrucciones.    |
| RNF-02 | **Seguridad:** sin contraseñas, tokens ni secretos en el código.                         |
| RNF-03 | **Integridad:** la base de datos rechaza valores inválidos (ej. severidad fuera de 0-7). |
| RNF-04 | **Trazabilidad:** toda modificación queda en el registro de auditoría.                   |
| RNF-05 | **Usabilidad:** interfaz responsiva, utilizable en computador y celular.                 |
| RNF-06 | **Mantenibilidad:** código comentado y versionado en GitHub.                             |
| RNF-07 | **Portabilidad:** cambiar de SQLite a PostgreSQL solo modificando `DATABASE_URL`.        |

## 5. Limitaciones

- Los datos son simulados; el comportamiento con tráfico real puede variar.
- SQLite es adecuada para un solo usuario o pocos usuarios, no para alto volumen.
- El proyecto es individual y tiene un tiempo limitado por los cortes académicos.
- Se usa el protocolo Syslog sobre UDP, que no garantiza la entrega de mensajes
  ni los cifra.

## 6. Versiones del proyecto

| Momento | Versión     | Propósito                                                  |
| ------- | ----------- | ---------------------------------------------------------- |
| Inicio  | v0.1.0 alfa | Base del proyecto: estructura, modelo de datos y servidor. |
| Corte 2 | v0.2.0 MVP  | Demostrar el flujo esencial de extremo a extremo.          |
| Corte 3 | v1.0.0      | Herramienta madura, asegurada y desplegada.                |
