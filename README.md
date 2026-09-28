# 📡 NOC Syslog Inteligente

Sistema NOC (Centro de Operaciones de Red) basado en Syslog, con defensa frente
a acciones de agentes de inteligencia artificial.

> Proyecto académico · Administración y Gestión de Redes · 2026-2
> **Autor:** Dany Murillo · **Docente:** Ing. John Harold Pérez Calderón
> **Versión:** v0.2.0 (MVP) · ⚠️ Todos los equipos, IP y eventos son **SIMULADOS** (IP RFC 5737).

![Dashboard](docs/evidencias/C46_fase4_resumen.png)

## Funcionalidades

- **Inventario editable** de equipos Cisco, Fortinet y Huawei.
- **Recepción Syslog** por UDP (con lista permitida), importación y simulación.
- **Parser multimarca:** RFC 3164, RFC 5424, Cisco IOS, Huawei VRP y Fortinet FortiOS.
- **Clasificación** por equipo, fabricante, fecha, facility y severidad (0 a 7).
- **Dashboard responsivo** con filtros, semáforo de equipos y alertas.
- **Incidentes:** creación, asignación, seguimiento y cierre.
- **Generador de configuraciones** Syslog comentadas.
- **Consola tipo PuTTY** de solo lectura, con comandos permitidos y bloqueados.
- **Política de defensa ante IA:** aprobación humana, suspensión automática y auditoría.

![Consola](docs/evidencias/C69_fase5_sesion_cisco.png)

## Seguridad

| Amenaza | Defensa |
|---|---|
| Instrucciones para IA escondidas en logs | Logs tratados como datos + detección de inyección |
| XSS a través de los logs | Escape de HTML en el navegador |
| Inyección de configuración | Patrones de caracteres permitidos |
| Comandos peligrosos | Consola de solo lectura, denegar por defecto |
| Agente de IA manipulado | Aprobación humana y suspensión automática |
| Inundación de logs | Deduplicación y control de tormentas |

## Instalación rápida

```powershell
git clone https://github.com/murillodanny058-cmd/noc-syslog-inteligente.git
cd noc-syslog-inteligente
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m backend.scripts.init_db
uvicorn backend.app.main:app --reload
```

Abra http://127.0.0.1:8000/ (dashboard) o http://127.0.0.1:8000/docs (API).

## Tecnologías

Python · FastAPI · SQLAlchemy · SQLite · HTML, CSS y JavaScript (sin frameworks) · Git y GitHub

## Documentación

| Documento | Contenido |
|---|---|
| [Planteamiento](docs/01_planteamiento.md) | Problema, objetivos, alcance, requisitos y limitaciones |
| [Modelo de datos](docs/02_modelo_datos.md) | Tablas, relaciones y restricciones |
| [Historias de usuario](docs/03_historias_usuario.md) | HU-01 a HU-21 con criterios de aceptación |
| [Pruebas funcionales](docs/04_pruebas_funcionales.md) | 84 pruebas, todas exitosas |
| [Arquitectura](docs/05_arquitectura.md) | Diagramas de arquitectura y flujos |
| [Política de defensa ante IA](docs/06_politica_defensa_ia.md) | Reglas, controles y respuesta |
| [Manual de usuario](docs/07_manual_usuario.md) | Instalación y uso paso a paso |
| [Índice de evidencias](docs/08_indice_evidencias.md) | Capturas C01 a C71 |
| [Registro de cambios](CHANGELOG.md) | Historial por versión |

## Versiones

| Momento | Versión | Estado |
|---|---|---|
| Inicio | v0.1.0 alfa | ✅ Entregada |
| Corte 2 | v0.2.0 MVP | ✅ Entregada |
| Corte 3 | v1.0.0 | ⏳ Marcha blanca, seguridad y despliegue |

<!-- FIN README -->