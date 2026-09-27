# Pruebas funcionales — NOC Syslog Inteligente

Todas las pruebas se realizaron en entorno local (http://127.0.0.1:8000/docs)
con datos **simulados**. Las capturas están en la carpeta `docs/evidencias/`.

> Las pruebas marcadas como **negativas** verifican que el sistema **rechace**
> datos incorrectos. Se consideran exitosas cuando el sistema responde con el
> error esperado.

## Fase 1 — Estructura y base de datos (v0.1.0 alfa)

| ID       | Prueba                          | Resultado esperado             | Resultado  | Captura |
| -------- | ------------------------------- | ------------------------------ | ---------- | ------- |
| PF-F1-01 | Crear base de datos (`init_db`) | 5 tablas y 4 equipos simulados | ✅ Exitosa | C01     |
| PF-F1-02 | Iniciar servidor                | `Application startup complete` | ✅ Exitosa | C02     |
| PF-F1-03 | GET `/api/health`               | 200, `status: ok`              | ✅ Exitosa | C03     |
| PF-F1-04 | `git status`                    | Sin `venv/` ni base de datos   | ✅ Exitosa | C04     |
| PF-F1-05 | Publicación en GitHub           | Repositorio con archivos       | ✅ Exitosa | C05     |
| PF-F1-06 | Etiqueta de versión             | Tag `v0.1.0` en GitHub         | ✅ Exitosa | C06     |

## Fase 2 — Inventario de equipos (CRUD)

| ID    | HU    | Tipo     | Prueba                     | Entrada                             | Esperado                                 | Resultado | Captura |
| ----- | ----- | -------- | -------------------------- | ----------------------------------- | ---------------------------------------- | --------- | ------- |
| PF-01 | HU-01 | Positiva | Listar equipos             | GET `/api/devices`                  | 200, lista de equipos                    | ✅        | C07     |
| PF-02 | HU-01 | Positiva | Filtrar por marca          | `vendor=Cisco`                      | 200, 2 equipos                           | ✅        | C08     |
| PF-03 | HU-02 | Positiva | Crear equipo               | SIM-DIST-SW03, 192.0.2.50           | 201, equipo con id 5                     | ✅        | C09     |
| PF-04 | HU-02 | Negativa | Nombre duplicado           | SIM-DIST-SW03 otra vez              | 409, "Ya existe un equipo..."            | ✅        | C10     |
| PF-05 | HU-02 | Negativa | IP con formato inválido    | 192.0.2.999                         | 422, "Dirección IP inválida"             | ✅        | C11     |
| PF-06 | HU-02 | Negativa | IP real en equipo simulado | 8.8.8.8                             | 422, "debe usar una IP de documentación" | ✅        | C12     |
| PF-07 | HU-03 | Positiva | Editar marca y estado      | id 5, Huawei, mantenimiento         | 200, campos cambiados                    | ✅        | C13     |
| PF-08 | HU-04 | Positiva | Eliminar equipo            | id 5                                | 204, sin contenido                       | ✅        | C14     |
| PF-09 | HU-04 | Negativa | Consultar equipo eliminado | id 5                                | 404, "No existe un equipo con id 5"      | ✅        | C15     |
| PF-10 | HU-05 | Positiva | Consultar auditoría        | GET `/api/audit`                    | 200, SEED, CREATE, UPDATE, DELETE        | ✅        | C16     |
| PF-11 | HU-01 | Positiva | Filtros combinados         | `vendor=Cisco&estado=mantenimiento` | 200, 1 equipo                            | ✅        | C17     |

**Resumen Fase 2:** 11 pruebas ejecutadas, 11 exitosas (7 positivas y 4 negativas).

### Observaciones

- **Defensa en profundidad:** la IP inválida (PF-05) la rechaza el esquema de
  validación (`schemas.py`), y la IP real (PF-06) la rechaza la regla de negocio
  (`devices.py`). Son dos capas de validación independientes.
- **Trazabilidad:** la auditoría conserva el historial del equipo eliminado,
  incluidos los valores anteriores y nuevos de cada cambio.
- **Mejora identificada:** los intentos rechazados (PF-04, PF-05, PF-06) no
  quedan en la auditoría. Registrarlos permitiría detectar intentos repetidos
  de un atacante o de un agente de IA. Se abordará en la política de defensa.
