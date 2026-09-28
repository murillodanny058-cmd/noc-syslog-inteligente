# Manual de usuario — NOC Syslog Inteligente v0.2.0

> Todos los equipos, direcciones IP y eventos son **SIMULADOS**.

## 1. Requisitos

- Windows 10/11 (también funciona en Linux o macOS).
- Python 3.11 o superior, con la opción "Add Python to PATH".
- Git.
- Un navegador moderno (Chrome, Edge o Firefox).

## 2. Instalación (solo la primera vez)

```powershell
git clone https://github.com/murillodanny058-cmd/noc-syslog-inteligente.git
cd noc-syslog-inteligente
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m backend.scripts.init_db
```

Si PowerShell bloquea la activación del entorno, ejecute primero:
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.

## 3. Iniciar y detener el sistema

```powershell
.\venv\Scripts\Activate.ps1
uvicorn backend.app.main:app --reload
```

- Dashboard: http://127.0.0.1:8000/
- Documentación de la API: http://127.0.0.1:8000/docs
- Para detenerlo: `Ctrl + C` en la terminal.

## 4. Uso del dashboard

### 4.1 Resumen

Muestra tarjetas con equipos, eventos, críticos (0 a 3), sospechosos e
incidentes abiertos; un gráfico por severidad (0 a 7); el semáforo de equipos
(rojo: eventos críticos, gris: en mantenimiento) y las listas de críticos y de
posibles inyecciones para IA. Se actualiza cada 15 segundos.
El botón **Simular tráfico** genera 30 mensajes de los tres fabricantes, más un
ataque de fuerza bruta y un intento de inyección.

### 4.2 Eventos

Filtre por fecha (desde y hasta), marca, equipo, severidad máxima o solo
sospechosos, y presione **Filtrar**. El botón **Crear incidente** de cada fila
convierte el evento en un incidente.

### 4.3 Incidentes

- **+ Nuevo incidente manual:** título, severidad, equipo y responsable.
- Los botones cambian según el estado: **Asignar** (abierto), **Iniciar trabajo**
  (asignado) y **Cerrar** (exige una resolución de al menos 10 caracteres).
- Un incidente cerrado no se puede modificar.

### 4.4 Inventario

Agregue, edite o elimine equipos. Los equipos simulados deben usar IP de
documentación: 192.0.2.x, 198.51.100.x o 203.0.113.x. Un equipo con eventos o
incidentes no se puede eliminar: márquelo como **inactivo**.

### 4.5 Configuraciones

Elija un equipo del inventario (o escriba los datos), el servidor NOC, puerto,
protocolo, severidad mínima, facility, interfaz y NTP. Presione **Generar
configuración**. Revise las **advertencias**, use **Copiar** y haga clic en un
comando de **Verificación** para probarlo en la consola.

### 4.6 Consola

Elija el equipo y quién escribe (**Operador** o **Agente de IA**). Escriba
`help` para ver los comandos permitidos. Use las flechas ↑ ↓ para el historial.
Colores: verde (lo escrito), blanco (respuesta), rojo (bloqueado), naranja
(inválido) y amarillo (no permitido). La consola es de solo lectura.

## 5. Recepción Syslog por red (UDP)

```powershell
# Terminal A: receptor (puerto 5514, lista permitida por defecto)
python -m backend.scripts.syslog_udp_listener

# Terminal B: emisor de prueba (5 formatos, fuerza bruta e inyección)
python -m backend.scripts.enviar_syslog_prueba

# Prueba del control de tormentas (150 mensajes distintos)
python -m backend.scripts.prueba_tormenta
```

Opciones del receptor: `--puerto`, `--host`, `--tipo real` y
`--permitidas 192.0.2.0/24` (redes autorizadas separadas por comas).

## 6. Acceso desde un celular (red doméstica)

```powershell
uvicorn backend.app.main:app --reload --host 0.0.0.0
```

En el celular, conectado a la misma Wi-Fi, abra `http://<IP-del-PC>:8000`
(consúltela con `ipconfig`). **Advertencia:** la v0.2.0 no tiene usuarios ni
contraseñas; úselo solo en redes de confianza.

## 7. Reiniciar los datos

Detenga el servidor, borre el archivo `data/noc_syslog.db` y ejecute:

```powershell
python -m backend.scripts.init_db
```

## 8. Solución de problemas

| Mensaje                      | Solución                                                            |
| ---------------------------- | ------------------------------------------------------------------- |
| `uvicorn no se reconoce`     | Active el entorno virtual.                                          |
| `No module named 'backend'`  | Ejecute los comandos desde la carpeta del proyecto.                 |
| `address already in use`     | Ya hay un servidor encendido: cierre la otra terminal.              |
| La página se ve sin estilos  | Recargue con `Ctrl + F5`.                                           |
| El celular no abre la página | Use `--host 0.0.0.0`, la IP del Wi-Fi y marque la red como privada. |

<!-- FIN MANUAL -->
