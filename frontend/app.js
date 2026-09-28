"use strict";
/*
 * NOC Syslog Inteligente — lógica del dashboard.
 * JavaScript puro (sin frameworks). Se comunica con la API en /api.
 *
 * REGLA DE SEGURIDAD: todo texto que viene de la API (sobre todo los mensajes
 * de los logs) se ESCAPA con la función esc() antes de mostrarlo. Así, si un
 * atacante mete código HTML o JavaScript dentro de un log, se muestra como
 * texto y nunca se ejecuta en el navegador (protección contra XSS).
 */

const SEVERIDADES = [
  "Emergency",
  "Alert",
  "Critical",
  "Error",
  "Warning",
  "Notice",
  "Informational",
  "Debug",
];
const NOMBRE_ESTADO = {
  abierto: "Abierto",
  asignado: "Asignado",
  en_progreso: "En progreso",
  cerrado: "Cerrado",
};
const ACTUALIZAR_CADA_MS = 15000; // el resumen se refresca solo cada 15 segundos

let equipos = []; // copia local del inventario
let vistaActual = "resumen";

// ===========================================================================
// Utilidades
// ===========================================================================
const $ = (selector) => document.querySelector(selector);

/** Convierte < > & " ' en texto seguro. NUNCA mostrar datos sin pasar por aquí. */
function esc(valor) {
  return String(valor ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
}

/** La API guarda las fechas en UTC; aquí se muestran en la hora local (Colombia). */
function fecha(iso) {
  if (!iso) return "—";
  let texto = String(iso).replace(/(\.\d{3})\d+/, "$1"); // máximo 3 decimales
  if (!/([zZ]|[+-]\d\d:\d\d)$/.test(texto)) texto += "Z"; // marcar como UTC
  return new Date(texto).toLocaleString("es-CO", {
    dateStyle: "short",
    timeStyle: "medium",
  });
}

/** Llama a la API y devuelve el JSON. Si hay error, lanza el mensaje del servidor. */
async function api(ruta, opciones = {}) {
  const respuesta = await fetch("/api" + ruta, {
    ...opciones,
    headers: {
      "Content-Type": "application/json",
      ...(opciones.headers || {}),
    },
  });
  if (respuesta.status === 204) return null;
  const datos = await respuesta.json().catch(() => ({}));
  if (!respuesta.ok) {
    let mensaje = datos.detail;
    if (Array.isArray(mensaje)) mensaje = mensaje.map((e) => e.msg).join(" · ");
    throw new Error(mensaje || `Error ${respuesta.status}`);
  }
  return datos;
}

/** Muestra un mensaje emergente abajo a la derecha. */
function aviso(texto, tipo = "ok") {
  const div = document.createElement("div");
  div.className = `aviso ${tipo}`;
  div.textContent = texto; // textContent nunca interpreta HTML
  $("#avisos").appendChild(div);
  setTimeout(() => div.remove(), 5000);
}

function insigniaSeveridad(n) {
  const s = Number(n);
  return `<span class="sev s${s}">${s} ${SEVERIDADES[s] ?? "?"}</span>`;
}

function nombreEquipo(id) {
  const equipo = equipos.find((e) => e.id === id);
  return equipo ? equipo.name : null;
}

function marcarConexion(ok) {
  $("#indicador").className = "punto " + (ok ? "ok" : "error");
  $("#actualizado").textContent = ok
    ? `Actualizado ${new Date().toLocaleTimeString("es-CO")}`
    : "Sin conexión con el servidor";
}

// ===========================================================================
// Navegación entre pestañas
// ===========================================================================
function mostrarVista(nombre) {
  if (!CARGADORES[nombre]) nombre = "resumen";
  vistaActual = nombre;
  document
    .querySelectorAll(".pestana")
    .forEach((b) => b.classList.toggle("activa", b.dataset.vista === nombre));
  document
    .querySelectorAll(".vista")
    .forEach((v) => v.classList.toggle("activa", v.id === `vista-${nombre}`));
  history.replaceState(null, "", `#${nombre}`);
  CARGADORES[nombre]();
}

// ===========================================================================
// VISTA 1: Resumen
// ===========================================================================
function tarjeta(titulo, numero, detalle, color = "") {
  return `<div class="tarjeta ${color}">
      <div class="titulo">${esc(titulo)}</div>
      <div class="numero">${esc(numero)}</div>
      <div class="detalle">${esc(detalle)}</div>
    </div>`;
}

function itemEvento(e) {
  const origen = nombreEquipo(e.device_id) || e.hostname || e.source_ip;
  const repeticiones =
    e.repeat_count > 1
      ? `<span class="rep">×${Number(e.repeat_count)}</span>`
      : "";
  return `<div class="item">
      <div class="item-cab">${insigniaSeveridad(e.severity)} <strong>${esc(origen)}</strong> ${repeticiones}
        <span class="tenue">${esc(fecha(e.received_at))}</span></div>
      <div class="item-msg">${esc(e.message)}</div>
    </div>`;
}

async function cargarResumen() {
  try {
    const r = await api("/dashboard/resumen");
    marcarConexion(true);
    const ev = r.eventos;
    const inc = r.incidentes;
    const eq = r.equipos;

    // Tarjetas
    $("#tarjetas").innerHTML = [
      tarjeta(
        "Equipos",
        eq.total,
        `${eq.por_estado.activo || 0} activos · ${eq.por_estado.mantenimiento || 0} en mantenimiento`,
      ),
      tarjeta(
        "Eventos",
        ev.total_eventos,
        `${ev.total_mensajes} mensajes · ${ev.ultima_hora} en la última hora`,
      ),
      tarjeta(
        "Críticos (0 a 3)",
        ev.criticos_0_a_3,
        "Requieren atención",
        ev.criticos_0_a_3 ? "rojo" : "",
      ),
      tarjeta(
        "Sospechosos",
        ev.sospechosos,
        "Posible inyección para IA",
        ev.sospechosos ? "morado" : "",
      ),
      tarjeta(
        "Incidentes abiertos",
        inc.abiertos,
        `${inc.total} en total`,
        inc.abiertos ? "naranja" : "",
      ),
    ].join("");

    // Gráfico de barras por severidad (0 a 7)
    const maximo = Math.max(1, ...ev.por_severidad.map((s) => s.eventos));
    $("#grafico-severidad").innerHTML = ev.por_severidad
      .map(
        (s) => `
      <div class="barra-fila">
        <span>${insigniaSeveridad(s.severidad)}</span>
        <div class="barra-pista">
          <div class="barra s${Number(s.severidad)}" style="width:${(Number(s.eventos) / maximo) * 100}%"></div>
        </div>
        <span class="barra-valor">${Number(s.eventos)}</span>
      </div>`,
      )
      .join("");

    // Semáforo de equipos
    $("#lista-equipos").innerHTML =
      eq.detalle
        .map((d) => {
          let color = "verde";
          let texto = "Sin eventos críticos";
          if (d.status !== "activo") {
            color = "gris";
            texto =
              `En ${d.status}` +
              (d.criticos_24h ? ` · ${d.criticos_24h} críticos` : "");
          } else if (d.criticos_24h > 0) {
            color = "rojo";
            texto = `${d.criticos_24h} eventos críticos`;
          }
          return `<div class="equipo">
          <span class="semaforo ${color}"></span>
          <div class="equipo-info">
            <strong>${esc(d.name)}</strong>
            <small>${esc(d.ip_address)} · ${esc(d.vendor)} · ${esc(texto)}</small>
          </div>
          <div class="equipo-cifras">${Number(d.eventos_24h)} eventos<br>${esc(fecha(d.ultimo_evento))}</div>
        </div>`;
        })
        .join("") || `<p class="vacio">No hay equipos</p>`;

    // Listas de críticos y sospechosos
    $("#lista-criticos").innerHTML =
      r.criticos_recientes.map(itemEvento).join("") ||
      `<p class="vacio">Sin eventos críticos</p>`;
    $("#lista-sospechosos").innerHTML =
      r.sospechosos_recientes.map(itemEvento).join("") ||
      `<p class="vacio">Ninguno detectado</p>`;
  } catch (error) {
    marcarConexion(false);
  }
}

async function simularTrafico() {
  const boton = $("#btn-simular");
  boton.disabled = true;
  try {
    const r = await api("/syslog/simulate?cantidad=30&incluir_ataques=true", {
      method: "POST",
    });
    aviso(
      `Simulación: ${r.total} mensajes → ${r.nuevo} nuevos, ${r.duplicado} duplicados, ${r.sospechosos} sospechosos`,
    );
    await cargarResumen();
  } catch (error) {
    aviso(error.message, "error");
  } finally {
    boton.disabled = false;
  }
}

// ===========================================================================
// VISTA 2: Eventos con filtros
// ===========================================================================
function filaEvento(e) {
  const equipo = nombreEquipo(e.device_id);
  const origen = equipo
    ? `<strong>${esc(equipo)}</strong>`
    : `${esc(e.hostname || "—")}<br><span class="tenue">${esc(e.source_ip)} · no registrado</span>`;
  const ia = e.flagged_suspicious
    ? `<br><span class="etiqueta-ia">⚠ POSIBLE INYECCIÓN IA</span>`
    : "";
  return `<tr class="${e.flagged_suspicious ? "sospechoso" : ""}">
      <td>${esc(fecha(e.received_at))}</td>
      <td>${insigniaSeveridad(e.severity)}</td>
      <td>${origen}</td>
      <td>${esc(e.vendor || "—")}</td>
      <td>${esc(e.app_name || "—")}</td>
      <td class="msg">${esc(e.message)}${ia}</td>
      <td>${Number(e.repeat_count)}</td>
      <td><button class="btn mini secundario" data-crear-incidente="${Number(e.id)}">Crear incidente</button></td>
    </tr>`;
}

async function cargarEventos() {
  const f = new FormData($("#filtros-eventos"));
  const p = new URLSearchParams({ limite: 200 });
  for (const campo of ["vendor", "device_id", "severidad_max"]) {
    if (f.get(campo)) p.set(campo, f.get(campo));
  }
  for (const campo of ["desde", "hasta"]) {
    if (f.get(campo)) p.set(campo, new Date(f.get(campo)).toISOString()); // hora local -> UTC
  }
  if (f.get("solo_sospechosos")) p.set("solo_sospechosos", "true");

  try {
    const eventos = await api(`/events?${p}`);
    $("#conteo-eventos").textContent =
      `${eventos.length} eventos (máximo 200, del más reciente al más antiguo)`;
    $("#tabla-eventos").innerHTML =
      eventos.map(filaEvento).join("") ||
      `<tr><td colspan="8" class="vacio">No hay eventos con esos filtros</td></tr>`;
  } catch (error) {
    aviso(error.message, "error");
  }
}

async function crearIncidenteDesdeEvento(idEvento) {
  try {
    const inc = await api(`/incidents/from-event/${idEvento}`, {
      method: "POST",
    });
    aviso(`Incidente #${inc.id} creado. Revíselo en la pestaña Incidentes.`);
  } catch (error) {
    aviso(error.message, "error");
  }
}

// ===========================================================================
// VISTA 3: Incidentes
// ===========================================================================
function tarjetaIncidente(i) {
  const id = Number(i.id);
  const acciones = [];
  if (i.status === "abierto") {
    acciones.push(
      `<button class="btn mini" data-accion="asignar" data-id="${id}">Asignar</button>`,
    );
  }
  if (i.status === "asignado") {
    acciones.push(
      `<button class="btn mini" data-accion="iniciar" data-id="${id}">Iniciar trabajo</button>`,
    );
  }
  if (i.status !== "cerrado") {
    acciones.push(
      `<button class="btn mini secundario" data-accion="cerrar" data-id="${id}">Cerrar</button>`,
    );
  }
  const equipo = nombreEquipo(i.device_id);
  return `<article class="incidente">
      <div class="item-cab">
        <span class="estado ${esc(i.status)}">${esc(NOMBRE_ESTADO[i.status] || i.status)}</span>
        ${insigniaSeveridad(i.severity)} <span class="tenue">#${id}</span>
      </div>
      <h3>${esc(i.title)}</h3>
      ${i.description ? `<p class="meta">${esc(i.description)}</p>` : ""}
      <p class="meta">
        Responsable: <strong>${esc(i.assigned_to || "sin asignar")}</strong>${equipo ? ` · Equipo: ${esc(equipo)}` : ""}<br>
        Creado: ${esc(fecha(i.created_at))}${i.closed_at ? ` · Cerrado: ${esc(fecha(i.closed_at))}` : ""}
      </p>
      ${i.resolution ? `<div class="resolucion"><strong>Resolución:</strong> ${esc(i.resolution)}</div>` : ""}
      ${acciones.length ? `<div class="botones">${acciones.join("")}</div>` : ""}
    </article>`;
}

async function cargarIncidentes() {
  const estado = $("#filtro-estado").value;
  try {
    const lista = await api(
      `/incidents${estado ? `?estado=${encodeURIComponent(estado)}` : ""}`,
    );
    $("#lista-incidentes").innerHTML =
      lista.map(tarjetaIncidente).join("") ||
      `<p class="vacio">No hay incidentes</p>`;
  } catch (error) {
    aviso(error.message, "error");
  }
}

async function accionIncidente(accion, id) {
  let cambios;
  if (accion === "asignar") {
    const nombre = prompt("¿Quién se hace responsable de este incidente?");
    if (!nombre) return;
    cambios = { assigned_to: nombre.trim() };
  } else if (accion === "iniciar") {
    cambios = { status: "en_progreso" };
  } else if (accion === "cerrar") {
    const resolucion = prompt("Describa la resolución (mínimo 10 caracteres):");
    if (!resolucion) return;
    cambios = { status: "cerrado", resolution: resolucion.trim() };
  } else {
    return;
  }
  try {
    await api(`/incidents/${Number(id)}`, {
      method: "PUT",
      body: JSON.stringify(cambios),
    });
    aviso(`Incidente #${id} actualizado`);
    cargarIncidentes();
  } catch (error) {
    aviso(error.message, "error"); // aquí se ven las reglas del servidor (ej. resolución corta)
  }
}

async function crearIncidenteManual(evento) {
  evento.preventDefault();
  const form = evento.target;
  const f = new FormData(form);
  const datos = {
    title: f.get("title").trim(),
    severity: Number(f.get("severity")),
  };
  if (f.get("device_id")) datos.device_id = Number(f.get("device_id"));
  if (f.get("assigned_to").trim())
    datos.assigned_to = f.get("assigned_to").trim();
  if (f.get("description").trim())
    datos.description = f.get("description").trim();
  try {
    const inc = await api("/incidents", {
      method: "POST",
      body: JSON.stringify(datos),
    });
    aviso(`Incidente #${inc.id} creado (${inc.status})`);
    form.reset();
    cargarIncidentes();
  } catch (error) {
    aviso(error.message, "error");
  }
}

// ===========================================================================
// VISTA 4: Inventario
// ===========================================================================
async function cargarEquipos() {
  equipos = await api("/devices");
  // Llena las listas desplegables de equipos (new Option escribe texto seguro)
  document.querySelectorAll(".select-equipos").forEach((select) => {
    const primera = select.options[0];
    select.innerHTML = "";
    select.appendChild(primera);
    equipos.forEach((d) => select.appendChild(new Option(d.name, d.id)));
  });
}

async function cargarInventario() {
  try {
    await cargarEquipos();
    $("#tabla-equipos").innerHTML =
      equipos
        .map(
          (d) => `
      <tr>
        <td><strong>${esc(d.name)}</strong></td>
        <td>${esc(d.ip_address)}</td>
        <td>${esc(d.vendor)}</td>
        <td>${esc(d.model || "—")}</td>
        <td>${esc(d.os_version || "—")}</td>
        <td>${esc(d.location || "—")}</td>
        <td><span class="estado-equipo ${esc(d.status)}">${esc(d.status)}</span></td>
        <td>${esc(fecha(d.updated_at))}</td>
        <td><div class="botones">
          <button class="btn mini secundario" data-editar="${Number(d.id)}">Editar</button>
          <button class="btn mini peligro" data-eliminar="${Number(d.id)}">Eliminar</button>
        </div></td>
      </tr>`,
        )
        .join("") ||
      `<tr><td colspan="9" class="vacio">No hay equipos</td></tr>`;
  } catch (error) {
    aviso(error.message, "error");
  }
}

function editarEquipo(id) {
  const d = equipos.find((e) => e.id === id);
  if (!d) return;
  const form = $("#form-equipo");
  for (const campo of [
    "id",
    "name",
    "ip_address",
    "vendor",
    "model",
    "os_version",
    "location",
    "status",
  ]) {
    form.elements[campo].value = d[campo] ?? "";
  }
  $("#titulo-form-equipo").textContent = `Editar equipo: ${d.name}`;
  form.scrollIntoView({ behavior: "smooth" });
}

function limpiarFormEquipo() {
  const form = $("#form-equipo");
  form.reset();
  form.elements.id.value = "";
  $("#titulo-form-equipo").textContent = "Agregar equipo";
}

async function guardarEquipo(evento) {
  evento.preventDefault();
  const f = new FormData(evento.target);
  const id = f.get("id");
  const datos = {};
  for (const campo of [
    "name",
    "ip_address",
    "vendor",
    "model",
    "os_version",
    "location",
    "status",
  ]) {
    const valor = String(f.get(campo) ?? "").trim();
    if (valor) datos[campo] = valor;
  }
  try {
    if (id) {
      await api(`/devices/${Number(id)}`, {
        method: "PUT",
        body: JSON.stringify(datos),
      });
    } else {
      await api("/devices", { method: "POST", body: JSON.stringify(datos) });
    }
    aviso(id ? "Equipo actualizado" : "Equipo creado");
    limpiarFormEquipo();
    cargarInventario();
  } catch (error) {
    aviso(error.message, "error"); // ej.: IP real en equipo simulado, nombre duplicado
  }
}

async function eliminarEquipo(id) {
  const d = equipos.find((e) => e.id === id);
  if (
    !confirm(
      `¿Eliminar el equipo ${d ? d.name : id}? La acción queda registrada en la auditoría.`,
    )
  )
    return;
  try {
    await api(`/devices/${id}`, { method: "DELETE" });
    aviso("Equipo eliminado");
    cargarInventario();
  } catch (error) {
    aviso(error.message, "error"); // ej.: tiene eventos asociados
  }
}

// ===========================================================================
// Arranque
// ===========================================================================
const CARGADORES = {
  resumen: cargarResumen,
  eventos: cargarEventos,
  incidentes: cargarIncidentes,
  inventario: cargarInventario,
};

function llenarSelectsSeveridad() {
  document.querySelectorAll(".select-severidad").forEach((select) => {
    const tieneOpcionVacia = select.options.length > 0; // "Todas"
    SEVERIDADES.forEach((nombre, n) => {
      const porDefecto = !tieneOpcionVacia && n === 3; // formularios: 3 (Error) por defecto
      select.appendChild(
        new Option(`${n} - ${nombre}`, n, porDefecto, porDefecto),
      );
    });
  });
}

function conectarEventos() {
  document
    .querySelectorAll(".pestana")
    .forEach((b) =>
      b.addEventListener("click", () => mostrarVista(b.dataset.vista)),
    );
  $("#btn-simular").addEventListener("click", simularTrafico);

  $("#filtros-eventos").addEventListener("submit", (e) => {
    e.preventDefault();
    cargarEventos();
  });
  $("#filtros-eventos").addEventListener("reset", () =>
    setTimeout(cargarEventos, 0),
  );
  $("#tabla-eventos").addEventListener("click", (e) => {
    const boton = e.target.closest("[data-crear-incidente]");
    if (boton) crearIncidenteDesdeEvento(boton.dataset.crearIncidente);
  });

  $("#filtro-estado").addEventListener("change", cargarIncidentes);
  $("#form-incidente").addEventListener("submit", crearIncidenteManual);
  $("#lista-incidentes").addEventListener("click", (e) => {
    const boton = e.target.closest("[data-accion]");
    if (boton) accionIncidente(boton.dataset.accion, boton.dataset.id);
  });

  $("#form-equipo").addEventListener("submit", guardarEquipo);
  $("#btn-cancelar-equipo").addEventListener("click", limpiarFormEquipo);
  $("#tabla-equipos").addEventListener("click", (e) => {
    const editar = e.target.closest("[data-editar]");
    const eliminar = e.target.closest("[data-eliminar]");
    if (editar) editarEquipo(Number(editar.dataset.editar));
    if (eliminar) eliminarEquipo(Number(eliminar.dataset.eliminar));
  });
}

async function iniciar() {
  llenarSelectsSeveridad();
  conectarEventos();
  try {
    await cargarEquipos();
  } catch {
    marcarConexion(false);
  }
  mostrarVista(location.hash.slice(1) || "resumen");
  setInterval(() => {
    if (vistaActual === "resumen") cargarResumen();
  }, ACTUALIZAR_CADA_MS);
}

document.addEventListener("DOMContentLoaded", iniciar);
