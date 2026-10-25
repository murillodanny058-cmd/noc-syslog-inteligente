"use strict";
/*
 * NOC Syslog Inteligente — Puertos e interfaces (Fase 10)
 *   - En Eventos: botón 🔌 con el puerto del evento -> qué hay conectado ahí
 *     (estado, VLAN, vecino CDP/LLDP, MAC) y otros eventos del mismo puerto.
 *   - En Inventario: botón "Puertos" -> tabla con todos los puertos del equipo.
 *
 * Usa funciones de app.js: api(), aviso(), $(), esc(), fecha(), insigniaSeveridad().
 * SEGURIDAD: todo dato que viene del equipo o del log pasa por esc().
 */

const NOMBRE_ESTADO_PUERTO = {
  up: "Conectado (up)",
  down: "Sin enlace (down)",
  "admin-down": "Apagado por config.",
  "err-disabled": "Bloqueado (err-disabled)",
  desconocido: "Desconocido",
};

/** Etiqueta de color con el estado del puerto (Conectado, Sin enlace, Apagado...). */
function insigniaPuerto(estado) {
  const e = estado || "desconocido";
  return `<span class="estado-puerto ${esc(e)}">${esc(NOMBRE_ESTADO_PUERTO[e] || e)}</span>`;
}

/** Abre la ventana de puertos con un título y su contenido. */
function abrirDialogoPuerto(titulo, html) {
  $("#dialogo-puerto-titulo").textContent = titulo;
  $("#dialogo-puerto-cuerpo").innerHTML = html; // todo dato ya pasó por esc()
  const d = $("#dialogo-puerto");
  if (!d.open) d.showModal();
}

/** Ficha HTML segura de un puerto: estado, VLAN, descripción, vecino, MAC y origen del dato. */
function fichaPuerto(p) {
  const fila = (etiqueta, valor) =>
    `<div class="ficha-fila"><span>${etiqueta}</span><strong>${valor}</strong></div>`;
  return `<div class="ficha-puerto">
      ${fila("Interfaz", `${esc(p.interfaz)} <span class="tenue">(${esc(p.corto || "")})</span>`)}
      ${fila("Estado", insigniaPuerto(p.estado))}
      ${fila("VLAN", esc(p.vlan || "—"))}
      ${fila("Descripción", esc(p.descripcion || "—"))}
      ${fila("Conectado a (CDP/LLDP)", esc(p.vecino || "— sin vecino detectado"))}
      ${fila("MAC aprendidas", `<span class="mono">${esc(p.mac || "—")}</span>`)}
      ${fila("Dato obtenido de", `${esc(p.origen)} · ${esc(fecha(p.actualizado))}`)}
    </div>`;
}

// ---------------------------------------------------------------------------
// Desde un EVENTO: ¿en qué puerto pasó?
// ---------------------------------------------------------------------------
async function verPuertoDeEvento(idEvento) {
  try {
    const r = await api(`/events/${Number(idEvento)}/port`);
    let html = `<p class="meta">Equipo: <strong>${esc(r.equipo || "—")}</strong></p>`;
    if (r.puerto) html += fichaPuerto(r.puerto);
    else if (r.interfaz)
      html += `<p class="meta">Puerto: <strong>${esc(r.interfaz)}</strong></p>`;
    if (r.nota) html += `<p class="nota">${esc(r.nota)}</p>`;
    if (r.eventos_del_puerto && r.eventos_del_puerto.length) {
      html += `<h3 class="subtitulo-panel">Últimos eventos de este puerto</h3>
        <ul class="lista-eventos-puerto">${r.eventos_del_puerto
          .map(
            (e) =>
              `<li>${insigniaSeveridad(e.severity)} <span class="tenue">${esc(fecha(e.received_at))}</span><br>${esc(e.message)}</li>`,
          )
          .join("")}</ul>`;
    }
    if (r.device_id) {
      html += `<div class="botones"><button type="button" class="btn secundario" data-ver-puertos="${Number(r.device_id)}">Ver todos los puertos del equipo</button></div>`;
    }
    abrirDialogoPuerto(`🔌 Puerto ${r.interfaz || "no identificado"}`, html);
  } catch (error) {
    aviso(error.message, "error");
  }
}

// ---------------------------------------------------------------------------
// Desde el INVENTARIO: todos los puertos del equipo
// ---------------------------------------------------------------------------
async function verPuertosEquipo(idEquipo) {
  const eq = equipos.find((e) => e.id === Number(idEquipo));
  try {
    const puertos = await api(`/devices/${Number(idEquipo)}/ports`);
    const arriba = puertos.filter((p) => p.estado === "up").length;
    let html = `<p class="meta">${puertos.length} puertos · ${arriba} conectados · ${
      eq && !eq.is_simulated
        ? "equipo REAL: los datos se leen por la consola real (solo lectura)"
        : "equipo SIMULADO: datos simulados"
    }</p>
      <div class="botones"><button type="button" class="btn" data-actualizar-puertos="${Number(idEquipo)}">Actualizar puertos</button></div>`;
    html += puertos.length
      ? `<div class="tabla-contenedor"><table class="tabla tabla-puertos">
          <thead><tr><th>Puerto</th><th>Estado</th><th>VLAN</th><th>Conectado a</th><th>MAC</th><th>Descripción</th></tr></thead>
          <tbody>${puertos
            .map(
              (p) => `<tr>
                <td><strong>${esc(p.corto || p.interfaz)}</strong></td>
                <td>${insigniaPuerto(p.estado)}</td>
                <td>${esc(p.vlan || "—")}</td>
                <td>${esc(p.vecino || "—")}</td>
                <td class="mono">${esc(p.mac || "—")}</td>
                <td>${esc(p.descripcion || "—")}</td>
              </tr>`,
            )
            .join("")}</tbody></table></div>`
      : `<p class="nota">Aún no hay puertos registrados. ${
          eq && !eq.is_simulated
            ? "Conecte el equipo en la pestaña Consola (modo REAL) y presione 'Actualizar puertos'."
            : ""
        }</p>`;
    abrirDialogoPuerto(`🔌 Puertos de ${eq ? eq.name : "equipo"}`, html);
  } catch (error) {
    aviso(error.message, "error");
  }
}

/** Botón 'Actualizar puertos' (en equipos reales se leen por la consola; puede tardar hasta 1 minuto). */
async function actualizarPuertos(idEquipo, boton) {
  boton.disabled = true;
  boton.textContent = "Leyendo puertos...";
  try {
    const r = await api(`/devices/${Number(idEquipo)}/ports/refresh`, {
      method: "POST",
    });
    aviso(`${r.equipo}: ${r.puertos} puertos actualizados (${r.origen})`);
    await verPuertosEquipo(idEquipo);
  } catch (error) {
    aviso(error.message, "error");
    boton.disabled = false;
    boton.textContent = "Actualizar puertos";
  }
}

// ---------------------------------------------------------------------------
// Eventos de la página
// ---------------------------------------------------------------------------
document.addEventListener("DOMContentLoaded", () => {
  $("#tabla-eventos").addEventListener("click", (e) => {
    const boton = e.target.closest("[data-puerto]");
    if (boton) verPuertoDeEvento(boton.dataset.puerto);
  });
  $("#tabla-equipos").addEventListener("click", (e) => {
    const boton = e.target.closest("[data-puertos]");
    if (boton) verPuertosEquipo(boton.dataset.puertos);
  });
  $("#dialogo-puerto").addEventListener("click", (e) => {
    const ver = e.target.closest("[data-ver-puertos]");
    const act = e.target.closest("[data-actualizar-puertos]");
    if (ver) verPuertosEquipo(ver.dataset.verPuertos);
    if (act) actualizarPuertos(act.dataset.actualizarPuertos, act);
    if (e.target === e.currentTarget) e.currentTarget.close(); // clic fuera = cerrar
  });
  $("#btn-cerrar-puerto").addEventListener("click", () =>
    $("#dialogo-puerto").close(),
  );
});

// --- FIN DEL ARCHIVO ---
