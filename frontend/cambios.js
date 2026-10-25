"use strict";
/*
 * NOC Syslog Inteligente — Cambios con aprobación humana (Fase 11)
 *   Propuesta -> Aprobación (otra persona) -> Respaldo + Ejecución -> Verificación -> Rollback
 *
 * Usa funciones de app.js: api(), aviso(), $(), esc(), fecha(), cargarEquipos(), equipos.
 * SEGURIDAD: el navegador NO decide nada; el servidor valida rol, estado y separación
 * de funciones. Aquí solo se muestran u ocultan botones para que sea más claro.
 */

const NOMBRE_ESTADO_CAMBIO = {
  propuesta: "Esperando aprobación",
  aprobada: "Aprobado",
  rechazada: "Rechazado",
  ejecutada: "Ejecutado",
  fallida: "Falló (revertido)",
  verificada: "Verificado ✔",
  verificacion_fallida: "Verificación falló",
  revertida: "Revertido",
};
const CAMPOS_PLANTILLA = {
  syslog_servidor: ["ip", "puerto", "nivel"],
  descripcion_puerto: ["interfaz", "descripcion"],
  estado_puerto: ["interfaz", "accion"],
};
const NOMBRE_PLANTILLA = {
  syslog_servidor: "Envío de logs al NOC",
  descripcion_puerto: "Descripción de puerto",
  estado_puerto: "Apagar / encender puerto",
};
let usuarioCambios = null; // { username, role }

function esAprobador() {
  return (
    usuarioCambios &&
    ["aprobador", "administrador"].includes(usuarioCambios.role)
  );
}

function mostrarCamposPlantilla() {
  const plantilla = $("#cam-plantilla").value;
  document.querySelectorAll("[data-campo]").forEach((label) => {
    label.hidden = !CAMPOS_PLANTILLA[plantilla].includes(label.dataset.campo);
  });
  $("#cam-previa").hidden = true;
}

function datosCambio() {
  const f = new FormData($("#form-cambio"));
  const plantilla = f.get("plantilla");
  const parametros = {};
  CAMPOS_PLANTILLA[plantilla].forEach((campo) => {
    const valor = String(f.get(campo) ?? "").trim();
    if (valor) parametros[campo] = valor;
  });
  return {
    device_id: Number(f.get("device_id")),
    plantilla,
    parametros,
    motivo: String(f.get("motivo") || "").trim(),
    origen: f.get("origen"),
  };
}

async function vistaPreviaCambio() {
  try {
    const r = await api("/changes/preview", {
      method: "POST",
      body: JSON.stringify(datosCambio()),
    });
    $("#cam-previa").hidden = false;
    $("#cam-previa-resumen").textContent = `${r.equipo}: ${r.resumen}`;
    $("#cam-previa-comandos").textContent = r.comandos.join("\n");
    $("#cam-previa-rollback").textContent = r.rollback.join("\n");
  } catch (error) {
    aviso(error.message, "error");
  }
}

async function proponerCambio(evento) {
  evento.preventDefault();
  const boton = $("#form-cambio button[type=submit]");
  if (boton.disabled) return; // v1.0.0: evita proponer dos veces con doble clic
  boton.disabled = true;
  try {
    const c = await api("/changes", {
      method: "POST",
      body: JSON.stringify(datosCambio()),
    });
    aviso(
      `Cambio #${c.id} propuesto. Debe aprobarlo OTRA persona con rol aprobador.`,
    );
    $("#cam-previa").hidden = true;
    $("#form-cambio").elements.motivo.value = "";
    await listarCambios();
  } catch (error) {
    aviso(error.message, "error");
  } finally {
    boton.disabled = false;
  }
}

function resumenParametros(c) {
  let p = {};
  try {
    p = JSON.parse(c.parametros);
  } catch {
    /* parámetros ilegibles: se muestran vacíos */
  }
  return Object.entries(p)
    .map(([k, v]) => `${k}: ${v}`)
    .join(" · ");
}

function bloqueTexto(titulo, texto) {
  return texto
    ? `<details class="detalle-cambio"><summary>${titulo}</summary><pre>${esc(texto)}</pre></details>`
    : "";
}

function tarjetaCambio(c) {
  const id = Number(c.id);
  const equipo = equipos.find((e) => e.id === c.device_id);
  const propio = usuarioCambios && usuarioCambios.username === c.propuesto_por;
  const acciones = [];
  if (c.estado === "propuesta") {
    if (esAprobador() && !propio) {
      acciones.push(
        `<button class="btn mini" data-cambio="review" data-decision="aprobada" data-id="${id}">Aprobar</button>`,
        `<button class="btn mini peligro" data-cambio="review" data-decision="rechazada" data-id="${id}">Rechazar</button>`,
      );
    } else {
      acciones.push(
        `<span class="nota">Esperando a un aprobador distinto de ${esc(c.propuesto_por)}.</span>`,
      );
    }
  }
  if (c.estado === "aprobada" && esAprobador()) {
    acciones.push(
      `<button class="btn mini" data-cambio="execute" data-id="${id}">Ejecutar (respaldo + cambio)</button>`,
    );
  }
  if (["ejecutada", "verificacion_fallida"].includes(c.estado)) {
    acciones.push(
      `<button class="btn mini" data-cambio="verify" data-id="${id}">Verificar</button>`,
    );
  }
  if (
    ["ejecutada", "verificada", "verificacion_fallida"].includes(c.estado) &&
    esAprobador()
  ) {
    acciones.push(
      `<button class="btn mini peligro" data-cambio="rollback" data-id="${id}">Deshacer (rollback)</button>`,
    );
  }
  const ia =
    c.origen === "agente_ia"
      ? ` <span class="etiqueta-ia">🤖 propuesto por agente de IA</span>`
      : "";
  return `<article class="incidente cambio">
      <div class="item-cab">
        <span class="estado cambio-${esc(c.estado)}">${esc(NOMBRE_ESTADO_CAMBIO[c.estado] || c.estado)}</span>
        <span class="tenue">#${id}</span>${c.simulado ? ' <span class="tenue">· equipo SIMULADO</span>' : ' <span class="etiqueta-real">REAL</span>'}
      </div>
      <h3>${esc(NOMBRE_PLANTILLA[c.plantilla] || c.plantilla)} · ${esc(equipo ? equipo.name : `equipo ${c.device_id}`)}</h3>
      <p class="meta">${esc(resumenParametros(c))}</p>
      <p class="meta">Motivo: ${esc(c.motivo)}${ia}</p>
      <p class="meta">Propuso: <strong>${esc(c.propuesto_por)}</strong> · ${esc(fecha(c.creado))}${
        c.aprobado_por
          ? `<br>Revisó: <strong>${esc(c.aprobado_por)}</strong> · ${esc(fecha(c.revisado))}`
          : ""
      }${c.ejecutado_por ? `<br>Ejecutó: <strong>${esc(c.ejecutado_por)}</strong> · ${esc(fecha(c.ejecutado))}` : ""}</p>
      <div class="comandos-cambio"><span class="tenue">Comandos que se envían:</span><pre>${esc(c.comandos)}</pre></div>
      <div class="comandos-cambio"><span class="tenue">Rollback (cómo deshacerlo):</span><pre>${esc(c.rollback)}</pre></div>
      ${bloqueTexto("Respaldo antes del cambio", c.respaldo)}
      ${bloqueTexto("Respuesta del equipo", c.salida)}
      ${bloqueTexto("Verificación / rollback", c.resultado)}
      ${c.nota_revision ? `<p class="meta">Nota de revisión: ${esc(c.nota_revision)}</p>` : ""}
      ${acciones.length ? `<div class="botones">${acciones.join("")}</div>` : ""}
    </article>`;
}

async function listarCambios() {
  try {
    const cambios = await api("/changes");
    $("#lista-cambios").innerHTML =
      cambios.map(tarjetaCambio).join("") ||
      `<p class="vacio">Todavía no hay cambios propuestos.</p>`;
  } catch (error) {
    aviso(error.message, "error");
  }
}

async function accionCambio(accion, id, decision) {
  const textos = {
    execute:
      "Se hará un RESPALDO y luego se enviarán los comandos al equipo. Si el equipo es REAL, debe estar conectado en la pestaña Consola. ¿Continuar?",
    rollback:
      "Se enviarán los comandos de ROLLBACK al equipo para deshacer el cambio. ¿Continuar?",
  };
  if (textos[accion] && !confirm(textos[accion])) return;
  try {
    const opciones = { method: "POST" };
    if (accion === "review") opciones.body = JSON.stringify({ decision });
    const c = await api(`/changes/${Number(id)}/${accion}`, opciones);
    aviso(
      `Cambio #${c.id}: ${NOMBRE_ESTADO_CAMBIO[c.estado] || c.estado}`,
      c.estado === "fallida" ? "error" : "ok",
    );
  } catch (error) {
    aviso(error.message, "error");
  }
  await listarCambios();
}

async function cargarCambios() {
  try {
    await cargarEquipos();
    if (!usuarioCambios) usuarioCambios = await api("/auth/me");
  } catch (error) {
    aviso(error.message, "error");
    return;
  }
  const select = $("#cam-equipo");
  const anterior = select.value;
  select.innerHTML = "";
  equipos
    .filter((e) => ["Cisco", "Huawei"].includes(e.vendor))
    .forEach((e) =>
      select.appendChild(
        new Option(
          `${e.name} (${e.vendor}${e.is_simulated ? "" : " · REAL"})`,
          e.id,
        ),
      ),
    );
  if (anterior) select.value = anterior;
  mostrarCamposPlantilla();
  await listarCambios();
}

CARGADORES.cambios = cargarCambios;

document.addEventListener("DOMContentLoaded", () => {
  $("#cam-plantilla").addEventListener("change", mostrarCamposPlantilla);
  $("#btn-cam-previa").addEventListener("click", vistaPreviaCambio);
  $("#form-cambio").addEventListener("submit", proponerCambio);
  $("#lista-cambios").addEventListener("click", (e) => {
    const b = e.target.closest("[data-cambio]");
    if (b) accionCambio(b.dataset.cambio, b.dataset.id, b.dataset.decision);
  });
});

// --- FIN DEL ARCHIVO ---
