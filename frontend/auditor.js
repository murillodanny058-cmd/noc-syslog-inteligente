"use strict";
/*
 * NOC Syslog Inteligente — Agente auditor de usuarios (Fase 12). SOLO ADMINISTRADOR.
 *   1) Ver sesiones: qué hizo un usuario de LOGIN a LOGOUT, con hallazgos por reglas.
 *   2) Generar informe: el agente de IA revisa las sesiones y redacta el informe.
 * Usa funciones de app.js: api(), aviso(), $(), esc(), fecha().
 * SEGURIDAD: todo texto se muestra con esc(); el informe de la IA también se escapa
 * antes de darle formato, así que nunca se interpreta como HTML.
 */

const NOMBRE_CIERRE = {
  logout: "Cerró con Salir",
  sin_cierre: "Sin cerrar (abrió otra sesión)",
  expirada: "Sin cerrar (venció)",
  activa: "Sesión activa",
  sin_acceso: "No logró entrar",
};
const NOMBRE_MOTOR = { hermes: "IA · Hermes Agent", claude: "IA · Claude", gemini: "IA · Gemini", reglas: "Reglas (sin IA)" };
let auditorListo = false;

/** datetime-local (hora local) -> ISO en UTC para la API. */
function aIso(valor) {
  return valor ? new Date(valor).toISOString() : "";
}

/** Fecha -> valor para un datetime-local en hora local. */
function aLocal(d) {
  const copia = new Date(d);
  copia.setMinutes(copia.getMinutes() - copia.getTimezoneOffset());
  return copia.toISOString().slice(0, 16);
}

function insigniaRiesgo(nivel) {
  return `<span class="riesgo riesgo-${esc(nivel)}">Riesgo ${esc(nivel)}</span>`;
}

/** Markdown simple -> HTML SEGURO: primero se escapa todo y después se da formato. */
function markdownSeguro(texto) {
  const negrita = (t) => t.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
  return String(texto ?? "")
    .split("\n")
    .map((linea) => {
      const l = esc(linea);
      if (/^#{1,2}\s/.test(linea)) return `<h3>${negrita(l.replace(/^#+\s*/, ""))}</h3>`;
      if (/^#{3,}\s/.test(linea)) return `<h4>${negrita(l.replace(/^#+\s*/, ""))}</h4>`;
      const item = linea.match(/^(\s*)[-*]\s+(.*)$/);
      if (item) {
        const sub = item[1].length >= 2 ? " sub" : "";
        return `<div class="md-item${sub}">• ${negrita(esc(item[2]))}</div>`;
      }
      return l.trim() ? `<p>${negrita(l)}</p>` : "";
    })
    .join("");
}

function datosAuditor() {
  const f = new FormData($("#form-auditor"));
  return {
    usuario: String(f.get("usuario") || ""),
    desde: aIso(f.get("desde")),
    hasta: aIso(f.get("hasta")),
  };
}

function validarPeriodo(d) {
  if (!d.usuario) return "Elija un usuario";
  const ahora = new Date();
  if (d.desde && new Date(d.desde) > ahora) return "La fecha 'Desde' no puede estar en el futuro";
  if (d.hasta && new Date(d.hasta) > ahora) return "La fecha 'Hasta' no puede estar en el futuro";
  if (d.desde && d.hasta && new Date(d.desde) > new Date(d.hasta))
    return "La fecha 'Desde' no puede ser posterior a 'Hasta'";
  return null;
}

function tarjetaSesion(s, n) {
  const hallazgos = s.hallazgos.length
    ? `<ul class="lista-simple">${s.hallazgos
        .map((h) => `<li><span class="riesgo riesgo-${esc(h.nivel)}">${esc(h.nivel)}</span> ${esc(h.texto)}</li>`)
        .join("")}</ul>`
    : `<p class="nota">Sin hallazgos.</p>`;
  const linea = s.linea_de_tiempo
    .map((e) => {
      const marca =
        e.resultado === "ok" ? "" : ` <span class="riesgo riesgo-medio">${esc(e.resultado.replace("_", " "))}</span>`;
      const veces = e.veces > 1 ? ` <span class="tenue">×${Number(e.veces)}</span>` : "";
      return `<li><span class="tenue">${esc(fecha(e.hora))}</span> ${esc(e.texto)}${veces}${marca}</li>`;
    })
    .join("");
  return `<article class="incidente sesion-auditor">
      <div class="item-cab">
        <span class="estado">${esc(NOMBRE_CIERRE[s.cierre] || s.cierre)}</span>
        ${insigniaRiesgo(s.riesgo)} <span class="tenue">Sesión ${n}</span>
      </div>
      <p class="meta"><strong>${esc(fecha(s.inicio))}</strong> → ${esc(fecha(s.fin))}
        · ${Number(s.duracion_min)} min · ${Number(s.acciones)} acciones</p>
      ${hallazgos}
      <details class="detalle-cambio"><summary>Línea de tiempo (${s.linea_de_tiempo.length})</summary>
        <ul class="linea-tiempo">${linea}</ul></details>
    </article>`;
}

async function verSesiones(evento) {
  evento?.preventDefault();
  const d = datosAuditor();
  const error = validarPeriodo(d);
  if (error) return aviso(error, "error");
  const q = new URLSearchParams({ usuario: d.usuario });
  if (d.desde) q.set("desde", d.desde);
  if (d.hasta) q.set("hasta", d.hasta);
  try {
    const r = await api(`/auditor/sesiones?${q}`);
    $("#aud-resumen").innerHTML = `<strong>${esc(r.usuario)}</strong>: ${Number(r.total_sesiones)} sesión(es) ${insigniaRiesgo(r.riesgo)}`;
    $("#aud-sesiones").innerHTML =
      r.sesiones
        .slice()
        .reverse() // la más reciente arriba
        .map((s, i) => tarjetaSesion(s, r.sesiones.length - i))
        .join("") ||
      `<p class="vacio">No hay actividad de este usuario en el periodo.</p>`;
  } catch (e) {
    aviso(e.message, "error");
  }
}

function mostrarInforme(inf) {
  $("#aud-informe").hidden = false;
  $("#aud-informe-cab").innerHTML =
    `Informe #${Number(inf.id)} · <strong>${esc(inf.usuario)}</strong> · ${insigniaRiesgo(inf.riesgo)}
     · <span class="etiqueta-ia">${esc(NOMBRE_MOTOR[inf.motor] || inf.motor)}${inf.modelo ? " (" + esc(inf.modelo) + ")" : ""}</span>
     · ${esc(fecha(inf.creado))}` + (inf.nota ? `<br><span class="nota">${esc(inf.nota)}</span>` : "");
  $("#aud-informe-texto").innerHTML = markdownSeguro(inf.contenido);
}

async function generarInforme() {
  const d = datosAuditor();
  const error = validarPeriodo(d);
  if (error) return aviso(error, "error");
  const boton = $("#btn-aud-informe");
  boton.disabled = true; // evita pedir dos informes con doble clic
  boton.textContent = "El agente está revisando...";
  try {
    const cuerpo = { usuario: d.usuario };
    if (d.desde) cuerpo.desde = d.desde;
    if (d.hasta) cuerpo.hasta = d.hasta;
    const inf = await api("/auditor/informe", { method: "POST", body: JSON.stringify(cuerpo) });
    mostrarInforme(inf);
    aviso(`Informe #${inf.id} listo (${NOMBRE_MOTOR[inf.motor] || inf.motor})`);
    await verSesiones();
    await listarInformes();
  } catch (e) {
    aviso(e.message, "error");
  } finally {
    boton.disabled = false;
    boton.textContent = "Generar informe con IA";
  }
}

async function listarInformes() {
  try {
    const lista = await api("/auditor/informes");
    $("#aud-historial").innerHTML =
      lista
        .map(
          (i) => `<details class="detalle-cambio"><summary>#${Number(i.id)} · ${esc(i.usuario)} ·
            ${esc(fecha(i.creado))} · riesgo ${esc(i.riesgo)} · ${esc(NOMBRE_MOTOR[i.motor] || i.motor)}
            · pedido por ${esc(i.pedido_por)}</summary>
            <div class="informe-ia">${markdownSeguro(i.contenido)}</div></details>`,
        )
        .join("") || `<p class="vacio">Todavía no hay informes.</p>`;
  } catch (e) {
    aviso(e.message, "error");
  }
}

async function cargarAuditoria() {
  let yo;
  try {
    yo = await api("/auth/me");
  } catch (e) {
    return aviso(e.message, "error");
  }
  if (yo.role !== "administrador") {
    $("#aud-contenido").hidden = true;
    $("#aud-sin-permiso").hidden = false;
    return;
  }
  try {
    const [motor, usuarios] = await Promise.all([api("/auditor/estado"), api("/auditor/usuarios")]);
    $("#aud-motor").textContent = `Motor del agente: ${motor.descripcion}${motor.modelo ? " · " + motor.modelo : ""}`;
    const select = $("#aud-usuario");
    const anterior = select.value;
    select.innerHTML = "";
    usuarios.forEach((u) =>
      select.appendChild(
        new Option(`${u.usuario}${u.rol ? " (" + u.rol + ")" : ""}${u.con_actividad ? "" : " · sin actividad"}`, u.usuario),
      ),
    );
    if (anterior) select.value = anterior;
    if (!auditorListo) {
      const ahora = new Date();
      $("#form-auditor").elements.hasta.value = aLocal(ahora);
      $("#form-auditor").elements.desde.value = aLocal(new Date(ahora - 24 * 3600 * 1000));
      auditorListo = true;
    }
    const maximo = aLocal(new Date());
    $("#form-auditor").elements.desde.max = maximo;
    $("#form-auditor").elements.hasta.max = maximo;
    await listarInformes();
  } catch (e) {
    aviso(e.message, "error");
  }
}

CARGADORES.auditoria = cargarAuditoria;

document.addEventListener("DOMContentLoaded", async () => {
  $("#form-auditor").addEventListener("submit", verSesiones);
  $("#btn-aud-informe").addEventListener("click", generarInforme);
  try {
    const yo = await api("/auth/me"); // la pestaña solo se muestra al administrador
    if (yo.role !== "administrador") $('[data-vista="auditoria"]').hidden = true;
  } catch {
    /* api() ya redirige al login si no hay sesión */
  }
});

// --- FIN DEL ARCHIVO ---
