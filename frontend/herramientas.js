"use strict";
/*
 * NOC Syslog Inteligente — Herramientas (Fase 5)
 *   - Generador de configuraciones Syslog comentadas
 *   - Consola simulada de solo lectura (tipo PuTTY)
 *
 * Usa funciones de app.js: api(), aviso(), $(), cargarEquipos() y la lista "equipos".
 * SEGURIDAD: toda salida se escribe con textContent, nunca como HTML.
 * Las salidas de la consola incluyen mensajes de logs (datos no confiables).
 */

const VENDORS_CONSOLA = ["Cisco", "Fortinet", "Huawei"];
const PROMPT_POR_VENDOR = {
  Cisco: (n) => `${n}#`,
  Fortinet: (n) => `${n} #`,
  Huawei: (n) => `<${n}>`,
};
const historialConsola = [];
let posicionHistorial = 0;
let pendienteConsola = null; // comando que llega desde "Verificación"

// ===========================================================================
// Generador de configuraciones
// ===========================================================================
async function cargarConfiguraciones() {
  try {
    await cargarEquipos();
  } catch (error) {
    aviso(error.message, "error");
    return;
  }
  const select = $("#cfg-equipo");
  const actual = select.value;
  select.innerHTML = "";
  select.appendChild(new Option("— Escribir los datos a mano —", ""));
  equipos
    .filter((e) => VENDORS_CONSOLA.includes(e.vendor))
    .forEach((e) =>
      select.appendChild(new Option(`${e.name} (${e.vendor})`, e.id)),
    );
  select.value = actual;
}

function elegirEquipoConfig() {
  const eq = equipos.find((e) => e.id === Number($("#cfg-equipo").value));
  if (!eq) return;
  const form = $("#form-config");
  form.elements.vendor.value = eq.vendor;
  form.elements.nombre_equipo.value = eq.name;
}

async function generarConfiguracion(evento) {
  evento.preventDefault();
  const f = new FormData(evento.target);
  const datos = {
    vendor: f.get("vendor"),
    servidor_ip: String(f.get("servidor_ip")).trim(),
    puerto: Number(f.get("puerto")),
    protocolo: f.get("protocolo"),
    severidad_minima: Number(f.get("severidad_minima")),
    facility: f.get("facility"),
    zona_horaria: String(f.get("zona_horaria")).trim(),
    desfase_horas: Number(f.get("desfase_horas")),
  };
  for (const campo of ["nombre_equipo", "interfaz_origen", "ntp_servidor"]) {
    const valor = String(f.get(campo) ?? "").trim();
    if (valor) datos[campo] = valor;
  }

  try {
    const r = await api("/config/generate", {
      method: "POST",
      body: JSON.stringify(datos),
    });

    $("#config-salida").textContent = r.configuracion; // textContent: se muestra tal cual

    const avisos = $("#config-advertencias");
    avisos.innerHTML = "";
    r.advertencias.forEach((texto) => {
      const li = document.createElement("li");
      li.textContent = texto;
      avisos.appendChild(li);
    });

    const verificacion = $("#config-verificacion");
    verificacion.innerHTML = "";
    r.verificacion.forEach((comando) => {
      const boton = document.createElement("button");
      boton.type = "button";
      boton.className = "btn mini secundario";
      boton.textContent = comando;
      boton.addEventListener("click", () =>
        probarEnConsola(comando, datos.nombre_equipo),
      );
      verificacion.appendChild(boton);
    });

    $("#config-resultado").hidden = false;
    aviso(`Configuración ${r.vendor} generada`);
  } catch (error) {
    aviso(error.message, "error"); // ej.: intento de inyección en la interfaz
  }
}

async function copiarConfiguracion() {
  try {
    await navigator.clipboard.writeText($("#config-salida").textContent);
    aviso("Configuración copiada al portapapeles");
  } catch {
    aviso(
      "No se pudo copiar automáticamente: selecciónela con el mouse y use Ctrl + C",
      "error",
    );
  }
}

function probarEnConsola(comando, nombreEquipo) {
  const eq = equipos.find((e) => e.name === nombreEquipo);
  pendienteConsola = { comando, id: eq ? eq.id : null };
  mostrarVista("consola");
}

// ===========================================================================
// Consola simulada
// ===========================================================================
function equipoConsola() {
  return equipos.find((e) => e.id === Number($("#con-equipo").value));
}

function escribirLinea(texto, clase = "") {
  const linea = document.createElement("div");
  linea.className = `t-linea ${clase}`;
  linea.textContent = texto; // NUNCA innerHTML: la salida puede traer texto de logs
  const pantalla = $("#terminal-salida");
  pantalla.appendChild(linea);
  pantalla.scrollTop = pantalla.scrollHeight;
}

function actualizarPrompt() {
  const eq = equipoConsola();
  $("#con-prompt").textContent = eq
    ? PROMPT_POR_VENDOR[eq.vendor](eq.name)
    : ">";
}

async function cargarPolitica(vendor) {
  try {
    const p = await api(
      `/console/commands?vendor=${encodeURIComponent(vendor)}`,
    );
    const permitidos = $("#politica-permitidos");
    permitidos.innerHTML = "";
    p.permitidos.forEach((c) => {
      const li = document.createElement("li");
      li.textContent = c;
      permitidos.appendChild(li);
    });
    const bloqueados = $("#politica-bloqueados");
    bloqueados.innerHTML = "";
    p.bloqueados.forEach((b) => {
      const li = document.createElement("li");
      li.textContent = `${b.ejemplos}: ${b.motivo}`;
      bloqueados.appendChild(li);
    });
  } catch (error) {
    aviso(error.message, "error");
  }
}

async function conectarConsola() {
  $("#terminal-salida").innerHTML = "";
  const eq = equipoConsola();
  actualizarPrompt();
  if (!eq) {
    escribirLinea(
      "No hay equipos Cisco, Fortinet o Huawei en el inventario.",
      "t-bloqueado",
    );
    return;
  }
  escribirLinea(`Conectando a ${eq.name} (${eq.ip_address})...`, "t-info");
  escribirLinea(
    "*** CONSOLA SIMULADA DE SOLO LECTURA · EQUIPO SIMULADO ***",
    "t-info",
  );
  escribirLinea(
    "Escriba 'help' para ver los comandos permitidos. Cada comando queda en la auditoría.",
    "t-info",
  );
  escribirLinea("");
  await cargarPolitica(eq.vendor);
}

async function cargarConsola() {
  try {
    await cargarEquipos();
  } catch (error) {
    aviso(error.message, "error");
    return;
  }
  const select = $("#con-equipo");
  const anterior = select.value;
  const compatibles = equipos.filter((e) => VENDORS_CONSOLA.includes(e.vendor));
  select.innerHTML = "";
  compatibles.forEach((e) =>
    select.appendChild(new Option(`${e.name} (${e.vendor})`, e.id)),
  );
  if (anterior) select.value = anterior;

  // Si venimos desde "Verificación", elegir ese equipo
  if (pendienteConsola && pendienteConsola.id)
    select.value = pendienteConsola.id;

  if (
    select.value !== anterior ||
    $("#terminal-salida").childElementCount === 0
  ) {
    await conectarConsola();
  }
  actualizarPrompt();

  if (pendienteConsola) {
    $("#con-comando").value = pendienteConsola.comando;
    pendienteConsola = null;
  }
  $("#con-comando").focus();
}

async function ejecutarComando(evento) {
  evento.preventDefault();
  const entrada = $("#con-comando");
  const comando = entrada.value.trim();
  const eq = equipoConsola();
  if (!comando || !eq) return;

  historialConsola.push(comando);
  posicionHistorial = historialConsola.length;
  entrada.value = "";

  const actor = $("#con-actor").value;
  const marca = actor === "agente_ia" ? "   [agente IA]" : "";
  escribirLinea(
    `${$("#con-prompt").textContent} ${comando}${marca}`,
    "t-comando",
  );

  try {
    const r = await api("/console/exec", {
      method: "POST",
      body: JSON.stringify({ device_id: eq.id, comando, actor }),
    });
    if (r.permitido) {
      (r.salida || "(sin resultados)")
        .split("\n")
        .forEach((l) => escribirLinea(l));
    } else {
      const etiqueta = {
        bloqueado: "BLOQUEADO",
        invalido: "INVÁLIDO",
        no_permitido: "NO PERMITIDO",
      };
      escribirLinea(
        `% ${etiqueta[r.categoria] || "RECHAZADO"}: ${r.motivo}`,
        `t-${r.categoria}`,
      );
    }
  } catch (error) {
    escribirLinea(`% Error: ${error.message}`, "t-bloqueado");
  }
  escribirLinea("");
}

function navegarHistorial(evento) {
  if (evento.key === "ArrowUp" && posicionHistorial > 0) {
    posicionHistorial--;
    evento.target.value = historialConsola[posicionHistorial];
    evento.preventDefault();
  } else if (evento.key === "ArrowDown") {
    if (posicionHistorial < historialConsola.length - 1) {
      posicionHistorial++;
      evento.target.value = historialConsola[posicionHistorial];
    } else {
      posicionHistorial = historialConsola.length;
      evento.target.value = "";
    }
    evento.preventDefault();
  }
}

function actualizarModoActor() {
  const esIA = $("#con-actor").value === "agente_ia";
  $("#terminal").classList.toggle("modo-ia", esIA);
  $("#aviso-ia").hidden = !esIA;
}

// ===========================================================================
// Registro de las vistas nuevas y de sus eventos
// ===========================================================================
CARGADORES.configuraciones = cargarConfiguraciones;
CARGADORES.consola = cargarConsola;

document.addEventListener("DOMContentLoaded", () => {
  $("#cfg-equipo").addEventListener("change", elegirEquipoConfig);
  $("#form-config").addEventListener("submit", generarConfiguracion);
  $("#btn-copiar-config").addEventListener("click", copiarConfiguracion);
  $("#form-consola").addEventListener("submit", ejecutarComando);
  $("#con-comando").addEventListener("keydown", navegarHistorial);
  $("#con-equipo").addEventListener("change", conectarConsola);
  $("#con-actor").addEventListener("change", actualizarModoActor);
  $("#btn-limpiar-consola").addEventListener("click", conectarConsola);
});

// --- FIN DEL ARCHIVO ---
