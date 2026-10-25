"use strict";
/*
 * NOC Syslog Inteligente — Herramientas (Fases 5 y 9)
 *   - Generador de configuraciones Syslog comentadas
 *   - Consola simulada de solo lectura (tipo PuTTY)
 *   - Consola REAL por cable de consola (puerto COM): comandos de solo lectura
 *     y captura de los logs que imprime el equipo
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

/** Al elegir un equipo en Configuraciones, copia su marca y su nombre al formulario. */
function elegirEquipoConfig() {
  const eq = equipos.find((e) => e.id === Number($("#cfg-equipo").value));
  if (!eq) return;
  const form = $("#form-config");
  form.elements.vendor.value = eq.vendor;
  form.elements.nombre_equipo.value = eq.name;
}

/** Botón 'Generar configuración': muestra la configuración, sus advertencias y la verificación. */
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

/** Copia la configuración generada al portapapeles. */
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

/** Lleva a la pestaña Consola con el equipo y el comando de verificación elegidos. */
function probarEnConsola(comando, nombreEquipo) {
  const eq = equipos.find((e) => e.name === nombreEquipo);
  pendienteConsola = { comando, id: eq ? eq.id : null };
  mostrarVista("consola");
}

// ===========================================================================
// Consola: simulada (Fase 5) o REAL por cable de consola (Fase 9)
// ===========================================================================
let serialUltimo = 0; // última línea de la consola real que ya se mostró
let serialTimer = null; // consulta periódica mientras la consola real está abierta
let serialEstado = null; // último estado recibido del servidor

/** True si la consola está en modo 'Equipo REAL por cable de consola'. */
function modoReal() {
  return $("#con-modo").value === "real";
}

/** Equipo elegido en la consola. */
function equipoConsola() {
  return equipos.find((e) => e.id === Number($("#con-equipo").value));
}

/** Agrega una línea a la pantalla de la consola (como texto, nunca como HTML). */
function escribirLinea(texto, clase = "") {
  const linea = document.createElement("div");
  linea.className = `t-linea ${clase}`;
  linea.textContent = texto; // NUNCA innerHTML: la salida puede traer texto de logs
  const pantalla = $("#terminal-salida");
  pantalla.appendChild(linea);
  while (pantalla.childElementCount > 1500) pantalla.firstChild.remove();
  pantalla.scrollTop = pantalla.scrollHeight;
}

/** Muestra el prompt del equipo (ej. Switch# o <HUAWEI>) junto al campo de comandos. */
function actualizarPrompt() {
  const eq = equipoConsola();
  if (modoReal() && serialEstado && serialEstado.conectado) {
    $("#con-prompt").textContent =
      serialEstado.prompt || `${serialEstado.equipo.name}#`;
    return;
  }
  $("#con-prompt").textContent = eq
    ? PROMPT_POR_VENDOR[eq.vendor](eq.name)
    : ">";
}

/** Panel derecho de la consola: comandos permitidos y bloqueados de la marca. */
async function cargarPolitica(vendor) {
  const base = modoReal() ? "/serial/commands" : "/console/commands";
  try {
    const p = await api(`${base}?vendor=${encodeURIComponent(vendor)}`);
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

/** Prepara la consola para el equipo elegido (simulada) o muestra el estado de la conexión (real). */
async function conectarConsola() {
  $("#terminal-salida").innerHTML = "";
  const eq = equipoConsola();
  actualizarPrompt();
  if (modoReal()) {
    serialUltimo = 0;
    escribirLinea(
      "*** CONSOLA REAL POR CABLE DE CONSOLA · SOLO LECTURA ***",
      "t-info",
    );
    escribirLinea("1) Conecte el cable de consola y cierre PuTTY.", "t-info");
    escribirLinea(
      "2) Presione 'Buscar puertos', elija el COM y presione 'Conectar'.",
      "t-info",
    );
    escribirLinea(
      "Los logs del equipo aparecerán aquí en amarillo y se guardarán en Eventos.",
      "t-info",
    );
    escribirLinea("");
    if (!eq) {
      escribirLinea(
        "No hay equipos REALES en el inventario. Registre el equipo del laboratorio " +
          "en Inventario con Tipo de equipo: Real (laboratorio).",
        "t-bloqueado",
      );
    } else {
      await cargarPolitica(eq.vendor);
    }
    await refrescarSerial();
    return;
  }
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

/** Pestaña Consola: arma la lista de equipos según el modo (SIM o REAL) y avisa si no hay reales. */
async function cargarConsola() {
  try {
    await cargarEquipos();
  } catch (error) {
    aviso(error.message, "error");
    return;
  }
  const real = modoReal();
  $("#panel-serial").hidden = !real;
  const select = $("#con-equipo");
  const anterior = select.value;
  const compatibles = equipos.filter(
    (e) =>
      VENDORS_CONSOLA.includes(e.vendor) && Boolean(e.is_simulated) !== real,
  );
  // v1.0.0: avisar en vez de elegir otro equipo en silencio
  if (real && !compatibles.length)
    aviso(
      "No hay equipos REALES en el inventario. Regístrelo en Inventario con Tipo: Real (laboratorio).",
      "error",
    );
  else if (
    real &&
    anterior &&
    !compatibles.some((e) => String(e.id) === anterior)
  )
    aviso(
      "Modo REAL: solo aparecen equipos registrados como Real. Si el suyo no está, regístrelo en Inventario.",
    );
  select.innerHTML = "";
  compatibles.forEach((e) =>
    select.appendChild(
      new Option(`${e.name} (${e.vendor}${real ? " · REAL" : ""})`, e.id),
    ),
  );
  if (anterior) select.value = anterior;
  if (!select.value && compatibles.length) select.value = compatibles[0].id;

  // Si venimos desde "Verificación", elegir ese equipo
  if (pendienteConsola && pendienteConsola.id)
    select.value = pendienteConsola.id;

  if (
    select.value !== anterior ||
    $("#terminal-salida").childElementCount === 0
  ) {
    await conectarConsola();
  } else if (real) {
    await refrescarSerial();
  }
  if (real && $("#ser-puerto").childElementCount === 0) await buscarPuertos();
  actualizarPrompt();

  if (pendienteConsola) {
    $("#con-comando").value = pendienteConsola.comando;
    pendienteConsola = null;
  }
  $("#con-comando").focus();
}

// ---------------------------------------------------------------------------
// Consola REAL (Fase 9)
// ---------------------------------------------------------------------------
async function buscarPuertos() {
  const select = $("#ser-puerto");
  select.innerHTML = "";
  try {
    const lista = await api("/serial/puertos");
    if (!lista.length) {
      select.appendChild(new Option("(no hay puertos: conecte el cable)", ""));
      return;
    }
    // Los puertos "Bluetooth" de Windows NO son el cable de consola: se marcan y van al final
    const esBluetooth = (p) => /bluetooth/i.test(p.descripcion);
    const ordenados = [
      ...lista.filter((p) => !esBluetooth(p)),
      ...lista.filter(esBluetooth),
    ];
    ordenados.forEach((p) => {
      const aviso = esBluetooth(p) ? "  ⚠ Bluetooth: NO es el cable" : "";
      select.appendChild(
        new Option(`${p.puerto} — ${p.descripcion}${aviso}`, p.puerto),
      );
    });
    // Preferir el adaptador USB-serial (el cable de consola)
    const usb = ordenados.find(
      (p) =>
        !esBluetooth(p) &&
        /usb|prolific|ftdi|ch34|cp21|serial/i.test(p.descripcion),
    );
    if (usb) select.value = usb.puerto;
    else if (ordenados.every(esBluetooth))
      escribirLinea(
        "⚠ Solo hay puertos Bluetooth: conecte el cable de consola USB y presione 'Buscar puertos'.",
        "t-invalido",
      );
  } catch (error) {
    select.appendChild(new Option("(error al buscar puertos)", ""));
    aviso(error.message, "error");
  }
}

/** Muestra el estado de la consola real (conectado, equipo, logs capturados, avisos) y sus líneas nuevas. */
function pintarEstadoSerial(e) {
  const caja = $("#ser-estado");
  if (e.conectado) {
    let texto = `🟢 Conectado a ${e.puerto} · ${e.equipo.name} · logs capturados: ${e.eventos_capturados}`;
    if (e.login_requerido)
      texto +=
        " · ⚠️ El equipo pide usuario/contraseña (inicie sesión una vez en PuTTY)";
    caja.textContent = texto;
    // Mostrar el puerto y el equipo que realmente están en uso
    const sel = $("#ser-puerto");
    if (![...sel.options].some((o) => o.value === e.puerto))
      sel.appendChild(new Option(e.puerto, e.puerto));
    sel.value = e.puerto;
    $("#ser-velocidad").value = String(e.velocidad);
    if (
      [...$("#con-equipo").options].some((o) => Number(o.value) === e.equipo.id)
    )
      $("#con-equipo").value = e.equipo.id;
  } else {
    caja.textContent = e.ultimo_error
      ? `🔴 ${e.ultimo_error}`
      : "⚪ Desconectado";
  }
  caja.classList.toggle("conectado", e.conectado);
  $("#btn-ser-conectar").disabled = e.conectado;
  $("#btn-ser-desconectar").disabled = !e.conectado;
  $("#ser-puerto").disabled = e.conectado;
  $("#ser-velocidad").disabled = e.conectado;
  $("#con-equipo").disabled = e.conectado;
}

/** Pide al servidor el estado de la consola real y las líneas nuevas. */
async function refrescarSerial() {
  if (!modoReal()) return detenerSondeo();
  let e;
  try {
    e = await api(`/serial/estado?desde=${serialUltimo}`);
  } catch (error) {
    return detenerSondeo();
  }
  if (e.ultimo < serialUltimo) {
    // El servidor se reinició: volver a pedir todo
    serialUltimo = 0;
    e = await api("/serial/estado?desde=0");
  }
  const clases = {
    log: "t-log",
    info: "t-info",
    error: "t-bloqueado",
    consola: "",
  };
  e.lineas.forEach((l) => escribirLinea(l.texto, clases[l.tipo] || ""));
  serialUltimo = e.ultimo;
  serialEstado = e;
  pintarEstadoSerial(e);
  actualizarPrompt();
  if (e.conectado && !serialTimer) {
    serialTimer = setInterval(refrescarSerial, 1500);
  } else if (!e.conectado) {
    detenerSondeo();
  }
}

/** Detiene la consulta periódica del estado de la consola real. */
function detenerSondeo() {
  if (serialTimer) clearInterval(serialTimer);
  serialTimer = null;
}

/** Botón 'Conectar': abre el puerto COM elegido con el equipo real. */
async function serialConectar() {
  const eq = equipoConsola();
  const puerto = $("#ser-puerto").value;
  if (!eq) return aviso("Elija un equipo REAL del inventario", "error");
  if (!puerto)
    return aviso("Elija un puerto COM (presione 'Buscar puertos')", "error");
  $("#btn-ser-conectar").disabled = true;
  escribirLinea(`Abriendo ${puerto}...`, "t-info");
  try {
    await api("/serial/conectar", {
      method: "POST",
      body: JSON.stringify({
        puerto,
        velocidad: Number($("#ser-velocidad").value),
        device_id: eq.id,
      }),
    });
    aviso(`Consola real conectada a ${eq.name}`);
  } catch (error) {
    escribirLinea(`% ${error.message}`, "t-bloqueado");
    aviso(error.message, "error");
  }
  await refrescarSerial();
}

/** Botón 'Desconectar': cierra el puerto COM. */
async function serialDesconectar() {
  try {
    await api("/serial/desconectar", { method: "POST" });
    aviso("Consola real desconectada");
  } catch (error) {
    aviso(error.message, "error");
  }
  await refrescarSerial();
}

/** Cambia entre consola simulada y equipo real, empezando con la pantalla limpia. */
function cambiarModo() {
  detenerSondeo();
  serialEstado = null;
  $("#con-equipo").disabled = false;
  $("#con-equipo").value = "";
  $("#terminal-salida").innerHTML = "";
  cargarConsola();
}

/** Envía el comando escrito a la consola (simulada o real) y muestra la respuesta. */
async function ejecutarComando(evento) {
  evento.preventDefault();
  const entrada = $("#con-comando");
  const comando = entrada.value.trim();
  const eq = equipoConsola();
  const real = modoReal();
  if (!comando || !eq) return;
  if (real && !(serialEstado && serialEstado.conectado)) {
    escribirLinea(
      "% Primero conecte la consola real (botón Conectar).",
      "t-invalido",
    );
    return;
  }

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
    const r = real
      ? await api("/serial/exec", {
          method: "POST",
          body: JSON.stringify({ comando, actor }),
        })
      : await api("/console/exec", {
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
  if (real) await refrescarSerial();
}

/** Flechas arriba/abajo: recorre los comandos escritos antes. */
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

/** Cambia el aspecto de la consola cuando 'Quién escribe' es el agente de IA. */
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
  // Fase 9: consola real
  $("#con-modo").addEventListener("change", cambiarModo);
  $("#btn-ser-puertos").addEventListener("click", buscarPuertos);
  $("#btn-ser-conectar").addEventListener("click", serialConectar);
  $("#btn-ser-desconectar").addEventListener("click", serialDesconectar);
});

// --- FIN DEL ARCHIVO ---
