"use strict";
/*
 * Sesión del usuario (Fase 7): muestra quién está conectado y permite salir.
 * Usa api() y $() de app.js. Si no hay sesión, api() redirige al login.
 */
document.addEventListener("DOMContentLoaded", async () => {
  try {
    const u = await api("/auth/me");
    $("#usuario-nombre").textContent = `${u.full_name} · ${u.role}`; // textContent: texto seguro
  } catch {
    /* api() ya redirige al login si no hay sesión */
  }
  $("#btn-salir").addEventListener("click", async () => {
    try {
      await api("/auth/logout", { method: "POST" });
    } catch {
      /* aunque falle, se vuelve al login */
    }
    location.href = "/login.html";
  });
});

// --- FIN DEL ARCHIVO ---
