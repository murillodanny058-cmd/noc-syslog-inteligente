"""
Crea un usuario ADMINISTRADOR desde la consola.
La contraseña se escribe de forma oculta y nunca queda en el código.

Uso:
    python -m backend.scripts.crear_admin
"""

import re
from getpass import getpass

from backend.app.database import Base, SessionLocal, engine
from backend.app.models import AuditLog, User
from backend.app.seguridad import hash_password, validar_fortaleza


def main():
    """Pide los datos por consola (contraseña oculta) y crea el administrador."""
    Base.metadata.create_all(bind=engine)

    usuario = input("Usuario administrador (minúsculas, ej. admin): ").strip().lower()
    if not re.fullmatch(r"[a-z0-9._-]{3,50}", usuario):
        print("[ERROR] Use de 3 a 50 caracteres: minúsculas, números, punto o guion.")
        return
    nombre = input("Nombre completo: ").strip() or usuario

    while True:
        clave = getpass("Contraseña (no se verá mientras escribe): ")
        error = validar_fortaleza(clave)
        if error:
            print(f"  {error}")
            continue
        if getpass("Repita la contraseña: ") != clave:
            print("  Las contraseñas no coinciden.")
            continue
        break

    db = SessionLocal()
    try:
        if db.query(User).filter(User.username == usuario).first():
            print(f"[ERROR] Ya existe el usuario '{usuario}'.")
            return
        u = User(username=usuario, full_name=nombre, role="administrador", password_hash=hash_password(clave))
        db.add(u)
        db.flush()
        db.add(
            AuditLog(
                actor="sistema",
                action="USER_CREATE",
                entity_type="users",
                entity_id=u.id,
                details=f"Administrador '{usuario}' creado por consola",
            )
        )
        db.commit()
        print(f"[OK] Administrador '{usuario}' creado. Ya puede iniciar sesión en el dashboard.")
    finally:
        db.close()


if __name__ == "__main__":
    main()

# --- FIN DEL ARCHIVO ---
