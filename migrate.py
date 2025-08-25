from sqlalchemy import create_engine, text

# même chemin que dans ton fichier database.py
DATABASE_URL = "sqlite:///./QR Event.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

with engine.connect() as conn:
    try:
        conn.execute(text("ALTER TABLE events ADD COLUMN checkin_login TEXT"))
        print("✅ Colonne 'checkin_login' ajoutée")
    except Exception as e:
        print("ℹ️ 'checkin_login' existe déjà ou erreur:", e)

    try:
        conn.execute(text("ALTER TABLE events ADD COLUMN checkin_password TEXT"))
        print("✅ Colonne 'checkin_password' ajoutée")
    except Exception as e:
        print("ℹ️ 'checkin_password' existe déjà ou erreur:", e)
