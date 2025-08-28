import os
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime

# ======================
# CONFIG DATABASE
# ======================
# Récupère l’URL PostgreSQL depuis les variables d’environnement (Render)
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise ValueError("⚠️ DATABASE_URL n'est pas défini dans tes variables d'environnement !")

# Création du moteur de connexion PostgreSQL
engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ======================
# DÉPENDANCE FASTAPI
# ======================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ======================
# MODELS
# ======================
class AdminUser(Base):
    __tablename__ = "admin_users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    password_hash = Column(String, nullable=True)
    token = Column(String, unique=True, nullable=True)
    token_expiry = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=False)

    # 🔥 Nouvel attribut : nombre de crédits d’événements
    participant_credits = Column(Integer, default=0)

    # ✅ Compte PayPal propre à l’admin
    paypal_client_id = Column(String, nullable=True)
    paypal_secret = Column(String, nullable=True)


    events = relationship("Event", back_populates="creator")


class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    description = Column(String)
    date = Column(String)
    location = Column(String)
    price = Column(Float)
    max_participants = Column(Integer, default=100)  # limite définie par l'admin
    created_by = Column(Integer, ForeignKey("admin_users.id"))

    # 🔥 nouveaux champs check-in
    checkin_login = Column(String, nullable=True)
    checkin_password = Column(String, nullable=True)

    # 🔥 Nouveaux attributs pour la logique business
    is_locked = Column(Boolean, default=False)   # devient True après 1er paiement public
    is_active = Column(Boolean, default=True)    # toggle activer/désactiver

    creator = relationship("AdminUser", back_populates="events")
    participants = relationship("Participant", back_populates="event")


class EventRegistration(Base):
    __tablename__ = "event_registrations"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)   # identifie le participant (AdminUser)
    event_id = Column(Integer, index=True)  # identifie l'événement
    payment_id = Column(String, unique=True, index=True)  # ID PayPal (évite doublons)
    created_at = Column(DateTime, default=datetime.utcnow)


class Participant(Base):
    __tablename__ = "participants"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    email = Column(String)
    amount = Column(Float)
    transaction_id = Column(String, unique=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    event_id = Column(Integer, ForeignKey("events.id"))
    event = relationship("Event", back_populates="participants")

    # scan QR
    scanned = Column(Boolean, default=False)
    scanned_at = Column(DateTime, nullable=True)

# ======================
# ACHATS DE CRÉDITS
# ======================
class CreditPurchase(Base):
    __tablename__ = "credit_purchases"

    id = Column(Integer, primary_key=True, index=True)
    admin_id = Column(Integer, ForeignKey("admin_users.id"))
    credits = Column(Integer, nullable=False)
    amount = Column(Float, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class AdminLog(Base):
    __tablename__ = "admin_logs"

    id = Column(Integer, primary_key=True, index=True)
    admin_id = Column(Integer, ForeignKey("admin_users.id"))
    action = Column(String, nullable=False)
    details = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
