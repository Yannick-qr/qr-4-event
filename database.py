import os
from sqlalchemy import (
    create_engine, Column, Integer, String, Float, Boolean, DateTime,
    ForeignKey, Text, Index
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime

# ======================
# HELPER : Date/heure UTC naïve
# ======================
def utcnow():
    """Retourne la date/heure actuelle en UTC (naïve)."""
    return datetime.utcnow()

# ======================
# CONFIG DATABASE
# ======================
# Récupère l’URL PostgreSQL depuis les variables d’environnement (Render)
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise ValueError("⚠️ DATABASE_URL n'est pas défini dans tes variables d'environnement !")

# Compat : SQLAlchemy >=1.4 recommande le schéma 'postgresql+psycopg2://'
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg2://", 1)
elif DATABASE_URL.startswith("postgresql://") and "+psycopg2" not in DATABASE_URL:
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1)

# Ajoute sslmode=require si manquant (Render / nombreux PaaS)
if "sslmode=" not in DATABASE_URL.lower():
    sep = "&" if "?" in DATABASE_URL else "?"
    DATABASE_URL = f"{DATABASE_URL}{sep}sslmode=require"

# Création du moteur de connexion PostgreSQL (robuste)
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=10,
    future=True
)

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
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=True)
    token = Column(String, unique=True, nullable=True)
    token_expiry = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=False, nullable=False)

    # 🔥 Nouvel attribut : nombre de crédits d’événements
    participant_credits = Column(Integer, default=0, nullable=False)

    # ✅ Compte PayPal propre à l’admin
    paypal_client_id = Column(String, nullable=True)
    paypal_secret = Column(String, nullable=True)

    # Relations
    events = relationship("Event", back_populates="creator", cascade="all, delete-orphan")
    logs = relationship("AdminLog", back_populates="admin", cascade="all, delete-orphan")
    credit_purchases = relationship("CreditPurchase", back_populates="admin", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<AdminUser id={self.id} email={self.email} active={self.is_active}>"

class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    description = Column(Text)  # Text pour descriptions longues
    date = Column(String, nullable=False)
    location = Column(String, nullable=False)
    price = Column(Float, nullable=False)
    max_participants = Column(Integer, default=100)  # limite définie par l'admin
    created_by = Column(Integer, ForeignKey("admin_users.id", ondelete="CASCADE"), index=True, nullable=False)

    # 🔥 nouveaux champs check-in
    checkin_login = Column(String, nullable=True)
    checkin_password = Column(String, nullable=True)

    # 🔥 Nouveaux attributs pour la logique business
    is_locked = Column(Boolean, default=False, nullable=False)   # devient True après 1er paiement public
    is_active = Column(Boolean, default=True, nullable=False)    # toggle activer/désactiver

    # ✅ Nouveau champ pour stocker l’URL de la photo
    image_url = Column(String, nullable=True)

    # Relations
    creator = relationship("AdminUser", back_populates="events")
    participants = relationship("Participant", back_populates="event", cascade="all, delete-orphan")
    registrations = relationship("EventRegistration", back_populates="event", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Event id={self.id} title={self.title} active={self.is_active}>"

class EventRegistration(Base):
    __tablename__ = "event_registrations"

    id = Column(Integer, primary_key=True, index=True)
    # identifie l'AdminUser (peut être None si achat public sans compte)
    user_id = Column(Integer, ForeignKey("admin_users.id", ondelete="SET NULL"), index=True, nullable=True)
    # identifie l'événement
    event_id = Column(Integer, ForeignKey("events.id", ondelete="CASCADE"), index=True, nullable=False)
    # ID PayPal (évite doublons)
    payment_id = Column(String, unique=True, index=True, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    # Relations (facultatives mais utiles)
    user = relationship("AdminUser", backref="event_registrations")
    event = relationship("Event", back_populates="registrations")

    def __repr__(self):
        return f"<EventRegistration id={self.id} event_id={self.event_id} payment_id={self.payment_id}>"

class Participant(Base):
    __tablename__ = "participants"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, index=True, nullable=False)
    amount = Column(Float, nullable=False)
    transaction_id = Column(String, unique=True, index=True, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    # 🔑 QR code logique : support du backend (peut rester NULL si on utilise l'id)
    qr_code = Column(String, unique=True, index=True, nullable=True)

    event_id = Column(Integer, ForeignKey("events.id", ondelete="CASCADE"), index=True, nullable=False)
    event = relationship("Event", back_populates="participants")

    # scan QR
    scanned = Column(Boolean, default=False, nullable=False)
    scanned_at = Column(DateTime, nullable=True)

    def __repr__(self):
        return f"<Participant id={self.id} email={self.email} event_id={self.event_id}>"

# Index composite utile pour les recherches/validations
Index("ix_participants_event_qr", Participant.event_id, Participant.qr_code)
Index("ix_participants_event_id", Participant.event_id)

# ======================
# ACHATS DE CRÉDITS
# ======================
class CreditPurchase(Base):
    __tablename__ = "credit_purchases"

    id = Column(Integer, primary_key=True, index=True)
    admin_id = Column(Integer, ForeignKey("admin_users.id", ondelete="CASCADE"), index=True, nullable=False)
    credits = Column(Integer, nullable=False)
    amount = Column(Float, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    admin = relationship("AdminUser", back_populates="credit_purchases")

    def __repr__(self):
        return f"<CreditPurchase id={self.id} admin_id={self.admin_id} credits={self.credits}>"

class AdminLog(Base):
    __tablename__ = "admin_logs"

    id = Column(Integer, primary_key=True, index=True)
    admin_id = Column(Integer, ForeignKey("admin_users.id", ondelete="CASCADE"), index=True, nullable=False)
    action = Column(String, nullable=False)
    details = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    admin = relationship("AdminUser", back_populates="logs")

    def __repr__(self):
        return f"<AdminLog id={self.id} admin_id={self.admin_id} action={self.action}>"
