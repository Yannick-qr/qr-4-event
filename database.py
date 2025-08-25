from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
from sqlalchemy import DateTime, ForeignKey
from datetime import datetime

DATABASE_URL = "sqlite:///./QREvent.db"  # ⚠️ adapte si tu veux Postgres/MySQL

engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}  # utile pour SQLite
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Dépendance pour FastAPI
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
    event_credits = Column(Integer, default=0)

    events = relationship("Event", back_populates="creator")


class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    description = Column(String)
    date = Column(String)
    location = Column(String)
    price = Column(Float)
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
    created_at = Column(String, default=lambda: datetime.utcnow().isoformat())


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
