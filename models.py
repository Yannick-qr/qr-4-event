from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base


class AdminUser(Base):
    __tablename__ = "admin_users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)

    is_active = Column(Boolean, default=False)

    # Token utilisé à la fois pour validation email + sessions
    token = Column(String, nullable=True)
    token_expiry = Column(DateTime, nullable=True)

    reset_token = Column(String, nullable=True)
    reset_token_expiry = Column(DateTime, nullable=True)

    # ⚡ Ajouté : crédits d’événements
    event_credits = Column(Integer, default=0)

    events = relationship("Event", back_populates="creator")


class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    description = Column(String, nullable=True)
    date = Column(String, nullable=False)
    location = Column(String, nullable=False)
    price = Column(Float, nullable=False)

    # ⚡ Ajouté : gestion statut
    is_active = Column(Boolean, default=True)
    is_locked = Column(Boolean, default=False)

    created_by = Column(Integer, ForeignKey("admin_users.id"))
    creator = relationship("AdminUser", back_populates="events")

    participants = relationship("Participant", back_populates="event")


class Participant(Base):
    __tablename__ = "participants"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, nullable=False)
    event_id = Column(Integer, ForeignKey("events.id"))
    amount = Column(Float, nullable=False)
    transaction_id = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # 👇 Nouveaux champs pour suivi des scans
    scanned = Column(Boolean, default=False)
    scanned_at = Column(DateTime, nullable=True)

    event = relationship("Event", back_populates="participants")
