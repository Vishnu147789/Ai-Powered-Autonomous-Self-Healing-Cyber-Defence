"""SQLAlchemy ORM models for attack detection, incidents, and healing actions."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship, declarative_base

Base = declarative_base()


class AttackEvent(Base):
    """Represents a detected malicious activity event."""

    __tablename__ = "attack_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    attack_type: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(String(50), nullable=False)
    detected_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )

    incidents: Mapped[list[Incident]] = relationship(
        "Incident", back_populates="attack_event", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return (
            f"AttackEvent(id={self.id!r}, source_ip={self.source_ip!r}, "
            f"attack_type={self.attack_type!r}, severity={self.severity!r}, "
            f"detected_at={self.detected_at!r})"
        )


class Incident(Base):
    """Represents a tracked incident derived from an attack event."""

    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    attack_event_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("attack_events.id"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="detected")
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    attack_event: Mapped[AttackEvent] = relationship("AttackEvent", back_populates="incidents")
    healing_actions: Mapped[list[HealingAction]] = relationship(
        "HealingAction", back_populates="incident", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return (
            f"Incident(id={self.id!r}, attack_event_id={self.attack_event_id!r}, "
            f"status={self.status!r}, created_at={self.created_at!r}, "
            f"resolved_at={self.resolved_at!r})"
        )


class HealingAction(Base):
    """Represents an automated self-healing action executed for an incident."""

    __tablename__ = "healing_actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    incident_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("incidents.id"), nullable=False, index=True
    )
    action_type: Mapped[str] = mapped_column(String(50), nullable=False)
    executed_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    incident: Mapped[Incident] = relationship("Incident", back_populates="healing_actions")

    def __repr__(self) -> str:
        return (
            f"HealingAction(id={self.id!r}, incident_id={self.incident_id!r}, "
            f"action_type={self.action_type!r}, executed_at={self.executed_at!r}, "
            f"success={self.success!r})"
        )
