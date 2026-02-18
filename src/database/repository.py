"""Repository helpers for persisting and retrieving security domain records."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.exc import SQLAlchemyError

from src.database import models
from src.database.connection import Session


def create_attack_event(
    session: Session,
    source_ip: str,
    attack_type: str,
    severity: str,
) -> models.AttackEvent:
    """Create and persist a new attack event.

    Args:
        session: Active SQLAlchemy session.
        source_ip: Source IP address associated with the detected attack.
        attack_type: Classification of the detected attack.
        severity: Severity level for the attack event.

    Returns:
        The persisted ``AttackEvent`` instance.

    Raises:
        SQLAlchemyError: If persistence fails.
    """
    attack_event = models.AttackEvent(
        source_ip=source_ip,
        attack_type=attack_type,
        severity=severity,
    )
    try:
        session.add(attack_event)
        session.commit()
        session.refresh(attack_event)
        return attack_event
    except SQLAlchemyError:
        session.rollback()
        raise


def create_incident(session: Session, attack_event_id: int) -> models.Incident:
    """Create and persist a new incident linked to an attack event.

    Args:
        session: Active SQLAlchemy session.
        attack_event_id: Identifier of the parent attack event.

    Returns:
        The persisted ``Incident`` instance.

    Raises:
        SQLAlchemyError: If persistence fails.
    """
    incident = models.Incident(
        attack_event_id=attack_event_id,
        status="detected",
    )
    try:
        session.add(incident)
        session.commit()
        session.refresh(incident)
        return incident
    except SQLAlchemyError:
        session.rollback()
        raise


def create_healing_action(
    session: Session,
    incident_id: int,
    action_type: str,
    success: bool,
) -> models.HealingAction:
    """Create and persist a new healing action for an incident.

    Args:
        session: Active SQLAlchemy session.
        incident_id: Identifier of the incident being mitigated.
        action_type: Type of action executed (e.g., block_ip, rotate_port).
        success: Whether the healing action succeeded.

    Returns:
        The persisted ``HealingAction`` instance.

    Raises:
        SQLAlchemyError: If persistence fails.
    """
    healing_action = models.HealingAction(
        incident_id=incident_id,
        action_type=action_type,
        success=success,
    )
    try:
        session.add(healing_action)
        session.commit()
        session.refresh(healing_action)
        return healing_action
    except SQLAlchemyError:
        session.rollback()
        raise


def update_incident_status(
    session: Session,
    incident_id: int,
    status: str,
) -> models.Incident | None:
    """Update the status of an existing incident.

    Args:
        session: Active SQLAlchemy session.
        incident_id: Identifier of the incident to update.
        status: New status value (e.g., detected, mitigated, resolved).

    Returns:
        The updated ``Incident`` instance, or ``None`` when not found.

    Raises:
        SQLAlchemyError: If the update transaction fails.
    """
    incident = session.get(models.Incident, incident_id)
    if incident is None:
        return None

    incident.status = status
    if status == "resolved":
        incident.resolved_at = datetime.utcnow()

    try:
        session.add(incident)
        session.commit()
        session.refresh(incident)
        return incident
    except SQLAlchemyError:
        session.rollback()
        raise


def get_recent_incidents(session: Session, limit: int = 20) -> list[models.Incident]:
    """Fetch the most recent incidents ordered by creation time descending.

    Args:
        session: Active SQLAlchemy session.
        limit: Maximum number of incidents to return.

    Returns:
        A list of recent ``Incident`` records.

    Raises:
        SQLAlchemyError: If the query execution fails.
    """
    try:
        incidents = (
            session.query(models.Incident)
            .order_by(models.Incident.created_at.desc())
            .limit(limit)
            .all()
        )
        return incidents
    except SQLAlchemyError:
        session.rollback()
        raise
