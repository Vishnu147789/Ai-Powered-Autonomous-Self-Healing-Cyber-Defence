"""Flask API blueprint exposing incident and system statistics endpoints."""

from __future__ import annotations

import logging

from flask import Blueprint, jsonify
from sqlalchemy.orm import joinedload

from src.database import models
from src.database.connection import get_session

logger = logging.getLogger(__name__)

api_bp = Blueprint("api", __name__, url_prefix="/api")


def _serialize_healing_action(action: models.HealingAction) -> dict[str, object]:
    """Serialize a healing action model into a JSON-compatible dict."""
    return {
        "id": action.id,
        "incident_id": action.incident_id,
        "action_type": action.action_type,
        "executed_at": action.executed_at.isoformat() if action.executed_at else None,
        "success": action.success,
    }


def _serialize_attack_event(event: models.AttackEvent | None) -> dict[str, object] | None:
    """Serialize an attack event model into a JSON-compatible dict."""
    if event is None:
        return None

    return {
        "id": event.id,
        "source_ip": event.source_ip,
        "attack_type": event.attack_type,
        "severity": event.severity,
        "detected_at": event.detected_at.isoformat() if event.detected_at else None,
    }


def _serialize_incident(incident: models.Incident) -> dict[str, object]:
    """Serialize an incident with related attack and healing details."""
    return {
        "id": incident.id,
        "attack_event_id": incident.attack_event_id,
        "status": incident.status,
        "created_at": incident.created_at.isoformat() if incident.created_at else None,
        "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
        "attack_event": _serialize_attack_event(incident.attack_event),
        "healing_actions": [
            _serialize_healing_action(action) for action in incident.healing_actions
        ],
    }


@api_bp.get("/incidents")
def get_incidents():
    """Return the most recent 20 incidents including related model details."""
    session_gen = get_session()
    try:
        session = next(session_gen)
        incidents = (
            session.query(models.Incident)
            .options(
                joinedload(models.Incident.attack_event),
                joinedload(models.Incident.healing_actions),
            )
            .order_by(models.Incident.created_at.desc())
            .limit(20)
            .all()
        )

        payload = {
            "status": "success",
            "data": [_serialize_incident(incident) for incident in incidents],
            "count": len(incidents),
        }
        return jsonify(payload), 200
    except Exception as exc:  # pragma: no cover
        logger.exception("Failed to fetch incidents: %s", exc)
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "Unable to fetch incidents at this time.",
                }
            ),
            500,
        )
    finally:
        session_gen.close()


@api_bp.get("/stats")
def get_stats():
    """Return aggregate incident counters for dashboard summary cards."""
    session_gen = get_session()
    try:
        session = next(session_gen)

        total_incidents = session.query(models.Incident).count()
        mitigated_count = (
            session.query(models.Incident)
            .filter(models.Incident.status == "mitigated")
            .count()
        )
        resolved_count = (
            session.query(models.Incident)
            .filter(models.Incident.status == "resolved")
            .count()
        )
        active_count = (
            session.query(models.Incident)
            .filter(models.Incident.status.notin_(["mitigated", "resolved"]))
            .count()
        )

        payload = {
            "status": "success",
            "data": {
                "total_incidents": total_incidents,
                "mitigated_count": mitigated_count,
                "resolved_count": resolved_count,
                "active_count": active_count,
            },
        }
        return jsonify(payload), 200
    except Exception as exc:  # pragma: no cover
        logger.exception("Failed to fetch stats: %s", exc)
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "Unable to fetch dashboard stats at this time.",
                }
            ),
            500,
        )
    finally:
        session_gen.close()
