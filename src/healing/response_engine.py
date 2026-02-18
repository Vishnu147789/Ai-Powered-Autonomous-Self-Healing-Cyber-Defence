"""Incident response engine for automated self-healing actions."""

from __future__ import annotations

import logging
import shutil
import subprocess

from sqlalchemy.orm import joinedload

from src.config.settings import settings
from src.database import models
from src.database.connection import get_session
from src.database.repository import create_healing_action, update_incident_status

logger = logging.getLogger(__name__)


def _build_block_command(source_ip: str) -> list[str] | None:
    """Build a firewall command for blocking an IP using available tooling.

    Args:
        source_ip: The IP address to block.

    Returns:
        A command list suitable for ``subprocess.run`` or ``None`` when no
        supported firewall utility is found.
    """
    if shutil.which("iptables"):
        return ["iptables", "-A", "INPUT", "-s", source_ip, "-j", "DROP"]

    if shutil.which("ufw"):
        return ["ufw", "deny", "from", source_ip]

    return None


def _execute_firewall_block(source_ip: str) -> bool:
    """Execute firewall blocking command safely without invoking a shell.

    Args:
        source_ip: The source IP address to block.

    Returns:
        ``True`` when the command succeeds, otherwise ``False``.
    """
    command = _build_block_command(source_ip)
    if command is None:
        logger.error("No supported firewall tool found; cannot block IP %s", source_ip)
        return False

    try:
        logger.info(
            "Blocking source_ip=%s using command=%s (duration_hint=%ss)",
            source_ip,
            command,
            settings.BLOCK_DURATION_SECONDS,
        )
        subprocess.run(command, check=True, capture_output=True, text=True)
        logger.info("Firewall block applied successfully for source_ip=%s", source_ip)
        return True
    except subprocess.CalledProcessError as exc:
        logger.error(
            "Firewall command failed for source_ip=%s exit_code=%s stderr=%s",
            source_ip,
            exc.returncode,
            (exc.stderr or "").strip(),
        )
        return False
    except OSError as exc:
        logger.exception("Firewall execution error for source_ip=%s: %s", source_ip, exc)
        return False


def handle_incident(incident_id: int) -> None:
    """Handle an incident by executing self-healing response actions.

    For ``packet_flood`` attacks, this function attempts to block the attacking
    source IP at the host firewall, records a healing action, and updates the
    incident status to ``mitigated`` only when blocking succeeds.

    Args:
        incident_id: Identifier of the incident to handle.
    """
    session_gen = get_session()
    session = None

    try:
        session = next(session_gen)
        incident = (
            session.query(models.Incident)
            .options(joinedload(models.Incident.attack_event))
            .filter(models.Incident.id == incident_id)
            .first()
        )

        if incident is None:
            logger.warning("Incident not found for incident_id=%s", incident_id)
            return

        attack_event = incident.attack_event
        if attack_event is None:
            logger.error("Incident %s has no linked attack event", incident_id)
            return

        logger.info(
            "Handling incident_id=%s attack_event_id=%s attack_type=%s",
            incident.id,
            attack_event.id,
            attack_event.attack_type,
        )

        if attack_event.attack_type != "packet_flood":
            logger.info(
                "No automated action configured for attack_type=%s incident_id=%s",
                attack_event.attack_type,
                incident.id,
            )
            return

        success = _execute_firewall_block(attack_event.source_ip)

        healing_action = create_healing_action(
            session=session,
            incident_id=incident.id,
            action_type="block_ip",
            success=success,
        )
        logger.info(
            "Recorded healing_action_id=%s incident_id=%s success=%s",
            healing_action.id,
            incident.id,
            success,
        )

        if success:
            updated = update_incident_status(
                session=session,
                incident_id=incident.id,
                status="mitigated",
            )
            if updated is not None:
                logger.info("Incident %s updated to status=mitigated", incident.id)
        else:
            logger.warning(
                "Incident %s remains unchanged because firewall block failed",
                incident.id,
            )

    except Exception as exc:  # pragma: no cover - must not crash caller
        logger.exception("Error while handling incident_id=%s: %s", incident_id, exc)
    finally:
        if session_gen is not None:
            session_gen.close()
