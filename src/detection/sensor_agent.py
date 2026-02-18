"""Network sensor agent that monitors packet rates and triggers incident response."""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from typing import Any

from scapy.all import IP, sniff

from src.config.settings import settings
from src.database.connection import get_session
from src.database.repository import create_attack_event, create_incident
from src.detection.anomaly_detector import AnomalyDetector
from src.healing import response_engine

logger = logging.getLogger(__name__)


class SensorAgent:
    """Sniffs network traffic and creates incidents for suspicious packet bursts.

    The agent tracks per-source-IP packet frequency over one-second windows.
    When an IP exceeds ``settings.PACKET_THRESHOLD_PER_SECOND``, the packet count
    is evaluated by an AI anomaly detector before incident creation.
    """

    def __init__(self, interface: str | None = None) -> None:
        """Initialize the sensor agent.

        Args:
            interface: Optional network interface to sniff. When ``None``, Scapy
                uses its default interface selection behavior.
        """
        self.interface = interface
        self._packet_counts: dict[str, int] = defaultdict(int)
        self._flagged_this_window: set[str] = set()
        self._window_started_at = time.monotonic()
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._sniff_thread: threading.Thread | None = None

        self._detector = AnomalyDetector(model_path=settings.MODEL_PATH)
        model_loaded = self._detector.load_model()
        if not model_loaded:
            logger.warning(
                "Anomaly detection model not found at %s; threshold-only traffic "
                "will be treated as normal until a model is trained/loaded.",
                settings.MODEL_PATH,
            )

    def start(self) -> None:
        """Start background packet sniffing without blocking the caller thread."""
        if self._sniff_thread and self._sniff_thread.is_alive():
            logger.info("SensorAgent is already running.")
            return

        self._stop_event.clear()
        self._sniff_thread = threading.Thread(
            target=self._run_sniffer,
            name="sensor-agent-sniffer",
            daemon=True,
        )
        self._sniff_thread.start()
        logger.info("SensorAgent started on interface=%s", self.interface or "default")

    def stop(self, timeout: float = 3.0) -> None:
        """Signal the background sniffer thread to stop.

        Args:
            timeout: Maximum seconds to wait for the thread to join.
        """
        self._stop_event.set()
        if self._sniff_thread and self._sniff_thread.is_alive():
            self._sniff_thread.join(timeout=timeout)

    def _run_sniffer(self) -> None:
        """Continuously run Scapy sniffing with resilient error handling."""
        while not self._stop_event.is_set():
            try:
                sniff(
                    iface=self.interface,
                    prn=self._on_packet,
                    store=False,
                    stop_filter=lambda _pkt: self._stop_event.is_set(),
                    timeout=1,
                )
            except Exception as exc:  # pragma: no cover - depends on runtime env
                logger.exception("Packet sniffing failed: %s", exc)
                time.sleep(1)

    def _on_packet(self, packet: Any) -> None:
        """Handle each sniffed packet, update counters, and trigger alerts."""
        try:
            self._roll_window_if_needed()

            if IP not in packet:
                return

            source_ip = str(packet[IP].src)
            if not source_ip:
                return

            should_evaluate = False
            with self._lock:
                self._packet_counts[source_ip] += 1
                count = self._packet_counts[source_ip]
                if (
                    count > settings.PACKET_THRESHOLD_PER_SECOND
                    and source_ip not in self._flagged_this_window
                ):
                    self._flagged_this_window.add(source_ip)
                    should_evaluate = True

            if should_evaluate:
                logger.warning(
                    "Packet threshold exceeded for source_ip=%s count=%s threshold=%s",
                    source_ip,
                    count,
                    settings.PACKET_THRESHOLD_PER_SECOND,
                )
                self._evaluate_and_respond(source_ip=source_ip, packet_count=count)

        except Exception as exc:  # pragma: no cover - callback must never crash sniffer
            logger.exception("Error processing packet: %s", exc)

    def _roll_window_if_needed(self) -> None:
        """Reset packet counters when the one-second monitoring window expires."""
        now = time.monotonic()
        if now - self._window_started_at < 1.0:
            return

        with self._lock:
            if now - self._window_started_at >= 1.0:
                self._packet_counts.clear()
                self._flagged_this_window.clear()
                self._window_started_at = now

    def _evaluate_and_respond(self, source_ip: str, packet_count: int) -> None:
        """Run anomaly detection and trigger incident flow only for anomalies."""
        try:
            is_anomaly = self._detector.predict([float(packet_count)])
        except Exception as exc:
            logger.exception(
                "Anomaly detector evaluation failed for source_ip=%s count=%s: %s",
                source_ip,
                packet_count,
                exc,
            )
            return

        if not is_anomaly:
            logger.info(
                "Traffic considered normal by anomaly detector for source_ip=%s count=%s",
                source_ip,
                packet_count,
            )
            return

        self._create_incident_and_respond(source_ip=source_ip, packet_count=packet_count)

    def _create_incident_and_respond(self, source_ip: str, packet_count: int) -> None:
        """Persist attack artifacts and invoke incident response flow."""
        session_gen = get_session()
        try:
            session = next(session_gen)
            attack_event = create_attack_event(
                session=session,
                source_ip=source_ip,
                attack_type="packet_flood",
                severity="high",
            )
            incident = create_incident(session=session, attack_event_id=attack_event.id)

            logger.info(
                "Created attack_event_id=%s incident_id=%s source_ip=%s packet_count=%s",
                attack_event.id,
                incident.id,
                source_ip,
                packet_count,
            )

            handler = getattr(response_engine, "handle_incident", None)
            if callable(handler):
                handler(incident.id)
            else:
                logger.warning(
                    "response_engine.handle_incident is not implemented; "
                    "incident_id=%s requires manual handling",
                    incident.id,
                )

        except Exception as exc:
            logger.exception("Failed to persist incident/trigger response: %s", exc)
        finally:
            session_gen.close()
