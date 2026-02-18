"""Main runtime controller for the cyber defense platform.

This module boots the network detection sensor and starts the Flask dashboard
service. The sensor runs in a background thread while the dashboard server runs
in the main thread.
"""

from __future__ import annotations

import logging

from src.config.settings import settings
from src.dashboard.app import app as dashboard_app
from src.detection.sensor_agent import SensorAgent

logger = logging.getLogger(__name__)


def _configure_logging() -> None:
    """Configure baseline logging for the controller process."""
    logging.basicConfig(
        level=logging.DEBUG if settings.DEBUG else logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


def run() -> None:
    """Start background detection and run the dashboard server.

    The sensor agent is started first and remains active while Flask serves the
    dashboard/API endpoints. Shutdown is handled gracefully, ensuring the sensor
    thread is stopped before process exit.
    """
    _configure_logging()

    sensor = SensorAgent()

    logger.info("Starting SensorAgent in background thread")
    sensor.start()

    logger.info(
        "Starting dashboard server on %s:%s (debug=%s)",
        settings.DASHBOARD_HOST,
        settings.DASHBOARD_PORT,
        settings.DEBUG,
    )

    try:
        dashboard_app.run(
            host=settings.DASHBOARD_HOST,
            port=settings.DASHBOARD_PORT,
            debug=settings.DEBUG,
        )
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received. Beginning graceful shutdown")
    finally:
        logger.info("Stopping SensorAgent")
        sensor.stop()
        logger.info("Shutdown complete")


if __name__ == "__main__":
    run()
