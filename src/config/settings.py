"""Application settings for the AI-Powered Autonomous Self-Healing Cyber Defense System.

This module centralizes environment-driven configuration so it can be imported
from anywhere in the project without side effects beyond loading ``.env``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

# Load environment variables from a local .env file when present.
load_dotenv()



def _to_bool(value: str | None, default: bool = False) -> bool:
    """Convert an environment variable string to a boolean safely."""
    if value is None:
        return default
    normalized = value.strip().lower()
    return normalized in {"1", "true", "t", "yes", "y", "on"}



def _to_int(value: str | None, default: int) -> int:
    """Convert an environment variable string to an int safely."""
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class Settings:
    """Runtime configuration values for application services.

    Attributes:
        APP_NAME: Human-readable name used in logs, UI labels, and metadata.
        DEBUG: Enables debug behavior for development diagnostics.
        DATABASE_URL: SQLAlchemy connection URL for persistent storage.
        MODEL_PATH: Filesystem path to the trained AI model artifact.
        PACKET_THRESHOLD_PER_SECOND: Max packets/sec before traffic is flagged.
        BLOCK_DURATION_SECONDS: Duration to keep automated block rules active.
        DASHBOARD_HOST: Network interface the Flask dashboard binds to.
        DASHBOARD_PORT: TCP port used by the dashboard web server.
    """

    APP_NAME: str = os.getenv(
        "APP_NAME", "AI-Powered Autonomous Self-Healing Cyber Defense System"
    )
    DEBUG: bool = _to_bool(os.getenv("DEBUG"), default=False)
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./cyber_defense.db")
    MODEL_PATH: str = os.getenv("MODEL_PATH", "./models/anomaly_model.pkl")
    PACKET_THRESHOLD_PER_SECOND: int = _to_int(
        os.getenv("PACKET_THRESHOLD_PER_SECOND"), default=1000
    )
    BLOCK_DURATION_SECONDS: int = _to_int(
        os.getenv("BLOCK_DURATION_SECONDS"), default=300
    )
    DASHBOARD_HOST: str = os.getenv("DASHBOARD_HOST", "0.0.0.0")
    DASHBOARD_PORT: int = _to_int(os.getenv("DASHBOARD_PORT"), default=5000)


# Shared settings instance for convenient imports across modules.
settings = Settings()
