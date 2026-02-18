"""Flask dashboard application entry point.

This module provides an app factory for the dashboard service, registers API
routes, and exposes a root route that renders the dashboard template.
"""

from __future__ import annotations

import logging

from flask import Flask, render_template

from src.config.settings import settings
from src.dashboard.api import api_bp


def configure_logging() -> None:
    """Configure application-wide logging for the dashboard service."""
    logging.basicConfig(
        level=logging.DEBUG if settings.DEBUG else logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


def create_app() -> Flask:
    """Create and configure the Flask dashboard application.

    Returns:
        A configured Flask application instance.
    """
    configure_logging()

    app = Flask(__name__, template_folder="templates")
    app.config["DEBUG"] = settings.DEBUG

    app.register_blueprint(api_bp)

    @app.get("/")
    def dashboard_home() -> str:
        """Render the main dashboard UI template."""
        return render_template("dashboard.html", app_name=settings.APP_NAME)

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        host=settings.DASHBOARD_HOST,
        port=settings.DASHBOARD_PORT,
        debug=settings.DEBUG,
    )
