"""Database connection and session management utilities.

This module configures the SQLAlchemy engine and session factory using project
settings, and provides a safe session dependency helper for use across the app.
"""

from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from src.config.settings import settings


# SQLAlchemy engine configured with 2.0/future style behavior.
engine = create_engine(settings.DATABASE_URL, future=True)

# Factory for creating database sessions bound to the configured engine.
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def get_session() -> Generator[Session, None, None]:
    """Yield a database session and ensure proper cleanup.

    Yields:
        Session: An active SQLAlchemy session bound to the project engine.

    Raises:
        SQLAlchemyError: Re-raised if a database-related error occurs while
            using the session.
    """
    session = SessionLocal()
    try:
        yield session
    except SQLAlchemyError:
        session.rollback()
        raise
    finally:
        session.close()
