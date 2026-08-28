"""Idempotently create the first administrator from environment settings."""

from __future__ import annotations

import uuid

from sqlalchemy import select

from src.auth import hash_password
from src.database import create_engine_from_url, create_session_factory
from src.repositories.orm_producer import UserRow
from src.settings import Settings, get_settings


def bootstrap_initial_admin(settings: Settings | None = None) -> bool:
    """Create the configured initial administrator once.

    Returns ``True`` only when a new account is created. Existing accounts are
    never promoted and their passwords are never reset implicitly.
    """

    settings = settings or get_settings()
    email = settings.initial_admin_email
    password = settings.initial_admin_password
    if not email and not password:
        return False
    if not email or not password:
        raise RuntimeError(
            "INITIAL_ADMIN_EMAIL and INITIAL_ADMIN_PASSWORD must be set together"
        )
    if len(password) < 12:
        raise RuntimeError("INITIAL_ADMIN_PASSWORD must contain at least 12 characters")
    if not settings.database_url:
        raise RuntimeError("Database configuration is required to create the administrator")

    normalized_email = email.lower().strip()
    engine = create_engine_from_url(settings.database_url)
    session = create_session_factory(engine)()
    try:
        existing = session.scalar(select(UserRow).where(UserRow.email == normalized_email))
        if existing is not None:
            if existing.role != "admin":
                raise RuntimeError(
                    "INITIAL_ADMIN_EMAIL already belongs to a non-admin account"
                )
            return False

        session.add(
            UserRow(
                id=f"user-{uuid.uuid4().hex}",
                email=normalized_email,
                password_hash=hash_password(password),
                role="admin",
                display_name=settings.initial_admin_display_name,
            )
        )
        session.commit()
        return True
    finally:
        session.close()
        engine.dispose()


def main() -> None:
    created = bootstrap_initial_admin()
    if created:
        print("[bootstrap] initial administrator created")
    else:
        print("[bootstrap] initial administrator not configured or already exists")


if __name__ == "__main__":
    main()
