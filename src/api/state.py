"""Shared API state, kept apart from server.py to avoid a circular import."""

from __future__ import annotations

from typing import Optional

from src.storage.database import Database

_db: Optional[Database] = None


def get_db() -> Database:
    """Return the process-wide Database, creating it on first use."""
    global _db
    if _db is None:
        _db = Database()
    return _db


def close_db() -> None:
    global _db
    if _db is not None:
        _db.close()
        _db = None
