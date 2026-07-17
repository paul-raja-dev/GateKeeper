"""
GateKeeper - Model Registry

All SQLAlchemy models MUST be imported here.

Why? Alembic's autogenerate compares Base.metadata (which contains all
registered models) against the actual database schema. If a model isn't
imported, Alembic won't know it exists and won't generate a migration for it.

Usage:
    from app.models import User, Session
"""

from app.models.session import Session
from app.models.user import User

__all__ = ["Session", "User"]
