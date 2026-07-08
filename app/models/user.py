"""
GateKeeper - User Model

The users table is the core of the entire IAM system.
Every other module (sessions, roles, API keys, audit logs) references this table.

Design decisions:
- UUID primary key: doesn't leak information like sequential IDs
- Email as unique identifier: industry standard for authentication
- Soft delete via is_active: never actually delete user data
- Separate is_verified flag: for email verification flow (Phase 5)
- Timestamps with timezone: always store in UTC, convert on display
"""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class User(Base):
    """
    User account model.

    Represents a registered user in the GateKeeper system.
    This is the central entity that all other modules reference.
    """

    __tablename__ = "users"

    # -- Primary Key ----------------------------------------------------------
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        # server_default uses PostgreSQL's gen_random_uuid() so the DB
        # generates the UUID even for raw SQL inserts
        server_default=func.gen_random_uuid(),
    )

    # -- Identity -------------------------------------------------------------
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
        comment="User's email address — primary login identifier",
    )
    hashed_password: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Bcrypt hash — NEVER store plaintext passwords",
    )
    full_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        comment="User's display name",
    )

    # -- Status Flags ---------------------------------------------------------
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        server_default="true",
        comment="Soft delete flag — inactive users cannot log in",
    )
    is_verified: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        server_default="false",
        comment="Email verification status",
    )
    is_superuser: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        server_default="false",
        comment="Admin flag — superusers bypass permission checks",
    )

    # -- Timestamps -----------------------------------------------------------
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        comment="Account creation timestamp (UTC)",
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        comment="Last modification timestamp (UTC)",
    )

    def __repr__(self) -> str:
        return f"<User {self.email}>"
