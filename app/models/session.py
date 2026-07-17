"""
GateKeeper - Session Model

Tracks active login sessions. Each time a user logs in, a new session
is created with a refresh token, device info, and IP address.

Design decisions:
- One session per login (same user can have multiple sessions = multiple devices)
- Refresh tokens are hashed (SHA-256) before storage — if the DB leaks,
  raw tokens can't be extracted
- Soft revoke via is_revoked — keeps audit trail of all sessions
- expires_at provides absolute expiry independent of revocation
- last_active_at tracks when the session was last used for refresh
"""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Session(Base):
    """
    Login session model.

    Each login creates a session. A user can have many active sessions
    (one per device/browser). Sessions are revoked on logout.
    """

    __tablename__ = "sessions"

    # -- Primary Key ----------------------------------------------------------
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )

    # -- Relationships --------------------------------------------------------
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="The user who owns this session",
    )

    # SQLAlchemy relationship for easy access: session.user
    user = relationship("User", lazy="selectin")

    # -- Token ----------------------------------------------------------------
    refresh_token_hash: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
        index=True,
        comment="SHA-256 hash of the refresh token",
    )

    # -- Device Info ----------------------------------------------------------
    ip_address: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
        comment="Client IP address (IPv4 or IPv6)",
    )
    user_agent: Mapped[str | None] = mapped_column(
        String(512),
        nullable=True,
        comment="Client User-Agent string (browser/device)",
    )

    # -- Status ---------------------------------------------------------------
    is_revoked: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        server_default="false",
        comment="Whether this session has been revoked (logged out)",
    )

    # -- Timestamps -----------------------------------------------------------
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        comment="When this session was created (login time)",
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment="When this session's refresh token expires",
    )
    last_active_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        comment="Last time this session was used to refresh",
    )

    def __repr__(self) -> str:
        return f"<Session {self.id} user={self.user_id}>"
