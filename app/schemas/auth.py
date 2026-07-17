"""
GateKeeper - Authentication Schemas

Pydantic models that define the shape of request/response data
for authentication endpoints.

These are NOT database models — they're data contracts:
- What the API expects from clients (request schemas)
- What the API returns to clients (response schemas)

Why separate from SQLAlchemy models?
- Never expose internal fields (hashed_password) to clients
- Validation rules differ from database constraints
- Request shape ≠ response shape ≠ database shape
"""

import re
import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, field_validator

# ---------------------------------------------------------------------------
# Request Schemas
# ---------------------------------------------------------------------------


class UserRegister(BaseModel):
    """
    Schema for user registration request.

    Validates:
    - Email format (via EmailStr)
    - Password strength (via custom validator)
    - Full name presence and length
    """

    email: EmailStr = Field(
        ...,
        description="User's email address",
        examples=["paul@example.com"],
    )
    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="Password (min 8 chars, must include upper, lower, digit)",
        examples=["StrongP@ss1"],
    )
    full_name: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="User's full name",
        examples=["Paul Raja"],
    )

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        """
        Normalize email to lowercase.

        Paul@Example.com and paul@example.com should be the same account.
        """
        return v.lower().strip()

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        """
        Enforce minimum password complexity.

        Requirements:
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one digit

        Why not require special characters?
        NIST guidelines (SP 800-63B) recommend against mandatory special
        characters — they lead to predictable patterns like "Password1!".
        Length + character variety is more effective.
        """
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one digit")
        return v

    @field_validator("full_name")
    @classmethod
    def clean_full_name(cls, v: str) -> str:
        """Strip whitespace from full name."""
        return v.strip()


class UserLogin(BaseModel):
    """Schema for user login request."""

    email: EmailStr = Field(
        ...,
        description="User's email address",
        examples=["paul@example.com"],
    )
    password: str = Field(
        ...,
        description="User's password",
        examples=["StrongP@ss1"],
    )

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        """Normalize email to lowercase."""
        return v.lower().strip()


# ---------------------------------------------------------------------------
# Response Schemas
# ---------------------------------------------------------------------------


class UserResponse(BaseModel):
    """
    Schema for user data in API responses.

    Note: hashed_password is NEVER included.
    model_config with from_attributes=True allows creating this
    from a SQLAlchemy User object directly.
    """

    id: uuid.UUID
    email: str
    full_name: str
    is_active: bool
    is_verified: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class TokenResponse(BaseModel):
    """Schema for JWT token response after successful login or refresh."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshTokenRequest(BaseModel):
    """Schema for token refresh request."""

    refresh_token: str = Field(
        ...,
        description="The refresh token received from login or previous refresh",
    )


class SessionResponse(BaseModel):
    """Schema for session data in API responses."""

    id: uuid.UUID
    ip_address: str | None
    user_agent: str | None
    created_at: datetime
    last_active_at: datetime
    is_current: bool = False

    model_config = {"from_attributes": True}
