"""
GateKeeper - Admin API

Endpoints for managing users. All routes here are restricted to
admins and superadmins via the require_role() dependency.

Endpoints:
    GET  /api/v1/admin/users             — List all users (admin+)
    PATCH /api/v1/admin/users/{id}/role  — Change a user's role (superadmin only)
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import User, UserRole
from app.schemas.auth import UserResponse
from app.utils.rbac import require_role

router = APIRouter()


# ---------------------------------------------------------------------------
# Request Schemas (admin-specific)
# ---------------------------------------------------------------------------


class RoleUpdateRequest(BaseModel):
    """Request body for changing a user's role."""

    role: UserRole


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get(
    "/users",
    response_model=list[UserResponse],
    summary="List all users",
    description="Returns all registered users. Requires admin or superadmin role.",
)
async def list_users(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role(UserRole.ADMIN, UserRole.SUPERADMIN)),
) -> list[User]:
    """
    List all users in the system.

    Only accessible to admins and superadmins.
    Returns users ordered by creation date (newest first).
    """
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    return list(result.scalars().all())


@router.patch(
    "/users/{user_id}/role",
    response_model=UserResponse,
    summary="Change a user's role",
    description="Promotes or demotes a user. Requires superadmin role.",
)
async def change_user_role(
    user_id: uuid.UUID,
    body: RoleUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.SUPERADMIN)),
) -> User:
    """
    Update the role of a specific user.

    Only superadmins can change roles — this prevents privilege escalation
    where an admin promotes themselves to superadmin.

    Args:
        user_id: UUID of the user to update
        body: New role to assign
        current_user: The authenticated superadmin making the request

    Raises:
        HTTPException 404: If the target user doesn't exist
        HTTPException 400: If trying to change your own role (safety guard)
    """
    # Prevent self-demotion — superadmins shouldn't be able to lock themselves out
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot change your own role",
        )

    # Find the target user
    result = await db.execute(select(User).where(User.id == user_id))
    target_user = result.scalar_one_or_none()

    if target_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Apply the role change
    target_user.role = body.role
    await db.commit()
    await db.refresh(target_user)

    return target_user
