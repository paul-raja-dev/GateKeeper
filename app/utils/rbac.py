"""
GateKeeper - RBAC Dependency

Provides the require_role() dependency factory for protecting routes
based on the authenticated user's role.

Usage:
    from app.utils.rbac import require_role
    from app.models.user import UserRole

    @router.get("/admin-only")
    async def admin_route(
        user: User = Depends(require_role(UserRole.ADMIN, UserRole.SUPERADMIN)),
    ):
        return {"message": f"Hello admin {user.email}"}

How it works:
    require_role() returns a FastAPI dependency that:
    1. Calls get_current_user to authenticate and load the user
    2. Checks if user.role is in the allowed roles
    3. Returns the user if allowed, raises 403 if not

Why a factory function and not a decorator?
    FastAPI's Depends() system works with callables. By returning a
    dependency function from require_role(), we can parameterise the
    allowed roles per-route while still composing naturally with Depends().
"""

from fastapi import Depends, HTTPException, status

from app.models.user import User, UserRole
from app.utils.dependencies import get_current_user


def require_role(*allowed_roles: UserRole):
    """
    Dependency factory that restricts a route to users with specific roles.

    Args:
        *allowed_roles: One or more UserRole values that are permitted.

    Returns:
        A FastAPI dependency that returns the current User if their role
        is in allowed_roles, or raises HTTP 403 otherwise.

    Example:
        Depends(require_role(UserRole.ADMIN))
        Depends(require_role(UserRole.ADMIN, UserRole.SUPERADMIN))
    """

    async def dependency(
        current_user: User = Depends(get_current_user),
    ) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to perform this action",
            )
        return current_user

    return dependency
