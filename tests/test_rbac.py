"""
Tests for Phase 4: Role-Based Access Control (RBAC)

Covers:
- Default role assignment on registration
- role field visible in /me endpoint
- Role-gated route enforcement (user, admin, superadmin)
- Admin user listing endpoint
- Superadmin role promotion
- Self-role-change guard
"""

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

REGISTER_URL = "/api/v1/auth/register"
LOGIN_URL = "/api/v1/auth/login"
ME_URL = "/api/v1/auth/me"
ADMIN_USERS_URL = "/api/v1/admin/users"


async def register_and_login(client, email: str, password: str = "StrongP@ss1") -> dict:
    """Register a user and return login token dict."""
    await client.post(
        REGISTER_URL,
        json={"email": email, "password": password, "full_name": "Test User"},
    )
    resp = await client.post(LOGIN_URL, json={"email": email, "password": password})
    return resp.json()


async def get_user_id(client, access_token: str) -> str:
    """Fetch the authenticated user's UUID via /me."""
    resp = await client.get(ME_URL, headers={"Authorization": f"Bearer {access_token}"})
    return resp.json()["id"]


# ---------------------------------------------------------------------------
# Role Field Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_new_user_has_default_role(client):
    """Newly registered users should have role='user'."""
    tokens = await register_and_login(client, "defaultrole@example.com")
    resp = await client.get(
        ME_URL, headers={"Authorization": f"Bearer {tokens['access_token']}"}
    )

    assert resp.status_code == 200
    assert resp.json()["role"] == "user"


@pytest.mark.asyncio
async def test_role_visible_in_me_endpoint(client):
    """The /me response must always include the role field."""
    tokens = await register_and_login(client, "rolevisible@example.com")
    resp = await client.get(
        ME_URL, headers={"Authorization": f"Bearer {tokens['access_token']}"}
    )

    assert "role" in resp.json()


# ---------------------------------------------------------------------------
# Admin Endpoint — Access Control
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_user_cannot_access_admin_route(client):
    """A regular user must receive 403 when hitting the admin users list."""
    tokens = await register_and_login(client, "noaccess@example.com")
    resp = await client.get(
        ADMIN_USERS_URL,
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )

    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_unauthenticated_cannot_access_admin_route(client):
    """Requests without a token must receive 401."""
    resp = await client.get(ADMIN_USERS_URL)
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Role Promotion via DB (simulate superadmin)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_admin_can_access_admin_route(client, db_session):
    """An admin-role user should be able to list all users."""
    from sqlalchemy import select

    from app.models.user import User, UserRole

    # Register and get user
    await register_and_login(client, "admin_access@example.com")

    # Promote directly in DB (simulates a superadmin promoting them)
    result = await db_session.execute(
        select(User).where(User.email == "admin_access@example.com")
    )
    user = result.scalar_one()
    user.role = UserRole.ADMIN
    await db_session.commit()

    # Re-login to get a fresh token reflecting the new role
    new_tokens = await client.post(
        LOGIN_URL,
        json={"email": "admin_access@example.com", "password": "StrongP@ss1"},
    )
    access_token = new_tokens.json()["access_token"]

    resp = await client.get(
        ADMIN_USERS_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_superadmin_can_change_user_role(client, db_session):
    """A superadmin should be able to promote a regular user to admin."""
    from sqlalchemy import select

    from app.models.user import User, UserRole

    # Register two users
    await register_and_login(client, "sa@example.com")
    target_tokens = await register_and_login(client, "target@example.com")
    target_id = await get_user_id(client, target_tokens["access_token"])

    # Promote first user to superadmin in DB
    result = await db_session.execute(
        select(User).where(User.email == "sa@example.com")
    )
    sa_user = result.scalar_one()
    sa_user.role = UserRole.SUPERADMIN
    await db_session.commit()

    # Re-login as superadmin
    sa_tokens = await client.post(
        LOGIN_URL,
        json={"email": "sa@example.com", "password": "StrongP@ss1"},
    )
    sa_access = sa_tokens.json()["access_token"]

    # Promote target user to admin
    resp = await client.patch(
        f"/api/v1/admin/users/{target_id}/role",
        json={"role": "admin"},
        headers={"Authorization": f"Bearer {sa_access}"},
    )

    assert resp.status_code == 200
    assert resp.json()["role"] == "admin"


@pytest.mark.asyncio
async def test_admin_cannot_change_roles(client, db_session):
    """An admin (not superadmin) must not be able to change roles — 403."""
    from sqlalchemy import select

    from app.models.user import User, UserRole

    target_tokens = await register_and_login(client, "victim@example.com")
    target_id = await get_user_id(client, target_tokens["access_token"])

    # Promote admin user
    await register_and_login(client, "admin_only@example.com")
    result = await db_session.execute(
        select(User).where(User.email == "admin_only@example.com")
    )
    admin_user = result.scalar_one()
    admin_user.role = UserRole.ADMIN
    await db_session.commit()

    admin_tokens = await client.post(
        LOGIN_URL,
        json={"email": "admin_only@example.com", "password": "StrongP@ss1"},
    )
    admin_access = admin_tokens.json()["access_token"]

    resp = await client.patch(
        f"/api/v1/admin/users/{target_id}/role",
        json={"role": "admin"},
        headers={"Authorization": f"Bearer {admin_access}"},
    )

    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_superadmin_cannot_change_own_role(client, db_session):
    """A superadmin must not be able to change their own role (safety guard)."""
    from sqlalchemy import select

    from app.models.user import User, UserRole

    await register_and_login(client, "selfchange@example.com")

    result = await db_session.execute(
        select(User).where(User.email == "selfchange@example.com")
    )
    sa_user = result.scalar_one()
    sa_user.role = UserRole.SUPERADMIN
    await db_session.commit()

    sa_tokens = await client.post(
        LOGIN_URL,
        json={"email": "selfchange@example.com", "password": "StrongP@ss1"},
    )
    sa_access = sa_tokens.json()["access_token"]
    sa_id = await get_user_id(client, sa_access)

    resp = await client.patch(
        f"/api/v1/admin/users/{sa_id}/role",
        json={"role": "user"},
        headers={"Authorization": f"Bearer {sa_access}"},
    )

    assert resp.status_code == 400
