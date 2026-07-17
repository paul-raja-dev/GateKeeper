"""
Tests for session management: refresh tokens, logout, and session listing.
"""

import pytest

# ---------------------------------------------------------------------------
# Login Token Pair Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_returns_refresh_token(client):
    """Login should now return both access_token and refresh_token."""
    # Register
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "session@example.com",
            "password": "StrongP@ss1",
            "full_name": "Session User",
        },
    )

    # Login
    response = await client.post(
        "/api/v1/auth/login",
        json={
            "email": "session@example.com",
            "password": "StrongP@ss1",
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert len(data["refresh_token"]) > 0


# ---------------------------------------------------------------------------
# Refresh Token Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_refresh_success(client):
    """Refreshing with a valid token should return a new token pair."""
    # Register + login
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "refresh@example.com",
            "password": "StrongP@ss1",
            "full_name": "Refresh User",
        },
    )
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "refresh@example.com", "password": "StrongP@ss1"},
    )
    old_refresh = login_resp.json()["refresh_token"]
    old_access = login_resp.json()["access_token"]

    # Refresh
    response = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": old_refresh},
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    # New tokens should be different from old ones
    assert data["refresh_token"] != old_refresh
    assert data["access_token"] != old_access


@pytest.mark.asyncio
async def test_refresh_token_rotation(client):
    """Using the same refresh token twice should fail (single-use)."""
    # Register + login
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "rotation@example.com",
            "password": "StrongP@ss1",
            "full_name": "Rotation User",
        },
    )
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "rotation@example.com", "password": "StrongP@ss1"},
    )
    refresh_token = login_resp.json()["refresh_token"]

    # First refresh — should succeed
    resp1 = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert resp1.status_code == 200

    # Second refresh with same token — should fail (already used)
    resp2 = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert resp2.status_code == 401


@pytest.mark.asyncio
async def test_refresh_invalid_token(client):
    """Refreshing with a garbage token should return 401."""
    response = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": "totally-fake-token"},
    )
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# Logout Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_logout_current_session(client):
    """Logout should revoke the current session's refresh token."""
    # Register + login
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "logout@example.com",
            "password": "StrongP@ss1",
            "full_name": "Logout User",
        },
    )
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "logout@example.com", "password": "StrongP@ss1"},
    )
    tokens = login_resp.json()

    # Logout
    response = await client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert response.status_code == 204

    # Try to refresh with the old token — should fail
    refresh_resp = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert refresh_resp.status_code == 401


@pytest.mark.asyncio
async def test_logout_all_sessions(client):
    """Logout-all should revoke all sessions."""
    # Register
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "logoutall@example.com",
            "password": "StrongP@ss1",
            "full_name": "Logout All User",
        },
    )

    # Login twice (simulate two devices)
    login1 = await client.post(
        "/api/v1/auth/login",
        json={"email": "logoutall@example.com", "password": "StrongP@ss1"},
    )
    login2 = await client.post(
        "/api/v1/auth/login",
        json={"email": "logoutall@example.com", "password": "StrongP@ss1"},
    )

    tokens1 = login1.json()
    tokens2 = login2.json()

    # Logout all using first session's token
    response = await client.post(
        "/api/v1/auth/logout-all",
        headers={"Authorization": f"Bearer {tokens1['access_token']}"},
    )
    assert response.status_code == 200
    assert "2" in response.json()["message"]  # "Logged out from 2 sessions"

    # Both refresh tokens should be revoked
    resp1 = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": tokens1["refresh_token"]},
    )
    assert resp1.status_code == 401

    resp2 = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": tokens2["refresh_token"]},
    )
    assert resp2.status_code == 401


# ---------------------------------------------------------------------------
# Session Listing Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_sessions(client):
    """Should list all active sessions with current session marked."""
    # Register + login
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "sessions@example.com",
            "password": "StrongP@ss1",
            "full_name": "Sessions User",
        },
    )
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "sessions@example.com", "password": "StrongP@ss1"},
    )
    token = login_resp.json()["access_token"]

    # List sessions
    response = await client.get(
        "/api/v1/sessions",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    sessions = response.json()
    assert len(sessions) >= 1
    # Current session should be marked
    current = [s for s in sessions if s["is_current"]]
    assert len(current) == 1


@pytest.mark.asyncio
async def test_revoke_specific_session(client):
    """Should be able to revoke a specific session by ID."""
    # Register + login twice
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "revoke@example.com",
            "password": "StrongP@ss1",
            "full_name": "Revoke User",
        },
    )
    login1 = await client.post(
        "/api/v1/auth/login",
        json={"email": "revoke@example.com", "password": "StrongP@ss1"},
    )
    await client.post(
        "/api/v1/auth/login",
        json={"email": "revoke@example.com", "password": "StrongP@ss1"},
    )

    token1 = login1.json()["access_token"]

    # List sessions using first token
    sessions_resp = await client.get(
        "/api/v1/sessions",
        headers={"Authorization": f"Bearer {token1}"},
    )
    sessions = sessions_resp.json()
    assert len(sessions) == 2

    # Find the non-current session and revoke it
    other_session = [s for s in sessions if not s["is_current"]][0]

    response = await client.delete(
        f"/api/v1/sessions/{other_session['id']}",
        headers={"Authorization": f"Bearer {token1}"},
    )
    assert response.status_code == 204

    # Verify only 1 session remains
    sessions_resp2 = await client.get(
        "/api/v1/sessions",
        headers={"Authorization": f"Bearer {token1}"},
    )
    assert len(sessions_resp2.json()) == 1
