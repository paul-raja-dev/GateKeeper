"""
Tests for authentication endpoints: register, login, and /me.
"""

import pytest

# ---------------------------------------------------------------------------
# Registration Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_register_success(client):
    """Registering with valid data should return 201 and user info."""
    response = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "test@example.com",
            "password": "StrongP@ss1",
            "full_name": "Test User",
        },
    )

    assert response.status_code == 201

    data = response.json()
    assert data["email"] == "test@example.com"
    assert data["full_name"] == "Test User"
    assert data["is_active"] is True
    assert data["is_verified"] is False
    assert "id" in data
    assert "created_at" in data
    # Password should NEVER be in the response
    assert "hashed_password" not in data
    assert "password" not in data


@pytest.mark.asyncio
async def test_register_duplicate_email(client):
    """Registering with an existing email should return 409."""
    user_data = {
        "email": "duplicate@example.com",
        "password": "StrongP@ss1",
        "full_name": "First User",
    }

    # First registration — should succeed
    response1 = await client.post("/api/v1/auth/register", json=user_data)
    assert response1.status_code == 201

    # Second registration with same email — should fail
    response2 = await client.post("/api/v1/auth/register", json=user_data)
    assert response2.status_code == 409
    assert "already exists" in response2.json()["detail"]


@pytest.mark.asyncio
async def test_register_weak_password(client):
    """Registering with a weak password should return 422."""
    # No uppercase letter
    response = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "weak@example.com",
            "password": "weakpassword1",
            "full_name": "Weak User",
        },
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_register_short_password(client):
    """Password shorter than 8 characters should return 422."""
    response = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "short@example.com",
            "password": "Short1",
            "full_name": "Short Pass",
        },
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_register_invalid_email(client):
    """Invalid email format should return 422."""
    response = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "not-an-email",
            "password": "StrongP@ss1",
            "full_name": "Bad Email",
        },
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_register_email_normalized(client):
    """Email should be normalized to lowercase."""
    response = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "UPPER@EXAMPLE.COM",
            "password": "StrongP@ss1",
            "full_name": "Upper Case",
        },
    )

    assert response.status_code == 201
    assert response.json()["email"] == "upper@example.com"


# ---------------------------------------------------------------------------
# Login Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_success(client):
    """Login with valid credentials should return 200 and a token."""
    # First register
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "login@example.com",
            "password": "StrongP@ss1",
            "full_name": "Login User",
        },
    )

    # Then login
    response = await client.post(
        "/api/v1/auth/login",
        json={
            "email": "login@example.com",
            "password": "StrongP@ss1",
        },
    )

    assert response.status_code == 200

    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert len(data["access_token"]) > 0


@pytest.mark.asyncio
async def test_login_wrong_password(client):
    """Login with wrong password should return 401."""
    # Register first
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "wrongpass@example.com",
            "password": "StrongP@ss1",
            "full_name": "Wrong Pass",
        },
    )

    # Login with wrong password
    response = await client.post(
        "/api/v1/auth/login",
        json={
            "email": "wrongpass@example.com",
            "password": "WrongPassword1",
        },
    )

    assert response.status_code == 401
    assert "Invalid email or password" in response.json()["detail"]


@pytest.mark.asyncio
async def test_login_nonexistent_email(client):
    """Login with non-existent email should return 401."""
    response = await client.post(
        "/api/v1/auth/login",
        json={
            "email": "nobody@example.com",
            "password": "StrongP@ss1",
        },
    )

    assert response.status_code == 401
    # Same error message as wrong password (anti-enumeration)
    assert "Invalid email or password" in response.json()["detail"]


# ---------------------------------------------------------------------------
# Protected Endpoint Tests (/me)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_me_with_valid_token(client):
    """GET /me with valid token should return user profile."""
    # Register
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "me@example.com",
            "password": "StrongP@ss1",
            "full_name": "Me User",
        },
    )

    # Login to get token
    login_response = await client.post(
        "/api/v1/auth/login",
        json={
            "email": "me@example.com",
            "password": "StrongP@ss1",
        },
    )
    token = login_response.json()["access_token"]

    # Access /me with the token
    response = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "me@example.com"
    assert data["full_name"] == "Me User"
    assert "hashed_password" not in data


@pytest.mark.asyncio
async def test_me_without_token(client):
    """GET /me without a token should return 401."""
    response = await client.get("/api/v1/auth/me")

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_me_with_invalid_token(client):
    """GET /me with an invalid token should return 401."""
    response = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer invalid-token-here"},
    )

    assert response.status_code == 401
