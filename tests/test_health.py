"""
Tests for system endpoints: health check and root.
"""

import pytest


@pytest.mark.asyncio
async def test_root_returns_service_info(client):
    """Root endpoint should return service name and version."""
    response = await client.get("/")

    assert response.status_code == 200

    data = response.json()
    assert data["service"] == "GateKeeper"
    assert "version" in data


@pytest.mark.asyncio
async def test_health_endpoint_returns_status(client):
    """
    Health endpoint should return a status field.

    Note: In CI/testing without a real database, the health endpoint
    will report 'degraded' status. That's expected behavior — the
    endpoint itself works correctly, it's the DB that's unavailable.
    """
    response = await client.get("/health")

    # Accept both 200 (DB connected) and 503 (DB not connected)
    assert response.status_code in (200, 503)

    data = response.json()
    assert "status" in data
    assert "version" in data
    assert "database" in data
    assert data["status"] in ("healthy", "degraded")
    assert data["database"] in ("connected", "disconnected")
