"""
Pytest Configuration & Shared Fixtures

Fixtures defined here are automatically available to all test files
without explicit imports.
"""

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import create_app


@pytest.fixture
def app():
    """Create a fresh FastAPI application instance for testing."""
    return create_app()


@pytest.fixture
async def client(app):
    """
    Async HTTP client for testing FastAPI endpoints.

    Uses httpx.AsyncClient with ASGITransport to call the app
    directly in-process — no actual HTTP server is started.
    This is fast, isolated, and doesn't require port binding.
    """
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as ac:
        yield ac
