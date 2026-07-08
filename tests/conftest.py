"""
Pytest Configuration & Shared Fixtures

Provides:
- Fresh FastAPI app instance per test
- Async HTTP client (no real server needed)
- Database session with automatic rollback after each test

Each test runs in its own database transaction that gets rolled back,
so tests don't pollute each other's data.
"""

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from app.config import get_settings
from app.database import Base, get_db
from app.main import create_app

# ---------------------------------------------------------------------------
# Database Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def anyio_backend():
    """Use asyncio as the async backend for tests."""
    return "asyncio"


@pytest.fixture
async def db_engine():
    """
    Create a test database engine.

    Uses the same DATABASE_URL from .env — tests run against
    the real database but each test's changes are rolled back.
    """
    settings = get_settings()
    engine = create_async_engine(settings.DATABASE_URL, echo=False)

    # Create all tables (in case migrations haven't been run)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    await engine.dispose()


@pytest.fixture
async def db_session(db_engine):
    """
    Provide a database session that rolls back after each test.

    This ensures test isolation — each test starts with a clean state.
    """
    async with db_engine.connect() as connection:
        # Start a transaction that we'll roll back
        transaction = await connection.begin()

        session = AsyncSession(bind=connection, expire_on_commit=False)

        yield session

        await session.close()
        await transaction.rollback()


# ---------------------------------------------------------------------------
# App & Client Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def app(db_session):
    """Create a FastAPI app with the test database session injected."""
    application = create_app()

    # Override the get_db dependency to use our test session
    async def _test_get_db():
        yield db_session

    application.dependency_overrides[get_db] = _test_get_db

    return application


@pytest.fixture
async def client(app):
    """
    Async HTTP client for testing FastAPI endpoints.

    Uses httpx.AsyncClient with ASGITransport to call the app
    directly in-process — no actual HTTP server is started.
    """
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as ac:
        yield ac
