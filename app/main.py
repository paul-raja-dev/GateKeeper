"""
GateKeeper - FastAPI Application Factory

This is the entry point for the entire application.

Why an application factory?
- Tests can create isolated app instances with different settings
- Initialization order is explicit and controllable
- Follows the same pattern used by Flask, Django, and production FastAPI apps
- Avoids global state issues with module-level app creation

Usage:
    # Development
    uvicorn app.main:app --reload

    # Production
    uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.database import check_db_connection
from app.logging_config import setup_logging

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Application Lifespan
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manages startup and shutdown events.

    Everything before `yield` runs on startup.
    Everything after `yield` runs on shutdown.

    This replaces the deprecated @app.on_event("startup") pattern.
    """
    # -- Startup --------------------------------------------------------------
    setup_logging()
    settings = get_settings()
    logger.info(
        "Starting %s v%s (debug=%s)",
        settings.APP_NAME,
        settings.APP_VERSION,
        settings.DEBUG,
    )

    # Verify database connectivity on startup
    db_ok = await check_db_connection()
    if db_ok:
        logger.info("Database connection established")
    else:
        logger.warning(
            "Database is not reachable — app started but some features may not work"
        )

    yield

    # -- Shutdown -------------------------------------------------------------
    logger.info("Shutting down %s", settings.APP_NAME)


# ---------------------------------------------------------------------------
# Application Factory
# ---------------------------------------------------------------------------


def create_app() -> FastAPI:
    """
    Create and configure the FastAPI application.

    Returns a fully configured FastAPI instance with:
    - Lifespan management (startup/shutdown)
    - Health check endpoint
    - OpenAPI docs (disabled in production)
    """
    settings = get_settings()

    application = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description="A production-ready Identity and Access Management (IAM) platform.",
        # Disable interactive docs in production for security.
        # Attackers use /docs to discover your API surface.
        docs_url="/docs" if settings.DEBUG else None,
        redoc_url="/redoc" if settings.DEBUG else None,
        lifespan=lifespan,
    )

    # Register routes
    _register_routes(application)

    return application


# ---------------------------------------------------------------------------
# Routes (will move to dedicated routers in Phase 2)
# ---------------------------------------------------------------------------


def _register_routes(application: FastAPI) -> None:
    """Register application routes."""

    @application.get(
        "/health",
        tags=["System"],
        summary="Health Check",
        response_description="Health status of the app and its dependencies.",
    )
    async def health_check():
        """
        Health check endpoint.

        Verifies:
        - Application is running
        - Database is reachable

        Used by:
        - Docker health checks
        - Load balancers
        - Monitoring systems (Uptime Robot, Pingdom, etc.)
        """
        settings = get_settings()
        db_connected = await check_db_connection()

        status = "healthy" if db_connected else "degraded"
        status_code = 200 if db_connected else 503

        return JSONResponse(
            content={
                "status": status,
                "version": settings.APP_VERSION,
                "database": "connected" if db_connected else "disconnected",
            },
            status_code=status_code,
        )

    @application.get(
        "/",
        tags=["System"],
        summary="Root",
        include_in_schema=False,
    )
    async def root():
        """Root endpoint — basic service identification."""
        settings = get_settings()
        return {
            "service": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "docs": "/docs" if settings.DEBUG else "Docs disabled in production",
        }


# ---------------------------------------------------------------------------
# Create the app instance
# ---------------------------------------------------------------------------
# This is what uvicorn imports: `uvicorn app.main:app`
app = create_app()
