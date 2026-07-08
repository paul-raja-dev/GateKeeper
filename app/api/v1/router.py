"""
GateKeeper - API v1 Router

Aggregates all v1 route modules into a single router.

Why aggregate routers?
    Instead of registering each module's router individually in main.py,
    we collect them here. main.py only needs to include v1_router once.
    As the project grows, this keeps main.py clean.

Usage in main.py:
    from app.api.v1.router import v1_router
    app.include_router(v1_router, prefix="/api/v1")
"""

from fastapi import APIRouter

from app.api.v1.auth import router as auth_router

v1_router = APIRouter()

# Register module routers with their prefixes and tags
v1_router.include_router(auth_router, prefix="/auth", tags=["Authentication"])
