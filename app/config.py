"""
GateKeeper - Configuration Management

All application settings are defined here using Pydantic Settings.
Settings are loaded from environment variables and .env file.

Why Pydantic Settings?
- Type-safe configuration (no raw string env vars)
- Validation at startup (app crashes loudly if config is wrong)
- Single source of truth for all settings
- IDE autocompletion and type checking
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.

    Required fields (no default) will cause the app to fail at startup
    if not provided. This is intentional — we want to fail fast rather
    than run with missing configuration.
    """

    # -- Application ----------------------------------------------------------
    APP_NAME: str = "GateKeeper"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = False

    # -- Database -------------------------------------------------------------
    # No default — the app MUST have a database connection.
    # Format: postgresql+asyncpg://user:password@host:port/database
    DATABASE_URL: str

    # -- Redis ----------------------------------------------------------------
    REDIS_URL: str = "redis://localhost:6379/0"

    # -- Security -------------------------------------------------------------
    # No default — never run with a predictable secret key.
    SECRET_KEY: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        # If an env var is set in both .env and the actual environment,
        # the actual environment wins. This is important for Docker/K8s
        # where secrets are injected as real env vars.
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    """
    Cached settings instance.

    Using lru_cache ensures we only parse the .env file once,
    not on every request. The settings object is effectively a singleton.
    """
    return Settings()
