"""
GateKeeper - Structured Logging Configuration

Sets up JSON-formatted logging for production use.

Why JSON logs?
- Log aggregation tools (ELK, Datadog, CloudWatch) parse JSON natively
- Structured fields make searching and filtering easy
- Human-readable logs are useless when you have 10,000 requests/second

In development (DEBUG=True), we fall back to a more readable format
because staring at JSON in your terminal is painful.
"""

import logging
import sys
from datetime import UTC, datetime

from app.config import get_settings


class JSONFormatter(logging.Formatter):
    """
    Formats log records as JSON lines.

    Each log line is a valid JSON object, making it easy for log
    aggregation services to parse without custom grok patterns.
    """

    def format(self, record: logging.LogRecord) -> str:
        import json

        log_data = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Include exception info if present
        if record.exc_info and record.exc_info[0] is not None:
            log_data["exception"] = self.formatException(record.exc_info)

        # Include any extra fields passed to the logger
        # e.g., logger.info("Login", extra={"user_id": 123})
        for key, value in record.__dict__.items():
            if key not in logging.LogRecord(
                "", 0, "", 0, "", (), None
            ).__dict__ and key not in ("message", "msg"):
                log_data[key] = value

        return json.dumps(log_data, default=str)


def setup_logging() -> None:
    """
    Configure application-wide logging.

    - Production: JSON format, INFO level
    - Development: Human-readable format, DEBUG level
    """
    settings = get_settings()

    # Root logger configuration
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG if settings.DEBUG else logging.INFO)

    # Remove any existing handlers (prevents duplicate logs on reload)
    root_logger.handlers.clear()

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)

    if settings.DEBUG:
        # Development: readable format
        formatter = logging.Formatter(
            fmt="%(asctime)s │ %(levelname)-8s │ %(name)-25s │ %(message)s",
            datefmt="%H:%M:%S",
        )
    else:
        # Production: JSON format
        formatter = JSONFormatter()

    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # Suppress noisy third-party loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(
        logging.INFO if settings.DEBUG else logging.WARNING
    )
