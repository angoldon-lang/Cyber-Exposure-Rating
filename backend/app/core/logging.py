"""Logging strutturato JSON con redazione automatica dei dati sensibili."""
from __future__ import annotations

import logging
import re
import sys
from typing import Any

import structlog

from app.core.config import settings

# Pattern che non devono MAI comparire nei log applicativi.
_REDACTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)(authorization\s*[:=]\s*)(bearer\s+)?[A-Za-z0-9._\-]{12,}"), r"\1<redacted>"),
    (re.compile(r"(?i)\b(api[_-]?key|token|secret|password|passwd|pwd)\b(\s*[:=]\s*)\S+"), r"\1\2<redacted>"),
    (re.compile(r"(?i)\b(hibp-api-key)\b(\s*[:=]\s*)\S+"), r"\1\2<redacted>"),
    (re.compile(r"://([^:/@\s]+):([^@/\s]+)@"), r"://\1:<redacted>@"),
]


def redact(value: str) -> str:
    for pattern, replacement in _REDACTION_PATTERNS:
        value = pattern.sub(replacement, value)
    return value


def _redaction_processor(_logger: Any, _name: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    for key, value in list(event_dict.items()):
        if isinstance(value, str):
            event_dict[key] = redact(value)
    return event_dict


def configure_logging() -> None:
    level = logging.DEBUG if settings.debug else logging.INFO
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=level)
    for noisy in ("uvicorn.access", "botocore", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    renderer = (
        structlog.dev.ConsoleRenderer()
        if settings.environment == "development"
        else structlog.processors.JSONRenderer()
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            _redaction_processor,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> Any:
    return structlog.get_logger(name)
