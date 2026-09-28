"""Small standard-library JSON logging layer.

The logging layer deliberately records identifiers and metadata rather than raw evidence. Callers
should still avoid putting secrets in log messages; the formatter masks common credential-shaped
values as a second safety layer.
"""

import json
import logging
import re
import sys
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

request_id_context: ContextVar[str | None] = ContextVar("request_id", default=None)

_SENSITIVE_VALUE = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|authorization)(\s*[=:]\s*)([^\s,;]+)"
)


def redact_log_text(value: str) -> str:
    """Mask common key/value credential patterns in a log message."""

    return _SENSITIVE_VALUE.sub(r"\1\2[REDACTED]", value)


class JsonFormatter(logging.Formatter):
    """Serialize log records as one compact JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_log_text(record.getMessage()),
        }
        request_id = request_id_context.get()
        if request_id:
            payload["request_id"] = request_id
        if record.exc_info and record.exc_info[0] is not None:
            payload["exception_type"] = record.exc_info[0].__name__
        return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))


def configure_logging(level: str = "INFO") -> None:
    """Configure one process-wide JSON handler without duplicating handlers on reload."""

    root = logging.getLogger()
    root.setLevel(level.upper())
    for handler in root.handlers:
        if getattr(handler, "_causalforge_json", False):
            handler.setFormatter(JsonFormatter())
            return

    handler = logging.StreamHandler(sys.stdout)
    handler._causalforge_json = True  # type: ignore[attr-defined]
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    """Return a named logger for application services."""

    return logging.getLogger(name)
