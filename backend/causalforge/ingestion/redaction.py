"""Recursive redaction for untrusted telemetry before persistence or model context."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

REDACTED = "[REDACTED]"
_SENSITIVE_KEYS = frozenset(
    {
        "password",
        "passwd",
        "token",
        "access_token",
        "refresh_token",
        "api_key",
        "apikey",
        "authorization",
        "secret_value",
        "private_key",
        "credential",
        "credentials",
    }
)


@dataclass(frozen=True)
class RedactionResult:
    """Redacted copy plus stable field paths for audit metadata."""

    value: Any
    paths: tuple[str, ...]


def _key_is_sensitive(key: str) -> bool:
    return key.casefold().replace("-", "_") in _SENSITIVE_KEYS


def _redact(value: Any, path: str) -> tuple[Any, list[str]]:
    if isinstance(value, Mapping):
        output: dict[str, Any] = {}
        paths: list[str] = []
        for key, child in value.items():
            key_text = str(key)
            child_path = f"{path}.{key_text}" if path else key_text
            if _key_is_sensitive(key_text):
                output[key_text] = REDACTED
                paths.append(child_path)
                continue
            redacted_child, child_paths = _redact(child, child_path)
            output[key_text] = redacted_child
            paths.extend(child_paths)
        return output, paths
    if isinstance(value, list):
        output_list: list[Any] = []
        paths = []
        for index, child in enumerate(value):
            child_path = f"{path}[{index}]"
            redacted_child, child_paths = _redact(child, child_path)
            output_list.append(redacted_child)
            paths.extend(child_paths)
        return output_list, paths
    return value, []


def redact_payload(payload: Mapping[str, Any]) -> RedactionResult:
    """Return a deep redacted copy without mutating the connector-owned payload."""

    value, paths = _redact(payload, "")
    return RedactionResult(value=value, paths=tuple(paths))
