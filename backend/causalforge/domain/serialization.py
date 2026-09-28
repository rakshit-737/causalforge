"""Stable serialization helpers used for hashes and audit-chain entries."""

import hashlib
import json
from datetime import date, datetime
from enum import Enum
from typing import Any
from uuid import UUID


def _json_default(value: Any) -> str:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, (UUID, Enum)):
        return str(value.value if isinstance(value, Enum) else value)
    raise TypeError(f"unsupported value for canonical JSON: {type(value).__name__}")


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize JSON-compatible data with stable ordering and no insignificant whitespace."""

    return json.dumps(
        value,
        default=_json_default,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_hex(value: Any) -> str:
    """Hash a canonical JSON representation and return lowercase hexadecimal SHA-256."""

    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def sha256_bytes(value: bytes) -> str:
    """Hash already-canonical bytes without serializing them again."""

    return hashlib.sha256(value).hexdigest()
