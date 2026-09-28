"""Canonical event normalizer."""

from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError

from causalforge.domain.events import CanonicalEvent
from causalforge.domain.serialization import sha256_hex
from causalforge.ingestion.redaction import RedactionResult, redact_payload


class NormalizationError(ValueError):
    """Raised when untrusted input cannot become a canonical event."""


class NormalizedEvent:
    """Canonical event plus redaction metadata retained by the ingestion service."""

    def __init__(self, event: CanonicalEvent, redaction: RedactionResult) -> None:
        self.event = event
        self.redaction = redaction


def _utc_now() -> datetime:
    return datetime.now(UTC)


def normalize_event(
    payload: Mapping[str, Any],
    *,
    parser_version: str,
    clock: Callable[[], datetime] = _utc_now,
) -> NormalizedEvent:
    """Hash raw input, redact it, and validate the canonical event contract."""

    if not isinstance(payload, Mapping):
        raise NormalizationError("event payload must be an object")

    raw_payload_sha256 = sha256_hex(payload)
    redaction = redact_payload(payload)
    redacted_payload = dict(redaction.value)
    redacted_payload["schema_version"] = "1.0"
    redacted_payload["parser_version"] = parser_version
    redacted_payload["raw_payload_sha256"] = raw_payload_sha256
    redacted_payload.setdefault("ingested_at", clock())

    try:
        event = CanonicalEvent.model_validate(redacted_payload)
    except ValidationError as exc:
        raise NormalizationError("event payload failed canonical validation") from exc
    return NormalizedEvent(event=event, redaction=redaction)
