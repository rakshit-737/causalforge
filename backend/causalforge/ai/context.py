"""Prompt-injection-resistant context construction.

Evidence and retrieved text are serialized as explicitly labeled untrusted data in a user message.
They are never interpolated into system instructions. This does not make hostile data trustworthy;
it preserves the boundary so the model and downstream verifier can reason about it safely.
"""

import re
from collections.abc import Mapping, Sequence
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from causalforge.ingestion.redaction import redact_payload

_INSTRUCTION_LIKE = re.compile(
    r"(?i)(ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|system\s+message|"
    r"call\s+(?:a\s+)?tool|execute\s+(?:this|the)|reveal\s+(?:the\s+)?prompt|"
    r"you\s+are\s+now)"
)


def _sanitize(value: Any, *, max_string_length: int = 4000) -> Any:
    if isinstance(value, str):
        cleaned = "".join(
            character for character in value if character in "\n\r\t" or ord(character) >= 32
        )
        return cleaned[:max_string_length]
    if isinstance(value, Mapping):
        return {
            str(key): _sanitize(child, max_string_length=max_string_length)
            for key, child in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_sanitize(child, max_string_length=max_string_length) for child in value]
    return value


class UntrustedFragment(BaseModel):
    """A redacted evidence/knowledge fragment with injection metadata."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    fragment_id: str = Field(min_length=1)
    source_family: str = Field(min_length=1)
    data: dict[str, Any]
    contains_instruction_like_text: bool


class SafeContext(BaseModel):
    """Structured context envelope that keeps trusted controls separate from untrusted data."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: UUID
    case_id: UUID
    objective: str = Field(min_length=1, max_length=1000)
    constraints: tuple[str, ...] = ()
    evidence: tuple[UntrustedFragment, ...] = ()
    knowledge: tuple[UntrustedFragment, ...] = ()


def _fragment(fragment_id: str, source_family: str, value: Mapping[str, Any]) -> UntrustedFragment:
    redacted = redact_payload(value)
    safe = _sanitize(redacted.value)
    serialized = repr(safe)
    return UntrustedFragment(
        fragment_id=fragment_id,
        source_family=source_family,
        data=safe if isinstance(safe, dict) else {"value": safe},
        contains_instruction_like_text=bool(_INSTRUCTION_LIKE.search(serialized)),
    )


def build_safe_context(
    *,
    tenant_id: UUID,
    case_id: UUID,
    objective: str,
    constraints: Sequence[str] = (),
    evidence: Sequence[tuple[str, str, Mapping[str, Any]]] = (),
    knowledge: Sequence[tuple[str, str, Mapping[str, Any]]] = (),
) -> SafeContext:
    """Build a bounded, redacted context without turning data into instructions."""

    return SafeContext(
        tenant_id=tenant_id,
        case_id=case_id,
        objective=objective,
        constraints=tuple(constraints),
        evidence=tuple(_fragment(*item) for item in evidence),
        knowledge=tuple(_fragment(*item) for item in knowledge),
    )
