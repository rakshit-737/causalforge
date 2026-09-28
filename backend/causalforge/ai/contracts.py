"""Typed contracts shared by model providers and structured-output consumers."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ChatMessage(BaseModel):
    """A message with a trust label kept outside provider instructions."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    role: Literal["system", "user", "assistant"]
    content: str = Field(min_length=1)
    content_class: Literal["trusted_instruction", "untrusted_data", "model_output"] = (
        "trusted_instruction"
    )


class StructuredRequest(BaseModel):
    """Provider-neutral structured completion request."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    task: str = Field(min_length=1, max_length=120)
    schema_name: str = Field(min_length=1, max_length=120)
    output_schema: dict[str, Any]
    messages: tuple[ChatMessage, ...] = Field(min_length=1)
    model: str | None = None
    max_output_tokens: int = Field(default=1200, ge=1, le=16_000)


class ProviderMetadata(BaseModel):
    """Non-secret provider identity recorded in audit metadata."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: str = Field(min_length=1)
    model: str = Field(min_length=1)
    mode: Literal["remote", "local", "rule_only"]


class ProviderResponse(BaseModel):
    """Unvalidated provider payload plus metadata; validation happens at the boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    metadata: ProviderMetadata
    payload: dict[str, Any]
    output_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class ProviderError(RuntimeError):
    """Base error for provider failures without raw prompt/response content."""


class ProviderUnavailableError(ProviderError):
    """Raised when no configured provider can serve a request."""


class ProviderResponseError(ProviderError):
    """Raised when a provider response cannot be safely parsed."""


class StructuredOutputError(ProviderError):
    """Raised when a provider payload violates the requested output model."""
