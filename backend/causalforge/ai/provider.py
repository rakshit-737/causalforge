"""Provider adapters behind a narrow structured-output interface."""

import json
from collections.abc import Callable, Mapping
from typing import Any, Protocol

import httpx

from causalforge.ai.contracts import (
    ProviderError,
    ProviderMetadata,
    ProviderResponse,
    ProviderResponseError,
    ProviderUnavailableError,
    StructuredRequest,
)
from causalforge.domain.serialization import sha256_hex


class LLMProvider(Protocol):
    """Provider interface; callers cannot access arbitrary tools through it."""

    @property
    def metadata(self) -> ProviderMetadata:
        """Return non-secret provider identity."""

    def complete(self, request: StructuredRequest) -> ProviderResponse:
        """Return a JSON object that the caller must validate against its output model."""


FallbackHandler = Callable[[StructuredRequest], Mapping[str, Any]]


class DeterministicFallbackProvider:
    """Rule-only provider with explicit handlers and a safe empty hypothesis result."""

    def __init__(
        self,
        *,
        handlers: Mapping[str, FallbackHandler] | None = None,
        model: str = "rule-only-v1",
    ) -> None:
        self.handlers = dict(handlers or {})
        self._metadata = ProviderMetadata(provider="causalforge", model=model, mode="rule_only")

    @property
    def metadata(self) -> ProviderMetadata:
        return self._metadata

    def complete(self, request: StructuredRequest) -> ProviderResponse:
        handler = self.handlers.get(request.task)
        if handler is not None:
            payload = dict(handler(request))
        elif request.task == "hypothesis_generation" and request.schema_name == "HypothesisBatch":
            payload = {
                "hypotheses": [],
                "mode": "rule_only",
                "rationale": "No model configured; deterministic detection remains authoritative.",
            }
        else:
            raise ProviderUnavailableError(
                f"no deterministic fallback handler is registered for task {request.task!r}"
            )
        return ProviderResponse(
            metadata=self.metadata,
            payload=payload,
            output_sha256=sha256_hex(payload),
        )


class OpenAICompatibleProvider:
    """OpenAI-compatible JSON-schema adapter for explicitly configured endpoints."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        model: str,
        timeout_seconds: float = 30.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not base_url.startswith(("http://", "https://")):
            raise ValueError("base_url must use http:// or https://")
        if not api_key:
            raise ValueError("api_key is required for the OpenAI-compatible provider")
        if not model:
            raise ValueError("model is required for the OpenAI-compatible provider")
        self._metadata = ProviderMetadata(provider="openai-compatible", model=model, mode="remote")
        self.model = model
        self.client = httpx.Client(
            base_url=base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            timeout=timeout_seconds,
            transport=transport,
        )

    @property
    def metadata(self) -> ProviderMetadata:
        return self._metadata

    def complete(self, request: StructuredRequest) -> ProviderResponse:
        body = {
            "model": request.model or self.model,
            "messages": [
                {"role": message.role, "content": message.content}
                for message in request.messages
            ],
            "temperature": 0,
            "max_tokens": request.max_output_tokens,
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": request.schema_name,
                    "strict": True,
                    "schema": request.output_schema,
                },
            },
        }
        try:
            response = self.client.post("/chat/completions", json=body)
            response.raise_for_status()
            response_body = response.json()
            content = response_body["choices"][0]["message"]["content"]
            payload = json.loads(content) if isinstance(content, str) else content
            if not isinstance(payload, dict):
                raise ProviderResponseError("provider returned a non-object structured payload")
        except ProviderError:
            raise
        except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError) as exc:
            raise ProviderResponseError("provider response could not be safely parsed") from exc
        return ProviderResponse(
            metadata=self.metadata,
            payload=payload,
            output_sha256=sha256_hex(payload),
        )

    def close(self) -> None:
        """Close the underlying client without exposing credentials."""

        self.client.close()
