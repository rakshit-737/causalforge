import json
from uuid import uuid4

import httpx
import pytest

from causalforge.ai.context import build_safe_context
from causalforge.ai.contracts import ProviderResponseError, ProviderUnavailableError
from causalforge.ai.provider import DeterministicFallbackProvider, OpenAICompatibleProvider
from causalforge.ai.schemas import HypothesisBatch
from causalforge.ai.structured_output import StructuredOutputClient


def context():
    return build_safe_context(
        tenant_id=uuid4(),
        case_id=uuid4(),
        objective="Generate hypotheses.",
    )


def test_rule_only_provider_returns_safe_empty_hypothesis_batch() -> None:
    client = StructuredOutputClient(DeterministicFallbackProvider())

    result = client.complete_with_context(
        task="hypothesis_generation",
        instruction="Return only structured hypotheses grounded in the supplied data.",
        context=context(),
        output_model=HypothesisBatch,
    )

    assert result.mode == "rule_only"
    assert result.hypotheses == ()


def test_unknown_rule_only_task_fails_closed() -> None:
    provider = DeterministicFallbackProvider()
    request = StructuredOutputClient(provider).build_request(
        task="unregistered_task",
        instruction="Do not invent facts.",
        context=context(),
        output_model=HypothesisBatch,
    )

    with pytest.raises(ProviderUnavailableError):
        provider.complete(request)


def test_openai_compatible_provider_sends_schema_and_parses_json() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "hypotheses": [],
                                    "mode": "model_assisted",
                                    "rationale": "No supported facts were supplied.",
                                }
                            )
                        }
                    }
                ]
            },
        )

    provider = OpenAICompatibleProvider(
        base_url="https://llm.example.test/v1",
        api_key="secret-not-logged",
        model="test-model",
        transport=httpx.MockTransport(handler),
    )
    client = StructuredOutputClient(provider)
    request = client.build_request(
        task="hypothesis_generation",
        instruction="Return structured output.",
        context=context(),
        output_model=HypothesisBatch,
    )

    result = client.complete(request, HypothesisBatch)
    body = captured["body"]
    assert result.mode == "model_assisted"
    assert body["response_format"]["json_schema"]["name"] == "HypothesisBatch"
    assert body["messages"][0]["role"] == "system"
    assert "untrusted evidence" in body["messages"][1]["content"]
    provider.close()


def test_openai_compatible_provider_does_not_expose_raw_response_in_parse_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [{"message": {"content": "not-json"}}]})

    provider = OpenAICompatibleProvider(
        base_url="https://llm.example.test/v1",
        api_key="secret-not-logged",
        model="test-model",
        transport=httpx.MockTransport(handler),
    )
    request = StructuredOutputClient(provider).build_request(
        task="hypothesis_generation",
        instruction="Return structured output.",
        context=context(),
        output_model=HypothesisBatch,
    )

    with pytest.raises(ProviderResponseError) as error:
        provider.complete(request)

    assert "not-json" not in str(error.value)
    provider.close()
