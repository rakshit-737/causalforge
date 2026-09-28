from uuid import uuid4

import pytest

from causalforge.ai.context import build_safe_context
from causalforge.ai.contracts import StructuredOutputError
from causalforge.ai.provider import DeterministicFallbackProvider
from causalforge.ai.schemas import HypothesisBatch
from causalforge.ai.structured_output import StructuredOutputClient


def test_extra_provider_fields_are_rejected() -> None:
    provider = DeterministicFallbackProvider(
        handlers={
            "hypothesis_generation": lambda request: {
                "hypotheses": [],
                "mode": "rule_only",
                "rationale": "safe",
                "unsupported": "must-be-rejected",
            }
        }
    )
    client = StructuredOutputClient(provider)
    context = build_safe_context(
        tenant_id=uuid4(),
        case_id=uuid4(),
        objective="Generate hypotheses.",
    )
    request = client.build_request(
        task="hypothesis_generation",
        instruction="Return only the requested schema.",
        context=context,
        output_model=HypothesisBatch,
    )

    with pytest.raises(StructuredOutputError, match="schema validation"):
        client.complete(request, HypothesisBatch)
