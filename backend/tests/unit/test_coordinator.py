from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from causalforge.domain.hypotheses import Hypothesis, RiskAssessment
from causalforge.workflow.coordinator import CollectionReceipt, FixtureCoordinator
from causalforge.workflow.verifier import TrustedSource

TENANT_ID = UUID("00000000-0000-0000-0000-000000000010")
CASE_ID = UUID("00000000-0000-0000-0000-000000000020")
HYPOTHESIS_ID = UUID("00000000-0000-0000-0000-000000000030")
NOW = datetime(2026, 9, 30, 10, 0, tzinfo=UTC)
SOURCE = TrustedSource(
    kind="fixture",
    name="fixture-lab",
    version="1.0",
    independent_family="fixture",
)


def hypothesis(*requirements: str) -> Hypothesis:
    return Hypothesis(
        schema_version="1.0",
        hypothesis_id=HYPOTHESIS_ID,
        case_id=CASE_ID,
        tenant_id=TENANT_ID,
        statement="orders-reader accessed a secret in the fixture",
        supporting_observation_ids=(uuid4(),),
        required_evidence=requirements,
        disconfirming_evidence=(),
        attack_technique_ids=("T1552.007",),
        initial_confidence=0.5,
        risk_if_true=RiskAssessment(severity="high", rationale="fixture scenario"),
        status="proposed",
    )


def event_payload(event_id: str) -> dict[str, object]:
    return {
        "event_id": event_id,
        "tenant_id": str(TENANT_ID),
        "source": {"kind": "fixture", "name": "fixture-lab", "version": "1.0"},
        "observed_at": "2026-09-30T10:00:00Z",
        "actor": {"kind": "service_account", "id": "orders-reader"},
        "action": "list",
        "object": {"kind": "secret", "namespace": "orders", "name": None},
        "outcome": "allowed",
        "attributes": {"workload_id": "orders-api"},
        "coverage": {
            "source_complete_for_window": True,
            "window_start": "2026-09-30T09:55:00Z",
            "window_end": "2026-09-30T10:05:00Z",
        },
    }


def test_coordinator_replays_fixture_and_builds_stable_receipt() -> None:
    payloads = [event_payload("00000000-0000-0000-0000-000000000101")]
    first = FixtureCoordinator().run(
        hypothesis("fixture event replay"),
        payloads,
        parser_version="fixture-1.0",
        trusted_source=SOURCE,
        now=NOW,
    )
    second = FixtureCoordinator().run(
        hypothesis("fixture event replay"),
        payloads,
        parser_version="fixture-1.0",
        trusted_source=SOURCE,
        now=NOW,
    )

    assert first == second
    assert first.status == "completed"
    assert len(first.events) == 1
    assert len(first.receipts) == 1
    assert first.receipts[0].trusted_source == SOURCE
    assert first.receipts[0].event_ids == (first.events[0].event_id,)
    assert first.receipts[0].receipt_hash


def test_coordinator_preserves_planner_unknowns_without_collecting() -> None:
    result = FixtureCoordinator().run(
        hypothesis("unsupported collector requirement"),
        [event_payload("00000000-0000-0000-0000-000000000101")],
        parser_version="fixture-1.0",
        trusted_source=SOURCE,
        now=NOW,
    )

    assert result.status == "insufficient_evidence"
    assert result.receipts == ()
    assert result.events == ()
    assert any(
        item.startswith("unsupported_requirement:") for item in result.unmet_requirements
    )


def test_receipt_rejects_hash_or_identity_tampering() -> None:
    result = FixtureCoordinator().run(
        hypothesis("fixture event replay"),
        [event_payload("00000000-0000-0000-0000-000000000101")],
        parser_version="fixture-1.0",
        trusted_source=SOURCE,
        now=NOW,
    )
    receipt = result.receipts[0]
    tampered = receipt.model_dump(mode="json")
    tampered["consumed_items"] = 99

    with pytest.raises(ValueError, match="receipt hash"):
        CollectionReceipt.model_validate(tampered)
