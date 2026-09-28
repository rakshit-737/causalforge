from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from causalforge.domain.evidence import EvidenceItem
from causalforge.domain.hypotheses import Hypothesis, RiskAssessment
from causalforge.ingestion.normalizer import normalize_event
from causalforge.workflow.verifier import VerificationPolicy, verify_hypothesis

TENANT_ID = UUID("00000000-0000-0000-0000-000000000010")
CASE_ID = UUID("00000000-0000-0000-0000-000000000020")


def evidence(*, event_id: UUID, source_kind: str, complete: bool = True) -> EvidenceItem:
    observed_at = datetime(2026, 9, 28, 10, 3, tzinfo=UTC)
    payload = {
        "event_id": str(event_id),
        "tenant_id": str(TENANT_ID),
        "source": {"kind": source_kind, "name": "fixture", "version": "1.0"},
        "observed_at": observed_at.isoformat(),
        "actor": {"kind": "service_account", "id": "orders-reader"},
        "action": "list",
        "object": {"kind": "secret", "namespace": "orders", "name": None},
        "outcome": "allowed",
        "attributes": {},
        "coverage": {
            "source_complete_for_window": complete,
            "window_start": "2026-09-28T10:00:00Z",
            "window_end": "2026-09-28T10:05:00Z",
        },
    }
    event = normalize_event(
        payload,
        parser_version="fixture-1.0",
        clock=lambda: datetime(2026, 9, 28, 10, 4, tzinfo=UTC),
    ).event
    return EvidenceItem.from_event(
        event,
        case_id=CASE_ID,
        collected_at=event.ingested_at,
        redaction_profile="default-v1",
        source_reliability=1.0,
        source_family=source_kind,
    )


def hypothesis(observation_ids: tuple[UUID, ...]) -> Hypothesis:
    return Hypothesis(
        schema_version="1.0",
        hypothesis_id=uuid4(),
        case_id=CASE_ID,
        tenant_id=TENANT_ID,
        statement="orders-reader enumerated Kubernetes secrets",
        supporting_observation_ids=observation_ids,
        required_evidence=("independent source", "complete collection window"),
        disconfirming_evidence=("audit denial",),
        attack_technique_ids=("T1552.007",),
        initial_confidence=0.6,
        risk_if_true=RiskAssessment(severity="high", rationale="secret material may be exposed"),
        status="proposed",
    )


def test_verifier_requires_independent_source_families() -> None:
    event_id = uuid4()
    decision = verify_hypothesis(
        hypothesis((event_id,)),
        [evidence(event_id=event_id, source_kind="kubernetes_audit")],
        now=datetime(2026, 9, 28, 11, tzinfo=UTC),
    )

    assert decision.status == "insufficient_evidence"
    assert decision.unmet_requirements == ("independent_source_families",)
    assert decision.supporting_evidence_ids


def test_verifier_supports_complete_independent_observations() -> None:
    first_id = uuid4()
    second_id = uuid4()
    decision = verify_hypothesis(
        hypothesis((first_id, second_id)),
        [
            evidence(event_id=first_id, source_kind="kubernetes_audit"),
            evidence(event_id=second_id, source_kind="runtime_sensor"),
        ],
        now=datetime(2026, 9, 28, 11, tzinfo=UTC),
    )

    assert decision.status == "supported"
    assert decision.coverage_sufficient is True
    assert decision.temporal_consistency is True
    assert decision.source_families == ("kubernetes_audit", "runtime_sensor")


def test_verifier_preserves_unknown_when_coverage_is_incomplete() -> None:
    first_id = uuid4()
    second_id = uuid4()
    decision = verify_hypothesis(
        hypothesis((first_id, second_id)),
        [
            evidence(event_id=first_id, source_kind="kubernetes_audit", complete=False),
            evidence(event_id=second_id, source_kind="runtime_sensor"),
        ],
        now=datetime(2026, 9, 28, 11, tzinfo=UTC),
    )

    assert decision.status == "insufficient_evidence"
    assert "complete_coverage" in decision.unmet_requirements


def test_verifier_enforces_deadline_and_budget() -> None:
    event_id = uuid4()
    late = verify_hypothesis(
        hypothesis((event_id,)),
        [evidence(event_id=event_id, source_kind="kubernetes_audit")],
        policy=VerificationPolicy(deadline=datetime(2026, 9, 28, 10, tzinfo=UTC)),
        now=datetime(2026, 9, 28, 11, tzinfo=UTC),
    )
    assert late.unmet_requirements == ("verification_deadline",)

    first_id = uuid4()
    second_id = uuid4()
    budget = verify_hypothesis(
        hypothesis((first_id, second_id)),
        [
            evidence(event_id=first_id, source_kind="kubernetes_audit"),
            evidence(event_id=second_id, source_kind="runtime_sensor"),
        ],
        policy=VerificationPolicy(max_evidence_items=1),
        now=datetime(2026, 9, 28, 11, tzinfo=UTC),
    )
    assert budget.status == "insufficient_evidence"
    assert budget.budget_exhausted is True
    assert "evidence_budget" in budget.unmet_requirements


def test_verifier_rejects_cross_tenant_evidence() -> None:
    event_id = uuid4()
    item = evidence(event_id=event_id, source_kind="kubernetes_audit")
    other = item.model_copy(update={"tenant_id": uuid4()})

    with pytest.raises(ValueError, match="tenant and case"):
        verify_hypothesis(hypothesis((event_id,)), [other])
