from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from causalforge.domain.claims import Claim, ConfidenceComponents
from causalforge.domain.evidence import EvidenceItem
from causalforge.domain.hypotheses import Hypothesis, RiskAssessment
from causalforge.ingestion.normalizer import normalize_event
from causalforge.workflow.verifier import (
    TrustedSource,
    VerificationPolicy,
    verify_claim,
    verify_hypothesis,
)

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


def claim_for(
    supporting: tuple[EvidenceItem, ...], contradictory: tuple[EvidenceItem, ...] = ()
) -> Claim:
    return Claim(
        schema_version="1.0",
        claim_id=uuid4(),
        case_id=CASE_ID,
        tenant_id=TENANT_ID,
        subject="orders-reader",
        predicate="list secret",
        object={"kind": "secret"},
        status="observed",
        supporting_evidence_ids=tuple(item.evidence_id for item in supporting),
        contradictory_evidence_ids=tuple(item.evidence_id for item in contradictory),
        confidence_components=ConfidenceComponents(
            source_reliability=1.0,
            temporal_consistency=1.0,
            coverage=1.0,
            contradiction_penalty=0.0,
            final=1.0,
        ),
        temporal_consistency=True,
        source_families=tuple(item.source_family for item in supporting),
        coverage_sufficient=True,
    )


def test_verifier_requires_independent_source_families() -> None:
    event_id = uuid4()
    decision = verify_hypothesis(
        hypothesis((event_id,)),
        [evidence(event_id=event_id, source_kind="kubernetes_audit")],
        now=datetime(2026, 9, 28, 11, tzinfo=UTC),
    )

    assert decision.status == "insufficient_evidence"
    assert "independent_source_families" in decision.unmet_requirements
    assert decision.supporting_evidence_ids


def test_hypothesis_verifier_never_promotes_free_text_without_semantic_evaluation() -> None:
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

    assert decision.status == "insufficient_evidence"
    assert decision.coverage_sufficient is True
    assert decision.temporal_consistency is True
    assert decision.source_families == ()
    assert "semantic_verification_required" in decision.unmet_requirements


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


def test_claim_verifier_promotes_only_independent_complete_support() -> None:
    first = evidence(event_id=uuid4(), source_kind="kubernetes_audit")
    second = evidence(event_id=uuid4(), source_kind="runtime_sensor")

    decision = verify_claim(
        claim_for((first, second)),
        [first, second],
        now=datetime(2026, 9, 28, 11, tzinfo=UTC),
        trusted_sources=(
            TrustedSource(
                kind="kubernetes_audit",
                name="fixture",
                version="1.0",
                independent_family="control_plane",
            ),
            TrustedSource(
                kind="runtime_sensor",
                name="fixture",
                version="1.0",
                independent_family="runtime",
            ),
        ),
    )

    assert decision.status == "verified"
    assert decision.coverage_sufficient is True


def test_claim_verifier_marks_contradictions_disputed_and_single_source_unknown() -> None:
    supporting = evidence(event_id=uuid4(), source_kind="kubernetes_audit")
    contradictory = evidence(event_id=uuid4(), source_kind="runtime_sensor")
    disputed = verify_claim(
        claim_for((supporting,), (contradictory,)),
        [supporting, contradictory],
        now=datetime(2026, 9, 28, 11, tzinfo=UTC),
    )
    unknown = verify_claim(
        claim_for((supporting,)),
        [supporting],
        now=datetime(2026, 9, 28, 11, tzinfo=UTC),
    )

    assert disputed.status == "disputed"
    assert disputed.contradictory_evidence_ids == (contradictory.evidence_id,)
    assert unknown.status == "unknown"
    assert "independent_source_families" in unknown.unmet_requirements


def test_claim_verifier_does_not_promote_mismatched_event_semantics() -> None:
    item = evidence(event_id=uuid4(), source_kind="kubernetes_audit")
    claim = claim_for((item,)).model_copy(update={"predicate": "exfiltrated secret"})

    decision = verify_claim(
        claim,
        [item],
        policy=VerificationPolicy(minimum_independent_source_families=2),
        now=datetime(2026, 9, 28, 11, tzinfo=UTC),
        trusted_sources=(
            TrustedSource(
                kind="kubernetes_audit",
                name="fixture",
                version="1.0",
                independent_family="control_plane",
            ),
        ),
    )

    assert decision.status == "unknown"
    assert "claim_semantics" in decision.unmet_requirements
