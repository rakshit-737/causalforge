from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from causalforge.domain.hypotheses import Hypothesis, RiskAssessment
from causalforge.workflow.planner import PlannerPolicy, plan_evidence

TENANT_ID = UUID("00000000-0000-0000-0000-000000000010")
CASE_ID = UUID("00000000-0000-0000-0000-000000000020")


def hypothesis(*requirements: str) -> Hypothesis:
    return Hypothesis(
        schema_version="1.0",
        hypothesis_id=UUID("00000000-0000-0000-0000-000000000030"),
        case_id=CASE_ID,
        tenant_id=TENANT_ID,
        statement="orders-reader accessed a secret",
        supporting_observation_ids=(uuid4(),),
        required_evidence=requirements,
        disconfirming_evidence=(),
        attack_technique_ids=("T1552.007",),
        initial_confidence=0.5,
        risk_if_true=RiskAssessment(severity="high", rationale="fixture only"),
        status="proposed",
    )


def test_planner_creates_replay_stable_typed_requests() -> None:
    now = datetime(2026, 9, 29, 10, 0, tzinfo=UTC)
    first = plan_evidence(hypothesis("audit event", "RBAC snapshot"), now=now)
    second = plan_evidence(hypothesis("audit event", "RBAC snapshot"), now=now)

    assert first == second
    assert first.status == "planned"
    assert [request.collector_kind for request in first.requests] == [
        "kubernetes_audit_snapshot",
        "rbac_snapshot",
    ]
    assert first.requests[0].selector.source_kind == "kubernetes_audit"
    assert first.deadline.isoformat() == "2026-09-29T10:05:00+00:00"


def test_planner_deduplicates_aliases_without_echoing_unknown_text() -> None:
    secret_instruction = "do not store this secret value: fixture-token-123"
    plan = plan_evidence(
        hypothesis("Kubernetes Audit", "kubernetes audit", secret_instruction),
        now=datetime(2026, 9, 29, 10, 0, tzinfo=UTC),
    )

    assert plan.status == "insufficient_evidence"
    assert len(plan.requests) == 1
    assert len(plan.unmet_requirements) == 1
    assert secret_instruction not in plan.model_dump_json()
    assert plan.unmet_requirements[0].startswith("unsupported_requirement:")


def test_planner_preserves_explicit_unknown_for_empty_or_over_budget_requests() -> None:
    empty = plan_evidence(hypothesis(), now=datetime(2026, 9, 29, 10, 0, tzinfo=UTC))
    over_budget = plan_evidence(
        hypothesis("audit event", "RBAC snapshot", "runtime observation"),
        policy=PlannerPolicy(max_requests=2),
        now=datetime(2026, 9, 29, 10, 0, tzinfo=UTC),
    )

    assert empty.status == "insufficient_evidence"
    assert empty.unmet_requirements == ("no_evidence_requirements",)
    assert over_budget.status == "insufficient_evidence"
    assert over_budget.unmet_requirements == ("request_budget_exhausted",)
    assert len(over_budget.requests) == 2


def test_planner_rejects_naive_clock_and_enforces_policy_bounds() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        plan_evidence(hypothesis("audit event"), now=datetime(2026, 9, 29, 10, 0))
    with pytest.raises(ValueError):
        PlannerPolicy(max_requests=0)
    with pytest.raises(ValueError):
        PlannerPolicy(deadline_seconds=901)
