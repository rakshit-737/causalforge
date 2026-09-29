from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from causalforge.domain.hypotheses import Hypothesis, RiskAssessment
from causalforge.workflow.collector import FixtureCollector
from causalforge.workflow.planner import PlannerPolicy, plan_evidence
from causalforge.workflow.verifier import TrustedSource

TENANT_ID = UUID("00000000-0000-0000-0000-000000000010")
CASE_ID = UUID("00000000-0000-0000-0000-000000000020")
NOW = datetime(2026, 9, 29, 10, 0, tzinfo=UTC)
SOURCE = TrustedSource(
    kind="kubernetes_audit",
    name="fixture-lab",
    version="1.0",
    independent_family="fixture",
)


def payload(
    event_id: str, *, tenant_id: UUID = TENANT_ID, action: str = "list"
) -> dict[str, object]:
    return {
        "event_id": event_id,
        "tenant_id": str(tenant_id),
        "source": {"kind": "kubernetes_audit", "name": "fixture-lab", "version": "1.0"},
        "observed_at": "2026-09-29T10:00:00Z",
        "actor": {"kind": "service_account", "id": "orders-reader"},
        "action": action,
        "object": {"kind": "secret", "namespace": "orders", "name": None},
        "outcome": "allowed",
        "attributes": {"workload_id": "orders-api"},
        "coverage": {
            "source_complete_for_window": True,
            "window_start": "2026-09-29T09:55:00Z",
            "window_end": "2026-09-29T10:05:00Z",
        },
    }


def request(*, max_items: int = 100):
    hypothesis = Hypothesis(
        schema_version="1.0",
        hypothesis_id=UUID("00000000-0000-0000-0000-000000000030"),
        case_id=CASE_ID,
        tenant_id=TENANT_ID,
        statement="fixture event is relevant",
        required_evidence=("fixture event replay",),
        risk_if_true=RiskAssessment(severity="low", rationale="fixture"),
        initial_confidence=0.1,
        status="proposed",
    )
    return plan_evidence(
        hypothesis,
        policy=PlannerPolicy(max_items_per_request=max_items, max_total_items=max_items),
        now=NOW,
    ).requests[0]


def test_fixture_collector_returns_canonical_events_and_attestation() -> None:
    collector = FixtureCollector(
        [payload("00000000-0000-0000-0000-000000000101")],
        parser_version="fixture-1.0",
        trusted_source=SOURCE,
    )

    result = collector.collect(
        request(),
        tenant_id=TENANT_ID,
        case_id=CASE_ID,
        deadline=NOW + timedelta(minutes=5),
        now=NOW,
    )

    assert result.status == "completed"
    assert len(result.events) == 1
    assert result.events[0].tenant_id == TENANT_ID
    assert result.trusted_source == SOURCE
    assert result.rejected_items == 0


def test_fixture_collector_enforces_deadline_tenant_scope_and_item_budget() -> None:
    collector = FixtureCollector(
        [
            payload("00000000-0000-0000-0000-000000000101"),
            payload("00000000-0000-0000-0000-000000000102", action="watch"),
        ],
        parser_version="fixture-1.0",
        trusted_source=SOURCE,
    )
    expired = collector.collect(
        request(max_items=1),
        tenant_id=TENANT_ID,
        case_id=CASE_ID,
        deadline=NOW,
        now=NOW,
    )
    truncated = collector.collect(
        request(max_items=1),
        tenant_id=TENANT_ID,
        case_id=CASE_ID,
        deadline=NOW + timedelta(minutes=5),
        now=NOW,
    )
    wrong_tenant = collector.collect(
        request(),
        tenant_id=UUID("00000000-0000-0000-0000-000000000011"),
        case_id=CASE_ID,
        deadline=NOW + timedelta(minutes=5),
        now=NOW,
    )

    assert expired.unmet_requirements == ("collection_deadline",)
    assert truncated.status == "truncated"
    assert truncated.unmet_requirements == ("item_budget",)
    assert wrong_tenant.status == "insufficient_evidence"
    assert wrong_tenant.events == ()
    assert wrong_tenant.unmet_requirements == ("fixture_scope_or_provenance",)


def test_fixture_collector_rejects_unattested_sources_and_malformed_payloads() -> None:
    collector = FixtureCollector(
        [
            {
                **payload("00000000-0000-0000-0000-000000000101"),
                "source": {"kind": "untrusted", "name": "fixture-lab", "version": "1.0"},
            },
            {"password": "must-not-appear"},
        ],
        parser_version="fixture-1.0",
        trusted_source=SOURCE,
    )
    result = collector.collect(
        request(),
        tenant_id=TENANT_ID,
        case_id=CASE_ID,
        deadline=NOW + timedelta(minutes=5),
        now=NOW,
    )

    assert result.status == "insufficient_evidence"
    assert result.rejected_items == 2
    assert "must-not-appear" not in result.model_dump_json()

    with pytest.raises(ValueError, match="source family"):
        collector.collect(
            request().model_copy(update={"source_family": "runtime_sensor"}),
            tenant_id=TENANT_ID,
            case_id=CASE_ID,
            deadline=NOW + timedelta(minutes=5),
            now=NOW,
        )
