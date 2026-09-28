from datetime import UTC, datetime, timedelta
from uuid import uuid4

from causalforge.detection.correlation import CorrelationEngine, CorrelationRule
from causalforge.ingestion.normalizer import normalize_event


def event(action: str, observed_at: datetime):
    return normalize_event(
        {
            "event_id": str(uuid4()),
            "tenant_id": str(uuid4()),
            "source": {"kind": "kubernetes_audit", "name": "fixture", "version": "1.0"},
            "observed_at": observed_at.isoformat(),
            "actor": {"kind": "service_account", "id": "orders-reader"},
            "action": action,
            "object": {"kind": "secret", "namespace": "orders", "name": None},
            "outcome": "allowed",
            "attributes": {},
            "coverage": {
                "source_complete_for_window": True,
                "window_start": (observed_at - timedelta(minutes=1)).isoformat(),
                "window_end": (observed_at + timedelta(minutes=5)).isoformat(),
            },
        },
        parser_version="fixture-1.0",
    ).event


def test_sequence_correlator_matches_ordered_events_in_window() -> None:
    rule = CorrelationRule(
        id="cf-sequence-001",
        title="Secret enumeration followed by service access",
        window_seconds=60,
        sequence=(
            {"action": "list", "object.kind": "secret"},
            {"action": "connect"},
        ),
        level="high",
    )
    start = datetime(2026, 9, 28, 10, 0, tzinfo=UTC)

    matches = CorrelationEngine().match(
        rule,
        [event("connect", start + timedelta(seconds=20)), event("list", start)],
    )

    assert len(matches) == 1
    assert matches[0].event_ids[0] != matches[0].event_ids[1]
    assert "within 60s" in matches[0].explanation


def test_sequence_correlator_rejects_events_outside_window() -> None:
    rule = CorrelationRule(
        id="cf-sequence-002",
        title="Bounded sequence",
        window_seconds=10,
        sequence=({"action": "list"}, {"action": "connect"}),
        level="medium",
    )
    start = datetime(2026, 9, 28, 10, 0, tzinfo=UTC)

    assert CorrelationEngine().match(
        rule,
        [event("list", start), event("connect", start + timedelta(seconds=11))],
    ) == []
