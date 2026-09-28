from datetime import UTC, datetime
from uuid import uuid4

from causalforge.graph.projector import TemporalAttackGraph, node_id
from causalforge.ingestion.normalizer import normalize_event


def test_projector_retains_provenance_and_temporal_edges() -> None:
    event = normalize_event(
        {
            "event_id": str(uuid4()),
            "tenant_id": str(uuid4()),
            "source": {"kind": "kubernetes_audit", "name": "fixture", "version": "1.0"},
            "observed_at": "2026-09-28T10:03:00Z",
            "actor": {"kind": "service_account", "id": "orders-reader"},
            "action": "list",
            "object": {"kind": "secret", "namespace": "orders", "name": None},
            "outcome": "allowed",
            "attributes": {"workload_id": "orders-api", "destination_service": "billing-api"},
            "coverage": {
                "source_complete_for_window": True,
                "window_start": "2026-09-28T10:00:00Z",
                "window_end": "2026-09-28T10:05:00Z",
            },
        },
        parser_version="fixture-1.0",
    ).event
    graph = TemporalAttackGraph()

    graph.project_event(event, evidence_id=uuid4())

    actor = node_id("service_account", "orders-reader")
    secret = node_id("secret", "orders/*")
    workload = node_id("workload", "orders-api")
    billing = node_id("service", "billing-api")
    assert secret in graph.neighbors(actor, relationship="accessed")
    assert actor in graph.neighbors(workload, relationship="uses_identity")
    assert billing in graph.neighbors(workload, relationship="communicated_with")
    edge_data = next(
        data
        for _, _, data in graph.graph.edges(actor, data=True)
        if data["relationship"] == "accessed"
    )
    assert len(edge_data["evidence_ids"]) == 1


def test_denied_event_is_not_projected_as_access() -> None:
    event = normalize_event(
        {
            "event_id": str(uuid4()),
            "tenant_id": str(uuid4()),
            "source": {"kind": "kubernetes_audit", "name": "fixture", "version": "1.0"},
            "observed_at": "2026-09-28T10:03:00Z",
            "actor": {"kind": "service_account", "id": "orders-reader"},
            "action": "list",
            "object": {"kind": "secret", "namespace": "orders", "name": None},
            "outcome": "denied",
            "attributes": {},
            "coverage": {
                "source_complete_for_window": True,
                "window_start": "2026-09-28T10:00:00Z",
                "window_end": "2026-09-28T10:05:00Z",
            },
        },
        parser_version="fixture-1.0",
    ).event
    graph = TemporalAttackGraph()
    graph.project_event(event, evidence_id=uuid4())

    actor = node_id("service_account", "orders-reader")
    assert graph.neighbors(actor, relationship="accessed") == []
    assert graph.neighbors(actor, relationship="blocked_by_policy") == [
        node_id("secret", "orders/*")
    ]


def test_path_respects_temporal_validity() -> None:
    graph = TemporalAttackGraph()
    event_time = datetime(2026, 9, 28, 10, 3, tzinfo=UTC)
    source = node_id("workload", "orders-api")
    target = node_id("service", "billing-api")
    graph.graph.add_edge(
        source,
        target,
        relationship="communicated_with",
        valid_from=event_time,
        valid_to=None,
    )

    assert graph.path(source, target, at=datetime(2026, 9, 28, 10, 2, tzinfo=UTC)) == []
    assert graph.path(source, target, at=event_time) == [source, target]
