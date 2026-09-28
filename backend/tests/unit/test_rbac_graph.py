from datetime import UTC, datetime
from uuid import uuid4

from causalforge.graph.projector import TemporalAttackGraph, node_id
from causalforge.graph.rbac import RBACRule


def test_rbac_rule_projects_capability_edges_with_provenance() -> None:
    evidence_id = uuid4()
    rule = RBACRule(
        subject_kind="service_account",
        subject_id="orders-reader",
        verbs=frozenset({"get", "list"}),
        resources=frozenset({"secrets"}),
        namespaces=frozenset({"orders"}),
        evidence_id=evidence_id,
        valid_from=datetime(2026, 9, 28, 10, 0, tzinfo=UTC),
    )
    graph = TemporalAttackGraph()

    graph.project_rbac_rule(rule)

    subject = node_id("service_account", "orders-reader")
    target = node_id("resource", "orders/secrets")
    assert target in graph.neighbors(subject, relationship="can_list")
    assert target in graph.neighbors(subject, relationship="can_read")
    assert all(
        str(evidence_id) in data["evidence_ids"]
        for _, _, data in graph.graph.edges(subject, data=True)
    )
