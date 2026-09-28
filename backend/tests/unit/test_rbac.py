from datetime import UTC, datetime
from uuid import uuid4

from causalforge.graph.rbac import RBACRule, RBACSnapshot, check_reachability


def rule(*, subject_id: str = "orders-reader") -> RBACRule:
    return RBACRule(
        subject_kind="service_account",
        subject_id=subject_id,
        verbs=frozenset({"get", "list"}),
        resources=frozenset({"secrets"}),
        namespaces=frozenset({"orders"}),
        evidence_id=uuid4(),
        valid_from=datetime(2026, 9, 28, 10, 0, tzinfo=UTC),
    )


def test_matching_rule_proves_allowed_and_preserves_evidence() -> None:
    evidence_id = uuid4()
    snapshot = RBACSnapshot(
        observed_at=datetime(2026, 9, 28, 10, 3, tzinfo=UTC),
        source_complete=True,
        rules=(rule(), rule(subject_id="other")),
    )
    result = check_reachability(
        snapshot,
        subject_kind="service_account",
        subject_id="orders-reader",
        verb="list",
        resource="secrets",
        namespace="orders",
        at=datetime(2026, 9, 28, 10, 3, tzinfo=UTC),
    )

    assert result.status == "allowed"
    assert len(result.matching_evidence_ids) == 1
    assert result.reason.startswith("a matching")
    assert evidence_id not in result.matching_evidence_ids


def test_complete_snapshot_without_match_is_denied() -> None:
    snapshot = RBACSnapshot(
        observed_at=datetime(2026, 9, 28, 10, 3, tzinfo=UTC),
        source_complete=True,
        rules=(rule(),),
    )

    result = check_reachability(
        snapshot,
        subject_kind="service_account",
        subject_id="orders-reader",
        verb="list",
        resource="secrets",
        namespace="billing",
    )

    assert result.status == "denied"
    assert result.matching_evidence_ids == ()


def test_incomplete_snapshot_without_match_is_unknown() -> None:
    snapshot = RBACSnapshot(
        observed_at=datetime(2026, 9, 28, 10, 3, tzinfo=UTC),
        source_complete=False,
        rules=(),
    )

    result = check_reachability(
        snapshot,
        subject_kind="service_account",
        subject_id="orders-reader",
        verb="list",
        resource="secrets",
        namespace="orders",
    )

    assert result.status == "unknown"


def test_rule_validity_is_temporal() -> None:
    snapshot = RBACSnapshot(
        observed_at=datetime(2026, 9, 28, 10, 3, tzinfo=UTC),
        source_complete=True,
        rules=(
            rule(),
        ),
    )

    result = check_reachability(
        snapshot,
        subject_kind="service_account",
        subject_id="orders-reader",
        verb="list",
        resource="secrets",
        namespace="orders",
        at=datetime(2026, 9, 28, 9, 59, tzinfo=UTC),
    )

    assert result.status == "denied"
