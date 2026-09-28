from pathlib import Path
from uuid import uuid4

from causalforge.detection.sigma_engine import SigmaEngine, load_rule, load_rules
from causalforge.ingestion.normalizer import normalize_event

ROOT = Path(__file__).parents[3]


def secret_list_event(outcome: str = "allowed"):
    return normalize_event(
        {
            "event_id": str(uuid4()),
            "tenant_id": str(uuid4()),
            "source": {"kind": "kubernetes_audit", "name": "fixture", "version": "1.0"},
            "observed_at": "2026-09-28T10:03:00Z",
            "actor": {"kind": "service_account", "id": "orders-reader"},
            "action": "list",
            "object": {"kind": "secret", "namespace": "orders", "name": None},
            "outcome": outcome,
            "attributes": {},
            "coverage": {
                "source_complete_for_window": True,
                "window_start": "2026-09-28T10:00:00Z",
                "window_end": "2026-09-28T10:05:00Z",
            },
        },
        parser_version="fixture-1.0",
    ).event


def test_sigma_subset_matches_fixture_rule_and_explains_fields() -> None:
    rule = load_rule(ROOT / "rules" / "sigma" / "kubernetes-secret-enumeration.yml")
    match = SigmaEngine().match(rule, secret_list_event())

    assert match is not None
    assert match.level == "high"
    assert "object.kind='secret'" in match.explanation
    assert "attack.t1552.007" in match.tags


def test_sigma_subset_does_not_promote_denied_operation() -> None:
    rule = load_rule(ROOT / "rules" / "sigma" / "kubernetes-secret-enumeration.yml")

    assert SigmaEngine().match(rule, secret_list_event("denied")) is None


def test_rule_loading_is_deterministic() -> None:
    rules = load_rules(ROOT / "rules" / "sigma")

    assert [rule.id for rule in rules] == ["cf-k8s-secret-list-001"]
