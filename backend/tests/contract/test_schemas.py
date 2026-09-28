import json
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

ROOT = Path(__file__).parents[3]
SCHEMA_DIR = ROOT / "schemas"
FORMAT_CHECKER = FormatChecker()


def identifier() -> str:
    return str(uuid4())


def sha() -> str:
    return "a" * 64


def base_ids() -> dict[str, str]:
    return {"tenant_id": identifier(), "case_id": identifier()}


def valid_instances() -> dict[str, dict[str, object]]:
    ids = base_ids()
    source = {"kind": "fixture", "name": "test", "version": "1.0"}
    coverage = {
        "source_complete_for_window": True,
        "window_start": "2026-09-27T10:00:00Z",
        "window_end": "2026-09-27T10:05:00Z",
    }
    evidence_id = identifier()
    return {
        "artifact-envelope.schema.json": {
            "schema_version": "1.0",
            "artifact_id": identifier(),
            **ids,
            "trace_id": identifier(),
            "producer": "test",
            "created_at": "2026-09-27T10:00:00Z",
            "input_artifact_ids": [],
            "payload": {"kind": "test"},
            "payload_sha256": sha(),
            "idempotency_key": "test-1",
        },
        "canonical-event.schema.json": {
            "schema_version": "1.0",
            "event_id": identifier(),
            "tenant_id": ids["tenant_id"],
            "source": source,
            "observed_at": "2026-09-27T10:03:00Z",
            "ingested_at": "2026-09-27T10:03:01Z",
            "actor": {"kind": "service_account", "id": "system:serviceaccount:orders:reader"},
            "action": "list",
            "object": {"kind": "secret", "namespace": "orders", "name": None},
            "outcome": "allowed",
            "attributes": {"request_uri": "/api/v1/secrets"},
            "coverage": coverage,
            "raw_payload_sha256": sha(),
            "parser_version": "test-1.0",
        },
        "evidence.schema.json": {
            "schema_version": "1.0",
            "evidence_id": evidence_id,
            **ids,
            "source": source,
            "observed_at": "2026-09-27T10:03:00Z",
            "collected_at": "2026-09-27T10:03:01Z",
            "parser_version": "test-1.0",
            "content_hash": sha(),
            "provenance_hash": sha(),
            "redaction_profile": "fixture-default",
            "coverage": coverage,
            "normalized": {"action": "list"},
            "raw_reference": None,
            "source_reliability": 0.9,
            "source_family": "kubernetes_audit",
        },
        "hypothesis.schema.json": {
            "schema_version": "1.0",
            "hypothesis_id": identifier(),
            **ids,
            "statement": "A workload abused its service account.",
            "supporting_observation_ids": [evidence_id],
            "required_evidence": ["audit event", "RBAC snapshot"],
            "disconfirming_evidence": ["complete deployment history"],
            "attack_technique_ids": ["T1552.007"],
            "initial_confidence": 0.5,
            "risk_if_true": {"severity": "high", "rationale": "Secret enumeration is possible."},
            "status": "proposed",
        },
        "claim.schema.json": {
            "schema_version": "1.0",
            "claim_id": identifier(),
            **ids,
            "subject": "orders-reader",
            "predicate": "listed",
            "object": "secret/orders-db",
            "status": "corroborated",
            "supporting_evidence_ids": [evidence_id],
            "contradictory_evidence_ids": [],
            "confidence_components": {
                "source_reliability": 0.9,
                "temporal_consistency": 1.0,
                "coverage": 0.8,
                "contradiction_penalty": 0.0,
                "final": 0.88,
            },
            "temporal_consistency": True,
            "source_families": ["kubernetes_audit", "rbac"],
            "coverage_sufficient": True,
        },
        "response-plan.schema.json": {
            "schema_version": "1.0",
            "plan_id": identifier(),
            **ids,
            "status": "candidate",
            "actions": [
                {
                    "action_id": identifier(),
                    "action_type": "revoke_test_rbac_binding",
                    "target": {"namespace": "orders", "binding": "orders-reader-test"},
                    "target_scope": "fixture/orders",
                    "preconditions": ["resource version matches snapshot"],
                    "expected_effects": ["secret listing is denied"],
                    "service_invariants": ["orders-to-billing health path remains available"],
                    "rollback": {"available": True, "procedure": "restore binding snapshot"},
                    "approval_class": "lab_safe",
                    "idempotency_key": "case-1-action-1",
                }
            ],
        },
        "audit-entry.schema.json": {
            "schema_version": "1.0",
            "entry_id": identifier(),
            **ids,
            "sequence": 1,
            "created_at": "2026-09-27T10:03:01Z",
            "actor": {"kind": "system", "id": "test", "role": "coordinator"},
            "event_type": "case.created",
            "tool_name": None,
            "model_provider": None,
            "model_id": None,
            "prompt_template_sha256": None,
            "retrieved_artifact_ids": [],
            "redacted_arguments_sha256": None,
            "output_sha256": None,
            "previous_entry_hash": sha(),
            "payload_sha256": sha(),
            "policy_decision": "allow",
            "approval_id": None,
            "execution_result": None,
            "entry_hash": sha(),
        },
    }


@pytest.mark.parametrize("schema_name", sorted(valid_instances()))
def test_schema_is_valid_and_accepts_reference_instance(schema_name: str) -> None:
    schema = json.loads((SCHEMA_DIR / schema_name).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FORMAT_CHECKER)
    validator.validate(valid_instances()[schema_name])


def test_canonical_event_rejects_unknown_top_level_fields() -> None:
    schema_name = "canonical-event.schema.json"
    schema = json.loads((SCHEMA_DIR / schema_name).read_text(encoding="utf-8"))
    instance = valid_instances()[schema_name] | {"secret_value": "must-not-be-here"}
    validator = Draft202012Validator(schema, format_checker=FORMAT_CHECKER)

    with pytest.raises(ValidationError):
        validator.validate(instance)


def test_schema_examples_use_real_uuid_values() -> None:
    for instance in valid_instances().values():
        keys = (
            "artifact_id",
            "event_id",
            "evidence_id",
            "hypothesis_id",
            "claim_id",
            "plan_id",
            "entry_id",
        )
        for key in keys:
            if key in instance:
                UUID(str(instance[key]))
