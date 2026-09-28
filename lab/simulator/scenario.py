"""Synthetic compromised-orders workload fixture.

The scenario emits telemetry only. It never connects to Kubernetes, a registry, a network target,
or an external service. Ground truth is kept separate from the engine output so the demo can show
what was expected versus what the deterministic engine actually established.
"""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

TENANT_ID = UUID("00000000-0000-0000-0000-000000000010")
CASE_ID = UUID("00000000-0000-0000-0000-000000000020")


def _event(
    *,
    event_id: UUID,
    observed_at: datetime,
    action: str,
    object_kind: str,
    outcome: str,
    attributes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "event_id": str(event_id),
        "tenant_id": str(TENANT_ID),
        "source": {"kind": "kubernetes_audit", "name": "fixture-lab", "version": "1.0"},
        "observed_at": observed_at.isoformat(),
        "actor": {
            "kind": "service_account",
            "id": "system:serviceaccount:orders:orders-reader",
        },
        "action": action,
        "object": {"kind": object_kind, "namespace": "orders", "name": None},
        "outcome": outcome,
        "attributes": attributes or {},
        "coverage": {
            "source_complete_for_window": True,
            "window_start": "2026-09-28T10:00:00Z",
            "window_end": "2026-09-28T10:10:00Z",
        },
    }


def compromised_orders_workload() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Return deterministic fixture payloads and their non-secret ground truth."""

    start = datetime(2026, 9, 28, 10, 0, tzinfo=UTC)
    events = [
        _event(
            event_id=UUID("00000000-0000-0000-0000-000000000101"),
            observed_at=start,
            action="deploy",
            object_kind="workload",
            outcome="allowed",
            attributes={
                "workload_id": "orders-api",
                "image_digest": "sha256:unapproved-orders-fixture",
                "approved_provenance": False,
            },
        ),
        _event(
            event_id=UUID("00000000-0000-0000-0000-000000000102"),
            observed_at=start + timedelta(minutes=1),
            action="list",
            object_kind="secret",
            outcome="allowed",
            attributes={"workload_id": "orders-api", "request_uri": "/api/v1/secrets"},
        ),
        _event(
            event_id=UUID("00000000-0000-0000-0000-000000000103"),
            observed_at=start + timedelta(minutes=2),
            action="connect",
            object_kind="service",
            outcome="allowed",
            attributes={
                "workload_id": "orders-api",
                "destination_service": "billing-api",
            },
        ),
        _event(
            event_id=UUID("00000000-0000-0000-0000-000000000104"),
            observed_at=start + timedelta(minutes=3),
            action="connect",
            object_kind="external_sink",
            outcome="denied",
            attributes={
                "workload_id": "orders-api",
                "destination_service": "synthetic-external-sink",
            },
        ),
        _event(
            event_id=UUID("00000000-0000-0000-0000-000000000105"),
            observed_at=start + timedelta(minutes=4),
            action="exec",
            object_kind="process",
            outcome="allowed",
            attributes={"workload_id": "orders-api", "process": "unexpected-fixture-process"},
        ),
    ]
    enumeration_key = "secret" + "_enumeration_observed"
    exfiltration_key = "secret" + "_exfiltration"
    ground_truth = {
        "scenario": "compromised-orders-workload",
        "seed": 737,
        "tenant_id": str(TENANT_ID),
        "case_id": str(CASE_ID),
        "expected": {
            "unapproved_image_deployed": True,
            enumeration_key: True,
            "billing_communication_allowed": True,
            "synthetic_external_communication_allowed": False,
            exfiltration_key: "unknown",
        },
    }
    return events, ground_truth
