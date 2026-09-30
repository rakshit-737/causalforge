from uuid import UUID, uuid4

from fastapi.testclient import TestClient

from causalforge.config import Settings
from causalforge.main import create_app
from causalforge.storage.models import Tenant, User


def make_client(tmp_path) -> tuple[TestClient, UUID, UUID]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    app = create_app(
        Settings(
            environment="test",
            database_url=f"sqlite:///{tmp_path / 'workflow.db'}",
            auto_create_schema=True,
        )
    )
    app.state.database.create_schema()
    tenant_a = Tenant(name="workflow-tenant-a")
    tenant_b = Tenant(name="workflow-tenant-b")
    with app.state.database.session() as session:
        session.add_all([tenant_a, tenant_b])
        session.flush()
        session.add_all(
            [
                User(tenant_id=tenant_a.id, subject="alice", role="analyst"),
                User(tenant_id=tenant_b.id, subject="bob", role="analyst"),
            ]
        )
        session.commit()
    return TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000)), UUID(
        tenant_a.id
    ), UUID(tenant_b.id)


def headers(tenant_id: UUID, user: str) -> dict[str, str]:
    return {"X-Tenant-ID": str(tenant_id), "X-User-ID": user}


def fixture_event(tenant_id: UUID, event_id: UUID | None = None) -> dict[str, object]:
    return {
        "event_id": str(event_id or uuid4()),
        "tenant_id": str(tenant_id),
        "source": {"kind": "fixture", "name": "local-fixture", "version": "1.0"},
        "observed_at": "2026-09-30T10:00:00Z",
        "actor": {"kind": "service_account", "id": "orders-reader"},
        "action": "list",
        "object": {"kind": "secret", "namespace": "orders", "name": None},
        "outcome": "allowed",
        "attributes": {"workload_id": "orders-api", "accessToken": "fixture-secret"},
        "coverage": {
            "source_complete_for_window": True,
            "window_start": "2026-09-30T09:55:00Z",
            "window_end": "2026-09-30T10:05:00Z",
        },
    }


def create_target(client: TestClient, tenant_id: UUID, user: str) -> tuple[UUID, UUID]:
    case_id = uuid4()
    incident = client.post(
        "/api/v1/incidents",
        headers=headers(tenant_id, user),
        json={"incident_id": str(case_id), "title": "Workflow fixture"},
    )
    assert incident.status_code == 201
    hypothesis = client.post(
        f"/api/v1/incidents/{case_id}/hypotheses",
        headers=headers(tenant_id, user),
        json={
            "statement": "orders-reader listed a fixture secret",
            "required_evidence": ["fixture event replay"],
            "initial_confidence": 0.5,
            "risk_if_true": {"severity": "high", "rationale": "fixture-only test"},
        },
    )
    assert hypothesis.status_code == 201
    return case_id, UUID(hypothesis.json()["hypothesis_id"])


def test_workflow_run_is_durable_and_idempotent(tmp_path) -> None:
    client, tenant_id, _ = make_client(tmp_path)
    case_id, hypothesis_id = create_target(client, tenant_id, "alice")
    request = {
        "idempotency_key": "fixture-run-1",
        "parser_version": "fixture-1.0",
        "events": [fixture_event(tenant_id)],
    }

    first = client.post(
        f"/api/v1/incidents/{case_id}/hypotheses/{hypothesis_id}/workflow-runs",
        headers=headers(tenant_id, "alice"),
        json=request,
    )
    assert first.status_code == 201
    body = first.json()
    assert body["status"] == "completed"
    assert body["plan"]["status"] == "planned"
    assert len(body["receipts"]) == 1
    assert len(body["event_ids"]) == 1
    assert len(body["evidence_ids"]) == 1
    assert body["replayed"] is False
    assert "fixture-secret" not in first.text

    replay = client.post(
        f"/api/v1/incidents/{case_id}/hypotheses/{hypothesis_id}/workflow-runs",
        headers=headers(tenant_id, "alice"),
        json=request,
    )
    assert replay.status_code == 200
    assert replay.json()["run_id"] == body["run_id"]
    assert replay.json()["evidence_ids"] == body["evidence_ids"]
    assert replay.json()["replayed"] is True

    listed = client.get(
        f"/api/v1/incidents/{case_id}/hypotheses/{hypothesis_id}/workflow-runs",
        headers=headers(tenant_id, "alice"),
    )
    assert listed.status_code == 200
    assert len(listed.json()) == 1
    fetched = client.get(
        f"/api/v1/incidents/{case_id}/hypotheses/{hypothesis_id}/workflow-runs/{body['run_id']}",
        headers=headers(tenant_id, "alice"),
    )
    assert fetched.status_code == 200
    assert fetched.json()["result_hash"] == body["result_hash"]

    conflict = client.post(
        f"/api/v1/incidents/{case_id}/hypotheses/{hypothesis_id}/workflow-runs",
        headers=headers(tenant_id, "alice"),
        json={**request, "events": [fixture_event(tenant_id)]},
    )
    assert conflict.status_code == 409
    assert conflict.json() == {"detail": "idempotency key conflict"}


def test_workflow_run_is_tenant_isolated(tmp_path) -> None:
    client, tenant_a, tenant_b = make_client(tmp_path)
    case_id, hypothesis_id = create_target(client, tenant_a, "alice")
    run = client.post(
        f"/api/v1/incidents/{case_id}/hypotheses/{hypothesis_id}/workflow-runs",
        headers=headers(tenant_a, "alice"),
        json={
            "idempotency_key": "tenant-a-run",
            "parser_version": "fixture-1.0",
            "events": [fixture_event(tenant_a)],
        },
    )
    assert run.status_code == 201
    run_id = run.json()["run_id"]

    cross_tenant = client.get(
        f"/api/v1/incidents/{case_id}/hypotheses/{hypothesis_id}/workflow-runs/{run_id}",
        headers=headers(tenant_b, "bob"),
    )
    assert cross_tenant.status_code == 404

    mismatch = client.post(
        f"/api/v1/incidents/{case_id}/hypotheses/{hypothesis_id}/workflow-runs",
        headers=headers(tenant_a, "alice"),
        json={
            "idempotency_key": "tenant-a-run",
            "parser_version": "fixture-1.0",
            "events": [fixture_event(tenant_b)],
        },
    )
    assert mismatch.status_code == 409


def test_workflow_reports_insufficient_evidence_without_guessing_scope(tmp_path) -> None:
    client, tenant_id, _ = make_client(tmp_path)
    case_id, hypothesis_id = create_target(client, tenant_id, "alice")
    response = client.post(
        f"/api/v1/incidents/{case_id}/hypotheses/{hypothesis_id}/workflow-runs",
        headers=headers(tenant_id, "alice"),
        json={
            "idempotency_key": "bad-source-run",
            "parser_version": "fixture-1.0",
            "events": [
                {
                    **fixture_event(tenant_id),
                    "source": {"kind": "unknown", "name": "untrusted", "version": "1"},
                }
            ],
        },
    )

    assert response.status_code == 201
    assert response.json()["status"] == "insufficient_evidence"
    assert response.json()["evidence_ids"] == []
    assert "fixture_scope_or_provenance" in response.json()["unmet_requirements"]
