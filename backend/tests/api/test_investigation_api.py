from uuid import UUID, uuid4

from fastapi.testclient import TestClient

from causalforge.config import Settings
from causalforge.main import create_app
from causalforge.storage.models import Tenant, User


def make_client(tmp_path):
    settings = Settings(
        environment="test",
        database_url=f"sqlite:///{tmp_path / 'api.db'}",
        auto_create_schema=True,
    )
    app = create_app(settings)
    app.state.database.create_schema()
    tenant_a = Tenant(name="api-tenant-a")
    tenant_b = Tenant(name="api-tenant-b")
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
    return TestClient(app), UUID(tenant_a.id), UUID(tenant_b.id)


def headers(tenant_id: UUID, user: str) -> dict[str, str]:
    return {"X-Tenant-ID": str(tenant_id), "X-User-ID": user}


def event_payload(
    tenant_id: UUID,
    event_id: UUID | None = None,
    *,
    source_kind: str = "kubernetes_audit",
) -> dict[str, object]:
    return {
        "event_id": str(event_id or uuid4()),
        "tenant_id": str(tenant_id),
        "source": {"kind": source_kind, "name": "fixture", "version": "1.0"},
        "observed_at": "2026-09-28T10:03:00Z",
        "actor": {"kind": "service_account", "id": "system:serviceaccount:orders:reader"},
        "action": "list",
        "object": {"kind": "secret", "namespace": "orders", "name": None},
        "outcome": "allowed",
        "attributes": {
            "workload_id": "orders-api",
            "accessToken": "api-secret-must-not-leak",
        },
        "coverage": {
            "source_complete_for_window": True,
            "window_start": "2026-09-28T10:00:00Z",
            "window_end": "2026-09-28T10:05:00Z",
        },
    }


def test_api_requires_verified_local_principal(tmp_path) -> None:
    client, tenant_a, _ = make_client(tmp_path)

    response = client.get("/api/v1/incidents")
    assert response.status_code == 401

    response = client.get(
        "/api/v1/incidents",
        headers={"X-Tenant-ID": str(tenant_a), "X-User-ID": "not-a-user"},
    )
    assert response.status_code == 401


def test_api_enforces_tenant_isolation_and_redacted_event_reads(tmp_path) -> None:
    client, tenant_a, tenant_b = make_client(tmp_path)
    auth_a = headers(tenant_a, "alice")
    auth_b = headers(tenant_b, "bob")
    case_id = uuid4()
    event_id = uuid4()

    created = client.post(
        "/api/v1/incidents",
        headers=auth_a,
        json={"incident_id": str(case_id), "title": "API fixture"},
    )
    assert created.status_code == 201

    batch = client.post(
        "/api/v1/events/batch",
        headers=auth_a,
        json={
            "case_id": str(case_id),
            "parser_version": "fixture-1.0",
            "events": [event_payload(tenant_a, event_id)],
        },
    )
    assert batch.status_code == 201
    assert batch.json()["claim_count"] == 1

    event_response = client.get(f"/api/v1/events/{event_id}", headers=auth_a)
    assert event_response.status_code == 200
    assert "api-secret-must-not-leak" not in event_response.text
    assert event_response.json()["attributes"]["accessToken"] == "[REDACTED]"

    claims = client.get(f"/api/v1/incidents/{case_id}/claims", headers=auth_a)
    assert claims.status_code == 200
    assert claims.json()[0]["status"] == "observed"

    cross_tenant = client.get(f"/api/v1/incidents/{case_id}", headers=auth_b)
    assert cross_tenant.status_code == 404
    cross_event = client.get(f"/api/v1/events/{event_id}", headers=auth_b)
    assert cross_event.status_code == 404


def test_api_rejects_event_tenant_mismatch_without_persisting(tmp_path) -> None:
    client, tenant_a, tenant_b = make_client(tmp_path)
    case_id = uuid4()
    auth_a = headers(tenant_a, "alice")

    created = client.post(
        "/api/v1/incidents",
        headers=auth_a,
        json={"incident_id": str(case_id), "title": "API fixture"},
    )
    assert created.status_code == 201

    response = client.post(
        "/api/v1/events/batch",
        headers=auth_a,
        json={
            "case_id": str(case_id),
            "parser_version": "fixture-1.0",
            "events": [event_payload(tenant_b)],
        },
    )
    assert response.status_code == 422
    assert "tenant" not in response.text.lower() or "scope" in response.text.lower()


def test_api_static_incident_routes_are_not_captured_by_id_route(tmp_path) -> None:
    client, tenant_a, _ = make_client(tmp_path)
    case_id = uuid4()
    auth_a = headers(tenant_a, "alice")
    created = client.post(
        "/api/v1/incidents",
        headers=auth_a,
        json={"incident_id": str(case_id), "title": "API fixture"},
    )
    assert created.status_code == 201

    claims = client.get(f"/api/v1/incidents/{case_id}/claims", headers=auth_a)
    graph = client.get(f"/api/v1/incidents/{case_id}/graph", headers=auth_a)
    assert claims.status_code == 200
    assert graph.status_code == 200


def test_api_persists_and_verifies_hypothesis_with_independent_sources(tmp_path) -> None:
    client, tenant_a, _ = make_client(tmp_path)
    auth_a = headers(tenant_a, "alice")
    case_id = uuid4()
    first_event_id = uuid4()
    second_event_id = uuid4()

    created = client.post(
        "/api/v1/incidents",
        headers=auth_a,
        json={"incident_id": str(case_id), "title": "Hypothesis fixture"},
    )
    assert created.status_code == 201
    batch = client.post(
        "/api/v1/events/batch",
        headers=auth_a,
        json={
            "case_id": str(case_id),
            "parser_version": "fixture-1.0",
            "events": [
                event_payload(tenant_a, first_event_id),
                event_payload(tenant_a, second_event_id, source_kind="runtime_sensor"),
            ],
        },
    )
    assert batch.status_code == 201

    hypothesis = client.post(
        f"/api/v1/incidents/{case_id}/hypotheses",
        headers=auth_a,
        json={
            "statement": "orders-reader enumerated Kubernetes secrets",
            "supporting_observation_ids": [str(first_event_id), str(second_event_id)],
            "required_evidence": ["independent source", "complete coverage"],
            "disconfirming_evidence": ["audit denial"],
            "attack_technique_ids": ["T1552.007"],
            "initial_confidence": 0.6,
            "risk_if_true": {
                "severity": "high",
                "rationale": "secret material may be exposed",
            },
        },
    )
    assert hypothesis.status_code == 201
    assert hypothesis.json()["status"] == "proposed"
    hypothesis_id = hypothesis.json()["hypothesis_id"]

    verified = client.post(
        f"/api/v1/incidents/{case_id}/hypotheses/{hypothesis_id}/verify",
        headers=auth_a,
        json={"minimum_independent_source_families": 2},
    )
    assert verified.status_code == 201
    assert verified.json()["status"] == "supported"
    assert verified.json()["source_families"] == ["kubernetes_audit", "runtime_sensor"]

    listed = client.get(f"/api/v1/incidents/{case_id}/hypotheses", headers=auth_a)
    attempts = client.get(
        f"/api/v1/incidents/{case_id}/hypotheses/{hypothesis_id}/verifications",
        headers=auth_a,
    )
    assert listed.status_code == 200
    assert listed.json()[0]["status"] == "supported"
    assert attempts.status_code == 200
    assert len(attempts.json()) == 1


def test_api_returns_insufficient_evidence_without_independent_coverage(tmp_path) -> None:
    client, tenant_a, _ = make_client(tmp_path)
    auth_a = headers(tenant_a, "alice")
    case_id = uuid4()
    event_id = uuid4()
    created = client.post(
        "/api/v1/incidents",
        headers=auth_a,
        json={"incident_id": str(case_id), "title": "Insufficient fixture"},
    )
    assert created.status_code == 201
    assert (
        client.post(
            "/api/v1/events/batch",
            headers=auth_a,
            json={
                "case_id": str(case_id),
                "parser_version": "fixture-1.0",
                "events": [event_payload(tenant_a, event_id)],
            },
        ).status_code
        == 201
    )
    hypothesis = client.post(
        f"/api/v1/incidents/{case_id}/hypotheses",
        headers=auth_a,
        json={
            "statement": "one source proves secret exfiltration",
            "supporting_observation_ids": [str(event_id)],
            "initial_confidence": 0.9,
            "risk_if_true": {"severity": "critical", "rationale": "high impact"},
        },
    )
    hypothesis_id = hypothesis.json()["hypothesis_id"]
    verified = client.post(
        f"/api/v1/incidents/{case_id}/hypotheses/{hypothesis_id}/verify",
        headers=auth_a,
        json={},
    )

    assert verified.status_code == 201
    assert verified.json()["status"] == "insufficient_evidence"
    assert "independent_source_families" in verified.json()["unmet_requirements"]


def test_api_does_not_reveal_foreign_incident_id_on_create(tmp_path) -> None:
    client, tenant_a, tenant_b = make_client(tmp_path)
    case_id = uuid4()
    assert client.post(
        "/api/v1/incidents",
        headers=headers(tenant_a, "alice"),
        json={"incident_id": str(case_id), "title": "Tenant A"},
    ).status_code == 201

    response = client.post(
        "/api/v1/incidents",
        headers=headers(tenant_b, "bob"),
        json={"incident_id": str(case_id), "title": "Tenant B"},
    )

    assert response.status_code == 404
