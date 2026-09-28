from fastapi.testclient import TestClient

from causalforge.config import Settings
from causalforge.main import create_app


def make_client(tmp_path) -> TestClient:
    settings = Settings(
        environment="test",
        database_url=f"sqlite:///{tmp_path / 'health.db'}",
        auto_create_schema=True,
        lab_only=True,
        external_network_enabled=False,
    )
    return TestClient(create_app(settings))


def test_liveness_does_not_depend_on_database(tmp_path) -> None:
    with make_client(tmp_path) as client:
        response = client.get("/health/live")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.headers["x-request-id"]


def test_readiness_reports_database_and_optional_redis(tmp_path) -> None:
    with make_client(tmp_path) as client:
        response = client.get("/health/ready", headers={"X-Request-ID": "test-request-1"})

    assert response.status_code == 200
    assert response.headers["x-request-id"] == "test-request-1"
    body = response.json()
    assert body["status"] == "ready"
    assert {check["name"] for check in body["checks"]} == {"database", "redis"}
    redis_check = next(check for check in body["checks"] if check["name"] == "redis")
    assert redis_check["status"] == "skipped"
    assert redis_check["detail"] == (
        "not_required_in_profile"
    )


def test_readiness_fails_closed_when_migrations_are_missing(tmp_path) -> None:
    settings = Settings(
        environment="test",
        database_url=f"sqlite:///{tmp_path / 'unmigrated.db'}",
        auto_create_schema=False,
    )

    with TestClient(create_app(settings)) as client:
        response = client.get("/health/ready")

    assert response.status_code == 503
    body = response.json()
    database_check = next(check for check in body["checks"] if check["name"] == "database")
    assert body["status"] == "not_ready"
    assert database_check["status"] == "error"
    assert "unmigrated.db" not in response.text
