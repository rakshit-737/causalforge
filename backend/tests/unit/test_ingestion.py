from datetime import UTC, datetime
from uuid import uuid4

import pytest

from causalforge.domain.serialization import sha256_hex
from causalforge.ingestion.deduplication import Deduplicator
from causalforge.ingestion.normalizer import NormalizationError, normalize_event


def payload(event_id: str | None = None, tenant_id: str | None = None) -> dict[str, object]:
    return {
        "event_id": event_id or str(uuid4()),
        "tenant_id": tenant_id or str(uuid4()),
        "source": {"kind": "kubernetes_audit", "name": "fixture", "version": "1.0"},
        "observed_at": "2026-09-28T10:03:00Z",
        "actor": {"kind": "service_account", "id": "system:serviceaccount:orders:reader"},
        "action": "list",
        "object": {"kind": "secret", "namespace": "orders", "name": None},
        "outcome": "allowed",
        "attributes": {
            "request_uri": "/api/v1/namespaces/orders/secrets",
            "secret_value": "do-not-store",
            "headers": {"Authorization": "Bearer do-not-store"},
        },
        "coverage": {
            "source_complete_for_window": True,
            "window_start": "2026-09-28T10:00:00Z",
            "window_end": "2026-09-28T10:05:00Z",
        },
    }


def test_normalizer_hashes_raw_input_and_redacts_nested_secrets() -> None:
    raw = payload()
    result = normalize_event(
        raw,
        parser_version="fixture-1.0",
        clock=lambda: datetime(2026, 9, 28, 10, 3, 1, tzinfo=UTC),
    )

    assert result.event.raw_payload_sha256 == sha256_hex(raw)
    assert result.event.attributes["secret_value"] == "[REDACTED]"
    assert result.event.attributes["headers"]["Authorization"] == "[REDACTED]"
    assert "do-not-store" not in str(result.event.canonical_payload())
    assert "attributes.secret_value" in result.redaction.paths
    assert "attributes.headers.Authorization" in result.redaction.paths


def test_normalizer_rejects_invalid_input_without_echoing_payload() -> None:
    bad = payload()
    bad.pop("actor")

    with pytest.raises(NormalizationError, match="failed canonical validation") as error:
        normalize_event(bad, parser_version="fixture-1.0")

    assert "do-not-store" not in str(error.value)


def test_deduplicator_ignores_producer_event_id() -> None:
    tenant_id = str(uuid4())
    first = normalize_event(
        payload("00000000-0000-0000-0000-000000000001", tenant_id), parser_version="1"
    ).event
    second = normalize_event(
        payload("00000000-0000-0000-0000-000000000002", tenant_id), parser_version="1"
    ).event
    deduplicator = Deduplicator()

    assert deduplicator.accept(first) is True
    assert deduplicator.accept(second) is False


def test_coverage_window_must_be_ordered() -> None:
    bad = payload()
    bad["coverage"] = {
        "source_complete_for_window": True,
        "window_start": "2026-09-28T10:05:00Z",
        "window_end": "2026-09-28T10:00:00Z",
    }

    with pytest.raises(NormalizationError):
        normalize_event(bad, parser_version="fixture-1.0")
