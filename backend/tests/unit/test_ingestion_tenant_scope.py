from uuid import uuid4

import pytest

from causalforge.ingestion.service import IngestionService
from causalforge.storage.db import Database


def test_ingestion_rejects_event_from_another_tenant(tmp_path) -> None:
    expected_tenant = uuid4()
    database = Database(f"sqlite:///{tmp_path / 'tenant-scope.db'}")
    database.create_schema()
    payload = {
        "event_id": str(uuid4()),
        "tenant_id": str(uuid4()),
        "source": {"kind": "fixture", "name": "test", "version": "1.0"},
        "observed_at": "2026-09-28T10:03:00Z",
        "actor": {"kind": "service_account", "id": "reader"},
        "action": "list",
        "object": {"kind": "secret", "namespace": "orders", "name": None},
        "outcome": "allowed",
        "attributes": {},
        "coverage": {
            "source_complete_for_window": True,
            "window_start": "2026-09-28T10:00:00Z",
            "window_end": "2026-09-28T10:05:00Z",
        },
    }

    with database.session() as session:
        with pytest.raises(ValueError, match="tenant"):
            IngestionService().ingest(
                session,
                payload=payload,
                case_id=uuid4(),
                expected_tenant_id=expected_tenant,
                parser_version="fixture-1.0",
            )
