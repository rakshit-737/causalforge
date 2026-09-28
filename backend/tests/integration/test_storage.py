from sqlalchemy import inspect

from causalforge.storage.db import Database
from causalforge.storage.models import Tenant
from causalforge.storage.repositories.users import UserRepository


def test_user_repository_requires_and_enforces_tenant_scope(tmp_path) -> None:
    database = Database(f"sqlite:///{tmp_path / 'repository.db'}")
    database.create_schema()
    repository = UserRepository()

    with database.session() as session:
        tenant_a = Tenant(name="tenant-a")
        tenant_b = Tenant(name="tenant-b")
        session.add_all([tenant_a, tenant_b])
        session.commit()

        repository.create(
            session,
            tenant_id=tenant_a.id,
            subject="analyst-a",
            role="analyst",
        )
        repository.create(
            session,
            tenant_id=tenant_b.id,
            subject="analyst-b",
            role="analyst",
        )
        session.commit()

        users_a = repository.list_for_tenant(session, tenant_id=tenant_a.id)
        users_b = repository.list_for_tenant(session, tenant_id=tenant_b.id)

    assert [user.subject for user in users_a] == ["analyst-a"]
    assert [user.subject for user in users_b] == ["analyst-b"]


def test_database_schema_contains_phase1_tables(tmp_path) -> None:
    database = Database(f"sqlite:///{tmp_path / 'schema.db'}")
    database.create_schema()

    assert set(inspect(database.engine).get_table_names()) == {
        "audit_entries",
            "claims",
            "claim_verification_records",
        "detections",
        "document_chunks",
        "documents",
        "events",
        "evidence_items",
        "incidents",
        "hypotheses",
        "tenants",
        "users",
        "verification_records",
    }
