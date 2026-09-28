from alembic import command
from alembic.config import Config
from sqlalchemy import inspect


def test_initial_alembic_migration_creates_phase1_tables(tmp_path, monkeypatch) -> None:
    database_url = f"sqlite:///{tmp_path / 'migration.db'}"
    monkeypatch.setenv("CF_DATABASE_URL", database_url)

    config = Config("backend/alembic.ini")
    command.upgrade(config, "head")

    from sqlalchemy import create_engine

    engine = create_engine(database_url)
    try:
        assert set(inspect(engine).get_table_names()) == {
            "alembic_version",
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
    finally:
        engine.dispose()
