"""Create event, evidence, and tamper-evident audit tables."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_security_evidence"
down_revision: str | None = "0001_core_infrastructure"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_kind", sa.String(length=80), nullable=False),
        sa.Column("source_name", sa.String(length=200), nullable=False),
        sa.Column("source_version", sa.String(length=80), nullable=False),
        sa.Column("actor_kind", sa.String(length=80), nullable=False),
        sa.Column("actor_id", sa.String(length=500), nullable=False),
        sa.Column("action", sa.String(length=120), nullable=False),
        sa.Column("object_kind", sa.String(length=120), nullable=False),
        sa.Column("object_namespace", sa.String(length=255), nullable=True),
        sa.Column("object_name", sa.String(length=255), nullable=True),
        sa.Column("object_uid", sa.String(length=255), nullable=True),
        sa.Column("outcome", sa.String(length=20), nullable=False),
        sa.Column("attributes", sa.JSON(), nullable=False),
        sa.Column("coverage_complete", sa.Boolean(), nullable=False),
        sa.Column("coverage_window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("coverage_window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("raw_payload_sha256", sa.String(length=64), nullable=False),
        sa.Column("parser_version", sa.String(length=120), nullable=False),
        sa.Column("deduplication_key", sa.String(length=64), nullable=False),
        sa.Column("canonical_payload", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id", "deduplication_key", name="uq_events_tenant_deduplication"
        ),
    )
    op.create_index("ix_events_tenant_id", "events", ["tenant_id"], unique=False)
    op.create_index(
        "ix_events_tenant_observed_at", "events", ["tenant_id", "observed_at"], unique=False
    )

    op.create_table(
        "evidence_items",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("case_id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("source_kind", sa.String(length=80), nullable=False),
        sa.Column("source_name", sa.String(length=200), nullable=False),
        sa.Column("source_version", sa.String(length=80), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("parser_version", sa.String(length=120), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("redaction_profile", sa.String(length=120), nullable=False),
        sa.Column("coverage_complete", sa.Boolean(), nullable=False),
        sa.Column("coverage_window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("coverage_window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("normalized", sa.JSON(), nullable=False),
        sa.Column("raw_reference", sa.String(length=500), nullable=True),
        sa.Column("source_reliability", sa.Float(), nullable=False),
        sa.Column("source_family", sa.String(length=120), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_evidence_items_case_id", "evidence_items", ["case_id"], unique=False)
    op.create_index("ix_evidence_items_tenant_id", "evidence_items", ["tenant_id"], unique=False)
    op.create_index(
        "ix_evidence_tenant_case_observed_at",
        "evidence_items",
        ["tenant_id", "case_id", "observed_at"],
        unique=False,
    )

    op.create_table(
        "audit_entries",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("case_id", sa.String(length=36), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor", sa.JSON(), nullable=False),
        sa.Column("event_type", sa.String(length=160), nullable=False),
        sa.Column("tool_name", sa.String(length=160), nullable=True),
        sa.Column("model_provider", sa.String(length=120), nullable=True),
        sa.Column("model_id", sa.String(length=160), nullable=True),
        sa.Column("prompt_template_sha256", sa.String(length=64), nullable=True),
        sa.Column("retrieved_artifact_ids", sa.JSON(), nullable=False),
        sa.Column("redacted_arguments_sha256", sa.String(length=64), nullable=True),
        sa.Column("output_sha256", sa.String(length=64), nullable=True),
        sa.Column("previous_entry_hash", sa.String(length=64), nullable=False),
        sa.Column("payload_sha256", sa.String(length=64), nullable=False),
        sa.Column("policy_decision", sa.String(length=20), nullable=False),
        sa.Column("approval_id", sa.String(length=36), nullable=True),
        sa.Column("execution_result", sa.JSON(), nullable=True),
        sa.Column("entry_hash", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("entry_hash"),
        sa.UniqueConstraint("tenant_id", "case_id", "sequence", name="uq_audit_case_sequence"),
    )
    op.create_index("ix_audit_entries_tenant_id", "audit_entries", ["tenant_id"], unique=False)
    op.create_index("ix_audit_entries_case_id", "audit_entries", ["case_id"], unique=False)
    op.create_index(
        "ix_audit_tenant_case_created_at",
        "audit_entries",
        ["tenant_id", "case_id", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_audit_tenant_case_created_at", table_name="audit_entries")
    op.drop_index("ix_audit_entries_case_id", table_name="audit_entries")
    op.drop_index("ix_audit_entries_tenant_id", table_name="audit_entries")
    op.drop_table("audit_entries")
    op.drop_index("ix_evidence_tenant_case_observed_at", table_name="evidence_items")
    op.drop_index("ix_evidence_items_tenant_id", table_name="evidence_items")
    op.drop_index("ix_evidence_items_case_id", table_name="evidence_items")
    op.drop_table("evidence_items")
    op.drop_index("ix_events_tenant_observed_at", table_name="events")
    op.drop_index("ix_events_tenant_id", table_name="events")
    op.drop_table("events")
