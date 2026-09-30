"""Add durable bounded workflow runs and collection receipts."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010_durable_workflow"
down_revision: str | None = "0009_evidence_provenance"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "workflow_runs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("case_id", sa.String(length=36), nullable=False),
        sa.Column("hypothesis_id", sa.String(length=36), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("request_hash", sa.String(length=64), nullable=False),
        sa.Column("plan_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("plan", sa.JSON(), nullable=False),
        sa.Column("unmet_requirements", sa.JSON(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("result_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "idempotency_key",
            name="uq_workflow_runs_tenant_idempotency_key",
        ),
    )
    op.create_index("ix_workflow_runs_tenant_id", "workflow_runs", ["tenant_id"], unique=False)
    op.create_index("ix_workflow_runs_case_id", "workflow_runs", ["case_id"], unique=False)
    op.create_index(
        "ix_workflow_runs_hypothesis_id",
        "workflow_runs",
        ["hypothesis_id"],
        unique=False,
    )
    op.create_index("ix_workflow_runs_plan_id", "workflow_runs", ["plan_id"], unique=False)
    op.create_index(
        "ix_workflow_runs_tenant_case_created",
        "workflow_runs",
        ["tenant_id", "case_id", "created_at"],
        unique=False,
    )

    op.create_table(
        "collection_receipts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workflow_run_id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("case_id", sa.String(length=36), nullable=False),
        sa.Column("hypothesis_id", sa.String(length=36), nullable=False),
        sa.Column("request_id", sa.String(length=36), nullable=False),
        sa.Column("collector_kind", sa.String(length=80), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("trusted_source", sa.JSON(), nullable=False),
        sa.Column("event_ids", sa.JSON(), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_items", sa.Integer(), nullable=False),
        sa.Column("rejected_items", sa.Integer(), nullable=False),
        sa.Column("unmet_requirements", sa.JSON(), nullable=False),
        sa.Column("receipt_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "workflow_run_id",
            "request_id",
            name="uq_collection_receipts_run_request",
        ),
    )
    op.create_index(
        "ix_collection_receipts_workflow_run_id",
        "collection_receipts",
        ["workflow_run_id"],
        unique=False,
    )
    op.create_index(
        "ix_collection_receipts_tenant_id",
        "collection_receipts",
        ["tenant_id"],
        unique=False,
    )
    op.create_index(
        "ix_collection_receipts_case_id",
        "collection_receipts",
        ["case_id"],
        unique=False,
    )
    op.create_index(
        "ix_collection_receipts_hypothesis_id",
        "collection_receipts",
        ["hypothesis_id"],
        unique=False,
    )
    op.create_index(
        "ix_collection_receipts_request_id",
        "collection_receipts",
        ["request_id"],
        unique=False,
    )
    op.create_index(
        "ix_collection_receipts_tenant_case_collected",
        "collection_receipts",
        ["tenant_id", "case_id", "collected_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_collection_receipts_tenant_case_collected",
        table_name="collection_receipts",
    )
    op.drop_index("ix_collection_receipts_request_id", table_name="collection_receipts")
    op.drop_index("ix_collection_receipts_hypothesis_id", table_name="collection_receipts")
    op.drop_index("ix_collection_receipts_case_id", table_name="collection_receipts")
    op.drop_index("ix_collection_receipts_tenant_id", table_name="collection_receipts")
    op.drop_index("ix_collection_receipts_workflow_run_id", table_name="collection_receipts")
    op.drop_table("collection_receipts")
    op.drop_index(
        "ix_workflow_runs_tenant_case_created",
        table_name="workflow_runs",
    )
    op.drop_index("ix_workflow_runs_plan_id", table_name="workflow_runs")
    op.drop_index("ix_workflow_runs_hypothesis_id", table_name="workflow_runs")
    op.drop_index("ix_workflow_runs_case_id", table_name="workflow_runs")
    op.drop_index("ix_workflow_runs_tenant_id", table_name="workflow_runs")
    op.drop_table("workflow_runs")
