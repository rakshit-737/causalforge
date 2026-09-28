"""Add durable claim verification attempt records."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008_claim_verification"
down_revision: str | None = "0007_hypothesis_workflow"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "claim_verification_records",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("incident_id", sa.String(length=36), nullable=False),
        sa.Column("claim_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("supporting_evidence_ids", sa.JSON(), nullable=False),
        sa.Column("contradictory_evidence_ids", sa.JSON(), nullable=False),
        sa.Column("source_families", sa.JSON(), nullable=False),
        sa.Column("coverage_sufficient", sa.Boolean(), nullable=False),
        sa.Column("temporal_consistency", sa.Boolean(), nullable=False),
        sa.Column("unmet_requirements", sa.JSON(), nullable=False),
        sa.Column("reason", sa.String(length=1000), nullable=False),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_evidence_items", sa.Integer(), nullable=False),
        sa.Column("budget_exhausted", sa.Boolean(), nullable=False),
        sa.Column("policy", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_claim_verification_records_tenant_id",
        "claim_verification_records",
        ["tenant_id"],
        unique=False,
    )
    op.create_index(
        "ix_claim_verification_records_incident_id",
        "claim_verification_records",
        ["incident_id"],
        unique=False,
    )
    op.create_index(
        "ix_claim_verification_records_claim_id",
        "claim_verification_records",
        ["claim_id"],
        unique=False,
    )
    op.create_index(
        "ix_claim_verification_tenant_incident_claim",
        "claim_verification_records",
        ["tenant_id", "incident_id", "claim_id", "checked_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_claim_verification_tenant_incident_claim",
        table_name="claim_verification_records",
    )
    op.drop_index("ix_claim_verification_records_claim_id", table_name="claim_verification_records")
    op.drop_index(
        "ix_claim_verification_records_incident_id", table_name="claim_verification_records"
    )
    op.drop_index(
        "ix_claim_verification_records_tenant_id", table_name="claim_verification_records"
    )
    op.drop_table("claim_verification_records")
