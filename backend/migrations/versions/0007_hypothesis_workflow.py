"""Add durable hypotheses and bounded verification attempt records."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007_hypothesis_workflow"
down_revision: str | None = "0006_event_identity"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "hypotheses",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("incident_id", sa.String(length=36), nullable=False),
        sa.Column("statement", sa.String(length=2000), nullable=False),
        sa.Column("supporting_observation_ids", sa.JSON(), nullable=False),
        sa.Column("required_evidence", sa.JSON(), nullable=False),
        sa.Column("disconfirming_evidence", sa.JSON(), nullable=False),
        sa.Column("attack_technique_ids", sa.JSON(), nullable=False),
        sa.Column("initial_confidence", sa.Float(), nullable=False),
        sa.Column("risk_if_true", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_hypotheses_tenant_id", "hypotheses", ["tenant_id"], unique=False)
    op.create_index("ix_hypotheses_incident_id", "hypotheses", ["incident_id"], unique=False)
    op.create_index(
        "ix_hypotheses_tenant_incident_status",
        "hypotheses",
        ["tenant_id", "incident_id", "status"],
        unique=False,
    )

    op.create_table(
        "verification_records",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("incident_id", sa.String(length=36), nullable=False),
        sa.Column("hypothesis_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("supporting_evidence_ids", sa.JSON(), nullable=False),
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
        "ix_verification_records_tenant_id", "verification_records", ["tenant_id"], unique=False
    )
    op.create_index(
        "ix_verification_records_incident_id",
        "verification_records",
        ["incident_id"],
        unique=False,
    )
    op.create_index(
        "ix_verification_records_hypothesis_id",
        "verification_records",
        ["hypothesis_id"],
        unique=False,
    )
    op.create_index(
        "ix_verification_tenant_incident_hypothesis",
        "verification_records",
        ["tenant_id", "incident_id", "hypothesis_id", "checked_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_verification_tenant_incident_hypothesis", table_name="verification_records")
    op.drop_index("ix_verification_records_hypothesis_id", table_name="verification_records")
    op.drop_index("ix_verification_records_incident_id", table_name="verification_records")
    op.drop_index("ix_verification_records_tenant_id", table_name="verification_records")
    op.drop_table("verification_records")
    op.drop_index("ix_hypotheses_tenant_incident_status", table_name="hypotheses")
    op.drop_index("ix_hypotheses_incident_id", table_name="hypotheses")
    op.drop_index("ix_hypotheses_tenant_id", table_name="hypotheses")
    op.drop_table("hypotheses")
