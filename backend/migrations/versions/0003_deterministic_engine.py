"""Create incident, detection, and claim tables."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_deterministic_engine"
down_revision: str | None = "0002_security_evidence"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "incidents",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("trigger_event_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_incidents_tenant_id", "incidents", ["tenant_id"], unique=False)
    op.create_index(
        "ix_incidents_tenant_status", "incidents", ["tenant_id", "status"], unique=False
    )

    op.create_table(
        "detections",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("incident_id", sa.String(length=36), nullable=False),
        sa.Column("rule_id", sa.String(length=160), nullable=False),
        sa.Column("event_id", sa.String(length=36), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("level", sa.String(length=20), nullable=False),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("explanation", sa.String(length=2000), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "incident_id",
            "rule_id",
            "event_id",
            name="uq_detections_incident_rule_event",
        ),
    )
    op.create_index("ix_detections_tenant_id", "detections", ["tenant_id"], unique=False)
    op.create_index("ix_detections_incident_id", "detections", ["incident_id"], unique=False)
    op.create_index(
        "ix_detections_tenant_incident", "detections", ["tenant_id", "incident_id"], unique=False
    )

    op.create_table(
        "claims",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("incident_id", sa.String(length=36), nullable=False),
        sa.Column("subject", sa.String(length=500), nullable=False),
        sa.Column("predicate", sa.String(length=255), nullable=False),
        sa.Column("object_value", sa.JSON(), nullable=True),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("supporting_evidence_ids", sa.JSON(), nullable=False),
        sa.Column("contradictory_evidence_ids", sa.JSON(), nullable=False),
        sa.Column("confidence_components", sa.JSON(), nullable=False),
        sa.Column("temporal_consistency", sa.Boolean(), nullable=False),
        sa.Column("source_families", sa.JSON(), nullable=False),
        sa.Column("coverage_sufficient", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_claims_tenant_id", "claims", ["tenant_id"], unique=False)
    op.create_index("ix_claims_incident_id", "claims", ["incident_id"], unique=False)
    op.create_index(
        "ix_claims_tenant_incident_status",
        "claims",
        ["tenant_id", "incident_id", "status"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_claims_tenant_incident_status", table_name="claims")
    op.drop_index("ix_claims_incident_id", table_name="claims")
    op.drop_index("ix_claims_tenant_id", table_name="claims")
    op.drop_table("claims")
    op.drop_index("ix_detections_tenant_incident", table_name="detections")
    op.drop_index("ix_detections_incident_id", table_name="detections")
    op.drop_index("ix_detections_tenant_id", table_name="detections")
    op.drop_table("detections")
    op.drop_index("ix_incidents_tenant_status", table_name="incidents")
    op.drop_index("ix_incidents_tenant_id", table_name="incidents")
    op.drop_table("incidents")
