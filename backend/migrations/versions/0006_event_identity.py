"""Separate internal event row IDs from producer event IDs."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006_event_identity"
down_revision: str | None = "0005_integrity_and_api"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("events") as batch_op:
        batch_op.add_column(sa.Column("producer_event_id", sa.String(length=36), nullable=True))
    op.execute("UPDATE events SET producer_event_id = id WHERE producer_event_id IS NULL")
    with op.batch_alter_table("events") as batch_op:
        batch_op.alter_column(
            "producer_event_id",
            existing_type=sa.String(length=36),
            nullable=False,
        )
        batch_op.create_unique_constraint(
            "uq_events_tenant_producer_id", ["tenant_id", "producer_event_id"]
        )
        batch_op.create_index("ix_events_producer_event_id", ["producer_event_id"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("events") as batch_op:
        batch_op.drop_index("ix_events_producer_event_id")
        batch_op.drop_constraint("uq_events_tenant_producer_id", type_="unique")
        batch_op.drop_column("producer_event_id")
