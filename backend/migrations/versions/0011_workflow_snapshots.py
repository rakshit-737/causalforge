"""Retain exact collection snapshots and evidence alias bindings for durable replay."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011_workflow_snapshots"
down_revision: str | None = "0010_durable_workflow"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Old runs cannot be reconstructed reliably after deduplication. Keep them intact,
    # but leave their snapshots NULL so reads fail closed rather than inventing provenance.
    with op.batch_alter_table("workflow_runs") as batch:
        batch.add_column(sa.Column("result_snapshot", sa.JSON(), nullable=True))
        batch.add_column(sa.Column("evidence_bindings", sa.JSON(), nullable=True))
        batch.add_column(sa.Column("record_hash", sa.String(length=64), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("workflow_runs") as batch:
        batch.drop_column("record_hash")
        batch.drop_column("evidence_bindings")
        batch.drop_column("result_snapshot")
