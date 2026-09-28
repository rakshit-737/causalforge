"""Add an integrity hash for the immutable evidence envelope."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009_evidence_provenance"
down_revision: str | None = "0008_claim_verification"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Existing rows are not silently declared trustworthy. The local schema is recreated in the
    # supported fixture path; a production migration must backfill this field with a reviewed,
    # versioned data migration before enabling reads.
    with op.batch_alter_table("evidence_items") as batch_op:
        batch_op.add_column(sa.Column("provenance_hash", sa.String(length=64), nullable=True))
    op.execute(
        "UPDATE evidence_items SET provenance_hash = "
        "'0000000000000000000000000000000000000000000000000000000000000000' "
        "WHERE provenance_hash IS NULL"
    )
    with op.batch_alter_table("evidence_items") as batch_op:
        batch_op.alter_column(
            "provenance_hash",
            existing_type=sa.String(length=64),
            nullable=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("evidence_items") as batch_op:
        batch_op.drop_column("provenance_hash")
