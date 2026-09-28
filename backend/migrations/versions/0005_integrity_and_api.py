"""Add case-scoped evidence uniqueness for idempotent attachment."""

from collections.abc import Sequence

from alembic import op

revision: str = "0005_integrity_and_api"
down_revision: str | None = "0004_knowledge_documents"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("evidence_items") as batch_op:
        batch_op.create_unique_constraint(
            "uq_evidence_tenant_case_content",
            ["tenant_id", "case_id", "content_hash"],
        )


def downgrade() -> None:
    with op.batch_alter_table("evidence_items") as batch_op:
        batch_op.drop_constraint("uq_evidence_tenant_case_content", type_="unique")
