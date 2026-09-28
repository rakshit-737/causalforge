"""Create tenant-scoped knowledge document tables."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_knowledge_documents"
down_revision: str | None = "0003_deterministic_engine"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "documents",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=True),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("source", sa.String(length=300), nullable=False),
        sa.Column("version", sa.String(length=120), nullable=False),
        sa.Column("license", sa.String(length=200), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_documents_tenant_id", "documents", ["tenant_id"], unique=False)
    op.create_index(
        "ix_documents_tenant_source", "documents", ["tenant_id", "source"], unique=False
    )
    op.create_index(
        "ix_documents_tenant_content_hash",
        "documents",
        ["tenant_id", "content_hash"],
        unique=False,
    )

    op.create_table(
        "document_chunks",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("document_id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=True),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("text", sa.String(length=10000), nullable=False),
        sa.Column("source", sa.String(length=300), nullable=False),
        sa.Column("version", sa.String(length=120), nullable=False),
        sa.Column("license", sa.String(length=200), nullable=False),
        sa.Column("source_hash", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("document_id", "ordinal"),
    )
    op.create_index(
        "ix_document_chunks_document_id", "document_chunks", ["document_id"], unique=False
    )
    op.create_index("ix_document_chunks_tenant_id", "document_chunks", ["tenant_id"], unique=False)
    op.create_index(
        "ix_document_chunks_tenant_text", "document_chunks", ["tenant_id"], unique=False
    )
    op.create_index(
        "ix_document_chunks_document_ordinal",
        "document_chunks",
        ["document_id", "ordinal"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_document_chunks_document_ordinal", table_name="document_chunks")
    op.drop_index("ix_document_chunks_tenant_text", table_name="document_chunks")
    op.drop_index("ix_document_chunks_tenant_id", table_name="document_chunks")
    op.drop_index("ix_document_chunks_document_id", table_name="document_chunks")
    op.drop_table("document_chunks")
    op.drop_index("ix_documents_tenant_content_hash", table_name="documents")
    op.drop_index("ix_documents_tenant_source", table_name="documents")
    op.drop_index("ix_documents_tenant_id", table_name="documents")
    op.drop_table("documents")
