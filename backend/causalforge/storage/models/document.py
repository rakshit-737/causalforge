"""Approved knowledge document and chunk persistence models."""

from datetime import datetime

from sqlalchemy import JSON, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from causalforge.storage.models.base import Base, UTCDateTime, utc_now


class DocumentRecord(Base):
    """Document metadata; tenant_id null means approved global knowledge."""

    __tablename__ = "documents"
    __table_args__ = (
        Index("ix_documents_tenant_source", "tenant_id", "source"),
        Index("ix_documents_tenant_content_hash", "tenant_id", "content_hash"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    source: Mapped[str] = mapped_column(String(300), nullable=False)
    version: Mapped[str] = mapped_column(String(120), nullable=False)
    license: Mapped[str] = mapped_column(String(200), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    document_metadata: Mapped[dict[str, object]] = mapped_column(
        "metadata", JSON, nullable=False, default=dict
    )
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, nullable=False)


class DocumentChunkRecord(Base):
    """Searchable chunk with provenance fields repeated for isolated retrieval results."""

    __tablename__ = "document_chunks"
    __table_args__ = (
        Index("ix_document_chunks_tenant_text", "tenant_id"),
        Index("ix_document_chunks_document_ordinal", "document_id", "ordinal", unique=True),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    document_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    text: Mapped[str] = mapped_column(String(10000), nullable=False)
    source: Mapped[str] = mapped_column(String(300), nullable=False)
    version: Mapped[str] = mapped_column(String(120), nullable=False)
    license: Mapped[str] = mapped_column(String(200), nullable=False)
    source_hash: Mapped[str] = mapped_column(String(64), nullable=False)
