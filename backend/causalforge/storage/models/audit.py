"""Hash-chained audit entry persistence model."""

from datetime import datetime

from sqlalchemy import JSON, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from causalforge.storage.models.base import Base, UTCDateTime


class AuditEntryRecord(Base):
    """Append-only audit row; the ledger validates the previous hash before insertion."""

    __tablename__ = "audit_entries"
    __table_args__ = (
        UniqueConstraint("tenant_id", "case_id", "sequence", name="uq_audit_case_sequence"),
        Index("ix_audit_tenant_case_created_at", "tenant_id", "case_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    case_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    actor: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False)
    event_type: Mapped[str] = mapped_column(String(160), nullable=False)
    tool_name: Mapped[str | None] = mapped_column(String(160), nullable=True)
    model_provider: Mapped[str | None] = mapped_column(String(120), nullable=True)
    model_id: Mapped[str | None] = mapped_column(String(160), nullable=True)
    prompt_template_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    retrieved_artifact_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    redacted_arguments_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    output_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    previous_entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_decision: Mapped[str] = mapped_column(String(20), nullable=False)
    approval_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    execution_result: Mapped[dict[str, object] | None] = mapped_column(JSON, nullable=True)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
