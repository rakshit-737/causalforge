"""Durable read-only workflow runs and collection receipts."""

from datetime import datetime

from sqlalchemy import JSON, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from causalforge.domain.serialization import sha256_hex
from causalforge.storage.models.base import Base, UTCDateTime, utc_now
from causalforge.workflow.coordinator import CollectionReceipt, CoordinatorResult


class WorkflowRunRecord(Base):
    """Immutable summary of one bounded coordinator run."""

    __tablename__ = "workflow_runs"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "idempotency_key",
            name="uq_workflow_runs_tenant_idempotency_key",
        ),
        Index("ix_workflow_runs_tenant_case_created", "tenant_id", "case_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    case_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    hypothesis_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    plan_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    plan: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    unmet_requirements: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    completed_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    result_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, nullable=False)

    @classmethod
    def from_result(
        cls,
        result: CoordinatorResult,
        *,
        idempotency_key: str,
        request_hash: str,
    ) -> "WorkflowRunRecord":
        """Map a validated coordinator result to an immutable persistence row."""

        payload = result.model_dump(mode="json")
        return cls(
            id=str(result.run_id),
            tenant_id=str(result.tenant_id),
            case_id=str(result.case_id),
            hypothesis_id=str(result.hypothesis_id),
            idempotency_key=idempotency_key,
            request_hash=request_hash,
            plan_id=str(result.plan.plan_id),
            status=result.status,
            plan=result.plan.model_dump(mode="json"),
            unmet_requirements=list(result.unmet_requirements),
            started_at=result.started_at,
            completed_at=result.completed_at,
            result_hash=sha256_hex(payload),
        )


class CollectionReceiptRecord(Base):
    """Immutable durable receipt for one typed collection request."""

    __tablename__ = "collection_receipts"
    __table_args__ = (
        UniqueConstraint(
            "workflow_run_id",
            "request_id",
            name="uq_collection_receipts_run_request",
        ),
        Index(
            "ix_collection_receipts_tenant_case_collected",
            "tenant_id",
            "case_id",
            "collected_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workflow_run_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    case_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    hypothesis_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    request_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    collector_kind: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    trusted_source: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False)
    event_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    collected_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    consumed_items: Mapped[int] = mapped_column(Integer, nullable=False)
    rejected_items: Mapped[int] = mapped_column(Integer, nullable=False)
    unmet_requirements: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    receipt_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, nullable=False)

    @classmethod
    def from_receipt(
        cls,
        receipt: CollectionReceipt,
        *,
        workflow_run_id: str,
        tenant_id: str,
        case_id: str,
        hypothesis_id: str,
    ) -> "CollectionReceiptRecord":
        """Map a validated receipt to an immutable persistence row."""

        return cls(
            id=str(receipt.receipt_id),
            workflow_run_id=workflow_run_id,
            tenant_id=tenant_id,
            case_id=case_id,
            hypothesis_id=hypothesis_id,
            request_id=str(receipt.request_id),
            collector_kind=receipt.collector_kind,
            status=receipt.status,
            trusted_source=receipt.trusted_source.model_dump(),
            event_ids=[str(value) for value in receipt.event_ids],
            collected_at=receipt.collected_at,
            consumed_items=receipt.consumed_items,
            rejected_items=receipt.rejected_items,
            unmet_requirements=list(receipt.unmet_requirements),
            receipt_hash=receipt.receipt_hash,
        )
