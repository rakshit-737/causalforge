"""Transactional persistence boundary for the local fixture workflow."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from causalforge.audit.ledger import AuditLedger
from causalforge.domain.hypotheses import Hypothesis
from causalforge.domain.serialization import sha256_hex
from causalforge.ingestion.service import IngestionService
from causalforge.storage.models import (
    CollectionReceiptRecord,
    EvidenceRecord,
    WorkflowRunRecord,
)
from causalforge.storage.repositories.evidence import EvidenceRepository
from causalforge.workflow.coordinator import FixtureCoordinator
from causalforge.workflow.planner import PlannerPolicy
from causalforge.workflow.verifier import TrustedSource

FIXTURE_TRUSTED_SOURCE = TrustedSource(
    kind="fixture",
    name="local-fixture",
    version="1.0",
    independent_family="fixture",
)


class WorkflowIdempotencyConflict(ValueError):
    """Raised when a key is replayed with a different request or scope."""


class WorkflowStateError(ValueError):
    """Raised when durable workflow state cannot be revalidated safely."""


@dataclass(frozen=True)
class DurableWorkflowResult:
    """Durable workflow snapshot returned before the caller commits its transaction."""

    run: WorkflowRunRecord
    receipts: tuple[CollectionReceiptRecord, ...]
    event_ids: tuple[UUID, ...]
    evidence_ids: tuple[UUID, ...]
    replayed: bool


def _checked_now(now: datetime | None) -> datetime:
    value = now or datetime.now(UTC)
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("workflow clock must be timezone-aware")
    return value.astimezone(UTC)


def _request_hash(
    payloads: Sequence[Mapping[str, Any]],
    *,
    parser_version: str,
    planner_policy: PlannerPolicy,
) -> str:
    return sha256_hex(
        {
            "parser_version": parser_version,
            "payloads": [dict(payload) for payload in payloads],
            "planner_policy": planner_policy.model_dump(mode="json"),
        }
    )


class DurableFixtureWorkflow:
    """Run the fixture coordinator and persist its bounded artifacts in one transaction."""

    def __init__(
        self,
        *,
        ingestion: IngestionService | None = None,
        audit: AuditLedger | None = None,
        coordinator: FixtureCoordinator | None = None,
    ) -> None:
        self.audit = audit or AuditLedger()
        self.ingestion = ingestion or IngestionService(audit_ledger=self.audit)
        self.coordinator = coordinator or FixtureCoordinator()

    def execute(
        self,
        session: Session,
        *,
        hypothesis: Hypothesis,
        payloads: Sequence[Mapping[str, Any]],
        parser_version: str,
        idempotency_key: str,
        actor: Mapping[str, str],
        planner_policy: PlannerPolicy | None = None,
        trusted_source: TrustedSource = FIXTURE_TRUSTED_SOURCE,
        now: datetime | None = None,
    ) -> DurableWorkflowResult:
        """Execute one tenant-scoped, fixture-only workflow with replay protection."""

        if hypothesis.tenant_id is None or hypothesis.case_id is None:
            raise WorkflowStateError("hypothesis scope is incomplete")
        if (
            not idempotency_key
            or len(idempotency_key) > 128
            or idempotency_key.strip() != idempotency_key
        ):
            raise ValueError("idempotency key must be 1-128 non-whitespace characters")
        if not parser_version.strip():
            raise ValueError("parser version is required")
        effective_policy = PlannerPolicy.model_validate(
            (planner_policy or PlannerPolicy()).model_dump()
        )
        request_hash = _request_hash(
            payloads,
            parser_version=parser_version,
            planner_policy=effective_policy,
        )
        existing = session.scalar(
            select(WorkflowRunRecord).where(
                WorkflowRunRecord.tenant_id == str(hypothesis.tenant_id),
                WorkflowRunRecord.idempotency_key == idempotency_key,
            )
        )
        if existing is not None:
            if (
                existing.case_id != str(hypothesis.case_id)
                or existing.hypothesis_id != str(hypothesis.hypothesis_id)
                or existing.request_hash != request_hash
            ):
                raise WorkflowIdempotencyConflict("idempotency key is already bound to another run")
            return self._snapshot(session, existing, replayed=True)

        started_at = _checked_now(now)
        result = self.coordinator.run(
            hypothesis,
            payloads,
            parser_version=parser_version,
            trusted_source=trusted_source,
            planner_policy=effective_policy,
            now=started_at,
        )
        run_record = WorkflowRunRecord.from_result(
            result,
            idempotency_key=idempotency_key,
            request_hash=request_hash,
        )
        session.add(run_record)
        session.flush()
        self.audit.append(
            session,
            tenant_id=hypothesis.tenant_id,
            case_id=hypothesis.case_id,
            actor=actor,
            event_type="workflow.plan.created",
            payload={
                "run_id": str(result.run_id),
                "plan_id": str(result.plan.plan_id),
                "hypothesis_id": str(hypothesis.hypothesis_id),
                "status": result.plan.status,
                "request_count": len(result.plan.requests),
                "unmet_requirements": list(result.plan.unmet_requirements),
                "idempotency_key_sha256": sha256_hex({"idempotency_key": idempotency_key}),
            },
            policy_decision="allow",
            created_at=result.plan.created_at,
            retrieved_artifact_ids=[str(hypothesis.hypothesis_id)],
        )

        collection_times = {
            event_id: receipt.collected_at
            for receipt in result.receipts
            for event_id in receipt.event_ids
        }
        evidence_ids: list[UUID] = []
        for event in result.events:
            ingested = self.ingestion.ingest_canonical(
                session,
                event=event,
                case_id=hypothesis.case_id,
                expected_tenant_id=hypothesis.tenant_id,
                collected_at=collection_times.get(event.event_id, result.completed_at),
                source_family=trusted_source.independent_family,
                actor=actor,
            )
            if ingested.evidence_record is not None:
                evidence_ids.append(UUID(ingested.evidence_record.id))

        receipt_records: list[CollectionReceiptRecord] = []
        for receipt in result.receipts:
            receipt_record = CollectionReceiptRecord.from_receipt(
                receipt,
                workflow_run_id=str(result.run_id),
                tenant_id=str(hypothesis.tenant_id),
                case_id=str(hypothesis.case_id),
                hypothesis_id=str(hypothesis.hypothesis_id),
            )
            session.add(receipt_record)
            receipt_records.append(receipt_record)
            self.audit.append(
                session,
                tenant_id=hypothesis.tenant_id,
                case_id=hypothesis.case_id,
                actor=actor,
                event_type="workflow.collection.receipt",
                payload={
                    "run_id": str(result.run_id),
                    "request_id": str(receipt.request_id),
                    "receipt_id": str(receipt.receipt_id),
                    "status": receipt.status,
                    "event_ids": [str(value) for value in receipt.event_ids],
                    "consumed_items": receipt.consumed_items,
                    "rejected_items": receipt.rejected_items,
                    "unmet_requirements": list(receipt.unmet_requirements),
                    "receipt_hash": receipt.receipt_hash,
                },
                policy_decision="allow",
                created_at=receipt.collected_at,
                retrieved_artifact_ids=[str(value) for value in receipt.event_ids],
            )
        if not result.receipts:
            self.audit.append(
                session,
                tenant_id=hypothesis.tenant_id,
                case_id=hypothesis.case_id,
                actor=actor,
                event_type="workflow.collection.skipped",
                payload={
                    "run_id": str(result.run_id),
                    "status": result.status,
                    "unmet_requirements": list(result.unmet_requirements),
                },
                policy_decision="allow",
                created_at=result.completed_at,
            )
        session.flush()
        return DurableWorkflowResult(
            run=run_record,
            receipts=tuple(receipt_records),
            event_ids=tuple(event.event_id for event in result.events),
            evidence_ids=tuple(dict.fromkeys(evidence_ids)),
            replayed=False,
        )

    def _snapshot(
        self,
        session: Session,
        run: WorkflowRunRecord,
        *,
        replayed: bool,
    ) -> DurableWorkflowResult:
        receipts = tuple(
            session.scalars(
                select(CollectionReceiptRecord)
                .where(
                    CollectionReceiptRecord.workflow_run_id == run.id,
                    CollectionReceiptRecord.tenant_id == run.tenant_id,
                    CollectionReceiptRecord.case_id == run.case_id,
                )
                .order_by(
                    CollectionReceiptRecord.collected_at.asc(),
                    CollectionReceiptRecord.id.asc(),
                )
            )
        )
        event_ids: list[UUID] = []
        for receipt in receipts:
            try:
                event_ids.extend(UUID(value) for value in receipt.event_ids)
            except (TypeError, ValueError) as exc:
                raise WorkflowStateError("stored collection receipt has invalid event IDs") from exc
        unique_event_ids = tuple(dict.fromkeys(event_ids))
        evidence_by_event: dict[str, UUID] = {}
        evidence_rows = session.scalars(
            select(EvidenceRecord).where(
                EvidenceRecord.tenant_id == run.tenant_id,
                EvidenceRecord.case_id == run.case_id,
            )
        )
        wanted = {str(value) for value in unique_event_ids}
        for row in evidence_rows:
            EvidenceRepository.verify_integrity(row)
            event_id = row.normalized.get("event_id")
            if isinstance(event_id, str) and event_id in wanted:
                evidence_by_event[event_id] = UUID(row.id)
        return DurableWorkflowResult(
            run=run,
            receipts=receipts,
            event_ids=unique_event_ids,
            evidence_ids=tuple(
                evidence_by_event[str(event_id)]
                for event_id in unique_event_ids
                if str(event_id) in evidence_by_event
            ),
            replayed=replayed,
        )
