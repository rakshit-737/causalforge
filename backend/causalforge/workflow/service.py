"""Transactional persistence boundary for the local fixture workflow."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from causalforge.audit.ledger import AuditLedger
from causalforge.domain.events import CanonicalEvent
from causalforge.domain.hypotheses import Hypothesis
from causalforge.domain.serialization import sha256_hex
from causalforge.ingestion.service import IngestionService
from causalforge.storage.models import (
    CollectionReceiptRecord,
    EventRecord,
    EvidenceRecord,
    HypothesisRecord,
    IncidentRecord,
    WorkflowRunRecord,
)
from causalforge.storage.repositories.evidence import EvidenceRepository
from causalforge.workflow.coordinator import (
    CollectionReceipt,
    CoordinatorResult,
    FixtureCoordinator,
)
from causalforge.workflow.planner import EvidencePlan, PlannerPolicy
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
    receipts: tuple[CollectionReceipt, ...]
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
    trusted_source: TrustedSource,
    hypothesis: Hypothesis,
) -> str:
    return sha256_hex(
        {
            "parser_version": parser_version,
            "payloads": [dict(payload) for payload in payloads],
            "planner_policy": planner_policy.model_dump(mode="json"),
            "trusted_source": trusted_source.model_dump(mode="json"),
            "hypothesis": hypothesis.model_dump(mode="json", exclude={"status"}),
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

        hypothesis = Hypothesis.model_validate(hypothesis.model_dump(mode="json"))
        incident = session.scalar(select(IncidentRecord).where(
            IncidentRecord.id == str(hypothesis.case_id),
            IncidentRecord.tenant_id == str(hypothesis.tenant_id),
        ))
        # Serialize runs for one hypothesis on PostgreSQL. SQLite's Database boundary
        # starts BEGIN IMMEDIATE, so the same path is serialized locally as well.
        target = session.scalar(select(HypothesisRecord).where(
            HypothesisRecord.id == str(hypothesis.hypothesis_id),
            HypothesisRecord.tenant_id == str(hypothesis.tenant_id),
            HypothesisRecord.incident_id == str(hypothesis.case_id),
        ).with_for_update())
        if incident is None or target is None or target.to_hypothesis() != hypothesis:
            raise WorkflowStateError("workflow target does not match persisted scope")
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
            trusted_source=trusted_source,
            hypothesis=hypothesis,
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
            run_identity=idempotency_key,
        )
        with session.begin_nested():
            return self._persist(
                session, result=result, hypothesis=hypothesis, actor=actor,
                idempotency_key=idempotency_key, request_hash=request_hash,
                trusted_source=trusted_source,
            )

    def _persist(
        self,
        session: Session,
        *,
        result: CoordinatorResult,
        hypothesis: Hypothesis,
        actor: Mapping[str, str],
        idempotency_key: str,
        request_hash: str,
        trusted_source: TrustedSource,
    ) -> DurableWorkflowResult:
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
        bindings: list[dict[str, str]] = []
        persisted_events: list[CanonicalEvent] = []
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
            evidence = ingested.evidence_record
            if evidence is None:
                raise WorkflowStateError("collected event has no durable evidence")
            EvidenceRepository.verify_integrity(evidence)
            persisted_events.append(ingested.normalized.event)
            bindings.append({
                "collected_event_id": str(event.event_id),
                "persisted_event_id": str(ingested.normalized.event.event_id),
                "evidence_id": evidence.id,
                "content_hash": evidence.content_hash,
                "provenance_hash": evidence.provenance_hash,
            })

        persisted_result = CoordinatorResult.model_validate(
            {
                **result.model_dump(mode="json"),
                "events": [event.model_dump(mode="json") for event in persisted_events],
            }
        )
        run_record = WorkflowRunRecord.from_result(
            persisted_result,
            idempotency_key=idempotency_key,
            request_hash=request_hash,
        )
        session.add(run_record)
        session.flush()

        for receipt in persisted_result.receipts:
            receipt_record = CollectionReceiptRecord.from_receipt(
                receipt,
                workflow_run_id=str(result.run_id),
                tenant_id=str(hypothesis.tenant_id),
                case_id=str(hypothesis.case_id),
                hypothesis_id=str(hypothesis.hypothesis_id),
            )
            session.add(receipt_record)
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
        if not persisted_result.receipts:
            self.audit.append(
                session,
                tenant_id=hypothesis.tenant_id,
                case_id=hypothesis.case_id,
                actor=actor,
                event_type="workflow.collection.skipped",
                payload={
                    "run_id": str(result.run_id),
                    "status": persisted_result.status,
                    "unmet_requirements": list(persisted_result.unmet_requirements),
                },
                policy_decision="allow",
                created_at=persisted_result.completed_at,
            )
        run_record.evidence_bindings = bindings
        run_record.record_hash = run_record.integrity_hash()
        self.audit.append(
            session, tenant_id=hypothesis.tenant_id, case_id=hypothesis.case_id,
            actor=actor, event_type="workflow.run.recorded", policy_decision="allow",
            payload={"run_id": run_record.id, "record_hash": run_record.record_hash},
            created_at=result.completed_at,
        )
        session.flush()
        return self._snapshot(session, run_record, replayed=False)

    def load(
        self,
        session: Session,
        *,
        tenant_id: UUID,
        case_id: UUID,
        hypothesis_id: UUID,
        run_id: UUID,
    ) -> DurableWorkflowResult | None:
        """Load one run only when every caller-supplied scope matches."""

        run = session.scalar(
            select(WorkflowRunRecord).where(
                WorkflowRunRecord.id == str(run_id),
                WorkflowRunRecord.tenant_id == str(tenant_id),
                WorkflowRunRecord.case_id == str(case_id),
                WorkflowRunRecord.hypothesis_id == str(hypothesis_id),
            )
        )
        if run is None:
            return None
        return self._snapshot(session, run, replayed=False)

    def _snapshot(
        self,
        session: Session,
        run: WorkflowRunRecord,
        *,
        replayed: bool,
    ) -> DurableWorkflowResult:
        if (
            run.result_snapshot is None
            or run.evidence_bindings is None
            or run.record_hash is None
        ):
            raise WorkflowStateError("stored workflow has no complete integrity envelope")
        if run.record_hash != run.integrity_hash():
            raise WorkflowStateError("stored workflow record hash mismatch")
        if sha256_hex(run.result_snapshot) != run.result_hash:
            raise WorkflowStateError("stored workflow snapshot hash mismatch")
        receipt_records = tuple(
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
        receipts = tuple(self._receipt_from_record(run, record) for record in receipt_records)
        if len({receipt.request_id for receipt in receipts}) != len(receipts):
            raise WorkflowStateError("stored workflow contains duplicate collection requests")
        event_ids = tuple(event_id for receipt in receipts for event_id in receipt.event_ids)
        if len(set(event_ids)) != len(event_ids):
            raise WorkflowStateError("stored workflow contains duplicate event IDs")
        unique_event_ids = event_ids
        event_rows = session.scalars(
            select(EventRecord).where(
                EventRecord.tenant_id == run.tenant_id,
                EventRecord.producer_event_id.in_([str(value) for value in unique_event_ids]),
            )
        )
        events_by_id: dict[str, CanonicalEvent] = {}
        for event_row in event_rows:
            event = event_row.to_event()
            if str(event.event_id) in events_by_id:
                raise WorkflowStateError("stored workflow maps an event ID to multiple rows")
            events_by_id[str(event.event_id)] = event
        if set(events_by_id) != {str(value) for value in unique_event_ids}:
            raise WorkflowStateError("stored workflow is missing a collected event")
        events = tuple(events_by_id[str(event_id)] for event_id in unique_event_ids)
        evidence_by_event: dict[str, UUID] = {}
        evidence_rows_by_event: dict[str, EvidenceRecord] = {}
        evidence_rows = session.scalars(
            select(EvidenceRecord).where(
                EvidenceRecord.tenant_id == run.tenant_id,
                EvidenceRecord.case_id == run.case_id,
            )
        )
        wanted = {str(value) for value in unique_event_ids}
        for evidence_row in evidence_rows:
            event_id = evidence_row.normalized.get("event_id")
            if isinstance(event_id, str) and event_id in wanted:
                EvidenceRepository.verify_integrity(evidence_row)
                if event_id in evidence_by_event:
                    raise WorkflowStateError(
                        "stored workflow maps an event to multiple evidence rows"
                    )
                evidence_by_event[event_id] = UUID(evidence_row.id)
                evidence_rows_by_event[event_id] = evidence_row
        if set(evidence_by_event) != wanted:
            raise WorkflowStateError("stored workflow is missing persisted evidence")
        bindings_by_event: dict[str, dict[str, str]] = {}
        for binding in run.evidence_bindings:
            event_id = binding.get("collected_event_id")
            if not event_id or event_id in bindings_by_event:
                raise WorkflowStateError("stored workflow has invalid evidence bindings")
            bindings_by_event[event_id] = binding
        if set(bindings_by_event) != wanted:
            raise WorkflowStateError("stored workflow evidence bindings are incomplete")
        for event_id, binding in bindings_by_event.items():
            evidence_row = evidence_rows_by_event[event_id]
            if (
                binding.get("persisted_event_id") != event_id
                or binding.get("evidence_id") != evidence_row.id
                or binding.get("content_hash") != evidence_row.content_hash
                or binding.get("provenance_hash") != evidence_row.provenance_hash
            ):
                raise WorkflowStateError("stored workflow evidence binding mismatch")
        plan = EvidencePlan.model_validate(run.plan)
        trusted_sources: list[TrustedSource] = []
        for receipt in receipts:
            if receipt.trusted_source not in trusted_sources:
                trusted_sources.append(receipt.trusted_source)
        try:
            durable_result = CoordinatorResult(
                schema_version="1.0",
                run_id=UUID(run.id),
                tenant_id=UUID(run.tenant_id),
                case_id=UUID(run.case_id),
                hypothesis_id=UUID(run.hypothesis_id),
                status=run.status,  # type: ignore[arg-type]
                plan=plan,
                receipts=receipts,
                events=events,
                trusted_sources=tuple(trusted_sources),
                started_at=run.started_at,
                completed_at=run.completed_at,
                unmet_requirements=tuple(run.unmet_requirements),
            )
        except (TypeError, ValueError) as exc:
            raise WorkflowStateError("stored workflow result is invalid") from exc
        if sha256_hex(durable_result.model_dump(mode="json")) != run.result_hash:
            raise WorkflowStateError("stored workflow result hash mismatch")
        try:
            snapshot_result = CoordinatorResult.model_validate(run.result_snapshot)
        except (TypeError, ValueError) as exc:
            raise WorkflowStateError("stored workflow snapshot is invalid") from exc
        if snapshot_result.model_dump(mode="json") != durable_result.model_dump(mode="json"):
            raise WorkflowStateError("stored workflow snapshot does not match durable rows")
        return DurableWorkflowResult(
            run=run,
            receipts=receipts,
            event_ids=unique_event_ids,
            evidence_ids=tuple(
                evidence_by_event[str(event_id)]
                for event_id in unique_event_ids
            ),
            replayed=replayed,
        )

    @staticmethod
    def _receipt_from_record(
        run: WorkflowRunRecord,
        record: CollectionReceiptRecord,
    ) -> CollectionReceipt:
        if (
            record.workflow_run_id != run.id
            or record.tenant_id != run.tenant_id
            or record.case_id != run.case_id
            or record.hypothesis_id != run.hypothesis_id
        ):
            raise WorkflowStateError("stored collection receipt scope mismatch")
        try:
            return CollectionReceipt.model_validate(
                {
                    "schema_version": "1.0",
                    "run_id": run.id,
                    "receipt_id": record.id,
                    "request_id": record.request_id,
                    "tenant_id": record.tenant_id,
                    "case_id": record.case_id,
                    "hypothesis_id": record.hypothesis_id,
                    "collector_kind": record.collector_kind,
                    "status": record.status,
                    "trusted_source": record.trusted_source,
                    "event_ids": record.event_ids,
                    "collected_at": record.collected_at,
                    "consumed_items": record.consumed_items,
                    "rejected_items": record.rejected_items,
                    "unmet_requirements": record.unmet_requirements,
                    "receipt_hash": record.receipt_hash,
                }
            )
        except (TypeError, ValueError) as exc:
            raise WorkflowStateError("stored collection receipt is invalid") from exc
