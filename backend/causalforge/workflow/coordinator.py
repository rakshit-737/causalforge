"""Pure orchestration for bounded, fixture-only evidence collection.

The coordinator joins the typed planner and attested fixture collector without persisting, calling
external systems, or promoting claims. It returns replay-stable plan/receipt artifacts that a future
durable worker can store in one transaction with audit entries.
"""

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from causalforge.domain.events import CanonicalEvent
from causalforge.domain.hypotheses import Hypothesis
from causalforge.domain.serialization import sha256_hex
from causalforge.workflow.collector import CollectionStatus, FixtureCollector
from causalforge.workflow.planner import EvidencePlan, PlannerPolicy, plan_evidence
from causalforge.workflow.verifier import TrustedSource

RunStatus = Literal["completed", "insufficient_evidence"]


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("coordinator timestamps must be timezone-aware")
    return value.astimezone(UTC)


def _now(value: datetime | None) -> datetime:
    return _utc(value or datetime.now(UTC))


class CollectionReceipt(BaseModel):
    """Tamper-evident summary of one typed collector invocation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"]
    receipt_id: UUID
    request_id: UUID
    tenant_id: UUID
    case_id: UUID
    hypothesis_id: UUID
    collector_kind: Literal["fixture_event_replay"]
    status: CollectionStatus
    trusted_source: TrustedSource
    event_ids: tuple[UUID, ...] = ()
    collected_at: datetime
    consumed_items: int = Field(ge=0)
    rejected_items: int = Field(ge=0)
    unmet_requirements: tuple[str, ...] = ()
    receipt_hash: str = Field(pattern=r"^[a-f0-9]{64}$")

    @field_validator("collected_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        return _utc(value)

    @model_validator(mode="after")
    def verify_identity(self) -> "CollectionReceipt":
        content = self.model_dump(mode="json", exclude={"receipt_id", "receipt_hash"})
        expected_hash = sha256_hex(content)
        expected_id = uuid5(
            NAMESPACE_URL,
            f"causalforge:collection-receipt:{self.request_id}:{expected_hash}",
        )
        if self.receipt_hash != expected_hash:
            raise ValueError("collection receipt hash mismatch")
        if self.receipt_id != expected_id:
            raise ValueError("collection receipt identity mismatch")
        if len(set(self.event_ids)) != len(self.event_ids):
            raise ValueError("collection receipt contains duplicate event IDs")
        return self


class CoordinatorResult(BaseModel):
    """Pure coordinator output; no field implies that a target or collector was written to."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"]
    run_id: UUID
    tenant_id: UUID
    case_id: UUID
    hypothesis_id: UUID
    status: RunStatus
    plan: EvidencePlan
    receipts: tuple[CollectionReceipt, ...] = ()
    events: tuple[CanonicalEvent, ...] = ()
    trusted_sources: tuple[TrustedSource, ...] = ()
    started_at: datetime
    completed_at: datetime
    unmet_requirements: tuple[str, ...] = ()

    @field_validator("started_at", "completed_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        return _utc(value)

    @model_validator(mode="after")
    def validate_scope_and_status(self) -> "CoordinatorResult":
        if self.plan.tenant_id != self.tenant_id or self.plan.case_id != self.case_id:
            raise ValueError("coordinator plan scope mismatch")
        if self.plan.hypothesis_id != self.hypothesis_id:
            raise ValueError("coordinator hypothesis scope mismatch")
        if self.completed_at < self.started_at:
            raise ValueError("coordinator completion precedes start")
        if any(
            event.tenant_id != self.tenant_id
            for event in self.events
        ):
            raise ValueError("coordinator returned a foreign-tenant event")
        if self.status == "completed" and self.unmet_requirements:
            raise ValueError("completed coordinator run cannot have unmet requirements")
        if self.status == "insufficient_evidence" and not self.unmet_requirements:
            raise ValueError("incomplete coordinator run requires unmet requirements")
        return self


class FixtureCoordinator:
    """Plan and execute only the fixture collector; all other capabilities fail closed."""

    def run(
        self,
        hypothesis: Hypothesis,
        payloads: Sequence[Mapping[str, Any]],
        *,
        parser_version: str,
        trusted_source: TrustedSource,
        planner_policy: PlannerPolicy | None = None,
        now: datetime | None = None,
    ) -> CoordinatorResult:
        started_at = _now(now)
        plan = plan_evidence(hypothesis, policy=planner_policy, now=started_at)
        run_id = uuid5(NAMESPACE_URL, f"causalforge:coordinator-run:{plan.plan_id}")
        unmet = list(plan.unmet_requirements)
        if plan.status != "planned":
            return self._result(
                run_id=run_id,
                hypothesis=hypothesis,
                plan=plan,
                receipts=(),
                events=(),
                trusted_sources=(),
                started_at=started_at,
                completed_at=started_at,
                unmet=unmet,
            )

        collector = FixtureCollector(
            payloads,
            parser_version=parser_version,
            trusted_source=trusted_source,
        )
        receipts: list[CollectionReceipt] = []
        events_by_id: dict[UUID, CanonicalEvent] = {}
        trusted_sources: list[TrustedSource] = []
        for request in plan.requests:
            if request.collector_kind != "fixture_event_replay":
                unmet.append(f"collector_unavailable:{request.collector_kind}")
                continue
            result = collector.collect(
                request,
                tenant_id=hypothesis.tenant_id,
                case_id=hypothesis.case_id,
                deadline=plan.deadline,
                now=started_at,
            )
            receipt = self._receipt(
                request_id=request.request_id,
                hypothesis=hypothesis,
                result=result,
            )
            receipts.append(receipt)
            trusted_sources.append(result.trusted_source)
            unmet.extend(result.unmet_requirements)
            for event in result.events:
                previous = events_by_id.get(event.event_id)
                if previous is not None and (
                    previous.model_dump(mode="json") != event.model_dump(mode="json")
                ):
                    unmet.append("conflicting_event_identity")
                    continue
                events_by_id[event.event_id] = CanonicalEvent.model_validate(
                    event.model_dump(mode="json")
                )

        unmet = list(dict.fromkeys(unmet))
        completed_at = _now(now or started_at)
        if not receipts:
            unmet.append("no_collection_receipt")
        status: RunStatus = "completed" if not unmet else "insufficient_evidence"
        return self._result(
            run_id=run_id,
            hypothesis=hypothesis,
            plan=plan,
            receipts=tuple(receipts),
            events=tuple(events_by_id.values()),
            trusted_sources=tuple(dict.fromkeys(trusted_sources)),
            started_at=started_at,
            completed_at=completed_at,
            unmet=unmet,
            status=status,
        )

    @staticmethod
    def _receipt(
        *,
        request_id: UUID,
        hypothesis: Hypothesis,
        result: Any,
    ) -> CollectionReceipt:
        content = {
            "schema_version": "1.0",
            "request_id": str(request_id),
            "tenant_id": str(hypothesis.tenant_id),
            "case_id": str(hypothesis.case_id),
            "hypothesis_id": str(hypothesis.hypothesis_id),
            "collector_kind": "fixture_event_replay",
            "status": result.status,
            "trusted_source": result.trusted_source.model_dump(mode="json"),
            "event_ids": [str(event.event_id) for event in result.events],
            "collected_at": result.collected_at.isoformat(),
            "consumed_items": result.consumed_items,
            "rejected_items": result.rejected_items,
            "unmet_requirements": list(result.unmet_requirements),
        }
        receipt_hash = sha256_hex(content)
        receipt_id = uuid5(
            NAMESPACE_URL,
            f"causalforge:collection-receipt:{request_id}:{receipt_hash}",
        )
        return CollectionReceipt.model_validate(
            {**content, "receipt_id": receipt_id, "receipt_hash": receipt_hash}
        )

    @staticmethod
    def _result(
        *,
        run_id: UUID,
        hypothesis: Hypothesis,
        plan: EvidencePlan,
        receipts: tuple[CollectionReceipt, ...],
        events: tuple[CanonicalEvent, ...],
        trusted_sources: tuple[TrustedSource, ...],
        started_at: datetime,
        completed_at: datetime,
        unmet: list[str],
        status: RunStatus | None = None,
    ) -> CoordinatorResult:
        unique_unmet = tuple(dict.fromkeys(unmet))
        resolved_status = status or ("completed" if not unique_unmet else "insufficient_evidence")
        return CoordinatorResult(
            schema_version="1.0",
            run_id=run_id,
            tenant_id=hypothesis.tenant_id,
            case_id=hypothesis.case_id,
            hypothesis_id=hypothesis.hypothesis_id,
            status=resolved_status,
            plan=plan,
            receipts=receipts,
            events=events,
            trusted_sources=trusted_sources,
            started_at=started_at,
            completed_at=completed_at,
            unmet_requirements=unique_unmet,
        )
