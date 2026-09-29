"""Typed read-only fixture collector with server-owned source attestation.

This adapter is intentionally local and finite. It accepts only an already-loaded fixture sequence,
normalizes each event, enforces tenant/case/deadline/item bounds, and returns canonical events plus
the trusted source registration needed by the verifier. It never opens a socket or executes a
command.
"""

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from causalforge.domain.events import CanonicalEvent, SourceRef
from causalforge.ingestion.normalizer import NormalizationError, normalize_event
from causalforge.workflow.planner import EvidenceRequest
from causalforge.workflow.verifier import TrustedSource

CollectionStatus = Literal["completed", "truncated", "insufficient_evidence"]


class CollectionResult(BaseModel):
    """Canonical read-only collection result and safe failure metadata."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: UUID
    tenant_id: UUID
    case_id: UUID
    status: CollectionStatus
    events: tuple[CanonicalEvent, ...] = ()
    trusted_source: TrustedSource
    collected_at: datetime
    consumed_items: int = Field(ge=0)
    rejected_items: int = Field(ge=0)
    unmet_requirements: tuple[str, ...] = ()

    @field_validator("collected_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("collection timestamp must be timezone-aware")
        return value.astimezone(UTC)


def _checked_now(now: datetime | None) -> datetime:
    value = now or datetime.now(UTC)
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("collector clock must be timezone-aware")
    return value.astimezone(UTC)


class FixtureCollector:
    """Collect only from a caller-supplied in-memory fixture sequence."""

    def __init__(
        self,
        payloads: Sequence[Mapping[str, Any]],
        *,
        parser_version: str,
        trusted_source: TrustedSource,
    ) -> None:
        if not payloads:
            raise ValueError("fixture collector requires at least one payload")
        if not parser_version.strip():
            raise ValueError("fixture parser version is required")
        self._payloads = tuple(dict(payload) for payload in payloads)
        self._parser_version = parser_version
        self._trusted_source = trusted_source

    def collect(
        self,
        request: EvidenceRequest,
        *,
        tenant_id: UUID,
        case_id: UUID,
        deadline: datetime,
        now: datetime | None = None,
    ) -> CollectionResult:
        """Execute one bounded fixture request without external side effects."""

        if request.collector_kind != "fixture_event_replay":
            raise ValueError("fixture collector received an unsupported collector kind")
        if request.source_family != self._trusted_source.independent_family:
            raise ValueError("fixture request source family is not attested by the collector")
        checked_at = _checked_now(now)
        if deadline.tzinfo is None or deadline.utcoffset() is None:
            raise ValueError("collection deadline must be timezone-aware")
        deadline = deadline.astimezone(UTC)
        if checked_at >= deadline:
            return self._result(
                request,
                tenant_id=tenant_id,
                case_id=case_id,
                collected_at=checked_at,
                events=(),
                rejected_items=0,
                status="insufficient_evidence",
                unmet_requirements=("collection_deadline",),
            )

        normalized: list[CanonicalEvent] = []
        rejected = 0
        for payload in self._payloads:
            try:
                event = normalize_event(
                    payload,
                    parser_version=self._parser_version,
                    clock=lambda: checked_at,
                ).event
            except NormalizationError:
                rejected += 1
                continue
            if event.tenant_id != tenant_id or event.source != self._source_ref():
                rejected += 1
                continue
            normalized.append(event)
            if len(normalized) == request.max_items:
                break

        truncated = len(normalized) < len(self._payloads) and len(normalized) == request.max_items
        if not normalized:
            return self._result(
                request,
                tenant_id=tenant_id,
                case_id=case_id,
                collected_at=checked_at,
                events=(),
                rejected_items=rejected,
                status="insufficient_evidence",
                unmet_requirements=("fixture_scope_or_provenance",),
            )
        return self._result(
            request,
            tenant_id=tenant_id,
            case_id=case_id,
            collected_at=checked_at,
            events=tuple(normalized),
            rejected_items=rejected,
            status="truncated" if truncated else "completed",
            unmet_requirements=("item_budget",) if truncated else (),
        )

    def _source_ref(self) -> SourceRef:
        return SourceRef(
            kind=self._trusted_source.kind,
            name=self._trusted_source.name,
            version=self._trusted_source.version,
        )

    def _result(
        self,
        request: EvidenceRequest,
        *,
        tenant_id: UUID,
        case_id: UUID,
        collected_at: datetime,
        events: tuple[CanonicalEvent, ...],
        rejected_items: int,
        status: CollectionStatus,
        unmet_requirements: tuple[str, ...],
    ) -> CollectionResult:
        return CollectionResult(
            request_id=request.request_id,
            tenant_id=tenant_id,
            case_id=case_id,
            status=status,
            events=events,
            trusted_source=self._trusted_source,
            collected_at=collected_at,
            consumed_items=len(events),
            rejected_items=rejected_items,
            unmet_requirements=unmet_requirements,
        )
