"""Deterministic, typed evidence planning with no collection side effects.

The planner converts a small allowlisted vocabulary of evidence requirements into read-only
collection requests. It never accepts a shell command, URL, connector name, or arbitrary query.
Unknown requirements remain explicit ``insufficient_evidence`` items instead of being guessed.
"""

from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field, field_validator

from causalforge.domain.hypotheses import Hypothesis
from causalforge.domain.serialization import sha256_hex

CollectorKind = Literal[
    "fixture_event_replay",
    "kubernetes_audit_snapshot",
    "rbac_snapshot",
    "runtime_sensor_snapshot",
]
PlanStatus = Literal["planned", "insufficient_evidence"]


class EvidenceSelector(BaseModel):
    """Closed selector fields available to a future read-only collector."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_kind: str | None = Field(default=None, min_length=1, max_length=80)
    action: str | None = Field(default=None, min_length=1, max_length=120)
    object_kind: str | None = Field(default=None, min_length=1, max_length=120)
    outcome: Literal["allowed", "denied", "error", "unknown"] | None = None
    namespace: str | None = Field(default=None, min_length=1, max_length=255)
    workload_id: str | None = Field(default=None, min_length=1, max_length=255)


class PlannerPolicy(BaseModel):
    """Hard bounds for one plan; all values are server-side policy inputs."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_requests: int = Field(default=8, ge=1, le=32, strict=True)
    max_items_per_request: int = Field(default=100, ge=1, le=1000, strict=True)
    max_total_items: int = Field(default=200, ge=1, le=10_000, strict=True)
    deadline_seconds: int = Field(default=300, ge=1, le=900, strict=True)


class EvidenceRequest(BaseModel):
    """One typed request that a future collector may execute read-only."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: UUID
    collector_kind: CollectorKind
    source_family: str = Field(min_length=1, max_length=120)
    purpose: Literal["audit_event", "rbac_snapshot", "runtime_observation", "fixture_replay"]
    selector: EvidenceSelector
    max_items: int = Field(ge=1, le=1000, strict=True)


class EvidencePlan(BaseModel):
    """A replay-stable plan artifact, not an execution receipt."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"]
    plan_id: UUID
    case_id: UUID
    tenant_id: UUID
    hypothesis_id: UUID
    status: PlanStatus
    requests: tuple[EvidenceRequest, ...] = Field(max_length=32)
    unmet_requirements: tuple[str, ...] = ()
    max_total_items: int = Field(ge=1, le=10_000, strict=True)
    deadline: datetime
    created_at: datetime

    @field_validator("deadline", "created_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("evidence plan timestamps must be timezone-aware")
        return value.astimezone(UTC)


_REQUIREMENT_MAP: dict[str, tuple[CollectorKind, str, str, EvidenceSelector]] = {
    "audit event": (
        "kubernetes_audit_snapshot",
        "kubernetes_audit",
        "audit_event",
        EvidenceSelector(source_kind="kubernetes_audit"),
    ),
    "kubernetes audit": (
        "kubernetes_audit_snapshot",
        "kubernetes_audit",
        "audit_event",
        EvidenceSelector(source_kind="kubernetes_audit"),
    ),
    "rbac snapshot": (
        "rbac_snapshot",
        "rbac",
        "rbac_snapshot",
        EvidenceSelector(source_kind="rbac"),
    ),
    "runtime observation": (
        "runtime_sensor_snapshot",
        "runtime_sensor",
        "runtime_observation",
        EvidenceSelector(source_kind="runtime_sensor"),
    ),
    "fixture event replay": (
        "fixture_event_replay",
        "fixture",
        "fixture_replay",
        EvidenceSelector(source_kind="fixture"),
    ),
}


def _checked_now(now: datetime | None) -> datetime:
    value = now or datetime.now(UTC)
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("evidence planner clock must be timezone-aware")
    return value.astimezone(UTC)


def _unmet_requirement(requirement: str) -> str:
    """Keep unsupported user text out of a plan artifact while retaining stable diagnostics."""

    digest = sha256_hex({"requirement": requirement})
    return f"unsupported_requirement:{digest}"


def plan_evidence(
    hypothesis: Hypothesis,
    *,
    policy: PlannerPolicy | None = None,
    now: datetime | None = None,
) -> EvidencePlan:
    """Create a bounded plan without executing a collector or inventing a query."""

    effective_policy = policy or PlannerPolicy()
    created_at = _checked_now(now)
    requirements = tuple(
        dict.fromkeys(item.strip().casefold() for item in hypothesis.required_evidence)
    )
    requests: list[EvidenceRequest] = []
    unmet: list[str] = []
    for requirement in requirements:
        capability = _REQUIREMENT_MAP.get(requirement)
        if capability is None:
            unmet.append(_unmet_requirement(requirement))
            continue
        if len(requests) >= effective_policy.max_requests:
            unmet.append("request_budget_exhausted")
            continue
        collector_kind, source_family, purpose, selector = capability
        request_id = uuid5(
            NAMESPACE_URL,
            f"causalforge:evidence-request:{hypothesis.hypothesis_id}:{requirement}",
        )
        requests.append(
            EvidenceRequest(
                request_id=request_id,
                collector_kind=collector_kind,
                source_family=source_family,
                purpose=purpose,  # type: ignore[arg-type]
                selector=selector,
                max_items=min(
                    effective_policy.max_items_per_request,
                    effective_policy.max_total_items,
                ),
            )
        )

    if not requirements:
        unmet.append("no_evidence_requirements")
    if not requests and "no_evidence_requirements" not in unmet:
        unmet.append("no_supported_collectors")

    plan_id = uuid5(
        NAMESPACE_URL,
        f"causalforge:evidence-plan:{hypothesis.hypothesis_id}:"
        f"{','.join(str(request.request_id) for request in requests)}",
    )
    return EvidencePlan(
        schema_version="1.0",
        plan_id=plan_id,
        case_id=hypothesis.case_id,
        tenant_id=hypothesis.tenant_id,
        hypothesis_id=hypothesis.hypothesis_id,
        status="planned" if not unmet else "insufficient_evidence",
        requests=tuple(requests),
        unmet_requirements=tuple(dict.fromkeys(unmet)),
        max_total_items=effective_policy.max_total_items,
        deadline=created_at + timedelta(seconds=effective_policy.deadline_seconds),
        created_at=created_at,
    )
