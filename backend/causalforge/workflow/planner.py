"""Deterministic, typed evidence planning with no collection side effects.

The planner converts a small allowlisted vocabulary of evidence requirements into read-only
collection requests. It never accepts a shell command, URL, connector name, or arbitrary query.
Unknown requirements remain explicit ``insufficient_evidence`` items instead of being guessed.
"""

from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from causalforge.domain.hypotheses import Hypothesis
from causalforge.domain.serialization import sha256_hex

CollectorKind = Literal[
    "fixture_event_replay",
    "kubernetes_audit_snapshot",
    "rbac_snapshot",
    "runtime_sensor_snapshot",
]
PlanStatus = Literal["planned", "insufficient_evidence"]
EvidencePurpose = Literal["audit_event", "rbac_snapshot", "runtime_observation", "fixture_replay"]
EvidenceIntent = Literal["support", "disconfirm", "both"]


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
    purpose: EvidencePurpose
    intent: EvidenceIntent = "support"
    selector: EvidenceSelector
    max_items: int = Field(ge=1, le=1000, strict=True)

    @model_validator(mode="after")
    def validate_capability(self) -> "EvidenceRequest":
        capability = next(
            entry for entry in _REQUIREMENT_MAP.values() if entry[0] == self.collector_kind
        )
        if (self.source_family, self.purpose, self.selector.source_kind) != (
            capability[1], capability[2], capability[3].source_kind,
        ):
            raise ValueError("evidence request does not match its registered capability")
        return self


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

    @model_validator(mode="after")
    def validate_plan(self) -> "EvidencePlan":
        lifetime = (self.deadline - self.created_at).total_seconds()
        if not 0 < lifetime <= 900:
            raise ValueError("plan lifetime must be positive and at most 900 seconds")
        if sum(request.max_items for request in self.requests) > self.max_total_items:
            raise ValueError("request allocations exceed the total evidence budget")
        if len({request.collector_kind for request in self.requests}) != len(self.requests):
            raise ValueError("a plan cannot repeat a collector capability")
        if self.status == "planned" and (not self.requests or self.unmet_requirements):
            raise ValueError("a planned result requires requests and no unmet requirements")
        if self.status == "insufficient_evidence" and not self.unmet_requirements:
            raise ValueError("an incomplete plan requires an explanation")
        scope = _scope(self.tenant_id, self.case_id, self.hypothesis_id)
        for request in self.requests:
            content = request.model_dump(mode="json", exclude={"request_id"})
            if request.request_id != _identity("evidence-request", {**scope, **content}):
                raise ValueError("request identity does not match its scope and contents")
        if self.plan_id != _identity("evidence-plan", self.model_dump(
            mode="json", exclude={"plan_id"}
        )):
            raise ValueError("plan identity does not match its contents")
        return self


_REQUIREMENT_MAP: dict[str, tuple[CollectorKind, str, EvidencePurpose, EvidenceSelector]] = {
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
        EvidenceSelector(),
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


def _identity(kind: str, content: dict[str, object]) -> UUID:
    return uuid5(NAMESPACE_URL, f"causalforge:{kind}:{sha256_hex(content)}")


def _scope(tenant_id: UUID, case_id: UUID, hypothesis_id: UUID) -> dict[str, object]:
    return {
        "tenant_id": str(tenant_id), "case_id": str(case_id), "hypothesis_id": str(hypothesis_id),
    }


def plan_evidence(
    hypothesis: Hypothesis,
    *,
    policy: PlannerPolicy | None = None,
    now: datetime | None = None,
) -> EvidencePlan:
    """Create a bounded plan without executing a collector or inventing a query."""

    effective_policy = PlannerPolicy.model_validate((policy or PlannerPolicy()).model_dump())
    hypothesis = Hypothesis.model_validate(hypothesis.model_dump())
    created_at = _checked_now(now)
    requirements = (*hypothesis.required_evidence, *hypothesis.disconfirming_evidence)
    if len(requirements) > 64 or any(len(item) > 500 for item in requirements):
        raise ValueError("evidence requirements exceed planning limits")
    requests: list[EvidenceRequest] = []
    unmet: list[str] = []
    selected: dict[
        CollectorKind,
        tuple[str, EvidencePurpose, EvidenceSelector, EvidenceIntent],
    ] = {}
    for requirement_set, intent in (
        (hypothesis.required_evidence, "support"),
        (hypothesis.disconfirming_evidence, "disconfirm"),
    ):
        for requirement in requirement_set:
            entry = _REQUIREMENT_MAP.get(requirement.strip().casefold())
            if entry is None:
                unmet.append(_unmet_requirement(requirement))
                continue
            kind, family, purpose, selector = entry
            resolved_intent: EvidenceIntent = "support" if intent == "support" else "disconfirm"
            if kind in selected and selected[kind][3] != resolved_intent:
                resolved_intent = "both"
            selected[kind] = family, purpose, selector, resolved_intent

    scope = _scope(hypothesis.tenant_id, hypothesis.case_id, hypothesis.hypothesis_id)
    remaining = effective_policy.max_total_items
    for index, (collector_kind, selected_capability) in enumerate(sorted(selected.items())):
        if len(requests) >= effective_policy.max_requests:
            unmet.append("request_budget_exhausted")
            continue
        if remaining == 0:
            unmet.append("item_budget_exhausted")
            continue
        source_family, purpose, selector, resolved_intent = selected_capability
        pending = min(len(selected) - index, effective_policy.max_requests - len(requests))
        allocated = min(effective_policy.max_items_per_request, max(1, remaining // pending))
        content: dict[str, object] = {
            "collector_kind": collector_kind,
            "source_family": source_family,
            "purpose": purpose,
            "intent": resolved_intent,
            "selector": selector.model_dump(mode="json"),
            "max_items": allocated,
        }
        requests.append(
            EvidenceRequest.model_validate({
                **content, "request_id": _identity("evidence-request", {**scope, **content}),
            })
        )
        remaining -= allocated

    if not requirements:
        unmet.append("no_evidence_requirements")
    if not requests and "no_evidence_requirements" not in unmet:
        unmet.append("no_supported_collectors")

    plan_content: dict[str, object] = {
        **scope,
        "schema_version": "1.0",
        "status": "planned" if not unmet else "insufficient_evidence",
        "requests": [request.model_dump(mode="json") for request in requests],
        "unmet_requirements": sorted(set(unmet)),
        "max_total_items": effective_policy.max_total_items,
        "deadline": (created_at + timedelta(seconds=effective_policy.deadline_seconds)).isoformat(),
        "created_at": created_at.isoformat(),
    }
    # Normalize datetime JSON once before computing the exact serialized artifact identity.
    plan_content["deadline"] = str(plan_content["deadline"]).replace("+00:00", "Z")
    plan_content["created_at"] = created_at.isoformat().replace("+00:00", "Z")
    return EvidencePlan.model_validate(
        {**plan_content, "plan_id": _identity("evidence-plan", plan_content)}
    )
