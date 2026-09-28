"""Deterministic Kubernetes-style RBAC reachability.

RBAC is additive: a matching rule proves that an action is authorized, but the absence of a rule
is only a denial when the snapshot declares complete coverage. Incomplete snapshots return
``unknown`` instead of silently implying that access was impossible.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

ReachabilityStatus = Literal["allowed", "denied", "unknown"]


class RBACRule(BaseModel):
    """One normalized allow rule from a role and binding snapshot."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    subject_kind: str = Field(min_length=1)
    subject_id: str = Field(min_length=1)
    verbs: frozenset[str] = Field(min_length=1)
    resources: frozenset[str] = Field(min_length=1)
    namespaces: frozenset[str] = Field(default_factory=lambda: frozenset({"*"}))
    resource_names: frozenset[str] | None = None
    evidence_id: UUID
    valid_from: datetime
    valid_to: datetime | None = None

    @field_validator("valid_from", "valid_to")
    @classmethod
    def require_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("RBAC validity timestamps must be timezone-aware")
        return value

    def valid_at(self, at: datetime | None) -> bool:
        """Return whether this rule is active at the requested instant."""

        if at is None:
            return True
        if self.valid_from > at:
            return False
        return self.valid_to is None or at < self.valid_to


class RBACSnapshot(BaseModel):
    """A point-in-time RBAC view with an explicit completeness declaration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    observed_at: datetime
    source_complete: bool
    rules: tuple[RBACRule, ...] = ()

    @field_validator("observed_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("RBAC snapshot timestamps must be timezone-aware")
        return value


@dataclass(frozen=True)
class ReachabilityResult:
    """Explainable RBAC reachability outcome."""

    status: ReachabilityStatus
    matching_evidence_ids: tuple[UUID, ...]
    reason: str


def _matches(patterns: frozenset[str], value: str) -> bool:
    return "*" in patterns or value in patterns


def _rule_matches(
    rule: RBACRule,
    *,
    subject_kind: str,
    subject_id: str,
    verb: str,
    resource: str,
    namespace: str | None,
    resource_name: str | None,
    at: datetime | None,
) -> bool:
    if rule.subject_kind != subject_kind or rule.subject_id != subject_id:
        return False
    if not _matches(rule.verbs, verb) or not _matches(rule.resources, resource):
        return False
    if namespace is not None and not _matches(rule.namespaces, namespace):
        return False
    if namespace is None and "*" not in rule.namespaces:
        return False
    if rule.resource_names is not None and (
        resource_name is None or not _matches(rule.resource_names, resource_name)
    ):
        return False
    return rule.valid_at(at)


def check_reachability(
    snapshot: RBACSnapshot,
    *,
    subject_kind: str,
    subject_id: str,
    verb: str,
    resource: str,
    namespace: str | None = None,
    resource_name: str | None = None,
    at: datetime | None = None,
) -> ReachabilityResult:
    """Evaluate one action without treating incomplete snapshots as complete denials."""

    matching = tuple(
        rule.evidence_id
        for rule in snapshot.rules
        if _rule_matches(
            rule,
            subject_kind=subject_kind,
            subject_id=subject_id,
            verb=verb,
            resource=resource,
            namespace=namespace,
            resource_name=resource_name,
            at=at or snapshot.observed_at,
        )
    )
    if matching:
        return ReachabilityResult(
            status="allowed",
            matching_evidence_ids=matching,
            reason="a matching RBAC allow rule is present",
        )
    if not snapshot.source_complete:
        return ReachabilityResult(
            status="unknown",
            matching_evidence_ids=(),
            reason="RBAC snapshot coverage is incomplete",
        )
    return ReachabilityResult(
        status="denied",
        matching_evidence_ids=(),
        reason="complete RBAC snapshot contains no matching allow rule",
    )
