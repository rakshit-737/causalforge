"""Deterministic incident state-transition contract.

This module has no persistence or target access. It only validates the preconditions that a
future coordinator must satisfy before recording a transition.
"""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final, Literal


class IncidentState(StrEnum):
    """Persisted incident lifecycle states."""

    NEW = "NEW"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    EVIDENCE_COLLECTED = "EVIDENCE_COLLECTED"
    VERIFIED = "VERIFIED"
    RESPONSE_PLANNED = "RESPONSE_PLANNED"
    SIMULATED = "SIMULATED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    EXECUTING = "EXECUTING"
    VALIDATING = "VALIDATING"
    CLOSED = "CLOSED"
    REJECTED = "REJECTED"
    DISPUTED = "DISPUTED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    ROLLED_BACK = "ROLLED_BACK"
    FAILED_RECONCILIATION = "FAILED_RECONCILIATION"


PolicyDecision = Literal["allow", "deny", "needs_review"]


class InvalidTransitionError(ValueError):
    """Raised when a lifecycle transition or one of its gates is invalid."""


@dataclass(frozen=True)
class TransitionContext:
    """Evidence and gate results required to record one state transition."""

    artifacts: frozenset[str] = field(default_factory=frozenset)
    policy_decision: PolicyDecision = "allow"
    audit_persisted: bool = False


_ALLOWED_TRANSITIONS: Final[dict[IncidentState, frozenset[IncidentState]]] = {
    IncidentState.NEW: frozenset({IncidentState.TRIAGED, IncidentState.REJECTED}),
    IncidentState.TRIAGED: frozenset({IncidentState.INVESTIGATING, IncidentState.REJECTED}),
    IncidentState.INVESTIGATING: frozenset(
        {
            IncidentState.EVIDENCE_COLLECTED,
            IncidentState.DISPUTED,
            IncidentState.INSUFFICIENT_EVIDENCE,
        }
    ),
    IncidentState.EVIDENCE_COLLECTED: frozenset(
        {
            IncidentState.VERIFIED,
            IncidentState.DISPUTED,
            IncidentState.INSUFFICIENT_EVIDENCE,
        }
    ),
    IncidentState.VERIFIED: frozenset({IncidentState.RESPONSE_PLANNED, IncidentState.DISPUTED}),
    IncidentState.RESPONSE_PLANNED: frozenset(
        {IncidentState.SIMULATED, IncidentState.REJECTED, IncidentState.DISPUTED}
    ),
    IncidentState.SIMULATED: frozenset(
        {IncidentState.AWAITING_APPROVAL, IncidentState.REJECTED, IncidentState.DISPUTED}
    ),
    IncidentState.AWAITING_APPROVAL: frozenset(
        {IncidentState.EXECUTING, IncidentState.REJECTED}
    ),
    IncidentState.EXECUTING: frozenset(
        {IncidentState.VALIDATING, IncidentState.FAILED_RECONCILIATION}
    ),
    IncidentState.VALIDATING: frozenset(
        {
            IncidentState.CLOSED,
            IncidentState.ROLLED_BACK,
            IncidentState.FAILED_RECONCILIATION,
        }
    ),
    IncidentState.ROLLED_BACK: frozenset({IncidentState.CLOSED}),
    IncidentState.DISPUTED: frozenset({IncidentState.INVESTIGATING, IncidentState.CLOSED}),
    IncidentState.INSUFFICIENT_EVIDENCE: frozenset(
        {IncidentState.INVESTIGATING, IncidentState.CLOSED}
    ),
    IncidentState.FAILED_RECONCILIATION: frozenset({IncidentState.CLOSED}),
    IncidentState.CLOSED: frozenset(),
    IncidentState.REJECTED: frozenset(),
}


_REQUIRED_ARTIFACTS: Final[dict[tuple[IncidentState, IncidentState], frozenset[str]]] = {
    (IncidentState.NEW, IncidentState.TRIAGED): frozenset({"triage_record"}),
    (IncidentState.TRIAGED, IncidentState.INVESTIGATING): frozenset({"investigation_request"}),
    (IncidentState.INVESTIGATING, IncidentState.EVIDENCE_COLLECTED): frozenset(
        {"evidence_bundle"}
    ),
    (IncidentState.INVESTIGATING, IncidentState.DISPUTED): frozenset({"dispute_record"}),
    (IncidentState.INVESTIGATING, IncidentState.INSUFFICIENT_EVIDENCE): frozenset(
        {"coverage_assessment"}
    ),
    (IncidentState.EVIDENCE_COLLECTED, IncidentState.VERIFIED): frozenset(
        {"verification_record"}
    ),
    (IncidentState.EVIDENCE_COLLECTED, IncidentState.DISPUTED): frozenset({"dispute_record"}),
    (IncidentState.EVIDENCE_COLLECTED, IncidentState.INSUFFICIENT_EVIDENCE): frozenset(
        {"coverage_assessment"}
    ),
    (IncidentState.VERIFIED, IncidentState.RESPONSE_PLANNED): frozenset({"response_plan"}),
    (IncidentState.VERIFIED, IncidentState.DISPUTED): frozenset({"dispute_record"}),
    (IncidentState.RESPONSE_PLANNED, IncidentState.SIMULATED): frozenset({"simulation_result"}),
    (IncidentState.RESPONSE_PLANNED, IncidentState.REJECTED): frozenset({"rejection_record"}),
    (IncidentState.RESPONSE_PLANNED, IncidentState.DISPUTED): frozenset({"dispute_record"}),
    (IncidentState.SIMULATED, IncidentState.AWAITING_APPROVAL): frozenset(
        {"approval_request"}
    ),
    (IncidentState.SIMULATED, IncidentState.REJECTED): frozenset({"rejection_record"}),
    (IncidentState.SIMULATED, IncidentState.DISPUTED): frozenset({"dispute_record"}),
    (IncidentState.AWAITING_APPROVAL, IncidentState.EXECUTING): frozenset(
        {"approval_token", "approval_record"}
    ),
    (IncidentState.AWAITING_APPROVAL, IncidentState.REJECTED): frozenset({"rejection_record"}),
    (IncidentState.EXECUTING, IncidentState.VALIDATING): frozenset({"execution_result"}),
    (IncidentState.EXECUTING, IncidentState.FAILED_RECONCILIATION): frozenset(
        {"reconciliation_failure"}
    ),
    (IncidentState.VALIDATING, IncidentState.CLOSED): frozenset({"postcondition_result"}),
    (IncidentState.VALIDATING, IncidentState.ROLLED_BACK): frozenset({"rollback_result"}),
    (IncidentState.VALIDATING, IncidentState.FAILED_RECONCILIATION): frozenset(
        {"reconciliation_failure"}
    ),
    (IncidentState.ROLLED_BACK, IncidentState.CLOSED): frozenset({"rollback_verified"}),
    (IncidentState.DISPUTED, IncidentState.INVESTIGATING): frozenset(
        {"investigation_request"}
    ),
    (IncidentState.DISPUTED, IncidentState.CLOSED): frozenset({"closure_record"}),
    (IncidentState.INSUFFICIENT_EVIDENCE, IncidentState.INVESTIGATING): frozenset(
        {"investigation_request"}
    ),
    (IncidentState.INSUFFICIENT_EVIDENCE, IncidentState.CLOSED): frozenset(
        {"closure_record"}
    ),
    (IncidentState.FAILED_RECONCILIATION, IncidentState.CLOSED): frozenset(
        {"closure_record"}
    ),
}


def _coerce_state(value: IncidentState | str) -> IncidentState:
    try:
        return value if isinstance(value, IncidentState) else IncidentState(value)
    except ValueError as exc:
        raise InvalidTransitionError(f"Unknown incident state: {value!r}") from exc


def allowed_targets(current: IncidentState | str) -> frozenset[IncidentState]:
    """Return the states reachable from ``current`` without changing anything."""

    return _ALLOWED_TRANSITIONS[_coerce_state(current)]


def required_artifacts(
    current: IncidentState | str, target: IncidentState | str
) -> frozenset[str]:
    """Return the artifact names required for a transition."""

    current_state = _coerce_state(current)
    target_state = _coerce_state(target)
    return _REQUIRED_ARTIFACTS.get((current_state, target_state), frozenset())


def validate_transition(
    current: IncidentState | str,
    target: IncidentState | str,
    context: TransitionContext,
) -> IncidentState:
    """Validate a transition and return the normalized target state.

    The function intentionally requires the caller to prove that the audit entry was persisted.
    A future coordinator should call this immediately before committing the transition and audit
    record in one transaction; this pure contract does not perform persistence itself.
    """

    current_state = _coerce_state(current)
    target_state = _coerce_state(target)

    if target_state not in _ALLOWED_TRANSITIONS[current_state]:
        raise InvalidTransitionError(
            f"Invalid transition: {current_state.value} -> {target_state.value}"
        )
    if context.policy_decision != "allow":
        raise InvalidTransitionError(
            f"Transition {current_state.value} -> {target_state.value} requires policy allow; "
            f"received {context.policy_decision!r}"
        )
    if not context.audit_persisted:
        raise InvalidTransitionError("A persisted audit entry is required for every transition")

    missing = required_artifacts(current_state, target_state) - context.artifacts
    if missing:
        names = ", ".join(sorted(missing))
        raise InvalidTransitionError(
            f"Transition {current_state.value} -> {target_state.value} is missing "
            f"artifacts: {names}"
        )
    return target_state
