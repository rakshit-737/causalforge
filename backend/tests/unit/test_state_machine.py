import pytest

from causalforge.domain.state_machine import (
    IncidentState,
    InvalidTransitionError,
    TransitionContext,
    allowed_targets,
    required_artifacts,
    validate_transition,
)


def context(
    *artifacts: str,
    policy_decision: str = "allow",
    audit_persisted: bool = True,
) -> TransitionContext:
    return TransitionContext(
        artifacts=frozenset(artifacts),
        policy_decision=policy_decision,  # type: ignore[arg-type]
        audit_persisted=audit_persisted,
    )


def test_valid_transition_requires_artifact_policy_and_audit() -> None:
    result = validate_transition(
        IncidentState.NEW,
        IncidentState.TRIAGED,
        context("triage_record"),
    )

    assert result is IncidentState.TRIAGED


def test_invalid_transition_is_rejected() -> None:
    with pytest.raises(InvalidTransitionError, match="Invalid transition"):
        validate_transition(
            IncidentState.NEW,
            IncidentState.VERIFIED,
            context("verification_record"),
        )


def test_missing_artifact_is_rejected() -> None:
    with pytest.raises(InvalidTransitionError, match="missing artifacts"):
        validate_transition(IncidentState.NEW, IncidentState.TRIAGED, context())


def test_policy_denial_is_rejected_before_transition() -> None:
    with pytest.raises(InvalidTransitionError, match="requires policy allow"):
        validate_transition(
            IncidentState.NEW,
            IncidentState.TRIAGED,
            context("triage_record", policy_decision="deny"),
        )


def test_missing_audit_persistence_is_rejected() -> None:
    with pytest.raises(InvalidTransitionError, match="persisted audit"):
        validate_transition(
            IncidentState.NEW,
            IncidentState.TRIAGED,
            context("triage_record", audit_persisted=False),
        )


def test_recovery_from_insufficient_evidence_requires_new_investigation_request() -> None:
    assert required_artifacts(
        IncidentState.INSUFFICIENT_EVIDENCE,
        IncidentState.INVESTIGATING,
    ) == frozenset({"investigation_request"})

    result = validate_transition(
        IncidentState.INSUFFICIENT_EVIDENCE,
        IncidentState.INVESTIGATING,
        context("investigation_request"),
    )

    assert result is IncidentState.INVESTIGATING


def test_closed_has_no_outgoing_targets() -> None:
    assert allowed_targets(IncidentState.CLOSED) == frozenset()
