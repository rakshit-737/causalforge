"""Tenant-scoped incident, evidence, claim, timeline, and graph endpoints."""

from typing import Annotated, Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from causalforge.api.auth import Principal, get_principal
from causalforge.api.deps import get_case_engine, get_database
from causalforge.api.routes_events import _run
from causalforge.api.schemas import (
    ClaimResponse,
    EvidenceResponse,
    GraphResponse,
    HypothesisCreateRequest,
    HypothesisResponse,
    IncidentResponse,
    InvestigationRequest,
    InvestigationResponse,
    VerificationRequest,
    VerificationResponse,
)
from causalforge.domain.events import CanonicalEvent
from causalforge.domain.hypotheses import Hypothesis
from causalforge.graph.projector import TemporalAttackGraph
from causalforge.security.engine import DeterministicCaseEngine
from causalforge.storage.db import Database
from causalforge.storage.models import (
    ClaimRecord,
    EvidenceRecord,
    HypothesisRecord,
    IncidentRecord,
    VerificationRecord,
)
from causalforge.storage.repositories.evidence import EvidenceRepository
from causalforge.workflow.verifier import VerificationPolicy, verify_hypothesis

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])


class IncidentCreateRequest(BaseModel):
    """Create an empty incident identity before a replay is submitted."""

    model_config = ConfigDict(extra="forbid")

    incident_id: UUID | None = None
    title: str = Field(min_length=1, max_length=255)
    severity: str = Field(default="medium", min_length=1, max_length=20)


def _incident_response(record: IncidentRecord) -> IncidentResponse:
    return IncidentResponse(
        incident_id=UUID(record.id),
        tenant_id=UUID(record.tenant_id),
        status=record.status,
        severity=record.severity,
        title=record.title,
        created_at=record.created_at,
        updated_at=record.updated_at,
        version=record.version,
    )


def _get_incident(session: Session, *, tenant_id: UUID, incident_id: UUID) -> IncidentRecord | None:
    return session.scalar(
        select(IncidentRecord).where(
            IncidentRecord.id == str(incident_id),
            IncidentRecord.tenant_id == str(tenant_id),
        )
    )


def _claim_response(record: ClaimRecord) -> ClaimResponse:
    return ClaimResponse(
        claim_id=UUID(record.id),
        case_id=UUID(record.incident_id),
        tenant_id=UUID(record.tenant_id),
        subject=record.subject,
        predicate=record.predicate,
        object=record.object_value,
        status=record.status,
        supporting_evidence_ids=[UUID(value) for value in record.supporting_evidence_ids],
        contradictory_evidence_ids=[UUID(value) for value in record.contradictory_evidence_ids],
        confidence_components=record.confidence_components,
        coverage_sufficient=record.coverage_sufficient,
    )


def _evidence_response(record: EvidenceRecord) -> EvidenceResponse:
    EvidenceRepository.verify_integrity(record)
    return EvidenceResponse(
        evidence_id=UUID(record.id),
        case_id=UUID(record.case_id),
        tenant_id=UUID(record.tenant_id),
        source_kind=record.source_kind,
        source_name=record.source_name,
        observed_at=record.observed_at,
        collected_at=record.collected_at,
        content_hash=record.content_hash,
        redaction_profile=record.redaction_profile,
        normalized=record.normalized,
        source_reliability=record.source_reliability,
        source_family=record.source_family,
    )


def _hypothesis_response(record: HypothesisRecord) -> HypothesisResponse:
    hypothesis = record.to_hypothesis()
    return HypothesisResponse(
        hypothesis_id=hypothesis.hypothesis_id,
        case_id=hypothesis.case_id,
        tenant_id=hypothesis.tenant_id,
        statement=hypothesis.statement,
        supporting_observation_ids=list(hypothesis.supporting_observation_ids),
        required_evidence=list(hypothesis.required_evidence),
        disconfirming_evidence=list(hypothesis.disconfirming_evidence),
        attack_technique_ids=list(hypothesis.attack_technique_ids),
        initial_confidence=hypothesis.initial_confidence,
        risk_if_true=hypothesis.risk_if_true,
        status=hypothesis.status,
        created_at=record.created_at,
        updated_at=record.updated_at,
        version=record.version,
    )


def _verification_response(record: VerificationRecord) -> VerificationResponse:
    return VerificationResponse(
        verification_id=UUID(record.id),
        hypothesis_id=UUID(record.hypothesis_id),
        status=record.status,
        supporting_evidence_ids=[UUID(value) for value in record.supporting_evidence_ids],
        source_families=list(record.source_families),
        coverage_sufficient=record.coverage_sufficient,
        temporal_consistency=record.temporal_consistency,
        unmet_requirements=list(record.unmet_requirements),
        reason=record.reason,
        checked_at=record.checked_at,
        consumed_evidence_items=record.consumed_evidence_items,
        budget_exhausted=record.budget_exhausted,
    )


def _get_hypothesis(
    session: Session, *, tenant_id: UUID, incident_id: UUID, hypothesis_id: UUID
) -> HypothesisRecord | None:
    return session.scalar(
        select(HypothesisRecord).where(
            HypothesisRecord.id == str(hypothesis_id),
            HypothesisRecord.tenant_id == str(tenant_id),
            HypothesisRecord.incident_id == str(incident_id),
        )
    )


@router.post("", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
def create_incident(
    request: IncidentCreateRequest,
    principal: Annotated[Principal, Depends(get_principal)],
    database: Annotated[Database, Depends(get_database)],
    engine: Annotated[DeterministicCaseEngine, Depends(get_case_engine)],
) -> IncidentResponse:
    """Create a tenant-scoped incident without collecting target evidence."""

    from uuid import uuid4

    incident_id = request.incident_id or uuid4()
    with database.session() as session:
        existing = session.get(IncidentRecord, str(incident_id))
        if existing is not None and existing.tenant_id != str(principal.tenant_id):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="incident not found")
        if existing is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="incident already exists",
            )
        incident = engine._get_or_create_incident(
            session,
            tenant_id=principal.tenant_id,
            case_id=incident_id,
            title=request.title,
            actor=principal.audit_actor,
        )
        incident.severity = request.severity
        session.commit()
        return _incident_response(incident)


@router.get("", response_model=list[IncidentResponse])
def list_incidents(
    principal: Annotated[Principal, Depends(get_principal)],
    database: Annotated[Database, Depends(get_database)],
) -> list[IncidentResponse]:
    """List only incidents owned by the requested tenant."""

    with database.session() as session:
        rows = list(
            session.scalars(
                select(IncidentRecord)
                .where(IncidentRecord.tenant_id == str(principal.tenant_id))
                .order_by(IncidentRecord.created_at.desc())
            )
        )
    return [_incident_response(row) for row in rows]


@router.post(
    "/{incident_id}/investigations",
    response_model=InvestigationResponse,
    status_code=status.HTTP_201_CREATED,
)
def investigate_incident(
    incident_id: UUID,
    request: InvestigationRequest,
    principal: Annotated[Principal, Depends(get_principal)],
    database: Annotated[Database, Depends(get_database)],
    engine: Annotated[DeterministicCaseEngine, Depends(get_case_engine)],
) -> InvestigationResponse:
    if request.case_id != incident_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="case_id must match incident_id",
        )
    with database.session() as session:
        if _get_incident(
            session, tenant_id=principal.tenant_id, incident_id=incident_id
        ) is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="incident not found")
    return _run(
        request,
        tenant_id=principal.tenant_id,
        database=database,
        engine=engine,
        actor=principal.audit_actor,
    )


@router.get("/{incident_id}/claims", response_model=list[ClaimResponse])
def list_claims(
    incident_id: UUID,
    principal: Annotated[Principal, Depends(get_principal)],
    database: Annotated[Database, Depends(get_database)],
) -> list[ClaimResponse]:
    with database.session() as session:
        if _get_incident(
            session, tenant_id=principal.tenant_id, incident_id=incident_id
        ) is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="incident not found")
        rows = list(
            session.scalars(
                select(ClaimRecord)
                .where(
                    ClaimRecord.tenant_id == str(principal.tenant_id),
                    ClaimRecord.incident_id == str(incident_id),
                )
                .order_by(ClaimRecord.created_at.asc())
            )
        )
    return [_claim_response(row) for row in rows]


@router.get("/{incident_id}/evidence", response_model=list[EvidenceResponse])
def list_evidence(
    incident_id: UUID,
    principal: Annotated[Principal, Depends(get_principal)],
    database: Annotated[Database, Depends(get_database)],
) -> list[EvidenceResponse]:
    with database.session() as session:
        if _get_incident(
            session, tenant_id=principal.tenant_id, incident_id=incident_id
        ) is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="incident not found")
        rows = list(
            session.scalars(
                select(EvidenceRecord)
                .where(
                    EvidenceRecord.tenant_id == str(principal.tenant_id),
                    EvidenceRecord.case_id == str(incident_id),
                )
                .order_by(EvidenceRecord.observed_at.asc())
            )
        )
    return [_evidence_response(row) for row in rows]


@router.post(
    "/{incident_id}/hypotheses",
    response_model=HypothesisResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_hypothesis(
    incident_id: UUID,
    request: HypothesisCreateRequest,
    principal: Annotated[Principal, Depends(get_principal)],
    database: Annotated[Database, Depends(get_database)],
    engine: Annotated[DeterministicCaseEngine, Depends(get_case_engine)],
) -> HypothesisResponse:
    """Persist a proposed explanation; verification is a separate bounded operation."""

    hypothesis_id = request.hypothesis_id or uuid4()
    with database.session() as session:
        if _get_incident(
            session, tenant_id=principal.tenant_id, incident_id=incident_id
        ) is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="incident not found")
        if session.get(HypothesisRecord, str(hypothesis_id)) is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="hypothesis already exists",
            )
        hypothesis = Hypothesis(
            schema_version="1.0",
            hypothesis_id=hypothesis_id,
            case_id=incident_id,
            tenant_id=principal.tenant_id,
            statement=request.statement,
            supporting_observation_ids=tuple(request.supporting_observation_ids),
            required_evidence=tuple(request.required_evidence),
            disconfirming_evidence=tuple(request.disconfirming_evidence),
            attack_technique_ids=tuple(request.attack_technique_ids),
            initial_confidence=request.initial_confidence,
            risk_if_true=request.risk_if_true,
            status="proposed",
        )
        record = HypothesisRecord.from_hypothesis(hypothesis)
        session.add(record)
        session.flush()
        engine.audit.append(
            session,
            tenant_id=principal.tenant_id,
            case_id=incident_id,
            actor=principal.audit_actor,
            event_type="hypothesis.created",
            payload={
                "hypothesis_id": record.id,
                "status": record.status,
                "supporting_observation_count": len(record.supporting_observation_ids),
            },
            policy_decision="allow",
        )
        session.commit()
        return _hypothesis_response(record)


@router.get("/{incident_id}/hypotheses", response_model=list[HypothesisResponse])
def list_hypotheses(
    incident_id: UUID,
    principal: Annotated[Principal, Depends(get_principal)],
    database: Annotated[Database, Depends(get_database)],
) -> list[HypothesisResponse]:
    with database.session() as session:
        if _get_incident(
            session, tenant_id=principal.tenant_id, incident_id=incident_id
        ) is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="incident not found")
        rows = list(
            session.scalars(
                select(HypothesisRecord)
                .where(
                    HypothesisRecord.tenant_id == str(principal.tenant_id),
                    HypothesisRecord.incident_id == str(incident_id),
                )
                .order_by(HypothesisRecord.created_at.asc())
            )
        )
    return [_hypothesis_response(row) for row in rows]


@router.post(
    "/{incident_id}/hypotheses/{hypothesis_id}/verify",
    response_model=VerificationResponse,
    status_code=status.HTTP_201_CREATED,
)
def verify_incident_hypothesis(
    incident_id: UUID,
    hypothesis_id: UUID,
    request: VerificationRequest,
    principal: Annotated[Principal, Depends(get_principal)],
    database: Annotated[Database, Depends(get_database)],
    engine: Annotated[DeterministicCaseEngine, Depends(get_case_engine)],
) -> VerificationResponse:
    """Verify one hypothesis against all integrity-checked evidence already in the case."""

    policy = VerificationPolicy.model_validate(request.model_dump())
    with database.session() as session:
        if _get_incident(
            session, tenant_id=principal.tenant_id, incident_id=incident_id
        ) is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="incident not found")
        hypothesis_record = _get_hypothesis(
            session,
            tenant_id=principal.tenant_id,
            incident_id=incident_id,
            hypothesis_id=hypothesis_id,
        )
        if hypothesis_record is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="hypothesis not found"
            )
        evidence_rows = list(
            session.scalars(
                select(EvidenceRecord)
                .where(
                    EvidenceRecord.tenant_id == str(principal.tenant_id),
                    EvidenceRecord.case_id == str(incident_id),
                )
                .order_by(EvidenceRecord.observed_at.asc(), EvidenceRecord.id.asc())
            )
        )
        try:
            decision = verify_hypothesis(
                hypothesis_record.to_hypothesis(),
                tuple(EvidenceRepository.to_domain(row) for row in evidence_rows),
                policy=policy,
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="evidence verification failed integrity checks",
            ) from exc

        verification = VerificationRecord.from_decision(
            decision,
            tenant_id=principal.tenant_id,
            case_id=incident_id,
            policy=policy,
        )
        session.add(verification)
        hypothesis_record.status = decision.status
        hypothesis_record.updated_at = decision.checked_at
        hypothesis_record.version += 1
        session.flush()
        engine.audit.append(
            session,
            tenant_id=principal.tenant_id,
            case_id=incident_id,
            actor=principal.audit_actor,
            event_type="hypothesis.verified",
            payload={
                "hypothesis_id": str(hypothesis_id),
                "verification_id": verification.id,
                "status": decision.status,
                "supporting_evidence_ids": [
                    str(value) for value in decision.supporting_evidence_ids
                ],
                "unmet_requirements": list(decision.unmet_requirements),
            },
            policy_decision="allow",
            created_at=decision.checked_at,
        )
        session.commit()
        return _verification_response(verification)


@router.get(
    "/{incident_id}/hypotheses/{hypothesis_id}/verifications",
    response_model=list[VerificationResponse],
)
def list_hypothesis_verifications(
    incident_id: UUID,
    hypothesis_id: UUID,
    principal: Annotated[Principal, Depends(get_principal)],
    database: Annotated[Database, Depends(get_database)],
) -> list[VerificationResponse]:
    with database.session() as session:
        if _get_hypothesis(
            session,
            tenant_id=principal.tenant_id,
            incident_id=incident_id,
            hypothesis_id=hypothesis_id,
        ) is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="hypothesis not found"
            )
        rows = list(
            session.scalars(
                select(VerificationRecord)
                .where(
                    VerificationRecord.tenant_id == str(principal.tenant_id),
                    VerificationRecord.incident_id == str(incident_id),
                    VerificationRecord.hypothesis_id == str(hypothesis_id),
                )
                .order_by(VerificationRecord.checked_at.desc())
            )
        )
    return [_verification_response(row) for row in rows]


@router.get("/{incident_id}/timeline", response_model=list[EvidenceResponse])
def timeline(
    incident_id: UUID,
    principal: Annotated[Principal, Depends(get_principal)],
    database: Annotated[Database, Depends(get_database)],
) -> list[EvidenceResponse]:
    return list_evidence(incident_id, principal, database)


@router.get("/{incident_id}/graph", response_model=GraphResponse)
def graph(
    incident_id: UUID,
    principal: Annotated[Principal, Depends(get_principal)],
    database: Annotated[Database, Depends(get_database)],
) -> GraphResponse:
    with database.session() as session:
        if _get_incident(
            session, tenant_id=principal.tenant_id, incident_id=incident_id
        ) is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="incident not found")
        evidence = list(
            session.scalars(
                select(EvidenceRecord).where(
                    EvidenceRecord.tenant_id == str(principal.tenant_id),
                    EvidenceRecord.case_id == str(incident_id),
                )
            )
        )
    projected = TemporalAttackGraph()
    for record in evidence:
        EvidenceRepository.verify_integrity(record)
        event = CanonicalEvent.model_validate(record.normalized)
        projected.project_event(event, evidence_id=record.id)
    return GraphResponse.model_validate(projected.as_dict())


@router.get("/{incident_id}/response-plans", response_model=list[dict[str, Any]])
def response_plans(
    incident_id: UUID,
    principal: Annotated[Principal, Depends(get_principal)],
    database: Annotated[Database, Depends(get_database)],
) -> list[dict[str, Any]]:
    with database.session() as session:
        if _get_incident(
            session, tenant_id=principal.tenant_id, incident_id=incident_id
        ) is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="incident not found")
    return []


@router.get("/{incident_id}", response_model=IncidentResponse)
def get_incident(
    incident_id: UUID,
    principal: Annotated[Principal, Depends(get_principal)],
    database: Annotated[Database, Depends(get_database)],
) -> IncidentResponse:
    """Return one incident after all static subroutes have had a chance to match."""

    with database.session() as session:
        record = _get_incident(
            session, tenant_id=principal.tenant_id, incident_id=incident_id
        )
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="incident not found")
    return _incident_response(record)
