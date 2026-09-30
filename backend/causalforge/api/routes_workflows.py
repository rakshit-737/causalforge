"""Tenant-scoped durable, fixture-only investigation workflow endpoints."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from causalforge.api.auth import Principal, get_principal
from causalforge.api.deps import get_case_engine, get_database
from causalforge.api.schemas import (
    FixtureWorkflowRequest,
    WorkflowRunResponse,
)
from causalforge.security.engine import DeterministicCaseEngine
from causalforge.storage.db import Database
from causalforge.storage.models import (
    HypothesisRecord,
    IncidentRecord,
    WorkflowRunRecord,
)
from causalforge.workflow.service import (
    DurableFixtureWorkflow,
    DurableWorkflowResult,
    WorkflowIdempotencyConflict,
    WorkflowStateError,
)

router = APIRouter(prefix="/api/v1/incidents", tags=["workflow"])


def _scoped_hypothesis(
    session: Session,
    *,
    tenant_id: UUID,
    incident_id: UUID,
    hypothesis_id: UUID,
) -> HypothesisRecord | None:
    return session.scalar(
        select(HypothesisRecord).where(
            HypothesisRecord.id == str(hypothesis_id),
            HypothesisRecord.tenant_id == str(tenant_id),
            HypothesisRecord.incident_id == str(incident_id),
        )
    )


def _workflow_response(snapshot: DurableWorkflowResult) -> WorkflowRunResponse:
    try:
        from causalforge.workflow.planner import EvidencePlan

        plan = EvidencePlan.model_validate(snapshot.run.plan)
        return WorkflowRunResponse(
            run_id=UUID(snapshot.run.id),
            tenant_id=UUID(snapshot.run.tenant_id),
            case_id=UUID(snapshot.run.case_id),
            hypothesis_id=UUID(snapshot.run.hypothesis_id),
            idempotency_key=snapshot.run.idempotency_key,
            status=snapshot.run.status,
            plan=plan,
            receipts=list(snapshot.receipts),
            event_ids=list(snapshot.event_ids),
            evidence_ids=list(snapshot.evidence_ids),
            unmet_requirements=list(snapshot.run.unmet_requirements),
            started_at=snapshot.run.started_at,
            completed_at=snapshot.run.completed_at,
            result_hash=snapshot.run.result_hash,
            replayed=snapshot.replayed,
        )
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="workflow state failed integrity checks",
        ) from exc


@router.post(
    "/{incident_id}/hypotheses/{hypothesis_id}/workflow-runs",
    response_model=WorkflowRunResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_workflow_run(
    incident_id: UUID,
    hypothesis_id: UUID,
    request: FixtureWorkflowRequest,
    response: Response,
    principal: Annotated[Principal, Depends(get_principal)],
    database: Annotated[Database, Depends(get_database)],
    engine: Annotated[DeterministicCaseEngine, Depends(get_case_engine)],
) -> WorkflowRunResponse:
    """Plan and collect only from caller-supplied local fixtures."""

    with database.session() as session:
        incident = session.scalar(
            select(IncidentRecord).where(
                IncidentRecord.id == str(incident_id),
                IncidentRecord.tenant_id == str(principal.tenant_id),
            )
        )
        hypothesis_record = _scoped_hypothesis(
            session,
            tenant_id=principal.tenant_id,
            incident_id=incident_id,
            hypothesis_id=hypothesis_id,
        )
        if incident is None or hypothesis_record is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="workflow target not found",
            )
        try:
            snapshot = DurableFixtureWorkflow(
                ingestion=engine.ingestion,
                audit=engine.audit,
            ).execute(
                session,
                hypothesis=hypothesis_record.to_hypothesis(),
                payloads=request.events,
                parser_version=request.parser_version,
                idempotency_key=request.idempotency_key,
                actor=principal.audit_actor,
            )
        except WorkflowIdempotencyConflict as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="idempotency key conflict",
            ) from exc
        except (TypeError, ValueError, WorkflowStateError) as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="workflow request could not be accepted",
            ) from exc
        session.commit()
        response.status_code = status.HTTP_200_OK if snapshot.replayed else status.HTTP_201_CREATED
        return _workflow_response(snapshot)


@router.get(
    "/{incident_id}/hypotheses/{hypothesis_id}/workflow-runs",
    response_model=list[WorkflowRunResponse],
)
def list_workflow_runs(
    incident_id: UUID,
    hypothesis_id: UUID,
    principal: Annotated[Principal, Depends(get_principal)],
    database: Annotated[Database, Depends(get_database)],
    engine: Annotated[DeterministicCaseEngine, Depends(get_case_engine)],
) -> list[WorkflowRunResponse]:
    """List durable workflow runs without crossing tenant, case, or hypothesis scope."""

    service = DurableFixtureWorkflow(ingestion=engine.ingestion, audit=engine.audit)
    with database.session() as session:
        incident = session.scalar(
            select(IncidentRecord).where(
                IncidentRecord.id == str(incident_id),
                IncidentRecord.tenant_id == str(principal.tenant_id),
            )
        )
        if incident is None or _scoped_hypothesis(
            session,
            tenant_id=principal.tenant_id,
            incident_id=incident_id,
            hypothesis_id=hypothesis_id,
        ) is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="workflow target not found",
            )
        runs = list(
            session.scalars(
                select(WorkflowRunRecord)
                .where(
                    WorkflowRunRecord.tenant_id == str(principal.tenant_id),
                    WorkflowRunRecord.case_id == str(incident_id),
                    WorkflowRunRecord.hypothesis_id == str(hypothesis_id),
                )
                .order_by(WorkflowRunRecord.created_at.desc())
            )
        )
        try:
            snapshots = [
                service.load(
                    session,
                    tenant_id=principal.tenant_id,
                    case_id=incident_id,
                    hypothesis_id=hypothesis_id,
                    run_id=UUID(run.id),
                )
                for run in runs
            ]
        except WorkflowStateError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="workflow state failed integrity checks",
            ) from exc
    return [_workflow_response(snapshot) for snapshot in snapshots if snapshot is not None]


@router.get(
    "/{incident_id}/hypotheses/{hypothesis_id}/workflow-runs/{run_id}",
    response_model=WorkflowRunResponse,
)
def get_workflow_run(
    incident_id: UUID,
    hypothesis_id: UUID,
    run_id: UUID,
    principal: Annotated[Principal, Depends(get_principal)],
    database: Annotated[Database, Depends(get_database)],
    engine: Annotated[DeterministicCaseEngine, Depends(get_case_engine)],
) -> WorkflowRunResponse:
    """Read one workflow run only inside the authenticated tenant and case scope."""

    with database.session() as session:
        try:
            snapshot = DurableFixtureWorkflow(
                ingestion=engine.ingestion,
                audit=engine.audit,
            ).load(
                session,
                tenant_id=principal.tenant_id,
                case_id=incident_id,
                hypothesis_id=hypothesis_id,
                run_id=run_id,
            )
        except WorkflowStateError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="workflow state failed integrity checks",
            ) from exc
    if snapshot is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="workflow run not found")
    return _workflow_response(snapshot)
