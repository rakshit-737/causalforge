"""Tenant-scoped event ingestion and inspection endpoints."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status

from causalforge.api.auth import Principal, get_principal
from causalforge.api.deps import get_case_engine, get_database
from causalforge.api.schemas import (
    DetectionResponse,
    EventBatchIngestRequest,
    EventIngestRequest,
    EventResponse,
    IncidentResponse,
    InvestigationResponse,
)
from causalforge.security.engine import DeterministicCaseEngine
from causalforge.storage.db import Database
from causalforge.storage.models.event import EventRecord
from causalforge.storage.repositories.events import EventRepository

router = APIRouter(prefix="/api/v1/events", tags=["events"])


def _response(record: EventRecord) -> EventResponse:
    return EventResponse(
        event_id=UUID(record.producer_event_id),
        tenant_id=UUID(record.tenant_id),
        observed_at=record.observed_at,
        ingested_at=record.ingested_at,
        source_kind=record.source_kind,
        source_name=record.source_name,
        actor_kind=record.actor_kind,
        actor_id=record.actor_id,
        action=record.action,
        object_kind=record.object_kind,
        object_namespace=record.object_namespace,
        object_name=record.object_name,
        outcome=record.outcome,
        attributes=record.attributes,
        raw_payload_sha256=record.raw_payload_sha256,
        parser_version=record.parser_version,
    )


def _run(
    request: EventBatchIngestRequest,
    *,
    tenant_id: UUID,
    database: Database,
    engine: DeterministicCaseEngine,
    actor: dict[str, str],
) -> InvestigationResponse:
    try:
        with database.session() as session:
            result = engine.process(
                session,
                tenant_id=tenant_id,
                case_id=request.case_id,
                payloads=request.events,
                parser_version=request.parser_version,
                title=request.title,
                actor=actor,
            )
            session.commit()
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="event batch failed canonical validation or tenant scope validation",
        ) from exc
    return InvestigationResponse(
        incident=IncidentResponse(
            incident_id=UUID(result.incident.id),
            tenant_id=UUID(result.incident.tenant_id),
            status=result.incident.status,
            severity=result.incident.severity,
            title=result.incident.title,
            created_at=result.incident.created_at,
            updated_at=result.incident.updated_at,
            version=result.incident.version,
        ),
        ingested_count=len(result.ingested),
        duplicate_count=sum(1 for item in result.ingested if item.duplicate),
        detection_count=len(result.detections),
        claim_count=len(result.claims),
        correlations_count=len(result.correlations),
        detections=[
            DetectionResponse(
                detection_id=UUID(record.id),
                rule_id=record.rule_id,
                event_id=UUID(record.event_id),
                title=record.title,
                level=record.level,
                tags=record.tags,
                explanation=record.explanation,
                detected_at=record.detected_at,
            )
            for record in result.detections
        ],
    )


@router.post("", response_model=InvestigationResponse, status_code=status.HTTP_201_CREATED)
def ingest_event(
    request: EventIngestRequest,
    principal: Annotated[Principal, Depends(get_principal)],
    database: Annotated[Database, Depends(get_database)],
    engine: Annotated[DeterministicCaseEngine, Depends(get_case_engine)],
) -> InvestigationResponse:
    """Ingest one event through the deterministic case engine."""

    return _run(
        EventBatchIngestRequest(
            case_id=request.case_id,
            parser_version=request.parser_version,
            events=[request.event],
            title=request.title,
        ),
        tenant_id=principal.tenant_id,
        database=database,
        engine=engine,
        actor=principal.audit_actor,
    )


@router.post("/batch", response_model=InvestigationResponse, status_code=status.HTTP_201_CREATED)
def ingest_batch(
    request: EventBatchIngestRequest,
    principal: Annotated[Principal, Depends(get_principal)],
    database: Annotated[Database, Depends(get_database)],
    engine: Annotated[DeterministicCaseEngine, Depends(get_case_engine)],
) -> InvestigationResponse:
    """Ingest a bounded deterministic replay batch."""

    return _run(
        request,
        tenant_id=principal.tenant_id,
        database=database,
        engine=engine,
        actor=principal.audit_actor,
    )


@router.get("/{event_id}", response_model=EventResponse)
def get_event(
    event_id: UUID,
    principal: Annotated[Principal, Depends(get_principal)],
    database: Annotated[Database, Depends(get_database)],
) -> EventResponse:
    """Return one redacted event only inside the requested tenant."""

    with database.session() as session:
        record = EventRepository().get_for_tenant(
            session,
            tenant_id=str(principal.tenant_id),
            event_id=str(event_id),
        )
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="event not found")
    return _response(record)
