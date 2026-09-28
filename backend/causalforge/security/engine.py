"""Rule-only deterministic case engine.

This engine is intentionally not an agent. It wires together normalized evidence, deterministic
Sigma matching, graph projection, and direct observation claims. No claim is promoted beyond
``observed`` and no target write is available here.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from causalforge.audit.ledger import AuditLedger
from causalforge.detection.correlation import CorrelationEngine, CorrelationMatch, CorrelationRule
from causalforge.detection.sigma_engine import SigmaEngine, SigmaRule
from causalforge.domain.claims import Claim
from causalforge.graph.projector import TemporalAttackGraph
from causalforge.graph.rbac import RBACSnapshot
from causalforge.ingestion.service import IngestionService, IngestResult
from causalforge.storage.models import ClaimRecord, DetectionRecord, IncidentRecord


@dataclass(frozen=True)
class EngineResult:
    """Deterministic case-processing result suitable for a fixture API or report stage."""

    incident: IncidentRecord
    ingested: tuple[IngestResult, ...]
    detections: tuple[DetectionRecord, ...]
    correlations: tuple[CorrelationMatch, ...]
    claims: tuple[ClaimRecord, ...]
    graph: TemporalAttackGraph


def _severity_rank(level: str) -> int:
    return {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(level, 2)


def _max_severity(current: str, candidate: str) -> str:
    return candidate if _severity_rank(candidate) > _severity_rank(current) else current


class DeterministicCaseEngine:
    """Process a bounded event batch for one tenant-scoped incident."""

    def __init__(
        self,
        *,
        rules: Iterable[SigmaRule],
        correlation_rules: Iterable[CorrelationRule] = (),
        ingestion: IngestionService | None = None,
        sigma: SigmaEngine | None = None,
        audit: AuditLedger | None = None,
    ) -> None:
        ledger = audit or AuditLedger()
        self.rules = tuple(rules)
        self.correlation_rules = tuple(correlation_rules)
        self.ingestion = ingestion or IngestionService(audit_ledger=ledger)
        self.sigma = sigma or SigmaEngine()
        self.correlation = CorrelationEngine()
        self.audit = ledger

    def _get_or_create_incident(
        self,
        session: Session,
        *,
        tenant_id: UUID,
        case_id: UUID,
        title: str,
    ) -> IncidentRecord:
        incident = session.scalar(select(IncidentRecord).where(IncidentRecord.id == str(case_id)))
        if incident is not None:
            if incident.tenant_id != str(tenant_id):
                raise ValueError("incident does not belong to the requested tenant")
            return incident
        incident = IncidentRecord(
            id=str(case_id),
            tenant_id=str(tenant_id),
            status="NEW",
            severity="medium",
            title=title,
        )
        session.add(incident)
        session.flush()
        self.audit.append(
            session,
            tenant_id=tenant_id,
            case_id=case_id,
            actor={"kind": "system", "id": "deterministic-engine", "role": "coordinator"},
            event_type="incident.created",
            payload={"title": title},
            policy_decision="allow",
        )
        return incident

    @staticmethod
    def _is_claim_candidate(result: IngestResult) -> bool:
        event = result.normalized.event
        return event.outcome == "allowed" and event.object.kind in {"secret", "configmap"}

    def process(
        self,
        session: Session,
        *,
        tenant_id: UUID,
        case_id: UUID,
        payloads: Iterable[Mapping[str, Any]],
        parser_version: str,
        title: str = "Deterministic security investigation",
        actor: Mapping[str, str] | None = None,
        rbac_snapshot: RBACSnapshot | None = None,
    ) -> EngineResult:
        """Process events idempotently and return evidence-backed deterministic outputs."""

        incident = self._get_or_create_incident(
            session,
            tenant_id=tenant_id,
            case_id=case_id,
            title=title,
        )
        graph = TemporalAttackGraph()
        if rbac_snapshot is not None:
            for rule in rbac_snapshot.rules:
                graph.project_rbac_rule(rule)
        ingested: list[IngestResult] = []
        events = []
        for payload in payloads:
            result = self.ingestion.ingest(
                session,
                payload=payload,
                case_id=case_id,
                expected_tenant_id=tenant_id,
                parser_version=parser_version,
                actor=actor,
            )
            ingested.append(result)
            if result.duplicate or result.evidence_record is None:
                continue
            events.append(result.normalized.event)
            graph.project_event(
                result.normalized.event,
                evidence_id=result.evidence_record.id,
            )

        matches = self.sigma.detect(self.rules, events)
        correlations = [
            match
            for rule in self.correlation_rules
            for match in self.correlation.match(rule, events)
        ]
        detections: list[DetectionRecord] = []
        new_detection_ids: list[str] = []
        for match in matches:
            existing = session.scalar(
                select(DetectionRecord).where(
                    DetectionRecord.tenant_id == str(tenant_id),
                    DetectionRecord.incident_id == str(case_id),
                    DetectionRecord.rule_id == match.rule_id,
                    DetectionRecord.event_id == match.event_id,
                )
            )
            if existing is not None:
                detections.append(existing)
                continue
            detection_record = DetectionRecord.from_match(
                match,
                tenant_id=str(tenant_id),
                incident_id=str(case_id),
                detected_at=next(
                    event.observed_at for event in events if str(event.event_id) == match.event_id
                ),
                record_id=str(uuid4()),
            )
            session.add(detection_record)
            session.flush()
            detections.append(detection_record)
            new_detection_ids.append(detection_record.id)
            incident.severity = _max_severity(incident.severity, match.level)
            incident.updated_at = datetime.now(UTC)

        claims: list[ClaimRecord] = []
        for result in ingested:
            if (
                result.duplicate
                or result.evidence_record is None
                or not self._is_claim_candidate(result)
            ):
                continue
            event = result.normalized.event
            claim = Claim.observed_from_event(
                event,
                case_id=case_id,
                evidence_id=UUID(result.evidence_record.id),
                source_reliability=result.evidence_record.source_reliability,
            )
            claim_record = ClaimRecord.from_claim(claim, created_at=event.observed_at)
            session.add(claim_record)
            session.flush()
            claims.append(claim_record)

        if new_detection_ids or correlations or claims:
            self.audit.append(
                session,
                tenant_id=tenant_id,
                case_id=case_id,
                actor=actor
                or {"kind": "system", "id": "deterministic-engine", "role": "detector"},
                event_type="security-engine.processed",
                payload={
                    "detection_ids": new_detection_ids,
                    "correlation_ids": [
                        {"rule_id": match.rule_id, "event_ids": list(match.event_ids)}
                        for match in correlations
                    ],
                    "claim_ids": [record.id for record in claims],
                },
                policy_decision="allow",
            )
        return EngineResult(
            incident=incident,
            ingested=tuple(ingested),
            detections=tuple(detections),
            correlations=tuple(correlations),
            claims=tuple(claims),
            graph=graph,
        )
