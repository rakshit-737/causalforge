"""Append-only hash-chain audit ledger."""

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from causalforge.domain.serialization import canonical_json_bytes, sha256_bytes, sha256_hex
from causalforge.storage.models.audit import AuditEntryRecord

GENESIS_HASH = "0" * 64
AuditPolicyDecision = Literal["allow", "deny", "needs_review"]


def _require_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("audit timestamps must be timezone-aware")
    return value.astimezone(UTC)


def _hashable_fields(
    *,
    entry_id: str,
    tenant_id: str,
    case_id: str,
    sequence: int,
    created_at: datetime,
    actor: Mapping[str, str],
    event_type: str,
    tool_name: str | None,
    model_provider: str | None,
    model_id: str | None,
    prompt_template_sha256: str | None,
    retrieved_artifact_ids: list[str],
    redacted_arguments_sha256: str | None,
    output_sha256: str | None,
    previous_entry_hash: str,
    payload_sha256: str,
    policy_decision: AuditPolicyDecision,
    approval_id: str | None,
    execution_result: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Return exactly the fields included in an audit entry hash."""

    return {
        "entry_id": entry_id,
        "tenant_id": tenant_id,
        "case_id": case_id,
        "sequence": sequence,
        "created_at": created_at.isoformat(),
        "actor": dict(actor),
        "event_type": event_type,
        "tool_name": tool_name,
        "model_provider": model_provider,
        "model_id": model_id,
        "prompt_template_sha256": prompt_template_sha256,
        "retrieved_artifact_ids": retrieved_artifact_ids,
        "redacted_arguments_sha256": redacted_arguments_sha256,
        "output_sha256": output_sha256,
        "previous_entry_hash": previous_entry_hash,
        "payload_sha256": payload_sha256,
        "policy_decision": policy_decision,
        "approval_id": approval_id,
        "execution_result": dict(execution_result) if execution_result else None,
    }


def _entry_hash(fields: Mapping[str, Any]) -> str:
    previous = str(fields["previous_entry_hash"]).encode("ascii")
    return sha256_bytes(previous + canonical_json_bytes(fields))


class AuditLedger:
    """Persist and verify per-case audit chains."""

    def append(
        self,
        session: Session,
        *,
        tenant_id: UUID,
        case_id: UUID,
        actor: Mapping[str, str],
        event_type: str,
        payload: Mapping[str, Any],
        policy_decision: AuditPolicyDecision,
        created_at: datetime | None = None,
        tool_name: str | None = None,
        model_provider: str | None = None,
        model_id: str | None = None,
        prompt_template_sha256: str | None = None,
        retrieved_artifact_ids: list[str] | None = None,
        redacted_arguments_sha256: str | None = None,
        output_sha256: str | None = None,
        approval_id: UUID | None = None,
        execution_result: Mapping[str, Any] | None = None,
    ) -> AuditEntryRecord:
        """Append one entry, leaving commit ownership with the caller."""

        timestamp = _require_aware(created_at or datetime.now(UTC))
        tenant_key = str(tenant_id)
        case_key = str(case_id)
        artifact_ids = list(retrieved_artifact_ids or [])
        payload_hash = sha256_hex(payload)
        last_error: IntegrityError | None = None
        for _ in range(3):
            previous_entry = session.scalar(
                select(AuditEntryRecord)
                .where(
                    AuditEntryRecord.tenant_id == tenant_key,
                    AuditEntryRecord.case_id == case_key,
                )
                .order_by(AuditEntryRecord.sequence.desc())
            )
            sequence = (previous_entry.sequence + 1) if previous_entry else 1
            previous_hash = previous_entry.entry_hash if previous_entry else GENESIS_HASH
            entry_id = str(uuid4())
            fields = _hashable_fields(
                entry_id=entry_id,
                tenant_id=tenant_key,
                case_id=case_key,
                sequence=sequence,
                created_at=timestamp,
                actor=actor,
                event_type=event_type,
                tool_name=tool_name,
                model_provider=model_provider,
                model_id=model_id,
                prompt_template_sha256=prompt_template_sha256,
                retrieved_artifact_ids=artifact_ids,
                redacted_arguments_sha256=redacted_arguments_sha256,
                output_sha256=output_sha256,
                previous_entry_hash=previous_hash,
                payload_sha256=payload_hash,
                policy_decision=policy_decision,
                approval_id=str(approval_id) if approval_id else None,
                execution_result=execution_result,
            )
            record = AuditEntryRecord(
                id=entry_id,
                tenant_id=tenant_key,
                case_id=case_key,
                sequence=sequence,
                created_at=timestamp,
                actor=dict(actor),
                event_type=event_type,
                tool_name=tool_name,
                model_provider=model_provider,
                model_id=model_id,
                prompt_template_sha256=prompt_template_sha256,
                retrieved_artifact_ids=artifact_ids,
                redacted_arguments_sha256=redacted_arguments_sha256,
                output_sha256=output_sha256,
                previous_entry_hash=previous_hash,
                payload_sha256=payload_hash,
                policy_decision=policy_decision,
                approval_id=str(approval_id) if approval_id else None,
                execution_result=dict(execution_result) if execution_result else None,
                entry_hash=_entry_hash(fields),
            )
            try:
                with session.begin_nested():
                    session.add(record)
                    session.flush()
                return record
            except IntegrityError as exc:
                last_error = exc
                latest = session.scalar(
                    select(AuditEntryRecord)
                    .where(
                        AuditEntryRecord.tenant_id == tenant_key,
                        AuditEntryRecord.case_id == case_key,
                    )
                    .order_by(AuditEntryRecord.sequence.desc())
                )
                if latest is None or latest.sequence < sequence:
                    raise
        if last_error is not None:
            raise last_error
        raise RuntimeError("audit append retry loop exited without a result")

    def verify(self, session: Session, *, tenant_id: UUID, case_id: UUID) -> bool:
        """Verify sequence, predecessor links, and entry hashes for one scoped chain."""

        rows = list(
            session.scalars(
                select(AuditEntryRecord)
                .where(
                    AuditEntryRecord.tenant_id == str(tenant_id),
                    AuditEntryRecord.case_id == str(case_id),
                )
                .order_by(AuditEntryRecord.sequence.asc())
            )
        )
        previous_hash = GENESIS_HASH
        for expected_sequence, row in enumerate(rows, start=1):
            if row.sequence != expected_sequence or row.previous_entry_hash != previous_hash:
                return False
            fields = _hashable_fields(
                entry_id=row.id,
                tenant_id=row.tenant_id,
                case_id=row.case_id,
                sequence=row.sequence,
                created_at=_require_aware(row.created_at),
                actor=row.actor,
                event_type=row.event_type,
                tool_name=row.tool_name,
                model_provider=row.model_provider,
                model_id=row.model_id,
                prompt_template_sha256=row.prompt_template_sha256,
                retrieved_artifact_ids=row.retrieved_artifact_ids,
                redacted_arguments_sha256=row.redacted_arguments_sha256,
                output_sha256=row.output_sha256,
                previous_entry_hash=row.previous_entry_hash,
                payload_sha256=row.payload_sha256,
                policy_decision=row.policy_decision,  # type: ignore[arg-type]
                approval_id=row.approval_id,
                execution_result=row.execution_result,
            )
            if _entry_hash(fields) != row.entry_hash:
                return False
            previous_hash = row.entry_hash
        return True
