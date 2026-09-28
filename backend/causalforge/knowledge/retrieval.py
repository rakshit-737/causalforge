"""Deterministic local full-text retrieval with tenant isolation."""

import re
from collections.abc import Iterable
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from causalforge.domain.knowledge import KnowledgeChunk, KnowledgeCitation, KnowledgeDocument
from causalforge.storage.models.document import DocumentChunkRecord, DocumentRecord

_TOKEN = re.compile(r"[a-z0-9][a-z0-9_.:/-]{1,63}", re.IGNORECASE)


def _tokens(text: str) -> set[str]:
    return {token.casefold() for token in _TOKEN.findall(text)}


def _score(query_tokens: set[str], text: str) -> float:
    document_tokens = _tokens(text)
    if not query_tokens or not document_tokens:
        return 0.0
    overlap = len(query_tokens & document_tokens)
    phrase_bonus = 0.15 if " ".join(sorted(query_tokens)) in text.casefold() else 0.0
    return min(1.0, overlap / len(query_tokens) + phrase_bonus)


class KnowledgeRepository:
    """Persist approved documents and retrieve only global or requested-tenant content."""

    def upsert(
        self,
        session: Session,
        *,
        document: KnowledgeDocument,
        chunks: Iterable[KnowledgeChunk],
    ) -> DocumentRecord:
        tenant_filter = (
            DocumentRecord.tenant_id == str(document.tenant_id)
            if document.tenant_id
            else DocumentRecord.tenant_id.is_(None)
        )
        existing = session.scalar(
            select(DocumentRecord).where(
                tenant_filter,
                DocumentRecord.content_hash == document.content_hash,
            )
        )
        if existing is not None:
            return existing
        record = DocumentRecord(
            id=str(document.document_id),
            tenant_id=str(document.tenant_id) if document.tenant_id else None,
            title=document.title,
            source=document.source,
            version=document.version,
            license=document.license,
            content_hash=document.content_hash,
            document_metadata=document.metadata,
        )
        session.add(record)
        for chunk in chunks:
            session.add(
                DocumentChunkRecord(
                    id=str(chunk.chunk_id),
                    document_id=str(chunk.document_id),
                    tenant_id=str(chunk.tenant_id) if chunk.tenant_id else None,
                    ordinal=chunk.ordinal,
                    text=chunk.text,
                    source=chunk.source,
                    version=chunk.version,
                    license=chunk.license,
                    source_hash=chunk.source_hash,
                )
            )
        session.flush()
        return record

    def search(
        self,
        session: Session,
        *,
        tenant_id: UUID,
        query: str,
        limit: int = 8,
    ) -> list[tuple[KnowledgeCitation, str]]:
        """Return ranked citations from global and requested-tenant documents only."""

        if not query.strip():
            return []
        if not 1 <= limit <= 50:
            raise ValueError("limit must be between 1 and 50")
        query_tokens = _tokens(query)
        rows = session.execute(
            select(DocumentChunkRecord, DocumentRecord)
            .join(DocumentRecord, DocumentRecord.id == DocumentChunkRecord.document_id)
            .where(
                or_(
                    DocumentChunkRecord.tenant_id.is_(None),
                    DocumentChunkRecord.tenant_id == str(tenant_id),
                )
            )
        ).all()
        ranked: list[tuple[float, KnowledgeCitation, str]] = []
        for chunk, document in rows:
            score = _score(query_tokens, chunk.text)
            if score <= 0:
                continue
            ranked.append(
                (
                    score,
                    KnowledgeCitation(
                        document_id=UUID(document.id),
                        chunk_id=UUID(chunk.id),
                        source=chunk.source,
                        version=chunk.version,
                        license=chunk.license,
                        source_hash=chunk.source_hash,
                        tenant_id=UUID(chunk.tenant_id) if chunk.tenant_id else None,
                        retrieval_score=score,
                        ordinal=chunk.ordinal,
                    ),
                    chunk.text,
                )
            )
        ranked.sort(key=lambda item: (-item[0], str(item[1].document_id), item[1].ordinal))
        return [(citation, text) for _, citation, text in ranked[:limit]]
