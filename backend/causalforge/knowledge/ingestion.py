"""Deterministic Markdown knowledge ingestion."""

import re
from collections.abc import Mapping
from uuid import UUID, uuid4

from causalforge.domain.knowledge import KnowledgeChunk, KnowledgeDocument
from causalforge.domain.serialization import sha256_hex


def split_markdown(text: str, *, max_chars: int = 1600) -> list[str]:
    """Split Markdown into bounded, non-empty chunks while preserving headings."""

    if max_chars < 200:
        raise ValueError("max_chars must be at least 200")
    normalized = text.replace("\r\n", "\n").strip()
    if not normalized:
        return []
    sections = re.split(r"(?=^#{1,6}\s+)", normalized, flags=re.MULTILINE)
    chunks: list[str] = []
    for section in sections:
        section = section.strip()
        if not section:
            continue
        while len(section) > max_chars:
            cut = section.rfind("\n\n", 0, max_chars)
            if cut < max_chars // 2:
                cut = section.rfind(" ", 0, max_chars)
            if cut < max_chars // 2:
                cut = max_chars
            chunks.append(section[:cut].strip())
            section = section[cut:].strip()
        if section:
            chunks.append(section)
    return chunks


def build_document(
    *,
    title: str,
    source: str,
    version: str,
    license: str,
    text: str,
    tenant_id: UUID | None = None,
    metadata: Mapping[str, object] | None = None,
    document_id: UUID | None = None,
    max_chunk_chars: int = 1600,
) -> tuple[KnowledgeDocument, tuple[KnowledgeChunk, ...]]:
    """Create a content-hashed document and deterministic chunk IDs."""

    normalized = text.replace("\r\n", "\n").strip()
    document = KnowledgeDocument(
        schema_version="1.0",
        document_id=document_id or uuid4(),
        tenant_id=tenant_id,
        title=title,
        source=source,
        version=version,
        license=license,
        content_hash=sha256_hex({"text": normalized}),
        text=normalized,
        metadata=dict(metadata or {}),
    )
    chunks = tuple(
        KnowledgeChunk(
            schema_version="1.0",
            chunk_id=uuid4(),
            document_id=document.document_id,
            tenant_id=tenant_id,
            ordinal=ordinal,
            text=chunk,
            source=source,
            version=version,
            license=license,
            source_hash=document.content_hash,
        )
        for ordinal, chunk in enumerate(split_markdown(normalized, max_chars=max_chunk_chars))
    )
    return document, chunks
