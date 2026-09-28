"""Tenant-scoped knowledge and citation contracts."""

from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class KnowledgeDocument(BaseModel):
    """Approved document metadata and source content."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"]
    document_id: UUID
    tenant_id: UUID | None
    title: str = Field(min_length=1, max_length=300)
    source: str = Field(min_length=1, max_length=300)
    version: str = Field(min_length=1, max_length=120)
    license: str = Field(min_length=1, max_length=200)
    content_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    text: str = Field(min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)


class KnowledgeChunk(BaseModel):
    """A deterministic chunk that can be cited by a model or analyst."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"]
    chunk_id: UUID
    document_id: UUID
    tenant_id: UUID | None
    ordinal: int = Field(ge=0)
    text: str = Field(min_length=1)
    source: str = Field(min_length=1)
    version: str = Field(min_length=1)
    license: str = Field(min_length=1)
    source_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class KnowledgeCitation(BaseModel):
    """Stable citation metadata returned by retrieval."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    document_id: UUID
    chunk_id: UUID
    source: str
    version: str
    license: str
    source_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    tenant_id: UUID | None
    retrieval_score: float = Field(ge=0, le=1)
    ordinal: int = Field(ge=0)
