from uuid import uuid4

from causalforge.knowledge.ingestion import build_document, split_markdown


def test_markdown_ingestion_preserves_headings_and_bounds_chunks() -> None:
    text = "# Heading\n\n" + ("secret enumeration guidance " * 100)

    chunks = split_markdown(text, max_chars=240)

    assert chunks
    assert chunks[0].startswith("# Heading")
    assert all(0 < len(chunk) <= 240 for chunk in chunks)


def test_document_and_chunks_share_content_provenance() -> None:
    tenant_id = uuid4()
    document, chunks = build_document(
        title="Runbook",
        source="rules/runbooks/runbook.md",
        version="1.0",
        license="Apache-2.0",
        text="# Runbook\n\nUse read-only evidence.",
        tenant_id=tenant_id,
    )

    assert document.tenant_id == tenant_id
    assert chunks
    assert all(chunk.source_hash == document.content_hash for chunk in chunks)
    assert [chunk.ordinal for chunk in chunks] == list(range(len(chunks)))


def test_global_document_has_no_tenant_scope() -> None:
    document, _ = build_document(
        title="Global guidance",
        source="local",
        version="1.0",
        license="Apache-2.0",
        text="Shared guidance.",
    )

    assert document.tenant_id is None
