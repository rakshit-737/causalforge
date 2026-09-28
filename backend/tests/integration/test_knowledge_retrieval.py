from uuid import uuid4

from causalforge.knowledge.ingestion import build_document
from causalforge.knowledge.retrieval import KnowledgeRepository
from causalforge.storage.db import Database


def test_search_returns_global_and_requested_tenant_documents_only(tmp_path) -> None:
    tenant_a = uuid4()
    tenant_b = uuid4()
    database = Database(f"sqlite:///{tmp_path / 'knowledge.db'}")
    database.create_schema()
    repository = KnowledgeRepository()
    global_doc, global_chunks = build_document(
        title="Global Kubernetes guidance",
        source="global-runbook",
        version="1.0",
        license="Apache-2.0",
        text="Secret enumeration requires read-only evidence and careful provenance.",
    )
    tenant_a_doc, tenant_a_chunks = build_document(
        title="Tenant A response",
        source="tenant-a-runbook",
        version="1.0",
        license="internal",
        text="Tenant A uses a narrow egress response for billing.",
        tenant_id=tenant_a,
    )
    tenant_b_doc, tenant_b_chunks = build_document(
        title="Tenant B private response",
        source="tenant-b-runbook",
        version="1.0",
        license="internal",
        text="Tenant B uses a private emergency procedure.",
        tenant_id=tenant_b,
    )

    with database.session() as session:
        repository.upsert(session, document=global_doc, chunks=global_chunks)
        repository.upsert(session, document=tenant_a_doc, chunks=tenant_a_chunks)
        repository.upsert(session, document=tenant_b_doc, chunks=tenant_b_chunks)
        session.commit()

        results = repository.search(session, tenant_id=tenant_a, query="narrow egress response")
        global_results = repository.search(session, tenant_id=tenant_a, query="secret enumeration")

    assert results
    assert all(citation.tenant_id in {None, tenant_a} for citation, _ in results)
    assert all(citation.tenant_id != tenant_b for citation, _ in results)
    assert global_results[0][0].tenant_id is None


def test_search_is_deterministic_and_empty_query_is_safe(tmp_path) -> None:
    database = Database(f"sqlite:///{tmp_path / 'knowledge-empty.db'}")
    database.create_schema()
    repository = KnowledgeRepository()
    document, chunks = build_document(
        title="Guidance",
        source="fixture",
        version="1.0",
        license="Apache-2.0",
        text="Evidence provenance matters.",
    )
    tenant_id = uuid4()

    with database.session() as session:
        repository.upsert(session, document=document, chunks=chunks)
        session.commit()
        assert repository.search(session, tenant_id=tenant_id, query="   ") == []
        first = repository.search(session, tenant_id=tenant_id, query="evidence provenance")
        second = repository.search(session, tenant_id=tenant_id, query="evidence provenance")

    assert [(str(citation.chunk_id), score) for citation, score in first] == [
        (str(citation.chunk_id), score) for citation, score in second
    ]
