# Knowledge retrieval

CausalForge keeps incident facts and background knowledge separate. Evidence records are the
authority for what happened; approved runbooks and ATT&CK-like documents provide context and
citations only.

## Document scopes

- `tenant_id = null`: approved global knowledge, available to every tenant.
- `tenant_id = <id>`: tenant-private knowledge, available only to that tenant.

The repository applies the scope predicate before ranking. Tenant A cannot receive Tenant B's
chunks, even when the query terms are identical.

## Deterministic ingestion

Markdown is normalized, content-hashed, split into bounded chunks, and stored with repeated source
metadata. Each result carries document ID, chunk ID, source, version, license, source hash, tenant
scope, ordinal, and a deterministic retrieval score.

The current local retriever uses token overlap and deterministic ordering. It is intentionally
simple and reproducible; pgvector or a richer full-text index can be added behind the same
repository contract without making retrieval authoritative for incident claims.

## Safe model use

Retrieval results enter `SafeContext.knowledge` as untrusted fragments. A model can cite them for
runbook or technique context, but the report composer must still cite incident evidence IDs for
claims about the case.
