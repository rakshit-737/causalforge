# ADR 0001: PostgreSQL as the system of record with relational graph projection

## Status

Accepted for the MVP.

## Context

CausalForge needs tenant-scoped durable case state, immutable evidence references, audit-chain
ordering, temporal validity, queryable relationships, and optional vector retrieval. A separate
graph database would add operational weight before the investigation model is stable.

## Decision

Use PostgreSQL as the system of record. Store graph nodes and edges in relational tables with
explicit evidence IDs, validity timestamps, tenant IDs, and indexes. Use NetworkX or SQL queries
for deterministic path analysis in the first release. Add pgvector only for knowledge retrieval,
not as an authority for incident facts.

## Consequences

- Tenant isolation and audit ordering share one transaction boundary.
- The schema is portable and works in fixture SQLite tests where supported.
- Very large graph traversals may require later projections or a dedicated graph store.
- Every graph edge must retain provenance so a projection can be rebuilt.
