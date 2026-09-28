# CausalForge data model

## Versioning rules

All externally persisted or exchanged artifacts carry `schema_version`. UUIDs identify artifacts;
timestamps are timezone-aware UTC; hashes use lowercase SHA-256 hex; payloads are canonicalized
before hashing. Schemas in `schemas/` are the contract source for Phase 0.

## Canonical event

A canonical event describes an observation without embedding secret values:

```json
{
  "schema_version": "1.0",
  "event_id": "00000000-0000-0000-0000-000000000001",
  "tenant_id": "00000000-0000-0000-0000-000000000010",
  "source": {"kind": "kubernetes_audit", "name": "fixture-lab", "version": "1.0"},
  "observed_at": "2026-09-27T10:03:00Z",
  "ingested_at": "2026-09-27T10:03:01Z",
  "actor": {"kind": "service_account", "id": "system:serviceaccount:orders:orders-reader"},
  "action": "list",
  "object": {"kind": "secret", "namespace": "orders", "name": null},
  "outcome": "allowed",
  "attributes": {"request_uri": "/api/v1/namespaces/orders/secrets"},
  "coverage": {
    "source_complete_for_window": true,
    "window_start": "2026-09-27T10:00:00Z",
    "window_end": "2026-09-27T10:05:00Z"
  },
  "raw_payload_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "parser_version": "fixture-1.0"
}
```

## Evidence and claims

Evidence is immutable and records both observation and collection time, source family, reliability,
coverage, parser version, redaction profile, normalized content, and a content hash. A claim refers
to evidence IDs and has a state: `observed`, `derived`, `hypothesized`, `corroborated`, `verified`,
`disputed`, `rejected`, or `unknown`.

`verified` requires deterministic checks: required evidence exists, source independence is
sufficient, temporal ordering is valid, identity/authorization edges exist when required,
contradictions are resolved, hashes validate, and coverage is sufficient. A model score can never
perform that promotion.

## Graph

Nodes represent tenants, identities, workloads, pods, namespaces, services, images, repositories,
secrets, ConfigMaps, nodes, findings, events, techniques, and external indicators. Edges represent
relationships such as `uses_identity`, `can_list`, `accessed`, `communicated_with`, `depends_on`,
and `blocked_by_policy`. Every edge carries evidence IDs, source, confidence, and validity times.

The deterministic RBAC evaluator returns one of:

- `allowed`: a matching allow rule is present.
- `denied`: the snapshot declares complete coverage and no matching allow rule exists.
- `unknown`: the snapshot is incomplete, so absence cannot establish denial.

This rule is shared by the in-memory graph projector and the case engine; incomplete RBAC telemetry
never becomes a negative authorization fact.

## Response plan

A response plan contains typed actions only. Each action names an allowlisted action type, exact
target selector/scope, preconditions, expected effects, service invariants, rollback data,
approval class, idempotency key, and simulation result. It does not contain arbitrary commands.

## Audit chain

For an entry without `entry_hash`:

```text
entry_hash = SHA256(previous_entry_hash || canonical_json(entry_without_hash))
```

The chain records actor, case, tool, model/provider metadata, redacted argument hash, output hash,
policy decision, approval, and execution result. It is tamper-evident, not proof that an upstream
source was truthful.

## Deterministic case engine

The rule-only engine consumes a bounded batch of canonical payloads and persists, in order:

1. The incident identity and creation audit entry.
2. Redacted event/evidence records and evidence-ingestion audit entries.
3. Sigma matches and bounded sequence correlations.
4. Direct `observed` claims tied to evidence IDs.
5. A processing audit entry containing only IDs and structured metadata.

It does not create hypotheses, promote claims to `verified`, call an LLM, or execute target changes.
