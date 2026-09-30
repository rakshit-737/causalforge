# CausalForge implementation state

## Current phase

**Phase 4 — deterministic investigation API with durable fixture workflow**

## Completed in this checkpoint

- Inspected the requested folder and confirmed it was empty; no existing functionality was
  overwritten.
- Defined the architecture, trust boundaries, threat model, data model, and phased plan.
- Added versioned JSON schemas for canonical events, evidence, hypotheses, claims, response plans,
  and audit entries.
- Added the deterministic incident state-transition contract.
- Added contract and state-machine tests for the Phase 0 acceptance boundary.
- Added a minimal Python project configuration so the contract tests can run before services exist.
- Added immutable environment settings with local/lab safety validation and redacted URL logging.
- Added a FastAPI application factory with liveness/readiness endpoints and request correlation IDs.
- Added SQLAlchemy tenant/user models, a tenant-scoped user repository, and local SQLite bootstrap.
- Added an Alembic initial migration and PostgreSQL/Redis Docker Compose dependencies.
- Made schema creation explicit: local runtime readiness fails closed until the Alembic revision is
  current; isolated tests may opt into SQLite auto-creation.
- Added real Redis ping readiness when Redis is required and an explicit skipped status otherwise.
- Added Python 3.12 pinning and `uv.lock` for reproducible development environments.
- Added strict canonical event, evidence, claim, and RBAC models with timezone-aware validation.
- Added recursive secret redaction, deterministic payload hashes, duplicate suppression, and a
  tenant-checked ingestion service.
- Added event/evidence/audit persistence plus migrations `0002_security_evidence` and
  `0003_deterministic_engine`.
- Added an append-only per-case SHA-256 audit chain with tamper verification.
- Added temporal graph projection, JSON-safe graph snapshots, capability edges, and RBAC
  reachability that distinguishes allowed, denied, and unknown coverage.
- Added a tested Sigma-compatible subset, deterministic bounded sequence correlation, and the
  rule-only case engine that persists incidents, detections, and observed claims.
- Added a provider-neutral structured-output contract, OpenAI-compatible adapter, and deterministic
  fallback provider.
- Added strict Pydantic hypothesis output models and fail-closed malformed-output handling.
- Added prompt-injection-safe context construction with redaction, size bounds, instruction-like
  text flags, and explicit trusted/untrusted message separation.
- Added tenant-scoped/global knowledge document contracts, deterministic Markdown chunking, local
  token-overlap retrieval, citation metadata, and a Kubernetes secret-enumeration runbook.
- Added a local principal adapter that verifies `X-Tenant-ID`/`X-User-ID` against the local database;
  the tenant header is no longer trusted by itself.
- Added versioned event and incident APIs for bounded replay, tenant-isolated reads, claims,
  evidence, timeline, graph, and safe empty placeholders for future hypotheses/response plans.
- Added API contract tests for missing principals, tenant isolation, redaction, tenant mismatch,
  and static route ordering.
- Made evidence identifiers deterministic for a case/content pair so replay references remain
  stable even when server receipt times differ.
- Added the offline compromised-orders workload fixture, rule-only demo runner, deterministic
  Markdown report, and regression test. It uses in-memory SQLite and never connects to a cluster,
  credentials, an external network, or an LLM.
- Added durable hypothesis and verification-record tables with Alembic migrations `0007` and
  `0008`.
- Added a fail-closed verifier requiring independent source families, complete coverage, bounded
  evidence counts, and unexpired deadlines; unsuccessful checks remain explicit
  `insufficient_evidence` outcomes.
- Exposed tenant-scoped hypothesis creation/listing and durable verification-attempt API endpoints.
- Added deterministic claim verification with explicit `verified`, `unknown`, and `disputed`
  outcomes, durable attempt records, and API history endpoints.
- Hardened verification so independent source families must be server-attested, observed claim
  semantics must match the canonical event, and free-text hypotheses remain
  `insufficient_evidence` until a semantic verifier evaluates required/disconfirming evidence.
- Added strict claim gates for successful outcomes, source reliability, temporal span, citation
  completeness, and immutable nested-payload validation.
- Bound evidence integrity to the canonical event's tenant, source, parser, timestamps, coverage,
  content hash, and complete provenance-envelope hash before workflow evaluation (`0009`).
- Confined the development principal adapter to direct loopback requests without forwarding headers;
  added real SQLite rollback/savepoint and concurrent-writer regression coverage.
- Added a deterministic typed evidence planner with allowlisted collector capabilities, bounded
  budgets/deadlines, stable artifact identities, and hash-only diagnostics for unknown requirements.
- Added a local `FixtureCollector` that normalizes finite fixture payloads, enforces tenant/source/
  deadline/item scope, and returns server-owned source attestations without external side effects.
- Added durable workflow-run and collection-receipt persistence (`0010`), integrity snapshots and
  evidence bindings (`0011`), and a transactional fixture coordinator service.
- Added tenant-scoped workflow API endpoints with bounded request size, replay-safe idempotency keys,
  server-owned fixture trust, explicit `insufficient_evidence` outcomes, and integrity-checked reads.
- Added workflow audit entries, event/evidence persistence, and SQLite rollback/concurrency tests;
  different idempotency keys receive distinct run/receipt identities while event/evidence replay
  remains idempotent.

## Tests run

The focused Phase 4 checks now pass:

```text
uv run --extra dev python -m pytest  # 127 passed on CPython 3.12
python -m compileall -q backend
python -c "...Draft202012Validator.check_schema(...)..."  # 8 schemas pass
uv run --extra dev python -m alembic -c backend/alembic.ini upgrade head
uv run --extra dev python -m ruff check backend
uv run --extra dev python -m mypy backend/causalforge
uv run --extra dev python -m bandit -q -r backend/causalforge
uv run --extra dev python -m pip_audit --local  # no known vulnerabilities
```

## Known limitations

- No background worker, UI, or browser UI exists yet; the current workflow API is a synchronous,
  bounded local-fixture path, not a Kubernetes runtime or external collector broker.
- Remote ATT&CK/STIX ingestion and vector retrieval are not implemented yet; local approved
  Markdown retrieval is deterministic and tenant-scoped.
- PostgreSQL and Redis containers are declared but were not started in this environment because
  Docker is unavailable; the tested runtime uses local SQLite and the Redis probe's failure path.
- Graph snapshots, RBAC snapshots, and correlation matches are not yet exposed as durable API
  resources; their deterministic services are covered by local tests.
- The Sigma implementation is intentionally a subset; full Sigma condition grammar and anomaly
  ranking are not implemented.
- The state transition function validates a proposed transition but does not yet persist lifecycle
  transitions through a coordinator.
- The local principal adapter is a development identity check, not production authentication or
  authorization middleware; production token verification and secret management remain open.
- Hypothesis verification is evidence-bound but currently evaluates already-collected evidence;
  the durable fixture workflow does not yet provide a background retry/deadline worker or automatic
  contradiction matcher. Claim contradictions must currently be explicitly cited by a workflow
  caller.
- API-submitted telemetry has no server-owned source attestation, so API claim verification remains
  `unknown`; a trusted collector integration is required before the API can promote a claim.
- The attested collector remains fixture-only. It now persists canonical events, evidence, receipts,
  snapshots, bindings, and audit entries through the bounded API path; trusted Kubernetes, RBAC, and
  runtime collectors are still future integrations.

## Next smallest task

Add a durable worker abstraction for queued read-only collection with the same tenant, deadline,
budget, idempotency, audit, and fail-closed invariants; keep external connectors disabled until
each source has a server-owned attestation and fixture-backed contract tests.

## Architectural constraints carried forward

- The LLM never gets a generic shell or direct target access.
- `verified` is a deterministic promotion state, not a model confidence label.
- `unknown` is a first-class result for insufficient coverage.
- Production-like writes stay disabled until policy, approval, scope, precondition, and rollback
  metadata all exist.
