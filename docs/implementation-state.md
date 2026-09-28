# CausalForge implementation state

## Current phase

**Phase 2 — deterministic security engine (local fixture checkpoint)**

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

## Tests run

The focused Phase 1 checks now pass:

```text
uv run --extra dev python -m pytest  # 54 passed on CPython 3.12
python -m compileall -q backend
python -c "...Draft202012Validator.check_schema(...)..."  # 7 schemas pass
uv run --extra dev python -m alembic -c backend/alembic.ini upgrade head
uv run --extra dev python -m ruff check backend
uv run --extra dev python -m mypy backend/causalforge
uv run --extra dev python -m bandit -q -r backend/causalforge
uv run --extra dev python -m pip_audit --local  # no known vulnerabilities
```

Optional quality checks were not available in the current environment because `ruff` and `mypy`
are not installed:

```text
ruff check backend
mypy backend/causalforge
```

## Known limitations

- No public event-ingestion API, worker, UI, or lab runtime exists yet.
- PostgreSQL and Redis containers are declared but were not started in this environment because
  Docker is unavailable; the tested runtime uses local SQLite and the Redis probe's failure path.
- Graph snapshots, RBAC snapshots, and correlation matches are not yet exposed as durable API
  resources; their deterministic services are covered by local tests.
- The Sigma implementation is intentionally a subset; full Sigma condition grammar and anomaly
  ranking are not implemented.
- The state transition function validates a proposed transition but does not yet persist lifecycle
  transitions through a coordinator.
- Authentication, authorization middleware, and production secret management are not implemented.

## Next smallest task

Implement Phase 3's provider-neutral AI boundary and retrieval layer with a deterministic fallback,
strict structured outputs, tenant-scoped knowledge retrieval, and prompt-injection tests.

## Architectural constraints carried forward

- The LLM never gets a generic shell or direct target access.
- `verified` is a deterministic promotion state, not a model confidence label.
- `unknown` is a first-class result for insufficient coverage.
- Production-like writes stay disabled until policy, approval, scope, precondition, and rollback
  metadata all exist.
