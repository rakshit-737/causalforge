# CausalForge implementation plan

This plan keeps the project runnable at each checkpoint and prevents the large product vision
from turning into an unsafe collection of stubs. Each phase has a small acceptance boundary.

## Phase 0 — architecture and contracts

**Status: complete for this checkpoint.**

- Define trust boundaries, threat model, state machine, and write-action boundary.
- Define versioned JSON schemas for canonical events, evidence, hypotheses, claims, response
  plans, and audit entries.
- Add a deterministic transition contract and contract tests.
- Record decisions about PostgreSQL graph storage and durable workflow boundaries.

## Phase 1 — core infrastructure

**Status: local infrastructure checkpoint complete; service/container integration remains.**

This increment finishes the local infrastructure boundary: dependency readiness measures real
dependencies (or explicitly says disabled), repository tests cover failure paths, migrations are
repeatable, and the Python 3.12 development environment is locked. Authentication, durable workers,
and live PostgreSQL/Redis container verification remain explicit follow-up work; declarations alone
are not acceptance evidence.

- Add FastAPI application, settings, health/readiness endpoints, and structured logging.
- Add SQLAlchemy/Alembic persistence and explicit tenant-scoped repositories.
- Add PostgreSQL/Redis Docker Compose profiles.
- Acceptance: migrations, health checks, and repository isolation tests work from a clean checkout.

## Phase 2 — deterministic security engine

**Status: complete for the local fixture checkpoint.**

- Implement canonical-event normalization, redaction, deduplication, evidence hashing, and the
  append-only audit chain.
- Project evidence into a temporal graph, capability edges, and explicit RBAC reachability states.
- Add a deliberately scoped Sigma-compatible matcher and bounded sequence correlation windows.
- Wire those services into a rule-only case engine that creates incidents, detections, and observed
  claims without an LLM or target writes.
- Acceptance: fixture events produce a detection, graph, and evidence-backed observed claim.

The graph and correlation outputs are currently in-memory projections returned by the deterministic
engine. Event, evidence, incident, detection, claim, and audit records are persisted; graph snapshots
and RBAC snapshots will receive durable API contracts in the next integration increment.

## Phase 3 - AI boundary and retrieval

**Status: complete for the local deterministic retrieval checkpoint.**

- Add provider-neutral structured-output adapter and deterministic rule-only fallback.
- Add tenant-scoped document retrieval and ATT&CK/STIX enrichment adapters.
- Add prompt-injection-resistant context construction and malformed-output tests.
- Acceptance: the same fixture investigation completes with or without an LLM provider.

The provider boundary, safe context construction, tenant-scoped local retrieval, deterministic
Markdown chunking, citation contracts, and a local Kubernetes runbook are implemented. Remote
ATT&CK/STIX ingestion and vector retrieval remain optional follow-up integrations.

## Phase 4 - investigation workflow

**Status: deterministic API checkpoint complete; durable hypotheses/planner/verifier remain.**

- Add durable coordinator, competing hypotheses, active evidence planning, typed tool broker,
  collector, verifier, risk assessor, and report composer.
- Add deadlines, budgets, idempotency, retries only for read operations, and incomplete-case
  preservation.
- Acceptance: the demo reaches `VERIFIED` or `INSUFFICIENT_EVIDENCE` without unsupported claims.

The local API now exposes tenant-verified event ingestion, incident lifecycle, evidence, claims,
timeline, and graph snapshots. It intentionally does not expose unverified model conclusions or
response execution.

## Phase 5 — response safety

- Add typed lab actions, OPA/Rego policy evaluation, approval records, counterfactual simulation,
  allowlisted executor, rollback, and post-action verification.
- Acceptance: Plan B blocks the suspected path while preserving the declared billing invariant;
  no action runs without a scoped approval and matching resource version.

## Phase 6 — analyst UI and local lab

- Add React incident list/detail views, temporal graph, claim/evidence matrix, simulation diff,
  approval flow, audit view, and SSE progress.
- Add fixture replay and optional kind manifests for `compromised-orders-workload`.
- Acceptance: an analyst can complete the demo in a browser without database inspection.

## Phase 7 — evaluation and hardening

- Add seeded CloudSecBench scenarios, baselines, metrics, ablations, and Markdown/JSON reports.
- Add CI, security scans, dependency audits, container hardening, backups, and operations docs.
- Acceptance: one command reproduces a fixture evaluation and CI passes without secrets.

## Working rules

1. Implement the smallest incomplete phase before starting the next phase.
2. Every write-capable operation needs a typed schema, policy decision, approval boundary, and
   audit event before an executor is added.
3. Optional integrations use real interfaces plus deterministic fixture adapters.
4. No hidden chain-of-thought or raw secrets are persisted.
5. Do not claim an integration works until a test or a clearly labeled local-only demo proves it.
