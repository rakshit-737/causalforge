# ADR 0002: Persisted task state before model orchestration

## Status

Accepted for the MVP.

## Context

Evidence collection is sequential, bounded, and resumable. In-memory agent conversations cannot
provide replay, idempotency, deadlines, or an audit trail. A model provider may be unavailable or
return malformed output.

## Decision

Represent coordinator and agent work as persisted, versioned task records with input/output
artifact IDs, idempotency keys, budgets, deadlines, and explicit status. Redis Streams/arq may
transport work, but PostgreSQL remains the source of truth. A deterministic rule-only path is a
first-class implementation, not an error fallback.

## Consequences

- A worker can resume or mark an investigation `INSUFFICIENT_EVIDENCE` without inventing progress.
- Every tool call and model result can be reconciled to a case.
- The first implementation has more schema and repository work before model features appear.
- Retries must be classified by effect; write actions are never automatically retried.
