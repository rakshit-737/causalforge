# Attested fixture collector

`causalforge.workflow.collector.FixtureCollector` is the first collector implementation behind the
typed evidence planner. It is deliberately a local adapter:

- input is a finite in-memory fixture sequence supplied by the caller;
- no network, subprocess, Kubernetes client, database, Redis, or LLM is used;
- each payload is normalized into a canonical event before it is returned;
- tenant scope, source identity, item limits, and an absolute deadline are enforced;
- malformed, foreign-tenant, and unattested events are rejected without returning raw payloads;
- successful results carry a server-owned `TrustedSource` attestation for later verification.

The collector returns `completed`, `truncated`, or `insufficient_evidence`. A result is not an
evidence-ledger write and does not claim that a future collector or external system was contacted.
Persistence, audit recording, and API wiring remain coordinator work; keeping this boundary pure
makes the fixture path deterministic and safe to test.
