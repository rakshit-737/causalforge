# Fixture workflow coordinator

`causalforge.workflow.coordinator.FixtureCoordinator` is a pure orchestration boundary joining the
typed evidence planner and the attested fixture collector. `DurableFixtureWorkflow` adds the
transactional persistence boundary used by the local API.

It produces:

- a replay-stable `EvidencePlan`;
- one tamper-evident `CollectionReceipt` per typed request;
- canonical events scoped to the hypothesis tenant and case;
- trusted source attestations for a future verifier;
- explicit `insufficient_evidence` requirements when planning or collection is incomplete.

The durable boundary persists workflow runs, collection receipts, canonical events, evidence
bindings, result snapshots, and audit entries. It is tenant- and hypothesis-scoped, rejects
idempotency-key reuse with a different request, and revalidates persisted hashes before reads.
Repeated requests with the same key replay the durable result; different keys produce separate run
identities while reusing idempotent event/evidence lineage where appropriate.

The fixture path does **not** contact external systems, execute commands, promote claims, or accept
caller-supplied source attestations. Incomplete planning, source mismatch, item-budget truncation,
and other bounded failures remain explicit `insufficient_evidence` outcomes.

API paths:

- `POST /api/v1/incidents/{incident_id}/hypotheses/{hypothesis_id}/workflow-runs`
- `GET /api/v1/incidents/{incident_id}/hypotheses/{hypothesis_id}/workflow-runs`
- `GET /api/v1/incidents/{incident_id}/hypotheses/{hypothesis_id}/workflow-runs/{run_id}`

Run the focused checks with:

```text
uv run --extra dev python -m pytest backend/tests/unit/test_coordinator.py
uv run --extra dev python -m pytest backend/tests/api/test_workflow_api.py
```
