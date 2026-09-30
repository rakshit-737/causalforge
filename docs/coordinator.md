# Fixture workflow coordinator

`causalforge.workflow.coordinator.FixtureCoordinator` is a pure orchestration boundary joining the
typed evidence planner and the attested fixture collector.

It produces:

- a replay-stable `EvidencePlan`;
- one tamper-evident `CollectionReceipt` per typed request;
- canonical events scoped to the hypothesis tenant and case;
- trusted source attestations for a future verifier;
- explicit `insufficient_evidence` requirements when planning or collection is incomplete.

It does **not** persist artifacts, append audit entries, contact external systems, execute commands,
or promote claims. The next coordinator increment is to persist these plan/receipt artifacts and
audit them transactionally through a durable worker/API path.

Run the focused checks with:

```text
uv run --extra dev python -m pytest backend/tests/unit/test_coordinator.py
```
