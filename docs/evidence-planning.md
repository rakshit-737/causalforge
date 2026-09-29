# Evidence planning

CausalForge now includes a deterministic evidence planner at
`causalforge.workflow.planner`. It converts a bounded vocabulary of hypothesis requirements into
typed, read-only collection requests without executing them.

Supported requirement kinds:

- `audit event` / `kubernetes audit`
- `RBAC snapshot`
- `runtime observation`
- `fixture event replay`

Each request has a stable ID, an allowlisted collector kind, a source family, a closed selector, and
a maximum item count. Unknown requirements are represented by a hash-only diagnostic so untrusted
free text is not echoed into a plan artifact. Empty requirements, request budgets, and unsupported
requirements produce `insufficient_evidence`.

The planner is intentionally pure. It does not call Kubernetes, Redis, PostgreSQL, a shell, or an
LLM, and it does not imply that collection occurred. A future trusted collector may execute these
requests only after authentication, authorization, deadline, budget, and audit integration.

The smallest local example is covered by `backend/tests/unit/test_planner.py` and can be exercised
with:

```text
uv run --extra dev python -m pytest backend/tests/unit/test_planner.py
```
