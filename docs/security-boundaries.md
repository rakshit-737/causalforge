# CausalForge security boundaries

## Read path

```text
source -> authenticated adapter -> schema validation -> redaction -> hash
       -> immutable evidence -> graph/detection/verifier
```

Read-only connectors may query only their declared source and target types. The broker validates
tool name, input schema, tenant/case scope, deadline, effect, and redaction behavior before the
connector runs. The model can request a catalogued query but cannot add a tool or alter its scope.

## Write path

```text
verified claims -> typed candidate plan -> counterfactual simulation
  -> policy decision -> human approval -> scope/precondition/version checks
  -> allowlisted lab executor -> post-action verification -> audit
```

Every gate is mandatory. Failure or ambiguity stops the path. Approval binds the exact action
payload, target scope, simulation snapshot, action hash, approver role, and expiry. A replayed or
mutated approval is invalid.

## Boundary rules

- No generic shell, arbitrary HTTP request, or unrestricted Kubernetes client is exposed to agents.
- No production-like write is available in fixture mode.
- A response action must be idempotent or have explicit rollback metadata before registration.
- State-version mismatch aborts execution; the executor never silently refreshes a target.
- The absence of an event is not negative evidence unless coverage says the source was complete.
- Tenant checks occur at API, service, repository, graph, retrieval, and executor boundaries.
- Logs contain IDs, hashes, counts, and structured decisions, not raw evidence or secrets.
- Prompt context separates control instructions from untrusted evidence and retrieved documents.
- Model output is parsed into strict schemas; unknown tool names and extra fields are rejected.

## Minimum approval classes

| Class | Example | Required gate |
|---|---|---|
| `read_only` | evidence query or simulation | broker + tenant scope |
| `lab_safe` | restore a test resource | lab environment + policy + approval |
| `availability_impacting` | pause/quarantine workload | policy + human responder approval |
| `production_change` | real RBAC/network/credential change | disabled in MVP; future dual control |

The initial implementation registers only `read_only` and narrowly scoped `lab_safe` actions.
