# CausalForge offline demonstration

> Synthetic fixture only. No Kubernetes cluster, credentials, external network, or LLM was used.

## Scenario

- Name: `compromised-orders-workload`
- Seed: `737`
- Events replayed: **5**
- Detections: **1**
- Evidence-backed observed claims: **1**
- Audit chain valid: **True**

## Established by the deterministic engine

- `system:serviceaccount:orders:orders-reader` — **list secret** — `observed` (evidence: dfb72841-7cfd-5ffc-808a-593ff110d569)
- The synthetic external communication was **attempted and denied**, not established as successful communication.

## Explicit unknown

- Successful secret exfiltration: **UNKNOWN / NOT ESTABLISHED**.
- Reason: the fixture contains no evidence proving that secret values left the workload.

## Graph facts

- Nodes: **14**
- Edges: **17**
- Attempted communication edges: **1**

## Ground truth targets

```json
{
  "unapproved_image_deployed": true,
  "secret_enumeration_observed": true,
  "billing_communication_allowed": true,
  "synthetic_external_communication_allowed": false,
  "secret_exfiltration": "unknown"
}
```

This report is generated from the rule-only path. Model-assisted hypotheses, claim verification, response simulation, and human approval are later phases.
