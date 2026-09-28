# CausalForge threat model

This is the Phase 0 design baseline. It describes what the control plane must protect before
connectors or response executors are implemented.

## Protected assets

- Evidence integrity, provenance, coverage, and retention.
- Tenant/case isolation and analyst authorization.
- Kubernetes identity, RBAC, workload, network, deployment, and artifact metadata.
- LLM credentials and retrieved knowledge scopes.
- Response policy, approval tokens, rollback data, and audit records.
- Availability of the investigation workflow.

## Trust zones

| Zone | Examples | Default trust |
|---|---|---|
| External/untrusted input | logs, telemetry fields, filenames, STIX text | hostile data |
| Connector boundary | Kubernetes/Falco/OTel/SBOM adapters | authenticated but fallible |
| CausalForge core | normalizer, ledger, graph, verifier | controlled code |
| Model context | prompt inputs and structured outputs | untrusted computation |
| Response boundary | policy, approval gateway, executor | highest scrutiny |
| Analyst browser | UI, uploaded knowledge, approval interaction | authenticated user boundary |

## Adversaries and abuse cases

1. **Malicious workload:** abuses a service account or fabricates runtime activity.
2. **Telemetry attacker:** injects prompt-injection text, replays events, or changes timestamps.
3. **Compromised connector:** returns forged evidence or attempts a write through a read tool.
4. **Malicious insider:** crosses tenant scope or approves an unsafe target.
5. **Compromised model/provider:** receives sensitive context or returns unsafe structured output.
6. **Agent failure:** loops, hallucinates evidence, overstates confidence, or broadens scope.
7. **Availability attacker:** floods ingestion or forces expensive evidence collection.

## Required controls

- Validate and normalize every input against a versioned schema; preserve source hashes.
- Redact secrets before persistence or model invocation; never place raw secret values in fixtures.
- Treat evidence and retrieved text as data in a separate prompt field, never as instructions.
- Use typed, catalogued tools with explicit effect, target types, scopes, deadlines, and redaction.
- Keep read tools and write actions in separate registries and credentials.
- Require tenant scope in every repository/API path and test cross-tenant denial.
- Verify source family independence, temporal ordering, coverage, replay status, and contradictions.
- Fail closed on policy ambiguity, state drift, missing rollback, invalid approval, or unknown
  action type.
- Apply deadlines, token budgets, tool budgets, circuit breakers, and bounded retries.
- Make fixture mode local-only and deny external network access by default.
- Hash-chain audit records and retain concise structured rationales rather than hidden chain-of-
  thought.
- Require a human approval that binds exact action, selector, scope, simulation hash, and expiry.

## Security assumptions

- The host, database, and configured identity provider are initially trusted enough to enforce
  access control; compromise of those systems is an operational incident for CausalForge itself.
- A source can be wrong even when authenticated; source reliability and coverage are explicit data.
- A graph edge means supported reachability only for its stated validity window and evidence set.
- The first release is a local lab; production connectors and multi-cloud credentials are out of
  scope.

## Out of scope for Phase 0/MVP

No exploit execution, malware, credential theft, arbitrary shell, real external target scanning,
automatic data deletion, autonomous production remediation, or claim that a complete source proves
absence outside its documented coverage window.
