# Offline demo

Run the reproducible local scenario:

```text
uv run --extra dev python scripts/demo.py --output reports/demo.md
```

or:

```text
make demo
```

The demo uses an in-memory SQLite database, fixture events, the deterministic Sigma subset, the
temporal graph, and the audit ledger. It requires no API key, Kubernetes cluster, Docker, Redis,
PostgreSQL, or external network access.

The generated report shows:

- an unapproved image deployment;
- allowed secret enumeration;
- allowed orders-to-billing communication;
- denied synthetic external communication;
- a valid audit chain;
- successful secret exfiltration explicitly marked **UNKNOWN / NOT ESTABLISHED**.

The demo intentionally does not execute a response or invent hypotheses. Those capabilities remain
behind the planned workflow, policy, simulation, and human approval phases.
