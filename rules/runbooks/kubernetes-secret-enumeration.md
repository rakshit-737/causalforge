# Kubernetes secret-enumeration response guidance

## Purpose

Use this runbook to investigate an allowed secret-list operation without assuming that secret
values were read or exfiltrated.

## Evidence requirements

- Kubernetes audit evidence showing the actor, action, object, outcome, and observation window.
- An RBAC snapshot showing whether the actor was authorized to list secrets.
- Workload identity evidence linking the service account to the workload.
- Network telemetry with documented coverage before making an exfiltration statement.

## Important distinction

An allowed `list secrets` operation establishes enumeration activity. It does not, by itself,
establish that secret values were retrieved or successfully exfiltrated. Preserve that conclusion
as `unknown` when payload or complete egress evidence is unavailable.

## Safe next steps

1. Collect read-only evidence through registered connectors.
2. Compare competing explanations and record contradictions.
3. Simulate a narrow RBAC and egress response before considering quarantine.
4. Require human approval for any availability- or access-affecting action.
