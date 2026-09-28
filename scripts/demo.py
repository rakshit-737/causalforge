"""Run the offline compromised-orders workload demonstration.

Usage:
    uv run --extra dev python scripts/demo.py
    uv run --extra dev python scripts/demo.py --output reports/demo.md
"""

import json
import sys
from argparse import ArgumentParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from lab.simulator.scenario import CASE_ID, TENANT_ID, compromised_orders_workload  # noqa: E402

from causalforge.detection.sigma_engine import load_rules  # noqa: E402
from causalforge.security.engine import DeterministicCaseEngine  # noqa: E402
from causalforge.storage.db import Database  # noqa: E402


def build_report() -> str:
    """Run the fixture in memory and render only evidence-backed conclusions."""

    events, ground_truth = compromised_orders_workload()
    database = Database("sqlite://")
    database.create_schema()
    engine = DeterministicCaseEngine(rules=load_rules(ROOT / "rules" / "sigma"))
    with database.session() as session:
        result = engine.process(
            session,
            tenant_id=TENANT_ID,
            case_id=CASE_ID,
            payloads=events,
            parser_version="fixture-1.0",
            title="Compromised orders workload",
        )
        session.commit()
        audit_valid = engine.audit.verify(session, tenant_id=TENANT_ID, case_id=CASE_ID)

    observed_claims = [
        f"- `{claim.subject}` — **{claim.predicate}** — `{claim.status}` "
        f"(evidence: {', '.join(claim.supporting_evidence_ids)})"
        for claim in result.claims
    ]
    graph = result.graph.as_dict()
    attempted = [
        edge
        for edge in graph["edges"]
        if edge.get("relationship") == "attempted_communication"
    ]
    return "\n".join(
        [
            "# CausalForge offline demonstration",
            "",
            "> Synthetic fixture only. No Kubernetes cluster, credentials, external network, "
            "or LLM was used.",
            "",
            "## Scenario",
            "",
            f"- Name: `{ground_truth['scenario']}`",
            f"- Seed: `{ground_truth['seed']}`",
            f"- Events replayed: **{len(events)}**",
            f"- Detections: **{len(result.detections)}**",
            f"- Evidence-backed observed claims: **{len(result.claims)}**",
            f"- Audit chain valid: **{audit_valid}**",
            "",
            "## Established by the deterministic engine",
            "",
            *observed_claims,
            "- The synthetic external communication was **attempted and denied**, not "
            "established as successful communication.",
            "",
            "## Explicit unknown",
            "",
            "- Successful secret exfiltration: **UNKNOWN / NOT ESTABLISHED**.",
            "- Reason: the fixture contains no evidence proving that secret values left the "
            "workload.",
            "",
            "## Graph facts",
            "",
            f"- Nodes: **{len(graph['nodes'])}**",
            f"- Edges: **{len(graph['edges'])}**",
            f"- Attempted communication edges: **{len(attempted)}**",
            "",
            "## Ground truth targets",
            "",
            "```json",
            json.dumps(ground_truth["expected"], indent=2),
            "```",
            "",
            "This report is generated from the rule-only path. Model-assisted hypotheses, claim "
            "verification, response simulation, and human approval are later phases.",
            "",
        ]
    )


def main() -> int:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()
    report = build_report()
    if args.output:
        output = args.output if args.output.is_absolute() else ROOT / args.output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(report, encoding="utf-8")
        print(output)
    else:
        print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
