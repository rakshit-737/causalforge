"""Evidence-backed temporal graph projector.

The projector only creates edges directly supported by a canonical event. It never turns an
absence of telemetry into a denied edge or infers reachability from a model suggestion.
"""

from datetime import date, datetime
from enum import Enum
from typing import Any
from uuid import UUID

import networkx as nx

from causalforge.domain.events import CanonicalEvent
from causalforge.graph.rbac import RBACRule


def node_id(kind: str, key: str) -> str:
    """Create a stable graph node identifier."""

    return f"{kind}:{key}"


def _object_key(event: CanonicalEvent) -> str:
    parts = [part for part in (event.object.namespace, event.object.name or "*") if part]
    return "/".join(parts) if parts else "*"


def _attribute_text(attributes: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = attributes.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _json_safe(value: Any) -> Any:
    """Convert graph metadata to values accepted by JSON encoders."""

    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, tuple | set | frozenset):
        return [_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    return value


class TemporalAttackGraph:
    """In-memory temporal graph whose edges retain evidence provenance."""

    def __init__(self) -> None:
        self.graph: nx.MultiDiGraph[str] = nx.MultiDiGraph()

    def _add_edge(
        self,
        source: str,
        target: str,
        *,
        relationship: str,
        event: CanonicalEvent,
        evidence_id: UUID | str,
        confidence: float = 1.0,
    ) -> None:
        self.graph.add_edge(
            source,
            target,
            key=str(event.event_id),
            relationship=relationship,
            evidence_ids=(str(evidence_id),),
            observed_at=event.observed_at,
            valid_from=event.observed_at,
            valid_to=None,
            confidence=confidence,
            source_family=event.source.kind,
        )

    def project_event(self, event: CanonicalEvent, *, evidence_id: UUID | str) -> None:
        """Project only relationships explicitly represented by one canonical event."""

        actor = node_id(event.actor.kind, event.actor.id)
        event_node = node_id("event", str(event.event_id))
        object_node = node_id(event.object.kind, _object_key(event))
        self.graph.add_node(actor, kind=event.actor.kind, canonical_key=event.actor.id)
        self.graph.add_node(
            event_node,
            kind="event",
            canonical_key=str(event.event_id),
            observed_at=event.observed_at,
            action=event.action,
            outcome=event.outcome,
        )
        self.graph.add_node(
            object_node,
            kind=event.object.kind,
            canonical_key=_object_key(event),
            namespace=event.object.namespace,
            name=event.object.name,
        )
        self._add_edge(
            actor,
            event_node,
            relationship="triggered",
            event=event,
            evidence_id=evidence_id,
        )

        if event.outcome == "allowed":
            self._add_edge(
                actor,
                object_node,
                relationship="accessed",
                event=event,
                evidence_id=evidence_id,
            )
        elif event.outcome == "denied":
            self._add_edge(
                actor,
                object_node,
                relationship="blocked_by_policy",
                event=event,
                evidence_id=evidence_id,
            )

        workload = _attribute_text(event.attributes, "workload_id", "workload", "source_workload")
        if workload:
            workload_node = node_id("workload", workload)
            self.graph.add_node(workload_node, kind="workload", canonical_key=workload)
            self._add_edge(
                workload_node,
                actor,
                relationship="uses_identity",
                event=event,
                evidence_id=evidence_id,
            )

        destination = _attribute_text(
            event.attributes,
            "destination_service",
            "target_service",
            "service",
        )
        if destination:
            destination_node = node_id("service", destination)
            self.graph.add_node(destination_node, kind="service", canonical_key=destination)
            source_node = node_id("workload", workload) if workload else actor
            self._add_edge(
                source_node,
                destination_node,
                relationship="communicated_with",
                event=event,
                evidence_id=evidence_id,
            )

    def project_rbac_rule(self, rule: RBACRule) -> None:
        """Project one authorization rule as a provenance-backed capability edge."""

        subject = node_id(rule.subject_kind, rule.subject_id)
        self.graph.add_node(subject, kind=rule.subject_kind, canonical_key=rule.subject_id)
        for namespace in sorted(rule.namespaces):
            for resource in sorted(rule.resources):
                target_key = f"{namespace}/{resource}"
                target = node_id("resource", target_key)
                self.graph.add_node(
                    target,
                    kind="resource",
                    canonical_key=target_key,
                    namespace=namespace,
                    resource=resource,
                )
                for verb in sorted(rule.verbs):
                    relationship = {
                        "get": "can_read",
                        "list": "can_list",
                    }.get(verb, f"can_{verb}")
                    self.graph.add_edge(
                        subject,
                        target,
                        key=f"rbac:{rule.evidence_id}:{verb}",
                        relationship=relationship,
                        evidence_ids=(str(rule.evidence_id),),
                        valid_from=rule.valid_from,
                        valid_to=rule.valid_to,
                        confidence=1.0,
                        source_family="kubernetes_rbac",
                    )

    def neighbors(
        self,
        source: str,
        *,
        at: datetime | None = None,
        relationship: str | None = None,
    ) -> list[str]:
        """Return evidence-backed outgoing neighbors valid at an optional timestamp."""

        if source not in self.graph:
            return []
        results: list[str] = []
        for _, target, data in self.graph.out_edges(source, data=True):
            if relationship and data.get("relationship") != relationship:
                continue
            if at is not None and not self._edge_valid_at(data, at):
                continue
            if target not in results:
                results.append(target)
        return results

    @staticmethod
    def _edge_valid_at(data: dict[str, Any], at: datetime) -> bool:
        valid_from = data.get("valid_from")
        valid_to = data.get("valid_to")
        return bool(
            isinstance(valid_from, datetime)
            and valid_from <= at
            and (valid_to is None or at < valid_to)
        )

    def path(
        self,
        source: str,
        target: str,
        *,
        at: datetime | None = None,
        relationships: set[str] | None = None,
    ) -> list[str]:
        """Return a shortest directed path using only valid, selected relationships."""

        graph: nx.DiGraph[str] = nx.DiGraph()
        for current, destination, data in self.graph.edges(data=True):
            if at is not None and not self._edge_valid_at(data, at):
                continue
            if relationships and data.get("relationship") not in relationships:
                continue
            graph.add_edge(current, destination)
        try:
            return nx.shortest_path(graph, source=source, target=target)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []

    def as_dict(self) -> dict[str, list[dict[str, Any]]]:
        """Return a JSON-ready graph snapshot for tests and a future API/UI."""

        nodes = [
            {"id": node, **{key: _json_safe(value) for key, value in attrs.items()}}
            for node, attrs in self.graph.nodes(data=True)
        ]
        edges = [
            {
                "source": source,
                "target": target,
                **{key: _json_safe(value) for key, value in attrs.items()},
            }
            for source, target, attrs in self.graph.edges(data=True)
        ]
        return {"nodes": nodes, "edges": edges}
