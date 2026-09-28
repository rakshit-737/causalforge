"""Explicitly scoped Sigma-compatible matcher.

This is a small deterministic subset, not a claim of full Sigma compatibility. It supports exact
field matching, lists of exact values, and ``contains``/``startswith``/``endswith`` modifiers in a
single selection condition.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from causalforge.domain.events import CanonicalEvent


class SigmaRule(BaseModel):
    """Validated subset of a Sigma rule accepted by the engine."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    title: str = Field(min_length=1)
    id: str = Field(min_length=1)
    status: str = Field(min_length=1)
    description: str | None = None
    logsource: dict[str, str] = Field(default_factory=dict)
    detection: dict[str, Any]
    level: Literal["informational", "low", "medium", "high", "critical"]
    tags: tuple[str, ...] = ()

    @field_validator("detection")
    @classmethod
    def validate_detection(cls, value: dict[str, Any]) -> dict[str, Any]:
        condition = value.get("condition")
        if not isinstance(condition, str):
            raise ValueError("detection.condition is required")
        selection_names = [name for name in value if name != "condition"]
        if condition not in selection_names:
            raise ValueError("only a single named selection condition is supported")
        if len(selection_names) != 1 or not isinstance(value[condition], Mapping):
            raise ValueError("only one mapping selection is supported")
        return value


@dataclass(frozen=True)
class DetectionMatch:
    """Deterministic match with a human-readable explanation."""

    rule_id: str
    event_id: str
    title: str
    level: str
    tags: tuple[str, ...]
    explanation: str


def _field_value(event: CanonicalEvent, field: str) -> Any:
    if field == "action":
        return event.action
    if field == "outcome":
        return event.outcome
    if field == "actor.kind":
        return event.actor.kind
    if field == "actor.id":
        return event.actor.id
    if field == "object.kind":
        return event.object.kind
    if field == "object.namespace":
        return event.object.namespace
    if field == "object.name":
        return event.object.name
    if field == "source.kind":
        return event.source.kind
    if field == "source.name":
        return event.source.name
    if field.startswith("attributes."):
        current: Any = event.attributes
        for part in field.removeprefix("attributes.").split("."):
            if not isinstance(current, Mapping):
                return None
            current = current.get(part)
        return current
    return None


def _matches_value(actual: Any, expected: Any, modifier: str | None) -> bool:
    expected_values = expected if isinstance(expected, list) else [expected]
    if modifier == "contains":
        return any(isinstance(actual, str) and str(value) in actual for value in expected_values)
    if modifier == "startswith":
        return any(
            isinstance(actual, str) and actual.startswith(str(value)) for value in expected_values
        )
    if modifier == "endswith":
        return any(
            isinstance(actual, str) and actual.endswith(str(value)) for value in expected_values
        )
    return any(actual == value for value in expected_values)


class SigmaEngine:
    """Run the supported deterministic Sigma subset against canonical events."""

    def match(self, rule: SigmaRule, event: CanonicalEvent) -> DetectionMatch | None:
        if not self._matches_logsource(rule.logsource, event):
            return None
        condition = str(rule.detection["condition"])
        selection = rule.detection[condition]
        mismatches: list[str] = []
        for field, expected in selection.items():
            if not isinstance(field, str):
                return None
            parts = field.split("|", maxsplit=1)
            actual = _field_value(event, parts[0])
            modifier = parts[1] if len(parts) == 2 else None
            if not _matches_value(actual, expected, modifier):
                mismatches.append(f"{field}={expected!r} (actual={actual!r})")
        if mismatches:
            return None
        fields = ", ".join(
            f"{field}={_field_value(event, field.split('|', 1)[0])!r}" for field in selection
        )
        return DetectionMatch(
            rule_id=rule.id,
            event_id=str(event.event_id),
            title=rule.title,
            level=rule.level,
            tags=rule.tags,
            explanation=f"Matched selection {condition}: {fields}",
        )

    @staticmethod
    def _matches_logsource(logsource: Mapping[str, str], event: CanonicalEvent) -> bool:
        product = logsource.get("product")
        category = logsource.get("category")
        if product == "kubernetes" and event.source.kind != "kubernetes_audit":
            return False
        if category == "audit" and "audit" not in event.source.kind:
            return False
        return True

    def detect(
        self,
        rules: Iterable[SigmaRule],
        events: Iterable[CanonicalEvent],
    ) -> list[DetectionMatch]:
        matches: list[DetectionMatch] = []
        seen: set[tuple[str, str]] = set()
        for rule in rules:
            for event in events:
                key = (rule.id, str(event.event_id))
                if key in seen:
                    continue
                match = self.match(rule, event)
                if match is not None:
                    matches.append(match)
                    seen.add(key)
        return matches


def load_rule(path: Path) -> SigmaRule:
    """Load and validate one YAML rule from disk."""

    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, Mapping):
        raise ValueError(f"Sigma rule must be a mapping: {path.name}")
    return SigmaRule.model_validate(dict(data))


def load_rules(directory: Path) -> list[SigmaRule]:
    """Load YAML rules in deterministic path order."""

    paths = sorted((*directory.glob("*.yml"), *directory.glob("*.yaml")))
    return [load_rule(path) for path in paths]
