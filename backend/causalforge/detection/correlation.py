"""Deterministic sequence correlation with bounded time windows."""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from causalforge.detection.sigma_engine import _field_value
from causalforge.domain.events import CanonicalEvent


class CorrelationRule(BaseModel):
    """A small, explicit sequence rule over canonical event fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    window_seconds: int = Field(gt=0, le=86_400)
    sequence: tuple[dict[str, Any], ...] = Field(min_length=2)
    level: Literal["informational", "low", "medium", "high", "critical"]
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class CorrelationMatch:
    """A matched event sequence and its explainable time window."""

    rule_id: str
    title: str
    event_ids: tuple[str, ...]
    first_observed_at: Any
    last_observed_at: Any
    level: str
    tags: tuple[str, ...]
    explanation: str


def _matches(event: CanonicalEvent, predicate: Mapping[str, Any]) -> bool:
    return all(
        _field_value(event, field) in (value if isinstance(value, list) else [value])
        for field, value in predicate.items()
    )


class CorrelationEngine:
    """Find ordered event sequences without unbounded search or implicit joins."""

    def match(
        self,
        rule: CorrelationRule,
        events: Iterable[CanonicalEvent],
    ) -> list[CorrelationMatch]:
        ordered = sorted(events, key=lambda event: (event.observed_at, str(event.event_id)))
        matches: list[CorrelationMatch] = []
        window = timedelta(seconds=rule.window_seconds)
        for start_index, start_event in enumerate(ordered):
            if not _matches(start_event, rule.sequence[0]):
                continue
            selected = [start_event]
            cursor = start_index + 1
            for predicate in rule.sequence[1:]:
                candidate = None
                while cursor < len(ordered):
                    event = ordered[cursor]
                    cursor += 1
                    if event.observed_at - start_event.observed_at > window:
                        break
                    if _matches(event, predicate):
                        candidate = event
                        break
                if candidate is None:
                    selected = []
                    break
                selected.append(candidate)
            if selected:
                matches.append(
                    CorrelationMatch(
                        rule_id=rule.id,
                        title=rule.title,
                        event_ids=tuple(str(event.event_id) for event in selected),
                        first_observed_at=selected[0].observed_at,
                        last_observed_at=selected[-1].observed_at,
                        level=rule.level,
                        tags=rule.tags,
                        explanation=(
                            f"Matched {len(selected)} ordered events within "
                            f"{rule.window_seconds}s"
                        ),
                    )
                )
        return matches
