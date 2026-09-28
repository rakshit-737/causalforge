"""Deterministic duplicate suppression for canonical events."""

from causalforge.domain.events import CanonicalEvent
from causalforge.domain.serialization import sha256_hex


def deduplication_key(event: CanonicalEvent) -> str:
    """Build a stable key that ignores a producer's event identifier."""

    payload = event.canonical_payload()
    payload.pop("event_id", None)
    payload.pop("raw_payload_sha256", None)
    payload.pop("ingested_at", None)
    return sha256_hex(payload)


class Deduplicator:
    """Process-local duplicate filter; a database uniqueness constraint is still required later."""

    def __init__(self) -> None:
        self._seen: set[str] = set()

    def accept(self, event: CanonicalEvent) -> bool:
        """Return true once for each event fingerprint."""

        key = deduplication_key(event)
        if key in self._seen:
            return False
        self._seen.add(key)
        return True
