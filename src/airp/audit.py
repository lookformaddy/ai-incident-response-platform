"""Hash-chained audit log.

Every mutating operation (detection, transition, mitigation, escalation,
postmortem) appends an entry whose hash commits to the previous entry's
hash, forming a tamper-evident chain: ``verify()`` recomputes every hash
and returns False if any entry was altered, removed, or reordered.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from .models import AuditEntry

GENESIS_PREV_HASH = "0" * 64


def _canonical(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


class AuditLog:
    """Append-only, hash-chained audit log (in-memory; JSON-serializable)."""

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    def __len__(self) -> int:
        return len(self._entries)

    @property
    def entries(self) -> list[AuditEntry]:
        return list(self._entries)

    def append(
        self,
        actor: str,
        action: str,
        payload: dict | None = None,
        *,
        timestamp: datetime | None = None,
    ) -> AuditEntry:
        ts = timestamp or datetime.now(timezone.utc)
        prev = self._entries[-1].entry_hash if self._entries else GENESIS_PREV_HASH
        canonical = _canonical(payload or {})
        material = "|".join(
            [prev, str(len(self._entries) + 1), ts.isoformat(), actor, action, canonical]
        )
        entry_hash = hashlib.sha256(material.encode("utf-8")).hexdigest()
        entry = AuditEntry(
            seq=len(self._entries) + 1,
            timestamp=ts,
            actor=actor,
            action=action,
            payload=canonical,
            prev_hash=prev,
            entry_hash=entry_hash,
        )
        self._entries.append(entry)
        return entry

    def verify(self) -> bool:
        """Recompute the whole chain; False on any tamper."""
        prev = GENESIS_PREV_HASH
        for entry in self._entries:
            if entry.prev_hash != prev:
                return False
            material = "|".join(
                [
                    entry.prev_hash,
                    str(entry.seq),
                    entry.timestamp.isoformat(),
                    entry.actor,
                    entry.action,
                    entry.payload,
                ]
            )
            if hashlib.sha256(material.encode("utf-8")).hexdigest() != entry.entry_hash:
                return False
            prev = entry.entry_hash
        return True

    def for_incident(self, incident_id: str) -> list[AuditEntry]:
        """Entries whose payload names this incident."""
        out: list[AuditEntry] = []
        for entry in self._entries:
            try:
                data = json.loads(entry.payload)
            except json.JSONDecodeError:
                continue
            if data.get("incident_id") == incident_id:
                out.append(entry)
        return out
