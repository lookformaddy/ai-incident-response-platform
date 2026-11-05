"""Incident store: lifecycle state machine + alert dedup/merge.

* ``create_from_alert`` / ``ingest`` — an alert opens a new incident, or
  merges into an already-open incident with the same signature (same
  service + metric + detector) when it arrives within ``merge_window``.
  Merges bump ``merged_count`` and raise severity if the new alert is
  worse; they never create a second page for the same underlying event.
* ``transition`` — the only way to move an incident between states. It
  validates against ``VALID_TRANSITIONS``, stamps the state timestamp,
  and appends a timeline entry. Illegal transitions raise ``ValueError``.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .models import (
    VALID_TRANSITIONS,
    Alert,
    Incident,
    IncidentState,
    Severity,
    TimelineEvent,
)


class IncidentStore:
    """In-memory incident store with dedup and a validated lifecycle."""

    def __init__(self, merge_window: timedelta = timedelta(minutes=60)) -> None:
        self.merge_window = merge_window
        self._incidents: dict[str, Incident] = {}
        self._counter = 0

    def __len__(self) -> int:
        return len(self._incidents)

    def _next_id(self) -> str:
        self._counter += 1
        return f"INC-{self._counter:04d}"

    def get(self, incident_id: str) -> Incident:
        try:
            return self._incidents[incident_id]
        except KeyError:
            raise KeyError(f"unknown incident: {incident_id}") from None

    def all(self) -> list[Incident]:
        return sorted(self._incidents.values(), key=lambda i: i.created_at)

    def open(self) -> list[Incident]:
        return [i for i in self.all() if i.is_open]

    def by_severity(self, severity: Severity) -> list[Incident]:
        return [i for i in self.all() if i.severity == severity]

    def create_from_alert(
        self, alert: Alert, *, title: str | None = None, owner: str = ""
    ) -> Incident:
        incident = Incident(
            incident_id=self._next_id(),
            title=title or f"{alert.metric} anomaly on {alert.service}",
            service=alert.service,
            severity=alert.severity,
            signature=alert.signature,
            created_at=alert.created_at,
            detected_at=alert.created_at,
            alert_ids=[alert.alert_id],
            owner=owner,
        )
        incident.timeline.append(
            TimelineEvent(
                at=alert.created_at,
                actor="detector",
                event="detected",
                detail=alert.message,
            )
        )
        self._incidents[incident.incident_id] = incident
        return incident

    def _merge_target(self, alert: Alert) -> Incident | None:
        for incident in self._incidents.values():
            if not incident.is_open:
                continue
            if incident.signature != alert.signature:
                continue
            last_seen = incident.timeline[-1].at if incident.timeline else incident.created_at
            if alert.created_at - last_seen <= self.merge_window:
                return incident
        return None

    def ingest(self, alert: Alert, *, owner: str = "") -> tuple[Incident, bool]:
        """Ingest one alert. Returns ``(incident, merged)``.

        ``merged=True`` means the alert was folded into an existing open
        incident instead of opening a new one.
        """
        target = self._merge_target(alert)
        if target is None:
            return self.create_from_alert(alert, owner=owner), False
        target.alert_ids.append(alert.alert_id)
        target.merged_count += 1
        if alert.severity.rank < target.severity.rank:
            target.severity = alert.severity
        target.timeline.append(
            TimelineEvent(
                at=alert.created_at,
                actor="detector",
                event="merged",
                detail=f"duplicate alert {alert.alert_id} merged: {alert.message}",
            )
        )
        return target, True

    def ingest_many(self, alerts: list[Alert], *, owner: str = "") -> list[Incident]:
        created: list[Incident] = []
        for alert in sorted(alerts, key=lambda a: a.created_at):
            incident, merged = self.ingest(alert, owner=owner)
            if not merged:
                created.append(incident)
        return created

    def transition(
        self,
        incident_id: str,
        new_state: IncidentState,
        *,
        actor: str,
        note: str = "",
        at: datetime | None = None,
    ) -> Incident:
        incident = self.get(incident_id)
        if new_state not in VALID_TRANSITIONS[incident.state]:
            raise ValueError(
                f"illegal transition {incident.state.value} -> {new_state.value} "
                f"for {incident_id}"
            )
        ts = at or datetime.now(timezone.utc)
        incident.state = new_state
        stamp = {
            IncidentState.TRIAGED: "triaged_at",
            IncidentState.MITIGATING: "mitigating_at",
            IncidentState.RESOLVED: "resolved_at",
            IncidentState.POSTMORTEM: "postmortem_at",
        }.get(new_state)
        if stamp is not None:
            setattr(incident, stamp, ts)
        incident.timeline.append(
            TimelineEvent(at=ts, actor=actor, event=new_state.value, detail=note)
        )
        return incident
