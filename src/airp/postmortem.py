"""Postmortem generator.

Reconstructs an incident's timeline from its own event log plus the
hash-chained audit log, derives contributing factors from the alerts
that opened it and the mitigations that contained it, and emits action
items with owners and due dates (SEV1/2: 7 days after resolution;
SEV3/4: 14 days). A postmortem can only be generated for a resolved
incident — generating one is what moves it to the POSTMORTEM state.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .audit import AuditLog
from .models import (
    ActionItem,
    CostRecord,
    Incident,
    IncidentState,
    Postmortem,
    Severity,
    TimelineEvent,
)

# Action-item templates keyed by the metric that drove the incident.
_FACTOR_ACTIONS: dict[str, tuple[str, str]] = {
    "error_rate": (
        "Add a regression test for the failure mode behind the error spike",
        "ml-platform-oncall",
    ),
    "latency_p95_ms": (
        "Profile the slow path and set a latency budget alert at 2x baseline",
        "ai-platform-oncall",
    ),
    "cost_per_min": (
        "Tighten the per-service cost budget and add a spend alert",
        "ai-platform-oncall",
    ),
    "guardrail_hit_rate": (
        "Review the guardrail rules that fired and tune the prompt template",
        "trust-safety-oncall",
    ),
    "drift_score": (
        "Schedule a retraining run on the drifted distribution and re-baseline",
        "ml-platform-oncall",
    ),
    "tokens_per_min": (
        "Audit token usage growth and cap per-tenant token budgets",
        "ai-platform-oncall",
    ),
}


def _due_date(incident: Incident) -> datetime:
    base = incident.resolved_at or datetime.now(timezone.utc)
    days = 7 if incident.severity in {Severity.SEV1, Severity.SEV2} else 14
    return base + timedelta(days=days)


def generate_postmortem(
    incident: Incident,
    audit: AuditLog | None = None,
    *,
    cost: CostRecord | None = None,
    generated_at: datetime | None = None,
) -> Postmortem:
    """Build a postmortem for a resolved incident."""
    if incident.state not in {IncidentState.RESOLVED, IncidentState.POSTMORTEM}:
        raise ValueError(
            f"postmortem requires a resolved incident, got {incident.state.value}"
        )
    ts = generated_at or datetime.now(timezone.utc)

    # Timeline: the incident's own events, enriched with audit entries
    # that name this incident (detection, mitigation, escalation).
    timeline: list[TimelineEvent] = list(incident.timeline)
    if audit is not None:
        for entry in audit.for_incident(incident.incident_id):
            timeline.append(
                TimelineEvent(
                    at=entry.timestamp,
                    actor=entry.actor,
                    event=entry.action,
                    detail=entry.payload,
                )
            )
    timeline.sort(key=lambda e: e.at)

    # Contributing factors: the distinct alert signatures, the mitigations
    # applied, and the detection delay.
    factors: list[str] = []
    seen: set[str] = set()
    for event in incident.timeline:
        if event.event == "detected":
            factor = f"Detector fired: {event.detail}"
            if factor not in seen:
                factors.append(factor)
                seen.add(factor)
        if event.event == "mitigation":
            factor = f"Mitigation applied: {event.detail}"
            if factor not in seen:
                factors.append(factor)
                seen.add(factor)
    if incident.merged_count:
        factors.append(
            f"{incident.merged_count} duplicate alert(s) were merged into this "
            "incident (alert-storm suppression worked, but the underlying "
            "signal kept firing)"
        )
    if incident.time_to_detect_minutes is not None:
        factors.append(
            f"Detection took {incident.time_to_detect_minutes:.1f} minutes "
            f"(target {15} minutes)"
        )
    if not factors:
        factors.append("No detector or mitigation events recorded on the timeline.")

    # Action items: one per contributing metric, plus a standing item to
    # review the playbook that was used.
    items: list[ActionItem] = []
    metrics = {a.split(":")[1] for a in {incident.signature} if ":" in a} | {
        event.detail.split()[0]
        for event in incident.timeline
        if event.event == "detected" and event.detail.split()
    }
    due = _due_date(incident)
    counter = 0
    for metric in sorted(metrics):
        title, owner = _FACTOR_ACTIONS.get(
            metric, ("Review the detector that fired for this incident", "ai-platform-oncall")
        )
        counter += 1
        items.append(
            ActionItem(
                item_id=f"AI-{incident.incident_id}-{counter:02d}",
                title=title,
                owner=owner,
                due_date=due,
                source=f"metric:{metric}",
            )
        )
    counter += 1
    items.append(
        ActionItem(
            item_id=f"AI-{incident.incident_id}-{counter:02d}",
            title="Review the mitigation playbook used and update it with what worked",
            owner=incident.owner or "ai-platform-oncall",
            due_date=due,
            source="playbook-review",
        )
    )

    summary = (
        f"{incident.severity.value} incident on {incident.service}: "
        f"{incident.title}. Detected in "
        f"{incident.time_to_detect_minutes if incident.time_to_detect_minutes is not None else '?'} min, "
        f"resolved in "
        f"{incident.time_to_resolve_minutes if incident.time_to_resolve_minutes is not None else '?'} min. "
        f"{len(items)} action item(s) assigned."
    )
    return Postmortem(
        incident_id=incident.incident_id,
        generated_at=ts,
        timeline=timeline,
        contributing_factors=factors,
        action_items=items,
        mttd_minutes=incident.time_to_detect_minutes,
        mttr_minutes=incident.time_to_resolve_minutes,
        cost=cost,
        summary=summary,
    )
