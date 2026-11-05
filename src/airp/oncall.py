"""On-call rotation + escalation policy engine.

* :class:`Rotation` — a weekly rotating roster; ``member_on_call(at)``
  is deterministic from the roster start date, so tests and demos agree
  on who is on call at any moment.
* :class:`EscalationEngine` — given an incident and "now", computes the
  current escalation level from the ack timeouts in the policy. A level
  is only entered when the previous level's ack timeout expired without
  an ack. Business-hours policies defer escalation outside the window
  instead of paging someone at 3 AM for a SEV4.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .models import EscalationLevel, EscalationPolicy, Incident, OnCallMember


@dataclass(frozen=True)
class Rotation:
    """Weekly rotation over a fixed roster."""

    members: tuple[OnCallMember, ...]
    start: datetime  # first member is on call from this instant
    period_days: int = 7

    def __post_init__(self) -> None:
        if not self.members:
            raise ValueError("rotation needs at least one member")
        if self.period_days < 1:
            raise ValueError("period_days must be >= 1")

    def member_on_call(self, at: datetime) -> OnCallMember:
        if at < self.start:
            return self.members[0]
        periods = (at - self.start).days // self.period_days
        return self.members[periods % len(self.members)]


def _is_business_hours(at: datetime, policy: EscalationPolicy) -> bool:
    return (
        at.weekday() < 5
        and policy.business_start_hour <= at.hour < policy.business_end_hour
    )


def next_business_hour_start(at: datetime, policy: EscalationPolicy) -> datetime:
    """Next instant inside the business window, at or after ``at``."""
    candidate = at.replace(minute=0, second=0, microsecond=0)
    while True:
        if _is_business_hours(candidate, policy):
            return candidate
        candidate += timedelta(hours=1)


@dataclass
class EscalationEngine:
    """Computes escalation level and next-escalation time for incidents."""

    policy: EscalationPolicy
    rotation: Rotation | None = None

    def current_level(
        self, incident: Incident, *, now: datetime, acked: bool = False
    ) -> int:
        """Escalation level (1-based) in force at ``now``.

        Level 1 is the initial page. Each subsequent level is entered
        once the previous level's ack timeout has expired without an ack.
        """
        if acked:
            return 1
        if self.policy.mode == "business_hours" and not _is_business_hours(
            now, self.policy
        ):
            return 1
        elapsed = (now - incident.created_at).total_seconds() / 60.0
        level = 1
        spent = 0.0
        for escalation_level in self.policy.levels:
            spent += escalation_level.ack_timeout_minutes
            if elapsed >= spent and level < len(self.policy.levels):
                level += 1
            else:
                break
        return level

    def next_escalation_at(
        self, incident: Incident, *, now: datetime, acked: bool = False
    ) -> datetime | None:
        """When the next level would be entered, or None if at the top."""
        level = self.current_level(incident, now=now, acked=acked)
        if acked or level >= len(self.policy.levels):
            return None
        if self.policy.mode == "business_hours" and not _is_business_hours(
            now, self.policy
        ):
            return next_business_hour_start(now, self.policy)
        spent = sum(
            l.ack_timeout_minutes for l in self.policy.levels[:level]
        )
        return incident.created_at + timedelta(minutes=spent)

    def members_for_level(self, level: int, *, now: datetime) -> tuple[OnCallMember, ...]:
        """Who gets paged at this level (rotation member for level 1)."""
        if level == 1 and self.rotation is not None:
            return (self.rotation.member_on_call(now),)
        return self.policy.levels[level - 1].members

    def page(
        self, incident: Incident, *, now: datetime, acked: bool = False
    ) -> dict:
        """One escalation decision: level, members paged, next escalation."""
        level = self.current_level(incident, now=now, acked=acked)
        return {
            "incident_id": incident.incident_id,
            "level": level,
            "paged": [m.name for m in self.members_for_level(level, now=now)],
            "acked": acked,
            "next_escalation_at": self.next_escalation_at(
                incident, now=now, acked=acked
            ),
        }


def default_policy() -> EscalationPolicy:
    """Three-level chain: primary (5 min) -> secondary (15 min) -> manager (30 min)."""
    return EscalationPolicy(
        policy_id="ai-platform-default",
        name="AI platform default",
        levels=(
            EscalationLevel(
                1,
                (OnCallMember("primary-oncall", "pager:primary", "primary"),),
                ack_timeout_minutes=5,
            ),
            EscalationLevel(
                2,
                (OnCallMember("secondary-oncall", "pager:secondary", "secondary"),),
                ack_timeout_minutes=15,
            ),
            EscalationLevel(
                3,
                (OnCallMember("eng-manager", "pager:manager", "manager"),),
                ack_timeout_minutes=30,
            ),
        ),
        mode="24x7",
    )
