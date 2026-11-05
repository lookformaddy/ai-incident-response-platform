"""Core domain models for the AI incident response platform.

Design notes
------------
* ``Severity`` carries its own SLO targets (ack and resolution) so the
  escalation and reporting layers never hard-code per-severity numbers.
* The incident lifecycle is a strict state machine: every transition is
  validated against ``VALID_TRANSITIONS`` and recorded on the timeline.
  There is no way to skip a state or move backwards.
* Everything is a plain dataclass with no I/O, so the domain logic is
  testable without a database or a network.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timedelta


class Severity(enum.Enum):
    """Incident severity tiers, SEV1 (most severe) to SEV4."""

    SEV1 = "SEV1"
    SEV2 = "SEV2"
    SEV3 = "SEV3"
    SEV4 = "SEV4"

    @property
    def rank(self) -> int:
        return {"SEV1": 1, "SEV2": 2, "SEV3": 3, "SEV4": 4}[self.value]

    @property
    def ack_target_minutes(self) -> int:
        """Minutes within which a human must acknowledge the page."""
        return {"SEV1": 5, "SEV2": 15, "SEV3": 60, "SEV4": 240}[self.value]

    @property
    def resolution_target_minutes(self) -> int:
        """Minutes within which the incident should be resolved."""
        return {"SEV1": 60, "SEV2": 240, "SEV3": 1440, "SEV4": 4320}[self.value]

    @classmethod
    def worse(cls, a: "Severity", b: "Severity") -> "Severity":
        """The more severe of two severities."""
        return a if a.rank <= b.rank else b


class IncidentState(enum.Enum):
    """Incident lifecycle states, in order."""

    DETECTED = "detected"
    TRIAGED = "triaged"
    MITIGATING = "mitigating"
    RESOLVED = "resolved"
    POSTMORTEM = "postmortem"


# Legal transitions. SEV1 incidents may jump straight from DETECTED to
# MITIGATING (triage happens in parallel); nothing may move backwards,
# and POSTMORTEM is terminal.
VALID_TRANSITIONS: dict[IncidentState, frozenset[IncidentState]] = {
    IncidentState.DETECTED: frozenset(
        {IncidentState.TRIAGED, IncidentState.MITIGATING}
    ),
    IncidentState.TRIAGED: frozenset({IncidentState.MITIGATING}),
    IncidentState.MITIGATING: frozenset({IncidentState.RESOLVED}),
    IncidentState.RESOLVED: frozenset({IncidentState.POSTMORTEM}),
    IncidentState.POSTMORTEM: frozenset(),
}

# Telemetry metric names produced by the synthetic generator and consumed
# by detectors, playbooks, and cost accounting. Keep this list in sync
# with telemetry.TelemetryGenerator.
METRICS: tuple[str, ...] = (
    "error_rate",
    "latency_p95_ms",
    "cost_per_min",
    "guardrail_hit_rate",
    "drift_score",
    "tokens_per_min",
)


@dataclass(frozen=True)
class TelemetryPoint:
    """One minute of synthetic telemetry for one AI service."""

    timestamp: datetime
    service: str
    error_rate: float = 0.0  # fraction of requests failing, 0..1
    latency_p95_ms: float = 0.0
    cost_per_min: float = 0.0  # USD spent per minute
    guardrail_hit_rate: float = 0.0  # fraction of requests blocked, 0..1
    drift_score: float = 0.0  # 0..1, feature/label drift vs training
    tokens_per_min: float = 0.0

    def metric(self, name: str) -> float:
        if name not in METRICS:
            raise ValueError(f"unknown metric: {name!r}")
        return getattr(self, name)


@dataclass(frozen=True)
class Alert:
    """A detector firing on a telemetry point."""

    alert_id: str
    signature: str  # service:metric:detector — the dedup key
    service: str
    metric: str
    detector: str
    value: float
    threshold: float
    severity: Severity
    created_at: datetime
    message: str = ""


@dataclass
class TimelineEvent:
    """One entry on an incident's timeline (state change, merge, action)."""

    at: datetime
    actor: str
    event: str
    detail: str = ""


@dataclass
class Incident:
    """A tracked AI incident, from detection through postmortem."""

    incident_id: str
    title: str
    service: str
    severity: Severity
    state: IncidentState = IncidentState.DETECTED
    signature: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now())
    detected_at: datetime | None = None
    triaged_at: datetime | None = None
    mitigating_at: datetime | None = None
    resolved_at: datetime | None = None
    postmortem_at: datetime | None = None
    alert_ids: list[str] = field(default_factory=list)
    merged_count: int = 0
    owner: str = ""
    timeline: list[TimelineEvent] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.detected_at is None:
            self.detected_at = self.created_at

    @property
    def is_open(self) -> bool:
        return self.state not in {IncidentState.RESOLVED, IncidentState.POSTMORTEM}

    @property
    def time_to_detect_minutes(self) -> float | None:
        """Minutes between the incident's first signal and detection.

        The generator plants an anomaly at a known start; detectors stamp
        ``detected_at``. When the caller records the anomaly start in
        ``created_at`` (the convention used by the demo), this is the MTTD.
        """
        if self.detected_at is None:
            return None
        return (self.detected_at - self.created_at).total_seconds() / 60.0

    @property
    def time_to_resolve_minutes(self) -> float | None:
        if self.detected_at is None or self.resolved_at is None:
            return None
        return (self.resolved_at - self.detected_at).total_seconds() / 60.0


@dataclass(frozen=True)
class MitigationAction:
    """One deterministic mitigation step inside a playbook."""

    name: str  # traffic_shift | model_rollback | prompt_kill_switch | rate_limit_tighten
    description: str
    destructive: bool = False
    requires_approval: bool = False
    params: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Playbook:
    """A named, deterministic mitigation plan for one incident class."""

    playbook_id: str
    name: str
    trigger_metric: str
    min_severity: Severity
    owner: str
    actions: tuple[MitigationAction, ...]


@dataclass
class ActionResult:
    """Outcome of one mitigation action during an execution."""

    action: MitigationAction
    status: str  # planned | applied | blocked | skipped
    detail: str = ""


@dataclass
class ExecutionResult:
    """Outcome of running a playbook against an incident."""

    playbook_id: str
    incident_id: str
    dry_run: bool
    approved_by: str | None
    results: list[ActionResult] = field(default_factory=list)

    @property
    def applied(self) -> list[ActionResult]:
        return [r for r in self.results if r.status == "applied"]

    @property
    def blocked(self) -> list[ActionResult]:
        return [r for r in self.results if r.status == "blocked"]


@dataclass(frozen=True)
class OnCallMember:
    name: str
    contact: str  # e.g. "pager:alice" — synthetic, no real addresses
    role: str = "responder"


@dataclass(frozen=True)
class EscalationLevel:
    level: int
    members: tuple[OnCallMember, ...]
    ack_timeout_minutes: int


@dataclass(frozen=True)
class EscalationPolicy:
    """Escalation chain for an incident.

    ``mode`` is ``"24x7"`` (page at any hour) or ``"business_hours"``
    (page only inside the window; outside it, escalation waits for the
    next business hour).
    """

    policy_id: str
    name: str
    levels: tuple[EscalationLevel, ...]
    mode: str = "24x7"
    business_start_hour: int = 9
    business_end_hour: int = 17

    def __post_init__(self) -> None:
        if self.mode not in {"24x7", "business_hours"}:
            raise ValueError(f"unknown escalation mode: {self.mode!r}")
        if not self.levels:
            raise ValueError("escalation policy needs at least one level")
        if tuple(l.level for l in self.levels) != tuple(
            range(1, len(self.levels) + 1)
        ):
            raise ValueError("escalation levels must be 1..N in order")


@dataclass
class ActionItem:
    """A postmortem follow-up with an owner and a due date."""

    item_id: str
    title: str
    owner: str
    due_date: datetime
    status: str = "open"  # open | done
    source: str = ""


@dataclass
class Postmortem:
    """Generated postmortem for a resolved incident."""

    incident_id: str
    generated_at: datetime
    timeline: list[TimelineEvent]
    contributing_factors: list[str]
    action_items: list[ActionItem]
    mttd_minutes: float | None
    mttr_minutes: float | None
    cost: "CostRecord | None" = None
    summary: str = ""


@dataclass(frozen=True)
class CostRecord:
    """Cost-of-incident accounting for one incident."""

    incident_id: str
    wasted_tokens: float
    wasted_cost_usd: float
    downtime_minutes: float
    sla_credit_usd: float
    baseline_cost_per_min: float


@dataclass(frozen=True)
class AuditEntry:
    """One hash-chained audit log entry."""

    seq: int
    timestamp: datetime
    actor: str
    action: str
    payload: str  # canonical JSON string
    prev_hash: str
    entry_hash: str
