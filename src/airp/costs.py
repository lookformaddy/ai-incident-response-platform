"""Cost-of-incident accounting and MTTD/MTTR/MTBF SLO reporting.

Costs are computed from the synthetic telemetry window covering the
incident: wasted tokens are the token volume above the healthy baseline,
wasted spend is that volume at the configured token price, and SLA
credits follow a simple downtime tier table. SLO reporting aggregates
MTTD (detect), MTTR (resolve), MTBF (time between incidents) and
per-severity counts, and flags each against its target.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from .models import CostRecord, Incident, IncidentState, Severity, TelemetryPoint
from .telemetry import BASELINES

# SLA credit tiers: (downtime minutes threshold, credit % of monthly spend)
SLA_CREDIT_TIERS: tuple[tuple[float, float], ...] = (
    (240.0, 0.25),
    (60.0, 0.10),
    (15.0, 0.05),
)

MTTD_TARGET_MINUTES = 15.0
MTTR_TARGET_MINUTES = 240.0


@dataclass(frozen=True)
class CostCalculator:
    """Wasted-token and SLA-credit accounting for one incident."""

    token_price_per_1k: float = 0.002  # USD per 1,000 tokens
    monthly_spend_usd: float = 10_000.0
    baseline_tokens_per_min: float = BASELINES["tokens_per_min"]
    baseline_cost_per_min: float = BASELINES["cost_per_min"]

    def sla_credit(self, downtime_minutes: float) -> float:
        for threshold, pct in SLA_CREDIT_TIERS:
            if downtime_minutes > threshold:
                return round(self.monthly_spend_usd * pct, 2)
        return 0.0

    def cost_for_incident(
        self,
        incident: Incident,
        points: list[TelemetryPoint],
        *,
        now: datetime | None = None,
    ) -> CostRecord:
        """Cost of ``incident`` from telemetry in its window.

        The window runs from detection to resolution (or ``now`` while the
        incident is still open). Wasted tokens are the per-minute excess
        over the healthy baseline, summed over the window; the same window
        is used for downtime.
        """
        start = incident.detected_at or incident.created_at
        end = incident.resolved_at or now or start
        window = [
            p
            for p in points
            if p.service == incident.service and start <= p.timestamp <= end
        ]
        wasted_tokens = sum(
            max(0.0, p.tokens_per_min - self.baseline_tokens_per_min)
            for p in window
        )
        wasted_cost = wasted_tokens / 1000.0 * self.token_price_per_1k
        downtime = max(0.0, (end - start).total_seconds() / 60.0)
        return CostRecord(
            incident_id=incident.incident_id,
            wasted_tokens=round(wasted_tokens, 2),
            wasted_cost_usd=round(wasted_cost, 2),
            downtime_minutes=round(downtime, 2),
            sla_credit_usd=self.sla_credit(downtime),
            baseline_cost_per_min=self.baseline_cost_per_min,
        )


@dataclass
class SLOReport:
    """Aggregate reliability report over a set of incidents."""

    incident_count: int
    mttd_minutes: float | None
    mttr_minutes: float | None
    mtbf_minutes: float | None
    availability_pct: float | None
    by_severity: dict[str, int]
    mttd_within_target: bool
    mttr_within_target: bool
    total_wasted_cost_usd: float
    total_sla_credit_usd: float

    def as_dict(self) -> dict:
        return {
            "incident_count": self.incident_count,
            "mttd_minutes": self.mttd_minutes,
            "mttr_minutes": self.mttr_minutes,
            "mtbf_minutes": self.mtbf_minutes,
            "availability_pct": self.availability_pct,
            "by_severity": self.by_severity,
            "mttd_within_target": self.mttd_within_target,
            "mttr_within_target": self.mttr_within_target,
            "total_wasted_cost_usd": self.total_wasted_cost_usd,
            "total_sla_credit_usd": self.total_sla_credit_usd,
        }


def _mean(values: list[float]) -> float | None:
    return round(sum(values) / len(values), 2) if values else None


def compute_slo(
    incidents: list[Incident],
    costs: list[CostRecord],
    *,
    window: timedelta | None = None,
    now: datetime | None = None,
) -> SLOReport:
    """Aggregate MTTD/MTTR/MTBF and availability over ``incidents``.

    MTBF is the mean gap between consecutive incident detections.
    Availability is 1 - (total downtime / window length); when no window
    is given it spans first detection to last resolution (or ``now``).
    """
    resolved = [i for i in incidents if i.state in {IncidentState.RESOLVED, IncidentState.POSTMORTEM}]
    mttd = _mean(
        [i.time_to_detect_minutes for i in incidents if i.time_to_detect_minutes is not None]
    )
    mttr = _mean(
        [i.time_to_resolve_minutes for i in resolved if i.time_to_resolve_minutes is not None]
    )
    detections = sorted(
        i.detected_at for i in incidents if i.detected_at is not None
    )
    gaps = [
        (b - a).total_seconds() / 60.0 for a, b in zip(detections, detections[1:])
    ]
    mtbf = _mean(gaps)
    by_severity = {s.value: 0 for s in Severity}
    for incident in incidents:
        by_severity[incident.severity.value] += 1
    availability: float | None = None
    if incidents:
        end = now or max(
            (i.resolved_at or i.detected_at) for i in incidents if i.detected_at
        )
        start = min(i.detected_at for i in incidents if i.detected_at)
        if window is not None:
            start = end - window
        span = (end - start).total_seconds() / 60.0
        if span > 0:
            # Union of [detected, resolved] intervals inside the period:
            # overlapping incidents share downtime, they do not add it.
            intervals = sorted(
                (
                    max(i.detected_at, start),
                    min(i.resolved_at or end, end),
                )
                for i in incidents
                if i.detected_at is not None
            )
            union_minutes = 0.0
            cur_start = cur_end = None
            for s, e in intervals:
                if e <= s:
                    continue
                if cur_start is None:
                    cur_start, cur_end = s, e
                elif s <= cur_end:
                    cur_end = max(cur_end, e)
                else:
                    union_minutes += (cur_end - cur_start).total_seconds() / 60.0
                    cur_start, cur_end = s, e
            if cur_start is not None:
                union_minutes += (cur_end - cur_start).total_seconds() / 60.0
            availability = round(max(0.0, 1.0 - union_minutes / span) * 100.0, 3)
    return SLOReport(
        incident_count=len(incidents),
        mttd_minutes=mttd,
        mttr_minutes=mttr,
        mtbf_minutes=mtbf,
        availability_pct=availability,
        by_severity=by_severity,
        mttd_within_target=mttd is not None and mttd <= MTTD_TARGET_MINUTES,
        mttr_within_target=mttr is not None and mttr <= MTTR_TARGET_MINUTES,
        total_wasted_cost_usd=round(sum(c.wasted_cost_usd for c in costs), 2),
        total_sla_credit_usd=round(sum(c.sla_credit_usd for c in costs), 2),
    )
