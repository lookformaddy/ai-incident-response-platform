"""Tests for postmortem generation, cost accounting, and SLO reporting."""
from datetime import datetime, timedelta, timezone

import pytest

from airp.audit import AuditLog
from airp.costs import CostCalculator, compute_slo
from airp.incidents import IncidentStore
from airp.models import Alert, IncidentState, Severity, TelemetryPoint
from airp.postmortem import generate_postmortem

T0 = datetime(2026, 11, 5, 9, 0, tzinfo=timezone.utc)


def _resolved_incident(severity=Severity.SEV2, metric="error_rate"):
    store = IncidentStore()
    alert = Alert("ALT-0001", f"chat-assistant:{metric}:det", "chat-assistant",
                  metric, "det", 0.3, 0.05, severity, T0,
                  f"{metric} 0.3 breached 0.05")
    incident = store.create_from_alert(alert)
    store.transition(incident.incident_id, IncidentState.TRIAGED, actor="oncall", at=T0 + timedelta(minutes=5))
    store.transition(incident.incident_id, IncidentState.MITIGATING, actor="oncall", at=T0 + timedelta(minutes=10))
    store.transition(incident.incident_id, IncidentState.RESOLVED, actor="oncall", at=T0 + timedelta(minutes=70))
    return store, incident


def _points(minutes=71, tokens=60_000.0):
    return [
        TelemetryPoint(
            timestamp=T0 + timedelta(minutes=m),
            service="chat-assistant",
            error_rate=0.1,
            latency_p95_ms=900.0,
            cost_per_min=3.0,
            guardrail_hit_rate=0.01,
            drift_score=0.1,
            tokens_per_min=tokens,
        )
        for m in range(minutes)
    ]


def test_postmortem_requires_resolved_incident():
    store = IncidentStore()
    alert = Alert("ALT-0001", "s:m:d", "chat-assistant", "error_rate", "d",
                  0.3, 0.05, Severity.SEV3, T0, "breach")
    incident = store.create_from_alert(alert)
    with pytest.raises(ValueError, match="requires a resolved incident"):
        generate_postmortem(incident)


def test_postmortem_reconstructs_timeline_and_factors():
    _, incident = _resolved_incident()
    audit = AuditLog()
    audit.append("detector", "incident_detected", {"incident_id": incident.incident_id}, timestamp=T0)
    audit.append("oncall", "playbook_executed", {"incident_id": incident.incident_id}, timestamp=T0 + timedelta(minutes=12))
    pm = generate_postmortem(incident, audit)
    assert pm.incident_id == incident.incident_id
    assert pm.mttd_minutes == 0.0
    assert pm.mttr_minutes == 70.0
    assert len(pm.timeline) == 6  # 4 lifecycle events + 2 audit entries
    assert any("Detector fired" in f for f in pm.contributing_factors)
    assert any("Detection took" in f for f in pm.contributing_factors)
    assert pm.action_items  # at least the metric item + playbook review
    assert all(a.status == "open" for a in pm.action_items)


def test_postmortem_action_items_have_owners_and_due_dates():
    _, incident = _resolved_incident(severity=Severity.SEV2)
    pm = generate_postmortem(incident)
    error_item = next(a for a in pm.action_items if a.source == "metric:error_rate")
    assert error_item.owner == "ml-platform-oncall"
    assert error_item.due_date == T0 + timedelta(minutes=70, days=7)
    assert "SEV2" in pm.summary


def test_postmortem_sev4_due_date_is_14_days():
    _, incident = _resolved_incident(severity=Severity.SEV4)
    pm = generate_postmortem(incident)
    assert pm.action_items[0].due_date == T0 + timedelta(minutes=70, days=14)


def test_cost_accounting_wasted_tokens_and_sla_credit():
    _, incident = _resolved_incident()
    calculator = CostCalculator()
    cost = calculator.cost_for_incident(incident, _points())
    # 71 minutes x 12,000 excess tokens = 852,000 wasted tokens.
    assert cost.wasted_tokens == pytest.approx(71 * 12_000.0)
    assert cost.wasted_cost_usd == pytest.approx(round(852_000 / 1000 * 0.002, 2))
    assert cost.downtime_minutes == 70.0
    # 70 minutes of downtime -> 10% tier on $10,000 monthly spend.
    assert cost.sla_credit_usd == 1000.0


def test_sla_credit_tiers():
    calculator = CostCalculator()
    assert calculator.sla_credit(10.0) == 0.0
    assert calculator.sla_credit(30.0) == 500.0
    assert calculator.sla_credit(100.0) == 1000.0
    assert calculator.sla_credit(300.0) == 2500.0


def test_cost_is_zero_when_volume_is_at_baseline():
    _, incident = _resolved_incident()
    calculator = CostCalculator()
    cost = calculator.cost_for_incident(incident, _points(tokens=48_000.0))
    assert cost.wasted_tokens == 0.0
    assert cost.wasted_cost_usd == 0.0


def test_slo_report_aggregates_mttd_mttr_mtbf():
    store1, i1 = _resolved_incident()
    store2 = IncidentStore()
    alert = Alert("ALT-0002", "s:m:d", "chat-assistant", "error_rate", "d",
                  0.3, 0.05, Severity.SEV3, T0 + timedelta(minutes=120), "breach")
    i2 = store2.create_from_alert(alert)
    store2.transition(i2.incident_id, IncidentState.TRIAGED, actor="x", at=T0 + timedelta(minutes=125))
    store2.transition(i2.incident_id, IncidentState.MITIGATING, actor="x", at=T0 + timedelta(minutes=130))
    store2.transition(i2.incident_id, IncidentState.RESOLVED, actor="x", at=T0 + timedelta(minutes=180))
    incidents = [i1, i2]
    report = compute_slo(incidents, [], now=T0 + timedelta(minutes=180))
    assert report.incident_count == 2
    assert report.mttd_minutes == 0.0
    assert report.mttr_minutes == pytest.approx((70.0 + 60.0) / 2)
    assert report.mtbf_minutes == 120.0
    assert report.by_severity == {"SEV1": 0, "SEV2": 1, "SEV3": 1, "SEV4": 0}
    assert report.mttd_within_target is True
    assert report.mttr_within_target is True


def test_slo_availability_uses_union_of_overlapping_incidents():
    # Two incidents overlapping almost entirely: union downtime is 70 min
    # of a 120-min window, not the 120 min a naive sum would give.
    _, i1 = _resolved_incident()
    store2 = IncidentStore()
    alert = Alert("ALT-0002", "s:m:d", "chat-assistant", "error_rate", "d",
                  0.3, 0.05, Severity.SEV3, T0 + timedelta(minutes=10), "breach")
    i2 = store2.create_from_alert(alert)
    store2.transition(i2.incident_id, IncidentState.TRIAGED, actor="x", at=T0 + timedelta(minutes=15))
    store2.transition(i2.incident_id, IncidentState.MITIGATING, actor="x", at=T0 + timedelta(minutes=20))
    store2.transition(i2.incident_id, IncidentState.RESOLVED, actor="x", at=T0 + timedelta(minutes=70))
    report = compute_slo(
        [i1, i2], [], window=timedelta(minutes=120), now=T0 + timedelta(minutes=120)
    )
    assert report.availability_pct == pytest.approx(41.667, abs=0.01)


def test_slo_report_empty_is_safe():
    report = compute_slo([], [])
    assert report.incident_count == 0
    assert report.mttd_minutes is None
    assert report.mttr_minutes is None
    assert report.mtbf_minutes is None
    assert report.availability_pct is None
    assert report.mttd_within_target is False
