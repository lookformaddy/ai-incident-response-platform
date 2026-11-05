"""Tests for the incident store: state machine, dedup/merge, lifecycle."""
from datetime import datetime, timedelta, timezone

import pytest

from airp.incidents import IncidentStore
from airp.models import Alert, IncidentState, Severity

T0 = datetime(2026, 11, 5, 9, 0, tzinfo=timezone.utc)


def _alert(minute=0, severity=Severity.SEV3, metric="error_rate", detector="err-high", service="chat-assistant"):
    return Alert(
        alert_id=f"ALT-{minute:04d}",
        signature=f"{service}:{metric}:{detector}",
        service=service,
        metric=metric,
        detector=detector,
        value=0.09,
        threshold=0.05,
        severity=severity,
        created_at=T0 + timedelta(minutes=minute),
        message="error_rate breached",
    )


def test_create_from_alert_opens_detected_incident():
    store = IncidentStore()
    incident = store.create_from_alert(_alert())
    assert incident.incident_id == "INC-0001"
    assert incident.state == IncidentState.DETECTED
    assert incident.severity == Severity.SEV3
    assert incident.alert_ids == ["ALT-0000"]
    assert incident.timeline[0].event == "detected"


def test_full_lifecycle_transitions():
    store = IncidentStore()
    incident = store.create_from_alert(_alert())
    store.transition(incident.incident_id, IncidentState.TRIAGED, actor="oncall", at=T0 + timedelta(minutes=2))
    store.transition(incident.incident_id, IncidentState.MITIGATING, actor="oncall", at=T0 + timedelta(minutes=5))
    store.transition(incident.incident_id, IncidentState.RESOLVED, actor="oncall", at=T0 + timedelta(minutes=40))
    store.transition(incident.incident_id, IncidentState.POSTMORTEM, actor="oncall", at=T0 + timedelta(minutes=60))
    assert incident.state == IncidentState.POSTMORTEM
    assert incident.triaged_at == T0 + timedelta(minutes=2)
    assert incident.resolved_at == T0 + timedelta(minutes=40)
    assert incident.time_to_resolve_minutes == 40.0
    assert len(incident.timeline) == 5


def test_sev1_may_skip_triage():
    store = IncidentStore()
    incident = store.create_from_alert(_alert(severity=Severity.SEV1))
    store.transition(incident.incident_id, IncidentState.MITIGATING, actor="oncall")
    assert incident.state == IncidentState.MITIGATING


def test_illegal_transitions_raise():
    store = IncidentStore()
    incident = store.create_from_alert(_alert())
    with pytest.raises(ValueError, match="illegal transition"):
        store.transition(incident.incident_id, IncidentState.RESOLVED, actor="oncall")
    with pytest.raises(ValueError, match="illegal transition"):
        store.transition(incident.incident_id, IncidentState.DETECTED, actor="oncall")
    store.transition(incident.incident_id, IncidentState.TRIAGED, actor="oncall")
    with pytest.raises(ValueError, match="illegal transition"):
        store.transition(incident.incident_id, IncidentState.RESOLVED, actor="oncall")


def test_unknown_incident_raises():
    store = IncidentStore()
    with pytest.raises(KeyError):
        store.get("INC-9999")
    with pytest.raises(KeyError):
        store.transition("INC-9999", IncidentState.TRIAGED, actor="oncall")


def test_duplicate_alerts_merge_into_one_incident():
    store = IncidentStore()
    incident, merged = store.ingest(_alert(minute=0))
    assert not merged
    same, merged = store.ingest(_alert(minute=10))
    assert merged
    assert same is incident
    assert len(store) == 1
    assert incident.merged_count == 1
    assert incident.alert_ids == ["ALT-0000", "ALT-0010"]


def test_merge_escalates_severity_to_the_worst_alert():
    store = IncidentStore()
    incident, _ = store.ingest(_alert(minute=0, severity=Severity.SEV3))
    store.ingest(_alert(minute=5, severity=Severity.SEV1))
    assert incident.severity == Severity.SEV1


def test_different_signature_opens_a_new_incident():
    store = IncidentStore()
    store.ingest(_alert(minute=0, metric="error_rate"))
    store.ingest(_alert(minute=5, metric="latency_p95_ms", detector="lat-high"))
    assert len(store) == 2


def test_merge_window_expiry_opens_a_new_incident():
    store = IncidentStore()
    store.ingest(_alert(minute=0))
    store.ingest(_alert(minute=61))
    assert len(store) == 2


def test_resolved_incidents_do_not_absorb_new_alerts():
    store = IncidentStore()
    incident, _ = store.ingest(_alert(minute=0))
    for state in (IncidentState.TRIAGED, IncidentState.MITIGATING, IncidentState.RESOLVED):
        store.transition(incident.incident_id, state, actor="oncall")
    new_incident, merged = store.ingest(_alert(minute=10))
    assert not merged
    assert new_incident is not incident
    assert len(store) == 2


def test_open_and_by_severity_filters():
    store = IncidentStore()
    i1, _ = store.ingest(_alert(minute=0, severity=Severity.SEV2))
    i2, _ = store.ingest(_alert(minute=1, metric="latency_p95_ms", detector="lat-high"))
    store.transition(i1.incident_id, IncidentState.TRIAGED, actor="x")
    store.transition(i1.incident_id, IncidentState.MITIGATING, actor="x")
    store.transition(i1.incident_id, IncidentState.RESOLVED, actor="x")
    assert store.open() == [i2]
    assert store.by_severity(Severity.SEV3) == [i2]
