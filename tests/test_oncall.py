"""Tests for on-call rotation and escalation policy engine."""
from datetime import datetime, timedelta, timezone

import pytest

from airp.incidents import IncidentStore
from airp.models import Alert, EscalationLevel, EscalationPolicy, OnCallMember, Severity
from airp.oncall import EscalationEngine, Rotation, default_policy, next_business_hour_start

T0 = datetime(2026, 11, 2, 9, 0, tzinfo=timezone.utc)  # a Monday


def _incident(minute=0):
    store = IncidentStore()
    alert = Alert("ALT-0001", "s:m:d", "chat-assistant", "error_rate", "d",
                  0.3, 0.05, Severity.SEV2, T0 + timedelta(minutes=minute), "breach")
    return store.create_from_alert(alert)


def _rotation():
    members = (
        OnCallMember("alice", "pager:alice"),
        OnCallMember("bob", "pager:bob"),
        OnCallMember("carol", "pager:carol"),
    )
    return Rotation(members=members, start=T0, period_days=7)


def test_rotation_cycles_weekly():
    rotation = _rotation()
    assert rotation.member_on_call(T0).name == "alice"
    assert rotation.member_on_call(T0 + timedelta(days=6)).name == "alice"
    assert rotation.member_on_call(T0 + timedelta(days=7)).name == "bob"
    assert rotation.member_on_call(T0 + timedelta(days=21)).name == "alice"
    assert rotation.member_on_call(T0 - timedelta(days=1)).name == "alice"


def test_rotation_requires_members():
    with pytest.raises(ValueError):
        Rotation(members=(), start=T0)


def test_escalation_advances_on_ack_timeouts():
    engine = EscalationEngine(policy=default_policy())
    incident = _incident()
    assert engine.current_level(incident, now=T0 + timedelta(minutes=1)) == 1
    assert engine.current_level(incident, now=T0 + timedelta(minutes=5)) == 2
    assert engine.current_level(incident, now=T0 + timedelta(minutes=20)) == 3
    assert engine.current_level(incident, now=T0 + timedelta(minutes=500)) == 3


def test_ack_freezes_escalation_at_level_one():
    engine = EscalationEngine(policy=default_policy())
    incident = _incident()
    assert engine.current_level(incident, now=T0 + timedelta(minutes=500), acked=True) == 1
    assert engine.next_escalation_at(incident, now=T0, acked=True) is None


def test_next_escalation_times():
    engine = EscalationEngine(policy=default_policy())
    incident = _incident()
    assert engine.next_escalation_at(incident, now=T0) == T0 + timedelta(minutes=5)
    assert engine.next_escalation_at(incident, now=T0 + timedelta(minutes=6)) == T0 + timedelta(minutes=20)
    assert engine.next_escalation_at(incident, now=T0 + timedelta(minutes=21)) is None


def test_page_returns_members_and_next_escalation():
    engine = EscalationEngine(policy=default_policy(), rotation=_rotation())
    incident = _incident()
    page = engine.page(incident, now=T0 + timedelta(minutes=1))
    assert page["level"] == 1
    assert page["paged"] == ["alice"]
    assert page["next_escalation_at"] == T0 + timedelta(minutes=5)
    page2 = engine.page(incident, now=T0 + timedelta(minutes=10))
    assert page2["level"] == 2
    assert page2["paged"] == ["secondary-oncall"]


def test_business_hours_policy_defers_overnight():
    policy = EscalationPolicy(
        policy_id="biz",
        name="Business hours",
        levels=(
            EscalationLevel(1, (OnCallMember("a", "pager:a"),), 5),
            EscalationLevel(2, (OnCallMember("b", "pager:b"),), 15),
        ),
        mode="business_hours",
        business_start_hour=9,
        business_end_hour=17,
    )
    engine = EscalationEngine(policy=policy)
    incident = _incident()
    # 20:00 Monday — outside business hours: stays at level 1, next
    # escalation is the next business-hour start (09:00 Tuesday).
    night = datetime(2026, 11, 2, 20, 0, tzinfo=timezone.utc)
    assert engine.current_level(incident, now=night) == 1
    assert engine.next_escalation_at(incident, now=night) == datetime(
        2026, 11, 3, 9, 0, tzinfo=timezone.utc
    )
    # 10:00 Monday — inside hours: normal escalation.
    day = datetime(2026, 11, 2, 10, 0, tzinfo=timezone.utc)
    assert engine.next_escalation_at(incident, now=day) is None  # single level


def test_next_business_hour_start_skips_weekend():
    policy = EscalationPolicy(
        policy_id="biz",
        name="Business hours",
        levels=(EscalationLevel(1, (OnCallMember("a", "pager:a"),), 5),),
        mode="business_hours",
    )
    # Saturday 12:00 -> Monday 09:00.
    saturday = datetime(2026, 11, 7, 12, 0, tzinfo=timezone.utc)
    assert next_business_hour_start(saturday, policy) == datetime(
        2026, 11, 9, 9, 0, tzinfo=timezone.utc
    )


def test_invalid_policy_rejected():
    with pytest.raises(ValueError):
        EscalationPolicy(policy_id="x", name="x", levels=(), mode="24x7")
    with pytest.raises(ValueError):
        EscalationPolicy(
            policy_id="x",
            name="x",
            levels=(EscalationLevel(2, (OnCallMember("a", "p"),), 5),),
            mode="24x7",
        )
    with pytest.raises(ValueError):
        EscalationPolicy(
            policy_id="x",
            name="x",
            levels=(EscalationLevel(1, (OnCallMember("a", "p"),), 5),),
            mode="whenever",
        )


def test_severity_ack_targets():
    assert Severity.SEV1.ack_target_minutes == 5
    assert Severity.SEV1.resolution_target_minutes == 60
    assert Severity.SEV4.ack_target_minutes == 240
    assert Severity.worse(Severity.SEV2, Severity.SEV3) == Severity.SEV2
