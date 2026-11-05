"""Tests for detectors: threshold rules, z-score, storm suppression."""
from datetime import datetime, timedelta, timezone

from airp.detectors import (
    AlertStormSuppressor,
    DetectorEngine,
    ThresholdRule,
    ZScoreDetector,
    default_engine,
)
from airp.models import Severity, TelemetryPoint

T0 = datetime(2026, 11, 5, 9, 0, tzinfo=timezone.utc)


def _points(metric_values, service="chat-assistant", metric="error_rate", start=T0):
    points = []
    for i, value in enumerate(metric_values):
        kwargs = {
            "timestamp": start + timedelta(minutes=i),
            "service": service,
            "error_rate": 0.005,
            "latency_p95_ms": 420.0,
            "cost_per_min": 1.8,
            "guardrail_hit_rate": 0.002,
            "drift_score": 0.08,
            "tokens_per_min": 48_000.0,
        }
        kwargs[metric] = value
        points.append(TelemetryPoint(**kwargs))
    return points


def test_threshold_rule_fires_only_after_sustained_breach():
    engine = DetectorEngine(rules=(ThresholdRule("err", "error_rate", 0.05, sustained_minutes=3),))
    assert engine.evaluate(_points([0.01, 0.09, 0.09])) == []
    alerts = engine.evaluate(_points([0.09]))
    assert len(alerts) == 1
    assert alerts[0].severity == Severity.SEV3
    assert alerts[0].value == 0.09


def test_threshold_rule_resets_streak_on_recovery():
    engine = DetectorEngine(rules=(ThresholdRule("err", "error_rate", 0.05, sustained_minutes=3),))
    assert engine.evaluate(_points([0.09, 0.09, 0.01, 0.09, 0.09])) == []
    assert len(engine.evaluate(_points([0.09], start=T0 + timedelta(minutes=5)))) == 1


def test_threshold_rule_direction_below():
    engine = DetectorEngine(rules=(ThresholdRule("low", "tokens_per_min", 1000.0, sustained_minutes=2, direction="below"),))
    assert len(engine.evaluate(_points([500.0, 400.0], metric="tokens_per_min"))) == 1


def test_invalid_rule_rejected():
    import pytest

    with pytest.raises(ValueError):
        ThresholdRule("x", "nope", 1.0)
    with pytest.raises(ValueError):
        ThresholdRule("x", "error_rate", 1.0, direction="sideways")
    with pytest.raises(ValueError):
        ThresholdRule("x", "error_rate", 1.0, sustained_minutes=0)


def test_zscore_detector_catches_slow_burn():
    detector = ZScoreDetector("lat-z", "latency_p95_ms", window=20, z_threshold=4.0, min_history=10)
    engine = DetectorEngine(z_detectors=(detector,))
    # 20 minutes of near-flat baseline (small jitter so std > 0), then a 3x jump.
    values = [420.0 + (i % 5) * 2.0 for i in range(20)] + [1300.0]
    alerts = engine.evaluate(_points(values, metric="latency_p95_ms"))
    assert len(alerts) == 1
    assert "z-score" in alerts[0].message


def test_zscore_detector_needs_history():
    detector = ZScoreDetector("lat-z", "latency_p95_ms", window=20, z_threshold=4.0, min_history=10)
    engine = DetectorEngine(z_detectors=(detector,))
    assert engine.evaluate(_points([5000.0] * 3, metric="latency_p95_ms")) == []


def test_storm_suppressor_cooldown_and_burst_cap():
    sup = AlertStormSuppressor(cooldown_minutes=15, max_per_hour=2)
    assert sup.allow("sig", T0)
    sup.record("sig", T0)
    assert not sup.allow("sig", T0 + timedelta(minutes=5))
    assert sup.suppressed_count["sig"] == 1
    assert sup.allow("sig", T0 + timedelta(minutes=16))
    sup.record("sig", T0 + timedelta(minutes=16))
    # Third alert inside the hour: burst cap hit.
    assert not sup.allow("sig", T0 + timedelta(minutes=32))
    # After an hour the window slides and it is allowed again.
    assert sup.allow("sig", T0 + timedelta(minutes=61))


def test_engine_suppresses_repeat_alerts_from_sustained_breach():
    engine = default_engine()
    points = _points([0.30] * 20, metric="error_rate")
    alerts = engine.evaluate(points)
    # err-critical (SEV1) and err-high (SEV2) each fire once; the cooldown
    # suppresses every repeat until it expires at minute 15, then each
    # rule re-fires once for the still-sustained breach (minute 17).
    assert len(alerts) == 4
    assert {a.severity for a in alerts} == {Severity.SEV1, Severity.SEV2}
    assert alerts[0].severity == Severity.SEV1
    assert [a.created_at.minute for a in alerts] == [1, 2, 17, 17]


def test_default_engine_detects_all_five_failure_modes():
    from airp.telemetry import Anomaly, TelemetryGenerator

    anomalies = (
        Anomaly("error_rate", 5, 10, 30.0, service="chat-assistant"),
        Anomaly("latency_p95_ms", 20, 10, 5.0, service="chat-assistant"),
        Anomaly("cost_per_min", 35, 10, 6.0, service="chat-assistant"),
        Anomaly("guardrail_hit_rate", 50, 10, 40.0, service="chat-assistant"),
        Anomaly("drift_score", 65, 10, 6.0, service="chat-assistant"),
    )
    points = TelemetryGenerator(seed=7, anomalies=anomalies).generate(80)
    alerts = default_engine().evaluate(points)
    metrics = {a.metric for a in alerts}
    assert metrics == {"error_rate", "latency_p95_ms", "cost_per_min", "guardrail_hit_rate", "drift_score"}
