"""Tests for the telemetry generator: determinism, bounds, anomalies."""
from datetime import datetime, timezone

import pytest

from airp.telemetry import Anomaly, TelemetryGenerator, BASELINES

START = datetime(2026, 11, 5, 9, 0, tzinfo=timezone.utc)


def test_generate_is_deterministic_for_a_seed():
    a = TelemetryGenerator(seed=7).generate(30)
    b = TelemetryGenerator(seed=7).generate(30)
    assert a == b
    c = TelemetryGenerator(seed=8).generate(30)
    assert a != c


def test_generate_shape_and_ordering():
    points = TelemetryGenerator(seed=7, services=("chat-assistant", "doc-summarizer")).generate(10)
    assert len(points) == 20
    timestamps = [p.timestamp for p in points]
    assert timestamps == sorted(timestamps)
    assert points[0].timestamp == START
    assert {p.service for p in points} == {"chat-assistant", "doc-summarizer"}


def test_rates_are_bounded_and_non_negative():
    points = TelemetryGenerator(seed=3).generate(60)
    for p in points:
        assert 0.0 <= p.error_rate <= 1.0
        assert 0.0 <= p.guardrail_hit_rate <= 1.0
        assert 0.0 <= p.drift_score <= 1.0
        assert p.latency_p95_ms >= 0
        assert p.cost_per_min >= 0
        assert p.tokens_per_min >= 0


def test_planted_anomaly_raises_the_metric_only_in_window():
    anomaly = Anomaly("latency_p95_ms", start_minute=5, duration_minutes=3, multiplier=10.0, service="chat-assistant")
    points = TelemetryGenerator(seed=7, anomalies=(anomaly,)).generate(10)
    chat = [p for p in points if p.service == "chat-assistant"]
    doc = [p for p in points if p.service == "doc-summarizer"]
    for i, p in enumerate(chat):
        if 5 <= i < 8:
            assert p.latency_p95_ms > BASELINES["latency_p95_ms"] * 5
        else:
            assert p.latency_p95_ms < BASELINES["latency_p95_ms"] * 3
    assert all(p.latency_p95_ms < BASELINES["latency_p95_ms"] * 3 for p in doc)


def test_unknown_metric_raises():
    point = TelemetryGenerator(seed=7).generate(1)[0]
    with pytest.raises(ValueError):
        point.metric("nope")


def test_window_filters_by_time():
    gen = TelemetryGenerator(seed=7)
    points = gen.generate(30)
    start = START
    end = datetime(2026, 11, 5, 9, 10, tzinfo=timezone.utc)
    window = gen.window(points, start, end)
    assert len(window) == 10 * len(gen.services)
    assert all(start <= p.timestamp < end for p in window)
