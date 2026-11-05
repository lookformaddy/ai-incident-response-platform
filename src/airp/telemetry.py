"""Deterministic synthetic telemetry for production AI services.

The generator produces one-minute telemetry points (error rate, latency,
cost, guardrail hits, drift, token volume) for a small fleet of generic
AI services. Anomalies are planted explicitly — a caller says "latency
spikes 4x on the chat service from minute 30 for 20 minutes" — so demos
and tests are reproducible from a seed. No network, no real providers.
"""
from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .models import METRICS, TelemetryPoint

# Healthy baselines per metric (per service, per minute).
BASELINES: dict[str, float] = {
    "error_rate": 0.005,
    "latency_p95_ms": 420.0,
    "cost_per_min": 1.80,
    "guardrail_hit_rate": 0.002,
    "drift_score": 0.08,
    "tokens_per_min": 48_000.0,
}

# Relative noise (std as a fraction of the baseline) per metric.
NOISE: dict[str, float] = {
    "error_rate": 0.25,
    "latency_p95_ms": 0.08,
    "cost_per_min": 0.10,
    "guardrail_hit_rate": 0.30,
    "drift_score": 0.15,
    "tokens_per_min": 0.06,
}

DEFAULT_SERVICES: tuple[str, ...] = (
    "chat-assistant",
    "doc-summarizer",
    "support-triage",
)


@dataclass(frozen=True)
class Anomaly:
    """A planted anomaly: one metric, one service, a time window."""

    metric: str
    start_minute: int
    duration_minutes: int
    multiplier: float
    service: str | None = None  # None = all services

    def applies_to(self, service: str, minute: int) -> bool:
        if self.service is not None and self.service != service:
            return False
        return self.start_minute <= minute < self.start_minute + self.duration_minutes


@dataclass
class TelemetryGenerator:
    """Seeded generator of per-minute synthetic telemetry."""

    seed: int = 7
    services: tuple[str, ...] = DEFAULT_SERVICES
    start: datetime = field(
        default_factory=lambda: datetime(2026, 11, 5, 9, 0, tzinfo=timezone.utc)
    )
    anomalies: tuple[Anomaly, ...] = ()

    def generate(self, minutes: int) -> list[TelemetryPoint]:
        """Generate ``minutes`` of telemetry per service, time-ordered."""
        rng = random.Random(self.seed)
        points: list[TelemetryPoint] = []
        for minute in range(minutes):
            ts = self.start + timedelta(minutes=minute)
            for service in self.services:
                values: dict[str, float] = {}
                for metric in METRICS:
                    base = BASELINES[metric]
                    value = base * (1.0 + rng.gauss(0.0, NOISE[metric]))
                    for anomaly in self.anomalies:
                        if anomaly.metric == metric and anomaly.applies_to(
                            service, minute
                        ):
                            value *= anomaly.multiplier
                    # Rates and drift are fractions in [0, 1]; everything else >= 0.
                    if metric in {"error_rate", "guardrail_hit_rate", "drift_score"}:
                        value = min(max(value, 0.0), 1.0)
                    else:
                        value = max(value, 0.0)
                    values[metric] = round(value, 4)
                points.append(
                    TelemetryPoint(
                        timestamp=ts,
                        service=service,
                        error_rate=values["error_rate"],
                        latency_p95_ms=values["latency_p95_ms"],
                        cost_per_min=values["cost_per_min"],
                        guardrail_hit_rate=values["guardrail_hit_rate"],
                        drift_score=values["drift_score"],
                        tokens_per_min=values["tokens_per_min"],
                    )
                )
        return points

    def window(
        self, points: list[TelemetryPoint], start: datetime, end: datetime
    ) -> list[TelemetryPoint]:
        """Points inside [start, end)."""
        return [p for p in points if start <= p.timestamp < end]


def baseline_cost_per_min(service: str = "") -> float:
    """Reference healthy cost rate, used by cost accounting."""
    _ = service  # baselines are fleet-wide in the synthetic model
    return BASELINES["cost_per_min"]


def describe_anomaly(anomaly: Anomaly) -> str:
    scope = anomaly.service or "all services"
    return (
        f"{anomaly.metric} x{anomaly.multiplier:g} on {scope} "
        f"minutes {anomaly.start_minute}–"
        f"{anomaly.start_minute + anomaly.duration_minutes - 1}"
    )


def _drift_trend(minutes: int, start: float = 0.08, slope: float = 0.004) -> list[float]:
    """Helper: a slowly rising drift curve (used by tests, not the demo)."""
    return [round(min(start + slope * m, 1.0), 4) for m in range(minutes)]


__all__ = [
    "Anomaly",
    "BASELINES",
    "DEFAULT_SERVICES",
    "NOISE",
    "TelemetryGenerator",
    "baseline_cost_per_min",
    "describe_anomaly",
]
