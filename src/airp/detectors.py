"""Detectors over synthetic telemetry: rule-based + statistical.

Two detector families, both deterministic and configurable:

* :class:`ThresholdRule` — a metric must breach a threshold for
  ``sustained_minutes`` consecutive minutes before firing. This is what
  keeps a single noisy minute from paging anyone.
* :class:`ZScoreDetector` — a rolling mean/std baseline per
  (service, metric); fires when the current value is ``z_threshold``
  standard deviations above the baseline. Catches drift and slow
  degradation that a fixed threshold would miss.

:class:`DetectorEngine` runs both families over a time-ordered stream and
applies :class:`AlertStormSuppressor`: a per-signature cooldown plus a
burst cap, so a flapping metric produces one page and a count, not a
hundred pages.
"""
from __future__ import annotations

import math
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime

from .models import METRICS, Alert, Severity, TelemetryPoint


@dataclass(frozen=True)
class ThresholdRule:
    """Fire when ``metric`` stays beyond ``threshold`` for N minutes."""

    rule_id: str
    metric: str
    threshold: float
    sustained_minutes: int = 3
    severity: Severity = Severity.SEV3
    direction: str = "above"  # "above" | "below"

    def __post_init__(self) -> None:
        if self.metric not in METRICS:
            raise ValueError(f"unknown metric: {self.metric!r}")
        if self.direction not in {"above", "below"}:
            raise ValueError(f"unknown direction: {self.direction!r}")
        if self.sustained_minutes < 1:
            raise ValueError("sustained_minutes must be >= 1")

    def breached(self, value: float) -> bool:
        return value > self.threshold if self.direction == "above" else value < self.threshold


@dataclass(frozen=True)
class ZScoreDetector:
    """Fire when a value is ``z_threshold`` std above its rolling baseline."""

    detector_id: str
    metric: str
    window: int = 30
    z_threshold: float = 4.0
    min_history: int = 10
    high_severity_z: float = 6.0

    def __post_init__(self) -> None:
        if self.metric not in METRICS:
            raise ValueError(f"unknown metric: {self.metric!r}")
        if self.window < self.min_history:
            raise ValueError("window must be >= min_history")

    def severity_for(self, z: float) -> Severity:
        return Severity.SEV2 if z >= self.high_severity_z else Severity.SEV3


class AlertStormSuppressor:
    """Per-signature cooldown + burst cap.

    * ``cooldown_minutes``: after an alert fires, the same signature is
      silent for this long (the repeat is counted, not re-paged).
    * ``max_per_hour``: hard cap of alerts per signature per rolling hour;
      excess is counted as suppressed.
    """

    def __init__(self, cooldown_minutes: int = 15, max_per_hour: int = 4) -> None:
        self.cooldown_minutes = cooldown_minutes
        self.max_per_hour = max_per_hour
        self._last_fired: dict[str, datetime] = {}
        self._fired_times: dict[str, deque[datetime]] = defaultdict(deque)
        self.suppressed_count: dict[str, int] = defaultdict(int)

    def allow(self, signature: str, now: datetime) -> bool:
        last = self._last_fired.get(signature)
        if last is not None:
            gap = (now - last).total_seconds() / 60.0
            if gap < self.cooldown_minutes:
                self.suppressed_count[signature] += 1
                return False
        times = self._fired_times[signature]
        while times and (now - times[0]).total_seconds() > 3600:
            times.popleft()
        if len(times) >= self.max_per_hour:
            self.suppressed_count[signature] += 1
            return False
        return True

    def record(self, signature: str, now: datetime) -> None:
        self._last_fired[signature] = now
        self._fired_times[signature].append(now)


@dataclass
class DetectorEngine:
    """Stateful engine: rules + z-score detectors + storm suppression."""

    rules: tuple[ThresholdRule, ...] = ()
    z_detectors: tuple[ZScoreDetector, ...] = ()
    suppressor: AlertStormSuppressor = field(default_factory=AlertStormSuppressor)
    _rule_streaks: dict[str, int] = field(default_factory=dict, init=False)
    _history: dict[tuple[str, str], deque[float]] = field(
        default_factory=dict, init=False
    )
    _counter: int = field(default=0, init=False)

    def _next_id(self) -> str:
        self._counter += 1
        return f"ALT-{self._counter:04d}"

    def evaluate(self, points: list[TelemetryPoint]) -> list[Alert]:
        """Run detectors over time-ordered points; returns fired alerts."""
        alerts: list[Alert] = []
        for point in sorted(points, key=lambda p: (p.timestamp, p.service)):
            alerts.extend(self._evaluate_point(point))
        return alerts

    def _evaluate_point(self, point: TelemetryPoint) -> list[Alert]:
        alerts: list[Alert] = []
        for rule in self.rules:
            value = point.metric(rule.metric)
            key = f"{point.service}:{rule.metric}:{rule.rule_id}"
            if rule.breached(value):
                self._rule_streaks[key] = self._rule_streaks.get(key, 0) + 1
            else:
                self._rule_streaks[key] = 0
            if self._rule_streaks.get(key, 0) >= rule.sustained_minutes:
                alert = self._maybe_alert(
                    service=point.service,
                    metric=rule.metric,
                    detector=rule.rule_id,
                    value=value,
                    threshold=rule.threshold,
                    severity=rule.severity,
                    at=point.timestamp,
                    message=(
                        f"{rule.metric} {value:.4g} breached {rule.threshold:.4g} "
                        f"for {rule.sustained_minutes} consecutive minutes"
                    ),
                )
                if alert is not None:
                    alerts.append(alert)
                # Reset the streak so a sustained breach fires once per
                # cooldown window instead of every minute.
                self._rule_streaks[key] = 0
        for detector in self.z_detectors:
            value = point.metric(detector.metric)
            hist_key = (point.service, detector.metric)
            history = self._history.setdefault(hist_key, deque(maxlen=detector.window))
            if len(history) >= detector.min_history:
                mean = sum(history) / len(history)
                var = sum((v - mean) ** 2 for v in history) / len(history)
                std = math.sqrt(var)
                if std > 0:
                    z = (value - mean) / std
                    if z >= detector.z_threshold:
                        alert = self._maybe_alert(
                            service=point.service,
                            metric=detector.metric,
                            detector=detector.detector_id,
                            value=value,
                            threshold=mean + detector.z_threshold * std,
                            severity=detector.severity_for(z),
                            at=point.timestamp,
                            message=(
                                f"{detector.metric} z-score {z:.2f} "
                                f"(value {value:.4g}, baseline {mean:.4g} ± {std:.4g})"
                            ),
                        )
                        if alert is not None:
                            alerts.append(alert)
            history.append(value)
        return alerts

    def _maybe_alert(
        self,
        *,
        service: str,
        metric: str,
        detector: str,
        value: float,
        threshold: float,
        severity: Severity,
        at: datetime,
        message: str,
    ) -> Alert | None:
        signature = f"{service}:{metric}:{detector}"
        if not self.suppressor.allow(signature, at):
            return None
        self.suppressor.record(signature, at)
        return Alert(
            alert_id=self._next_id(),
            signature=signature,
            service=service,
            metric=metric,
            detector=detector,
            value=value,
            threshold=threshold,
            severity=severity,
            created_at=at,
            message=message,
        )


def default_engine() -> DetectorEngine:
    """Sensible defaults: threshold rules for every failure mode plus a
    z-score detector on latency and drift (the two slow-burn signals)."""
    rules = (
        ThresholdRule("err-high", "error_rate", 0.05, sustained_minutes=3, severity=Severity.SEV2),
        ThresholdRule("err-critical", "error_rate", 0.20, sustained_minutes=2, severity=Severity.SEV1),
        ThresholdRule("lat-high", "latency_p95_ms", 1500.0, sustained_minutes=3, severity=Severity.SEV3),
        ThresholdRule("lat-critical", "latency_p95_ms", 4000.0, sustained_minutes=2, severity=Severity.SEV2),
        ThresholdRule("cost-high", "cost_per_min", 6.0, sustained_minutes=5, severity=Severity.SEV3),
        ThresholdRule("guardrail-high", "guardrail_hit_rate", 0.05, sustained_minutes=3, severity=Severity.SEV2),
        ThresholdRule("drift-high", "drift_score", 0.35, sustained_minutes=5, severity=Severity.SEV3),
    )
    z_detectors = (
        ZScoreDetector("lat-z", "latency_p95_ms", window=30, z_threshold=4.0),
        ZScoreDetector("drift-z", "drift_score", window=30, z_threshold=4.0),
    )
    return DetectorEngine(rules=rules, z_detectors=z_detectors)
