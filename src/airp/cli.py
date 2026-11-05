"""CLI for the AI incident response platform.

Usage:
    python -m airp.cli detect --minutes 120 --seed 7
    python -m airp.cli demo
    python -m airp.cli slo --minutes 120 --seed 7

``detect`` generates synthetic telemetry, runs the detectors, and prints
the incidents that open. ``demo`` runs the same pipeline plus a
mitigation dry-run and a postmortem sketch. ``slo`` prints the
MTTD/MTTR/MTBF report for the generated window.
"""
from __future__ import annotations

import argparse
import sys

from .audit import AuditLog
from .costs import CostCalculator, compute_slo
from .detectors import default_engine
from .incidents import IncidentStore
from .models import IncidentState
from .oncall import default_policy
from .playbooks import PlaybookRegistry
from .postmortem import generate_postmortem
from .telemetry import Anomaly, TelemetryGenerator

DEFAULT_ANOMALIES: tuple[Anomaly, ...] = (
    Anomaly("latency_p95_ms", start_minute=30, duration_minutes=20, multiplier=5.0, service="chat-assistant"),
    Anomaly("error_rate", start_minute=60, duration_minutes=15, multiplier=30.0, service="chat-assistant"),
    Anomaly("guardrail_hit_rate", start_minute=90, duration_minutes=10, multiplier=40.0, service="support-triage"),
)


def _build_pipeline(minutes: int, seed: int):
    """Generate telemetry, detect, ingest. Returns (points, alerts, store, audit)."""
    generator = TelemetryGenerator(seed=seed, anomalies=DEFAULT_ANOMALIES)
    points = generator.generate(minutes)
    engine = default_engine()
    alerts = engine.evaluate(points)
    store = IncidentStore()
    store.ingest_many(alerts)
    audit = AuditLog()
    for incident in store.all():
        audit.append(
            "detector",
            "incident_detected",
            {"incident_id": incident.incident_id, "severity": incident.severity.value},
            timestamp=incident.created_at,
        )
    return points, alerts, store, audit


def cmd_detect(args: argparse.Namespace) -> int:
    _, alerts, store, _ = _build_pipeline(args.minutes, args.seed)
    print(f"alerts fired: {len(alerts)} | incidents opened: {len(store)}")
    for incident in store.all():
        print(
            f"  {incident.incident_id} [{incident.severity.value}] "
            f"{incident.state.value} {incident.service}: {incident.title} "
            f"(alerts merged: {incident.merged_count})"
        )
    return 0


def cmd_slo(args: argparse.Namespace) -> int:
    points, _, store, _ = _build_pipeline(args.minutes, args.seed)
    calculator = CostCalculator()
    costs = [calculator.cost_for_incident(i, points) for i in store.all()]
    report = compute_slo(store.all(), costs)
    print("SLO report (synthetic window):")
    for key, value in report.as_dict().items():
        print(f"  {key}: {value}")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    points, alerts, store, audit = _build_pipeline(args.minutes, args.seed)
    registry = PlaybookRegistry()
    print("== AI Incident Response Platform — CLI demo (synthetic data) ==")
    print(f"alerts fired: {len(alerts)} | incidents opened: {len(store)}")
    calculator = CostCalculator()
    for incident in store.all():
        print(f"\n-- {incident.incident_id} [{incident.severity.value}] {incident.title}")
        playbook = registry.for_metric(incident.signature.split(":")[1])
        if playbook is not None:
            dry = registry.execute(playbook, incident, dry_run=True)
            print(f"   playbook {playbook.playbook_id} dry-run:")
            for r in dry.results:
                print(f"     [{r.status}] {r.action.name}: {r.detail}")
            result = registry.execute(
                playbook, incident, dry_run=False, approved_by="incident-commander"
            )
            for r in result.applied:
                print(f"     applied: {r.action.name} — {r.detail}")
        store.transition(incident.incident_id, IncidentState.TRIAGED, actor="oncall")
        store.transition(incident.incident_id, IncidentState.MITIGATING, actor="oncall")
        store.transition(incident.incident_id, IncidentState.RESOLVED, actor="oncall")
        cost = calculator.cost_for_incident(incident, points)
        pm = generate_postmortem(incident, audit, cost=cost)
        print(f"   postmortem: {pm.summary}")
        print(f"   cost: wasted ${cost.wasted_cost_usd} | SLA credit ${cost.sla_credit_usd}")
        for item in pm.action_items:
            print(f"     action: {item.title} (owner {item.owner}, due {item.due_date.date()})")
    print(f"\naudit log valid: {audit.verify()} ({len(audit)} entries)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AI incident response platform CLI")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("detect", "slo", "demo"):
        p = sub.add_parser(name)
        p.add_argument("--minutes", type=int, default=120)
        p.add_argument("--seed", type=int, default=7)
    args = parser.parse_args(argv)
    if args.command == "detect":
        return cmd_detect(args)
    if args.command == "slo":
        return cmd_slo(args)
    return cmd_demo(args)


if __name__ == "__main__":
    sys.exit(main())
