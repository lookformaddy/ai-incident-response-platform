"""End-to-end demo on synthetic data. Run: PYTHONPATH=src python scripts/demo.py

Plants three anomalies (latency blowout, error spike, guardrail breach),
runs the detectors, opens/merges incidents, escalates, runs each playbook
(dry-run, then apply with approval), resolves the incidents, generates
postmortems, and prints the SLO report and the audit-chain proof.
"""
import sys
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from airp.audit import AuditLog
from airp.costs import CostCalculator, compute_slo
from airp.detectors import default_engine
from airp.incidents import IncidentStore
from airp.models import IncidentState
from airp.oncall import EscalationEngine, Rotation, default_policy
from airp.playbooks import PlaybookRegistry
from airp.postmortem import generate_postmortem
from airp.telemetry import Anomaly, TelemetryGenerator, describe_anomaly


def main() -> None:
    anomalies = (
        Anomaly("latency_p95_ms", 30, 20, 5.0, service="chat-assistant"),
        Anomaly("error_rate", 60, 15, 30.0, service="chat-assistant"),
        Anomaly("guardrail_hit_rate", 90, 10, 40.0, service="support-triage"),
    )
    print("== AI Incident Response Platform demo (synthetic data) ==")
    for anomaly in anomalies:
        print(f"  planted: {describe_anomaly(anomaly)}")

    generator = TelemetryGenerator(seed=7, anomalies=anomalies)
    points = generator.generate(120)
    engine = default_engine()
    alerts = engine.evaluate(points)
    store = IncidentStore()
    created = store.ingest_many(alerts)
    audit = AuditLog()
    registry = PlaybookRegistry()
    calculator = CostCalculator()
    policy = default_policy()
    rotation = Rotation(
        members=policy.levels[0].members
        + policy.levels[1].members
        + policy.levels[2].members,
        start=points[0].timestamp,
    )
    escalation = EscalationEngine(policy=policy, rotation=rotation)

    print(f"\n-- detection: {len(alerts)} alerts fired, {len(created)} incidents opened "
          f"({engine.suppressor.suppressed_count} suppressed by storm control)")
    for incident in store.all():
        audit.append(
            "detector", "incident_detected",
            {"incident_id": incident.incident_id, "severity": incident.severity.value},
            timestamp=incident.created_at,
        )
        print(f"\n-- {incident.incident_id} [{incident.severity.value}] {incident.service}: {incident.title}")
        print(f"   detected {incident.detected_at} | merged duplicates: {incident.merged_count}")
        page = escalation.page(incident, now=incident.created_at + timedelta(minutes=7))
        print(f"   escalation at +7 min: level {page['level']}, paged {page['paged']}")

        metric = incident.signature.split(":")[1]
        playbook = registry.for_metric(metric)
        if playbook is None:
            print("   no playbook for this metric")
            continue
        dry = registry.execute(playbook, incident, dry_run=True)
        print(f"   playbook {playbook.playbook_id} (dry-run):")
        for r in dry.results:
            print(f"     [{r.status}] {r.action.name}: {r.detail}")
        result = registry.execute(playbook, incident, approved_by="incident-commander")
        for r in result.results:
            print(f"     [{r.status}] {r.action.name}: {r.detail}")
        audit.append(
            "incident-commander", "playbook_executed",
            {"incident_id": incident.incident_id, "playbook_id": playbook.playbook_id,
             "applied": [r.action.name for r in result.applied]},
            timestamp=incident.created_at + timedelta(minutes=12),
        )

        store.transition(incident.incident_id, IncidentState.TRIAGED, actor="oncall",
                         at=incident.created_at + timedelta(minutes=5))
        store.transition(incident.incident_id, IncidentState.MITIGATING, actor="oncall",
                         at=incident.created_at + timedelta(minutes=10))
        store.transition(incident.incident_id, IncidentState.RESOLVED, actor="oncall",
                         at=incident.created_at + timedelta(minutes=70))
        cost = calculator.cost_for_incident(incident, points)
        pm = generate_postmortem(incident, audit, cost=cost)
        print(f"   resolved in {incident.time_to_resolve_minutes:.0f} min | "
              f"wasted ${cost.wasted_cost_usd} | SLA credit ${cost.sla_credit_usd}")
        print(f"   postmortem: {pm.summary}")
        for item in pm.action_items:
            print(f"     action: {item.title} (owner {item.owner}, due {item.due_date.date()})")

    costs = [calculator.cost_for_incident(i, points) for i in store.all()]
    report = compute_slo(store.all(), costs, window=timedelta(minutes=120), now=points[-1].timestamp)
    print("\n-- SLO report:")
    for key, value in report.as_dict().items():
        print(f"   {key}: {value}")
    print(f"\n-- audit log: {len(audit)} entries, chain valid: {audit.verify()}")
    print(f"   system state after mitigations: model={registry.state.active_model}, "
          f"prompt_enabled={registry.state.prompt_enabled}, "
          f"rate_limit={registry.state.rate_limit_rps} rps")


if __name__ == "__main__":
    main()
