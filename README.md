# AI Incident Response Platform

Incident response for **production AI systems**: detect, triage, contain,
and learn from AI incidents — model misbehavior, guardrail breaches,
cost spikes, latency blowouts, and data-drift events.

Production AI fails differently from traditional software. A model can
degrade silently (drift), start emitting harmful content (guardrail
breach), or burn budget at 10x (cost spike) while every health check
still returns 200. This platform is the missing runbook layer: it watches
AI-specific telemetry, pages the right human, applies deterministic
mitigations with approval gates, and turns the whole event into a
postmortem with owners and due dates.

## What it does

- **Detectors** — threshold rules (sustained breach, per metric) plus
  rolling z-score detectors that catch slow-burn degradation a fixed
  threshold would miss. Alert-storm suppression (per-signature cooldown
  + burst cap) keeps one flapping metric from paging a hundred times.
- **Incident lifecycle** — a strict state machine
  `detected → triaged → mitigating → resolved → postmortem` (SEV1 may
  skip triage). Related alerts dedup and merge into the open incident
  for the same signature instead of opening a second page.
- **Mitigation playbooks** — deterministic actions: traffic shift, model
  rollback, prompt kill-switch, rate-limit tighten. Every run supports
  dry-run vs apply, and destructive actions require an approver.
- **On-call + escalation** — weekly rotating roster, escalation chains
  with ack timeouts, and business-hours vs 24/7 policies (business-hours
  policies defer overnight pages to the next business hour).
- **Postmortems** — timeline reconstruction from the incident log plus
  the hash-chained audit log, contributing-factor analysis, and action
  items with owners and due dates (7 days for SEV1/2, 14 for SEV3/4).
- **Cost + SLO reporting** — wasted-token and SLA-credit accounting per
  incident, plus MTTD / MTTR / MTBF and availability against targets.
- **Audit log** — SHA-256 hash-chained, tamper-evident; `verify()` proves
  the chain is intact.
- **FastAPI service + CLI**, deterministic synthetic telemetry generator
  (seeded; no network calls, no real LLM keys — the only "provider" is a
  scripted one).

## Architecture

See [docs/architecture.md](docs/architecture.md).

```
telemetry (synthetic, seeded) ──▶ detectors (rules + z-score, storm suppression)
                                        │ alerts
                                        ▼
incident store (state machine + dedup/merge) ──▶ on-call / escalation
                                        │
                                        ▼
                          playbooks (dry-run / apply, approval gates)
                                        │
                                        ▼
                    postmortem generator + cost/SLO reporting
                                        │
                                        ▼
                              hash-chained audit log
```

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# End-to-end demo on synthetic data (plants 3 anomalies, detects,
# mitigates, resolves, postmortems, reports SLOs)
make demo

# CLI: detect / SLO report
PYTHONPATH=src python -m airp.cli detect --minutes 120 --seed 7
PYTHONPATH=src python -m airp.cli slo --minutes 120 --seed 7

# Tests
make test

# API
PYTHONPATH=src uvicorn airp.service:app --reload
# POST /detect  → ingest telemetry, open/merge incidents
# GET  /incidents, /slo, /audit/verify
```

## Key design decisions

- **Deterministic everything.** Seeded telemetry, fixed detector
  thresholds, and a simulated system state mean the demo and the test
  suite reproduce bit-for-bit. Nothing depends on a live model.
- **Fail-closed mitigations.** Destructive actions (rollback,
  kill-switch) are blocked without an approver, but non-destructive
  actions in the same playbook still apply — the incident gets *some*
  containment immediately instead of waiting on a human.
- **Dedup by signature, not by text.** Alerts merge on
  `service:metric:detector` within a 60-minute window, so a flapping
  metric is one incident with a merge count, not twenty pages.
- **Audit chain, not just a log.** Each entry commits to the previous
  entry's hash, so a postmortem timeline can be trusted after the fact.
- **Severity carries its own SLOs.** Ack and resolution targets live on
  the `Severity` enum, so escalation and reporting never hard-code
  per-severity numbers in two places.

## Trade-offs

- In-memory stores (no database) keep the project self-contained and
  testable; a production deployment would persist incidents, telemetry,
  and the audit log in a durable store with the same interfaces.
- The z-score detector uses a simple rolling mean/std rather than a
  seasonal model — adequate for the synthetic one-hour windows here,
  and deliberately transparent about its assumptions.
- Telemetry is per-minute and synthetic; real deployments would ingest
  from an observability pipeline (OpenTelemetry, Prometheus) behind the
  same `TelemetryPoint` shape.

## What it demonstrates

End-to-end incident response for AI systems: AI-specific detection
(drift, guardrails, cost), a validated incident lifecycle, approval-gated
mitigation, on-call escalation, postmortem generation, cost/SLO
accounting, and tamper-evident auditing — the operational layer
enterprises ask about when an AI system goes wrong in production.

## License

MIT. All code is original; all data is synthetic.
