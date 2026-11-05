# Architecture — AI Incident Response Platform

## Problem

Production AI systems fail in ways traditional monitoring misses:
silent model drift, guardrail breaches that emit harmful content, runaway
token spend, and latency blowouts while health checks stay green. When
one of these happens, teams need a single, auditable path from "something
is wrong" to "we fixed it and learned from it" — detection, triage,
containment, escalation, and a postmortem — with approval gates on the
actions that can make things worse.

## Components

```
┌────────────────────────────┐
│ TelemetryGenerator         │  seeded, per-minute synthetic telemetry
│ (telemetry.py)             │  error_rate, latency_p95_ms, cost_per_min,
└────────────┬───────────────┘  guardrail_hit_rate, drift_score, tokens_per_min
             │ TelemetryPoint list
             ▼
┌────────────────────────────┐
│ DetectorEngine             │  ThresholdRule (sustained breach) +
│ (detectors.py)             │  ZScoreDetector (rolling baseline) +
│                            │  AlertStormSuppressor (cooldown + burst cap)
└────────────┬───────────────┘
             │ Alert list
             ▼
┌────────────────────────────┐
│ IncidentStore              │  strict state machine
│ (incidents.py)             │  detected → triaged → mitigating →
│                            │  resolved → postmortem; dedup/merge by
│                            │  service:metric:detector signature
└──────┬──────────┬──────────┘
       │          │
       ▼          ▼
┌──────────────┐  ┌──────────────────┐
│ Escalation   │  │ PlaybookRegistry │  deterministic actions on a
│ Engine       │  │ (playbooks.py)   │  simulated SystemState;
│ (oncall.py)  │  │                  │  dry-run vs apply; destructive
│ rotation +   │  │ traffic shift,   │  actions need approved_by
│ ack timeouts │  │ rollback, kill-  │
│ 24x7 / biz   │  │ switch, rate-    │
│ hours        │  │ limit tighten    │
└──────┬───────┘  └────────┬─────────┘
       │                   │
       ▼                   ▼
┌──────────────────────────────────────┐
│ Postmortem generator (postmortem.py) │  timeline from incident log +
│ Cost accounting + SLO report         │  audit log; factors; action items
│ (costs.py)                           │  MTTD/MTTR/MTBF, availability,
│                                      │  wasted tokens, SLA credits
└──────────────────┬───────────────────┘
                   │
                   ▼
┌──────────────────────────────────────┐
│ AuditLog (audit.py)                  │  SHA-256 hash chain; verify()
└──────────────────────────────────────┘

FastAPI service (service.py) and CLI (cli.py) sit on top of the same
domain objects; scripts/demo.py wires the whole pipeline end to end.
```

## Module map

| Module | Responsibility |
| --- | --- |
| `models.py` | Domain types: `Severity` (with SLO targets), `IncidentState`, `VALID_TRANSITIONS`, `Incident`, `Alert`, `TelemetryPoint`, `Playbook`, `MitigationAction`, `EscalationPolicy`, `Postmortem`, `CostRecord`, `AuditEntry` |
| `telemetry.py` | Seeded synthetic telemetry + planted anomalies |
| `detectors.py` | Threshold rules, z-score detectors, storm suppression |
| `incidents.py` | Lifecycle state machine, dedup/merge |
| `playbooks.py` | Deterministic mitigations, approval gates, simulated system state |
| `oncall.py` | Weekly rotation, escalation chains, business-hours policy |
| `postmortem.py` | Timeline reconstruction, factors, action items |
| `costs.py` | Wasted-token / SLA-credit accounting, SLO report |
| `audit.py` | Hash-chained audit log |
| `service.py` | FastAPI surface (in-memory state) |
| `cli.py` | `detect` / `slo` / `demo` commands |

## Data flow

1. **Ingest.** `TelemetryGenerator` emits per-minute `TelemetryPoint`s
   for a fleet of services. Anomalies are planted explicitly (metric,
   service, start, duration, multiplier) so runs are reproducible.
2. **Detect.** `DetectorEngine.evaluate` runs threshold rules (a metric
   must breach for N consecutive minutes) and z-score detectors (rolling
   mean/std baseline) over the time-ordered stream. The suppressor
   allows one alert per signature per cooldown window and caps bursts
   per hour; suppressed repeats are counted, not lost.
3. **Triage.** `IncidentStore.ingest` opens an incident per alert, or
   merges the alert into an already-open incident with the same
   signature within 60 minutes (bumping `merged_count`, escalating
   severity if the new alert is worse).
4. **Escalate.** `EscalationEngine` computes the current level from ack
   timeouts; level 1 pages the rotation member, later levels page the
   chain. Business-hours policies defer overnight pages to the next
   business hour.
5. **Mitigate.** `PlaybookRegistry.execute` runs the playbook for the
   incident's metric. Dry-run plans without mutating; apply mutates the
   simulated system state. Destructive actions without `approved_by`
   are reported `blocked` while the rest still apply.
6. **Resolve & learn.** Transitions move the incident to `resolved`;
   `generate_postmortem` rebuilds the timeline from the incident log
   and the audit log, derives factors, and emits owned action items.
   `CostCalculator` prices the incident (wasted tokens, SLA credits)
   and `compute_slo` aggregates MTTD/MTTR/MTBF.
7. **Audit.** Every detection, transition, mitigation, and escalation
   appends to the hash-chained `AuditLog`; `verify()` recomputes the
   chain.

## Key design decisions

- **Severity owns its SLOs.** Ack and resolution targets live on the
  `Severity` enum, so escalation and reporting read one source of truth.
- **Fail-closed mitigations.** Destructive actions are blocked without
  approval, but non-destructive actions in the same playbook still
  apply — partial containment beats waiting.
- **Dedup by signature.** `service:metric:detector` plus a 60-minute
  window turns a flapping metric into one incident with a merge count.
- **Deterministic by construction.** Seeded telemetry, fixed thresholds,
  simulated system state — the demo and tests reproduce exactly.
- **In-memory stores, swappable interfaces.** Stores are plain classes
  with no I/O, so a durable backend (Postgres, object store) can replace
  them without touching detectors, playbooks, or reporting.

## Trade-offs and limitations

- **No persistence.** Restarting the API service resets incidents and
  the audit log. A production deployment would persist all three stores
  and rehydrate the detector's rolling history.
- **Simple statistics.** The z-score detector uses rolling mean/std,
  not a seasonal or robust baseline; it is transparent and adequate for
  the synthetic windows here, and would need seasonality handling for
  real traffic patterns.
- **Simulated mitigations.** Actions mutate a `SystemState` object, not
  real infrastructure. The action *names* and *semantics* (traffic
  shift, rollback, kill-switch, rate-limit) map 1:1 to the real
  operations a platform team would wire behind the same interface.
- **Per-minute telemetry.** Real pipelines would ingest higher-frequency
  signals; the `TelemetryPoint` shape and detector contracts are
  frequency-agnostic.

## Failure modes handled

| Failure | Handling |
| --- | --- |
| Single noisy minute | Threshold rules require a sustained breach |
| Slow degradation under a fixed threshold | Z-score detector vs rolling baseline |
| Flapping metric paging 100 times | Cooldown + burst cap; merges into one incident |
| Destructive mitigation without approval | Blocked, reported, non-destructive actions still apply |
| Nobody acks the page | Escalation chain advances on ack timeouts |
| SEV4 at 3 AM | Business-hours policy defers to next business hour |
| Postmortem on an open incident | Rejected — postmortem requires `resolved` |
| Tampered audit history | `verify()` fails on any altered/reordered entry |
