"""FastAPI service for the AI incident response platform.

Endpoints
---------
GET  /health                    liveness
POST /detect                    ingest telemetry points, run detectors, open/merge incidents
GET  /incidents                 list incidents (optional ?state=)
GET  /incidents/{id}            one incident with its timeline
POST /incidents/{id}/transition move an incident through its lifecycle
POST /incidents/{id}/mitigate   run a playbook (dry_run / approved_by)
GET  /incidents/{id}/postmortem generate the postmortem for a resolved incident
GET  /slo                       MTTD/MTTR/MTBF report
GET  /audit/verify              verify the hash-chained audit log

Run: ``uvicorn airp.service:app --reload`` (PYTHONPATH=src).
The service keeps in-memory state; restart resets it.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .audit import AuditLog
from .costs import CostCalculator, compute_slo
from .detectors import default_engine
from .incidents import IncidentStore
from .models import IncidentState, Severity, TelemetryPoint, TimelineEvent
from .oncall import EscalationEngine, Rotation, default_policy
from .playbooks import PlaybookRegistry
from .postmortem import generate_postmortem
from .telemetry import DEFAULT_SERVICES

app = FastAPI(title="AI Incident Response Platform", version="0.1.0")

# Module-level platform state (in-memory; restart resets it).
engine = default_engine()
store = IncidentStore()
audit = AuditLog()
registry = PlaybookRegistry()
costs = CostCalculator()
rotation = None  # attach a Rotation to page a rotating roster member
escalation = EscalationEngine(policy=default_policy(), rotation=rotation)


class TelemetryPointIn(BaseModel):
    timestamp: datetime
    service: str = DEFAULT_SERVICES[0]
    error_rate: float = 0.0
    latency_p95_ms: float = 0.0
    cost_per_min: float = 0.0
    guardrail_hit_rate: float = 0.0
    drift_score: float = 0.0
    tokens_per_min: float = 0.0


class DetectIn(BaseModel):
    points: list[TelemetryPointIn] = Field(default_factory=list)


class TransitionIn(BaseModel):
    to_state: str
    actor: str = "api"
    note: str = ""


class MitigateIn(BaseModel):
    playbook_id: str
    dry_run: bool = False
    approved_by: str | None = None


def _incident_dict(incident) -> dict:
    return {
        "incident_id": incident.incident_id,
        "title": incident.title,
        "service": incident.service,
        "severity": incident.severity.value,
        "state": incident.state.value,
        "signature": incident.signature,
        "created_at": incident.created_at.isoformat(),
        "detected_at": incident.detected_at.isoformat() if incident.detected_at else None,
        "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
        "alert_ids": incident.alert_ids,
        "merged_count": incident.merged_count,
        "owner": incident.owner,
        "timeline": [
            {"at": e.at.isoformat(), "actor": e.actor, "event": e.event, "detail": e.detail}
            for e in incident.timeline
        ],
    }


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "incidents": len(store), "audit_entries": len(audit)}


@app.post("/detect")
def detect(payload: DetectIn) -> dict:
    points = [
        TelemetryPoint(
            timestamp=p.timestamp,
            service=p.service,
            error_rate=p.error_rate,
            latency_p95_ms=p.latency_p95_ms,
            cost_per_min=p.cost_per_min,
            guardrail_hit_rate=p.guardrail_hit_rate,
            drift_score=p.drift_score,
            tokens_per_min=p.tokens_per_min,
        )
        for p in payload.points
    ]
    alerts = engine.evaluate(points)
    created = store.ingest_many(alerts)
    for incident in created:
        audit.append(
            "detector",
            "incident_detected",
            {"incident_id": incident.incident_id, "severity": incident.severity.value},
            timestamp=incident.created_at,
        )
    return {
        "alerts": [
            {
                "alert_id": a.alert_id,
                "signature": a.signature,
                "severity": a.severity.value,
                "message": a.message,
            }
            for a in alerts
        ],
        "incidents_created": [i.incident_id for i in created],
        "open_incidents": len(store.open()),
    }


@app.get("/incidents")
def list_incidents(state: str | None = None) -> dict:
    incidents = store.all()
    if state is not None:
        try:
            wanted = IncidentState(state)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"unknown state: {state}") from None
        incidents = [i for i in incidents if i.state == wanted]
    return {"incidents": [_incident_dict(i) for i in incidents]}


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: str) -> dict:
    try:
        return _incident_dict(store.get(incident_id))
    except KeyError:
        raise HTTPException(status_code=404, detail="incident not found") from None


@app.post("/incidents/{incident_id}/transition")
def transition(incident_id: str, payload: TransitionIn) -> dict:
    try:
        new_state = IncidentState(payload.to_state)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"unknown state: {payload.to_state}") from None
    try:
        incident = store.transition(
            incident_id, new_state, actor=payload.actor, note=payload.note
        )
    except KeyError:
        raise HTTPException(status_code=404, detail="incident not found") from None
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
    audit.append(
        payload.actor,
        f"incident_{new_state.value}",
        {"incident_id": incident_id, "note": payload.note},
    )
    return _incident_dict(incident)


@app.post("/incidents/{incident_id}/mitigate")
def mitigate(incident_id: str, payload: MitigateIn) -> dict:
    try:
        incident = store.get(incident_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="incident not found") from None
    playbook = registry.playbooks.get(payload.playbook_id)
    if playbook is None:
        raise HTTPException(status_code=404, detail="playbook not found") from None
    result = registry.execute(
        playbook, incident, dry_run=payload.dry_run, approved_by=payload.approved_by
    )
    if not payload.dry_run and result.applied:
        incident.timeline.append(
            TimelineEvent(
                at=datetime.now(timezone.utc),
                actor=payload.approved_by or "api",
                event="mitigation",
                detail=", ".join(
                    f"{r.action.name}: {r.detail}" for r in result.applied
                ),
            )
        )
    audit.append(
        payload.approved_by or "api",
        "playbook_executed",
        {
            "incident_id": incident_id,
            "playbook_id": playbook.playbook_id,
            "dry_run": payload.dry_run,
            "applied": [r.action.name for r in result.applied],
            "blocked": [r.action.name for r in result.blocked],
        },
    )
    return {
        "playbook_id": result.playbook_id,
        "incident_id": result.incident_id,
        "dry_run": result.dry_run,
        "results": [
            {"action": r.action.name, "status": r.status, "detail": r.detail}
            for r in result.results
        ],
    }


@app.get("/incidents/{incident_id}/postmortem")
def postmortem(incident_id: str) -> dict:
    try:
        incident = store.get(incident_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="incident not found") from None
    try:
        pm = generate_postmortem(incident, audit)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
    return {
        "incident_id": pm.incident_id,
        "summary": pm.summary,
        "contributing_factors": pm.contributing_factors,
        "action_items": [
            {
                "item_id": a.item_id,
                "title": a.title,
                "owner": a.owner,
                "due_date": a.due_date.isoformat(),
                "status": a.status,
            }
            for a in pm.action_items
        ],
        "timeline": [
            {"at": e.at.isoformat(), "actor": e.actor, "event": e.event, "detail": e.detail}
            for e in pm.timeline
        ],
    }


@app.get("/slo")
def slo() -> dict:
    report = compute_slo(store.all(), [])
    return report.as_dict()


@app.get("/audit/verify")
def verify_audit() -> dict:
    return {"valid": audit.verify(), "entries": len(audit)}
