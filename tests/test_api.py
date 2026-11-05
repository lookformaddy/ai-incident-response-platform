"""API tests. Auto-skips when FastAPI is not installed (runs in CI)."""
import pytest

fastapi = pytest.importorskip("fastapi", reason="FastAPI not installed")
from fastapi.testclient import TestClient  # noqa: E402

from airp.service import app  # noqa: E402

POINTS = [
    {
        "timestamp": "2026-11-05T09:00:00Z",
        "service": "chat-assistant",
        "error_rate": 0.005,
        "latency_p95_ms": 420.0,
        "cost_per_min": 1.8,
        "guardrail_hit_rate": 0.002,
        "drift_score": 0.08,
        "tokens_per_min": 48000.0,
    }
]


def _breach_points(minutes=4, error_rate=0.30, service="chat-assistant"):
    """Breach points for one service. Each API test uses its own service
    so its alerts open fresh incidents instead of merging into an earlier
    test's still-open incident (the service is shared module-level state)."""
    points = []
    for m in range(minutes):
        p = dict(POINTS[0])
        p["timestamp"] = f"2026-11-05T09:{m:02d}:00Z"
        p["error_rate"] = error_rate
        p["service"] = service
        points.append(p)
    return points


def test_health():
    client = TestClient(app)
    data = client.get("/health").json()
    assert data["status"] == "ok"


def test_detect_opens_incident_and_lists_it():
    client = TestClient(app)
    resp = client.post("/detect", json={"points": _breach_points()})
    assert resp.status_code == 200
    data = resp.json()
    assert data["alerts"], "expected at least one alert"
    assert data["incidents_created"], "expected an incident to open"
    incident_id = data["incidents_created"][0]
    got = client.get(f"/incidents/{incident_id}").json()
    assert got["state"] == "detected"
    assert got["service"] == "chat-assistant"


def test_detect_with_healthy_telemetry_opens_nothing():
    client = TestClient(app)
    before = client.get("/incidents").json()["incidents"]
    resp = client.post("/detect", json={"points": POINTS})
    assert resp.json()["alerts"] == []
    after = client.get("/incidents").json()["incidents"]
    assert len(after) == len(before)


def test_transition_lifecycle_via_api():
    client = TestClient(app)
    incident_id = client.post("/detect", json={"points": _breach_points(service="svc-lifecycle")}).json()["incidents_created"][0]
    for state in ("triaged", "mitigating", "resolved"):
        resp = client.post(
            f"/incidents/{incident_id}/transition",
            json={"to_state": state, "actor": "oncall"},
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["state"] == state
    bad = client.post(
        f"/incidents/{incident_id}/transition",
        json={"to_state": "triaged", "actor": "oncall"},
    )
    assert bad.status_code == 409


def test_mitigate_dry_run_then_apply_with_approval():
    client = TestClient(app)
    incident_id = client.post("/detect", json={"points": _breach_points(service="svc-mitigate")}).json()["incidents_created"][0]
    dry = client.post(
        f"/incidents/{incident_id}/mitigate",
        json={"playbook_id": "error-spike", "dry_run": True},
    ).json()
    assert dry["dry_run"] is True
    # Dry-run plans the safe action; the destructive rollback is still
    # reported blocked because no approver was supplied.
    assert {r["action"]: r["status"] for r in dry["results"]} == {
        "traffic_shift": "planned",
        "model_rollback": "blocked",
    }
    blocked = client.post(
        f"/incidents/{incident_id}/mitigate",
        json={"playbook_id": "error-spike", "dry_run": False},
    ).json()
    assert any(r["status"] == "blocked" for r in blocked["results"])
    applied = client.post(
        f"/incidents/{incident_id}/mitigate",
        json={"playbook_id": "error-spike", "dry_run": False, "approved_by": "ic"},
    ).json()
    assert all(r["status"] == "applied" for r in applied["results"])


def test_postmortem_requires_resolution_and_slo_and_audit_endpoints():
    client = TestClient(app)
    incident_id = client.post("/detect", json={"points": _breach_points(service="svc-postmortem")}).json()["incidents_created"][0]
    early = client.get(f"/incidents/{incident_id}/postmortem")
    assert early.status_code == 409
    for state in ("triaged", "mitigating", "resolved"):
        client.post(f"/incidents/{incident_id}/transition", json={"to_state": state, "actor": "oncall"})
    pm = client.get(f"/incidents/{incident_id}/postmortem")
    assert pm.status_code == 200
    assert pm.json()["action_items"]
    slo = client.get("/slo").json()
    assert slo["incident_count"] >= 1
    assert slo["by_severity"]["SEV1"] >= 1
    audit = client.get("/audit/verify").json()
    assert audit["valid"] is True
    assert audit["entries"] >= 1


def test_unknown_incident_and_playbook_404():
    client = TestClient(app)
    assert client.get("/incidents/INC-9999").status_code == 404
    assert client.post(
        "/incidents/INC-9999/transition", json={"to_state": "triaged"}
    ).status_code == 404
    incident_id = client.post("/detect", json={"points": _breach_points(service="svc-404")}).json()["incidents_created"][0]
    assert client.post(
        f"/incidents/{incident_id}/mitigate", json={"playbook_id": "nope"}
    ).status_code == 404
