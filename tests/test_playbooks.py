"""Tests for mitigation playbooks: dry-run, approval gates, effects."""
from datetime import datetime, timezone

import pytest

from airp.incidents import IncidentStore
from airp.models import Alert, Severity
from airp.playbooks import (
    MODEL_ROLLBACK,
    PROMPT_KILL_SWITCH,
    PlaybookRegistry,
    SystemState,
    default_playbooks,
)

T0 = datetime(2026, 11, 5, 9, 0, tzinfo=timezone.utc)


def _incident(severity=Severity.SEV2):
    store = IncidentStore()
    alert = Alert("ALT-0001", "chat-assistant:error_rate:err-high", "chat-assistant",
                  "error_rate", "err-high", 0.3, 0.05, severity, T0, "breach")
    return store.create_from_alert(alert)


def test_registry_has_one_playbook_per_failure_mode():
    books = default_playbooks()
    assert {b.trigger_metric for b in books.values()} == {
        "latency_p95_ms", "error_rate", "guardrail_hit_rate", "cost_per_min", "drift_score",
    }
    assert books["error-spike"].min_severity == Severity.SEV2


def test_dry_run_plans_everything_and_mutates_nothing():
    registry = PlaybookRegistry()
    state_before = SystemState()
    result = registry.execute(
        registry.playbooks["latency-blowout"], _incident(), dry_run=True
    )
    assert result.dry_run
    assert all(r.status == "planned" for r in result.results)
    assert registry.state == state_before


def test_non_destructive_actions_apply_without_approval():
    registry = PlaybookRegistry()
    result = registry.execute(registry.playbooks["cost-spike"], _incident())
    assert all(r.status == "applied" for r in result.results)
    assert registry.state.rate_limit_rps == 25
    assert registry.state.traffic_weights["model-v2"] == 0.5


def test_destructive_action_blocked_without_approval_but_others_apply():
    registry = PlaybookRegistry()
    result = registry.execute(registry.playbooks["error-spike"], _incident())
    assert [r.status for r in result.results] == ["applied", "blocked"]
    assert result.blocked[0].action.name == MODEL_ROLLBACK
    assert registry.state.active_model == "model-v3"  # rollback did not happen
    assert registry.state.traffic_weights["model-v2"] == 0.5  # shift did happen


def test_destructive_action_applies_with_approval():
    registry = PlaybookRegistry()
    result = registry.execute(
        registry.playbooks["guardrail-breach"], _incident(), approved_by="incident-commander"
    )
    assert all(r.status == "applied" for r in result.results)
    assert registry.state.prompt_enabled is False
    assert result.approved_by == "incident-commander"


def test_model_rollback_swaps_versions_and_resets_traffic():
    state = SystemState()
    state.traffic_weights = {"model-v3": 0.5, "model-v2": 0.5}
    effect = state.apply(
        next(a for a in default_playbooks()["error-spike"].actions if a.name == MODEL_ROLLBACK)
    )
    assert state.active_model == "model-v2"
    assert state.traffic_weights == {"model-v2": 1.0, "model-v3": 0.0}
    assert "model-v2" in effect


def test_kill_switch_is_destructive_and_needs_approval():
    book = default_playbooks()["guardrail-breach"]
    kill = next(a for a in book.actions if a.name == PROMPT_KILL_SWITCH)
    assert kill.destructive and kill.requires_approval


def test_unknown_action_raises():
    from airp.models import MitigationAction

    state = SystemState()
    with pytest.raises(ValueError, match="unknown mitigation action"):
        state.apply(MitigationAction("self_destruct", "boom"))


def test_for_metric_lookup():
    registry = PlaybookRegistry()
    assert registry.for_metric("cost_per_min").playbook_id == "cost-spike"
    assert registry.for_metric("tokens_per_min") is None
