"""Mitigation playbooks: deterministic, approval-gated actions.

A playbook is a named list of deterministic actions for one incident
class. Actions run against a simulated :class:`SystemState` (traffic
weights, active model version, prompt kill-switch, rate limits) so the
whole flow is testable without touching a real service.

Safety model
------------
* ``dry_run=True`` plans every action and mutates nothing.
* Destructive actions (model rollback, prompt kill-switch) require
  ``approved_by``; without approval they are reported ``blocked`` and
  nothing else in the playbook is skipped — non-destructive actions
  still apply, so the incident gets *some* containment immediately.
* Every execution is recorded on the incident timeline by the caller.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .models import (
    ActionResult,
    ExecutionResult,
    Incident,
    MitigationAction,
    Playbook,
    Severity,
)

# Action names — the only actions the engine knows how to execute.
TRAFFIC_SHIFT = "traffic_shift"
MODEL_ROLLBACK = "model_rollback"
PROMPT_KILL_SWITCH = "prompt_kill_switch"
RATE_LIMIT_TIGHTEN = "rate_limit_tighten"


@dataclass
class SystemState:
    """Simulated production state that mitigations act on."""

    active_model: str = "model-v3"
    previous_model: str = "model-v2"
    traffic_weights: dict[str, float] = field(
        default_factory=lambda: {"model-v3": 1.0, "model-v2": 0.0}
    )
    prompt_enabled: bool = True
    rate_limit_rps: int = 100

    def apply(self, action: MitigationAction) -> str:
        """Apply one action deterministically; returns a human-readable effect."""
        if action.name == TRAFFIC_SHIFT:
            shift = float(action.params.get("shift_to_previous_pct", "50"))
            frac = shift / 100.0
            self.traffic_weights[self.previous_model] = round(
                self.traffic_weights.get(self.previous_model, 0.0) + frac, 4
            )
            self.traffic_weights[self.active_model] = round(
                max(0.0, self.traffic_weights.get(self.active_model, 1.0) - frac), 4
            )
            return f"shifted {shift:g}% of traffic to {self.previous_model}"
        if action.name == MODEL_ROLLBACK:
            old = self.active_model
            self.active_model, self.previous_model = self.previous_model, old
            self.traffic_weights = {self.active_model: 1.0, self.previous_model: 0.0}
            return f"rolled back {old} -> {self.active_model}"
        if action.name == PROMPT_KILL_SWITCH:
            self.prompt_enabled = False
            return "prompt disabled (kill-switch engaged)"
        if action.name == RATE_LIMIT_TIGHTEN:
            new_limit = int(action.params.get("new_rps", "25"))
            old = self.rate_limit_rps
            self.rate_limit_rps = new_limit
            return f"rate limit tightened {old} -> {new_limit} rps"
        raise ValueError(f"unknown mitigation action: {action.name!r}")


def default_playbooks() -> dict[str, Playbook]:
    """Built-in playbooks, one per incident class."""
    return {
        "latency-blowout": Playbook(
            playbook_id="latency-blowout",
            name="Latency blowout",
            trigger_metric="latency_p95_ms",
            min_severity=Severity.SEV3,
            owner="ai-platform-oncall",
            actions=(
                MitigationAction(
                    TRAFFIC_SHIFT,
                    "Shift 50% of traffic to the previous model version",
                    params={"shift_to_previous_pct": "50"},
                ),
                MitigationAction(
                    RATE_LIMIT_TIGHTEN,
                    "Tighten ingress rate limit to shed load",
                    params={"new_rps": "25"},
                ),
            ),
        ),
        "error-spike": Playbook(
            playbook_id="error-spike",
            name="Error-rate spike",
            trigger_metric="error_rate",
            min_severity=Severity.SEV2,
            owner="ai-platform-oncall",
            actions=(
                MitigationAction(
                    TRAFFIC_SHIFT,
                    "Shift 50% of traffic to the previous model version",
                    params={"shift_to_previous_pct": "50"},
                ),
                MitigationAction(
                    MODEL_ROLLBACK,
                    "Roll back to the previous model version",
                    destructive=True,
                    requires_approval=True,
                ),
            ),
        ),
        "guardrail-breach": Playbook(
            playbook_id="guardrail-breach",
            name="Guardrail breach",
            trigger_metric="guardrail_hit_rate",
            min_severity=Severity.SEV2,
            owner="trust-safety-oncall",
            actions=(
                MitigationAction(
                    PROMPT_KILL_SWITCH,
                    "Disable the offending prompt template immediately",
                    destructive=True,
                    requires_approval=True,
                ),
                MitigationAction(
                    RATE_LIMIT_TIGHTEN,
                    "Tighten ingress rate limit while investigating",
                    params={"new_rps": "10"},
                ),
            ),
        ),
        "cost-spike": Playbook(
            playbook_id="cost-spike",
            name="Cost spike",
            trigger_metric="cost_per_min",
            min_severity=Severity.SEV3,
            owner="ai-platform-oncall",
            actions=(
                MitigationAction(
                    RATE_LIMIT_TIGHTEN,
                    "Tighten ingress rate limit to cap spend",
                    params={"new_rps": "25"},
                ),
                MitigationAction(
                    TRAFFIC_SHIFT,
                    "Shift 50% of traffic to the cheaper previous model",
                    params={"shift_to_previous_pct": "50"},
                ),
            ),
        ),
        "drift-event": Playbook(
            playbook_id="drift-event",
            name="Data drift event",
            trigger_metric="drift_score",
            min_severity=Severity.SEV3,
            owner="ml-platform-oncall",
            actions=(
                MitigationAction(
                    MODEL_ROLLBACK,
                    "Roll back to the model trained on the prior distribution",
                    destructive=True,
                    requires_approval=True,
                ),
                MitigationAction(
                    TRAFFIC_SHIFT,
                    "Shift 50% of traffic to the previous model version",
                    params={"shift_to_previous_pct": "50"},
                ),
            ),
        ),
    }


class PlaybookRegistry:
    """Lookup + execution of playbooks against the simulated system state."""

    def __init__(
        self,
        playbooks: dict[str, Playbook] | None = None,
        state: SystemState | None = None,
    ) -> None:
        self.playbooks = playbooks if playbooks is not None else default_playbooks()
        self.state = state if state is not None else SystemState()

    def for_metric(self, metric: str) -> Playbook | None:
        for playbook in self.playbooks.values():
            if playbook.trigger_metric == metric:
                return playbook
        return None

    def execute(
        self,
        playbook: Playbook,
        incident: Incident,
        *,
        dry_run: bool = False,
        approved_by: str | None = None,
    ) -> ExecutionResult:
        result = ExecutionResult(
            playbook_id=playbook.playbook_id,
            incident_id=incident.incident_id,
            dry_run=dry_run,
            approved_by=approved_by,
        )
        for action in playbook.actions:
            if action.requires_approval and not approved_by:
                result.results.append(
                    ActionResult(
                        action=action,
                        status="blocked",
                        detail="destructive action requires approval (approved_by)",
                    )
                )
                continue
            if dry_run:
                result.results.append(
                    ActionResult(
                        action=action,
                        status="planned",
                        detail=f"dry-run: would {action.description.lower()}",
                    )
                )
                continue
            effect = self.state.apply(action)
            result.results.append(
                ActionResult(action=action, status="applied", detail=effect)
            )
        return result
