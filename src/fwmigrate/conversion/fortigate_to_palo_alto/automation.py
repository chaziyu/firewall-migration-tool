"""Opt-in deterministic automation for FortiGate to PAN-OS review decisions."""

from dataclasses import dataclass, replace
from enum import StrEnum

from .auto_decisions import classify_auto_decisions
from .decision_propagation import dependent_decision_keys
from .decisions import PANDecisionReviewState, PANMigrationDecisionSet
from .target_validation import validate_against_target


class AutomationPolicy(StrEnum):
    AUTO_APPLY_VERIFIED = "AUTO_APPLY_VERIFIED"
    AUTO_APPLY_DERIVED = "AUTO_APPLY_DERIVED"


@dataclass(frozen=True, slots=True)
class AutomationRunResult:
    decisions: PANMigrationDecisionSet
    audit: tuple[dict, ...]
    iterations: int
    stable: bool


def run_automation_until_stable(config, derived, decisions, target=None, device=None, *,
                                enabled_policies=(), max_iterations=None):
    """Apply explicitly enabled deterministic results without mutating source config."""
    policies = {AutomationPolicy(value) for value in enabled_policies}
    limit = max_iterations if max_iterations is not None else len(decisions.decisions) + 1
    if not isinstance(limit, int) or limit < 1:
        raise ValueError("max_iterations must be a positive integer")

    current = decisions
    audit = []
    for iteration in range(1, limit + 1):
        results = classify_auto_decisions(config, derived, current, target, device)
        conflicts = {item.decision_key for item in validate_against_target(config, current, target, device)}
        dependencies = dependent_decision_keys(config, current)
        blocked = set(conflicts)
        pending = list(conflicts)
        while pending:
            for key in dependencies.get(pending.pop(), ()):
                if key not in blocked:
                    blocked.add(key)
                    pending.append(key)

        updated = []
        changed = False
        for decision in current.decisions:
            result = results.get(decision.key, {})
            status = "CONFLICT" if decision.key in conflicts else result.get("status", "MANUAL")
            policy = (AutomationPolicy.AUTO_APPLY_VERIFIED if status == "VERIFIED" else
                      AutomationPolicy.AUTO_APPLY_DERIVED if status == "DERIVED" else None)
            if (decision.review_state != PANDecisionReviewState.CONFIRMED
                    and decision.mode.value != "UNSUPPORTED"
                    and decision.key not in blocked and policy in policies and result.get("value")):
                decision = replace(decision, value=result["value"],
                                   review_state=PANDecisionReviewState.CONFIRMED,
                                   evidence_source="ENGINEER", evidence_type="ENGINEER_AUTOMATION_POLICY",
                                   evidence_value=policy.value, target_object=result["value"])
                audit.append({"iteration": iteration, "decision_key": decision.key,
                              "status": status, "value": decision.value, "policy": policy.value})
                changed = True
            updated.append(decision)
        if not changed:
            return AutomationRunResult(current, tuple(audit), iteration, True)
        current = PANMigrationDecisionSet(tuple(sorted(updated, key=lambda item: item.key)))
    return AutomationRunResult(current, tuple(audit), limit, False)
