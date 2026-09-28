"""Authoritative FortiGate to PAN-OS migration orchestration.

This module is intentionally pair-specific. It composes existing source, decision,
planning, target-validation, and rendering components without introducing a
vendor-neutral migration model.
"""

from dataclasses import asdict, dataclass, replace
from enum import StrEnum
from typing import Any

from .artifact_status import classify_artifact_status
from .automation import AutomationPolicy, run_automation_until_stable
from .decisions import (
    PANDecisionMode,
    PANDecisionReviewState,
    PANMigrationDecision,
    PANMigrationDecisionSet,
    build_decision_set,
    make_decision_key,
)
from .options import PANMigrationOptions
from .plan_dependencies import PANPlanDependencyIndex, build_plan_dependency_index
from .planner import FortiGateToPaloAltoPlanner
from .recommendation_engine import build_recommendations
from .renderer import PANSetRenderer, RenderedMigration
from .requirements import build_mapping_requirements
from .support_guidance import build_support_guidance
from .target_intent import apply_target_intent
from .target_object_reuse import classify_target_object_reuse
from .target_plan_validation import assess_target_plan, validate_target_plan
from .target_suggestions import suggest_from_target
from .target_validation import validate_against_target
from .validation import MigrationValidationResult, validate_plan


class PANAutomationMode(StrEnum):
    REVIEW_ONLY = "REVIEW_ONLY"
    STRICT_VERIFIED = "STRICT_VERIFIED"
    VERIFIED_AND_DERIVED = "VERIFIED_AND_DERIVED"
    ENGINEER_INTENT = "ENGINEER_INTENT"


@dataclass(frozen=True, slots=True)
class PANMigrationPipelineResult:
    requirements: dict
    decisions: PANMigrationDecisionSet
    options: PANMigrationOptions
    plan: Any
    validation: MigrationValidationResult
    target_findings: tuple
    target_warnings: dict
    target_object_reuse: tuple
    target_plan_findings: tuple
    dependency_index: PANPlanDependencyIndex
    dispositions: dict
    render_blockers: dict
    recommendations: tuple
    support_guidance: tuple
    automation_audit: tuple[dict, ...]
    unresolved_decisions: tuple[PANMigrationDecision, ...]
    rendered: RenderedMigration
    artifact_status: str


def automation_policies(mode: PANAutomationMode | str) -> tuple[AutomationPolicy, ...]:
    mode = PANAutomationMode(mode)
    if mode is PANAutomationMode.REVIEW_ONLY:
        return ()
    if mode is PANAutomationMode.STRICT_VERIFIED:
        return (AutomationPolicy.AUTO_APPLY_VERIFIED,)
    return (AutomationPolicy.AUTO_APPLY_VERIFIED, AutomationPolicy.AUTO_APPLY_DERIVED)


def apply_explicit_options(config, decisions: PANMigrationDecisionSet,
                           options: PANMigrationOptions | dict | None) -> PANMigrationDecisionSet:
    """Apply explicit engineer mappings as confirmed decisions.

    Extra mappings are preserved as pair-specific decisions so existing CLI and
    API mapping documents remain backward compatible. No source or target value
    is inferred here.
    """
    if options is None:
        return decisions
    if isinstance(options, dict):
        options = PANMigrationOptions(**options)
    if not isinstance(options, PANMigrationOptions):
        raise TypeError("options must be PANMigrationOptions, a mapping, or null")

    by_key = {item.key: item for item in decisions.decisions}
    zones = {(item.vdom or "root", item.name) for item in getattr(config, "zones", ()) if item.name}
    interfaces = {(item.vdom or "root", item.name) for item in getattr(config, "interfaces", ()) if item.name}

    def confirm(vdom: str, kind: str, name: str, field: str, value: str | None) -> None:
        if value is None:
            return
        key = make_decision_key(vdom, kind, name, field)
        old = by_key.get(key)
        if old is None:
            old = PANMigrationDecision(vdom, kind, name, field, mode=PANDecisionMode.REQUIRED)
        by_key[key] = replace(
            old,
            value=value,
            review_state=PANDecisionReviewState.CONFIRMED,
            evidence_source="ENGINEER",
            evidence_type="EXPLICIT_MAPPING",
            evidence_value=value,
            target_object=value,
        )

    for vdom, mapping in options.vdoms.items():
        for field, value in asdict(mapping).items():
            confirm(vdom, "vdom", vdom, field, value)

    for vdom, mappings in options.interfaces.items():
        for name, mapping in mappings.items():
            for field, value in asdict(mapping).items():
                kind = (
                    "zone"
                    if field == "target_zone"
                    and (vdom, name) in zones
                    and (vdom, name) not in interfaces
                    else "interface"
                )
                confirm(vdom, kind, name, field, value)

    for vdom, mappings in (options.zones or {}).items():
        for name, mapping in mappings.items():
            confirm(vdom, "zone", name, "target_zone", mapping.target_zone)

    return PANMigrationDecisionSet(tuple(sorted(by_key.values(), key=lambda item: item.key)))


def run_migration_pipeline(
    source,
    derived,
    *,
    decisions: PANMigrationDecisionSet | None = None,
    options: PANMigrationOptions | dict | None = None,
    target=None,
    target_device: str | None = None,
    target_intent=None,
    automation_mode: PANAutomationMode | str = PANAutomationMode.REVIEW_ONLY,
    planner: FortiGateToPaloAltoPlanner | None = None,
) -> PANMigrationPipelineResult:
    """Run the complete supported FortiGate -> PAN-OS planning pipeline.

    Deterministic automation can confirm VERIFIED/DERIVED mappings, but
    suggestions and candidates remain unconfirmed. Planner input is always
    regenerated from the final decision set to prevent stale mappings.
    """
    mode = PANAutomationMode(automation_mode)
    requirements = build_mapping_requirements(source, derived)
    current = decisions or build_decision_set(source, derived, requirements)
    current = apply_explicit_options(source, current, options)

    if target_intent is not None:
        current = apply_target_intent(source, current, target_intent)

    target_warnings = {}
    if target is not None and target_device:
        current, target_warnings = suggest_from_target(source, current, target, target_device)

    automation = run_automation_until_stable(
        source,
        derived,
        current,
        target,
        target_device,
        enabled_policies=automation_policies(mode),
    )
    current = automation.decisions

    # All target validation and planning use the same final decisions.
    target_findings = validate_against_target(source, current, target, target_device)
    final_options = current.to_options()
    actual_planner = planner or FortiGateToPaloAltoPlanner()
    plan = actual_planner.plan(source, derived, options=final_options)

    target_object_reuse = classify_target_object_reuse(plan, target, target_device)
    dependencies = build_plan_dependency_index(plan, current)
    target_plan_findings = validate_target_plan(
        plan, target_object_reuse, target_findings, current, dependencies
    )
    dispositions, render_blockers = assess_target_plan(
        plan, target_object_reuse, target_findings, current, dependencies
    )
    validation = validate_plan(plan)
    support_guidance = build_support_guidance(plan, validation, current, target_findings)
    recommendations = build_recommendations(source, derived, current, target, target_device)
    rendered = PANSetRenderer().render(
        plan,
        validation,
        dispositions=dispositions,
        render_blockers=render_blockers,
        decision_keys=dependencies.decision_keys_by_item,
    )

    unresolved = tuple(
        item
        for item in current.decisions
        if item.mode not in {PANDecisionMode.AUTO, PANDecisionMode.UNSUPPORTED}
        and item.review_state is not PANDecisionReviewState.CONFIRMED
    )
    status = classify_artifact_status(rendered, pending_mapping_issues=unresolved).value
    rendered = replace(rendered, report={
        **rendered.report,
        "plan_status": status,
        "automation": {
            "mode": mode.value,
            "applied": len(automation.audit),
            "stable": automation.stable,
            "iterations": automation.iterations,
        },
        "unresolved_required_decisions": len(unresolved),
    })
    return PANMigrationPipelineResult(
        requirements=requirements,
        decisions=current,
        options=final_options,
        plan=plan,
        validation=validation,
        target_findings=target_findings,
        target_warnings=target_warnings,
        target_object_reuse=target_object_reuse,
        target_plan_findings=target_plan_findings,
        dependency_index=dependencies,
        dispositions=dispositions,
        render_blockers=render_blockers,
        recommendations=recommendations,
        support_guidance=support_guidance,
        automation_audit=automation.audit,
        unresolved_decisions=unresolved,
        rendered=rendered,
        artifact_status=status,
    )


__all__ = [
    "PANAutomationMode",
    "PANMigrationPipelineResult",
    "apply_explicit_options",
    "automation_policies",
    "run_migration_pipeline",
]
