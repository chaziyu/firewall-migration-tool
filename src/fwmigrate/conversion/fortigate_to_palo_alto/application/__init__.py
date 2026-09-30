"""Application services for the FortiGate to PAN-OS workflow."""

from .decision_documents import (
    build_decision_document,
    confirm_mapping_decisions,
    load_decision_document,
    options_mapping,
)
from .deployment_feedback import deployment_validation_feedback
from .review import (
    build_review_state,
    evidence_summary,
    auto_review_results,
    decision_evidence,
)
from .. import (
    PANAutomationMode,
    PANDecisionMode,
    PANDecisionReviewState,
    PANMigrationDecision,
    PANMigrationDecisionSet,
    PANMigrationOptions,
    build_decision_set,
    make_decision_key,
)
from ..automation import AutomationPolicy, run_automation_until_stable
from ..decision_propagation import (
    MigrationRuleType,
    apply_repeated_zone_action,
    apply_zone_to_members,
    rule_affected_decision_keys,
)
from ..plan_dependencies import build_plan_dependency_index, item_key
from ..support_guidance import build_support_guidance
from ..target_evidence import (
    reconcile_target_evidence,
    target_evidence_changed,
    target_evidence_identity,
)
from ..target_intent import apply_target_intent, export_target_intent
from ..target_object_reuse import classify_target_object_reuse
from ..target_plan_validation import assess_target_plan, validate_target_plan
from ..target_suggestions import target_device_metadata, target_devices
from ..validation import validate_plan
from ..target_suggestions import suggest_from_target
from ..target_suggestions import discover_target_candidates
from ..target_validation import validate_against_target
from ..requirements import build_mapping_requirements
from ..review_context import build_review_context
from ..review_evidence import build_review_evidence
from ..review_workflow import build_review_workflow
from ..auto_decisions import classify_auto_decisions
from .. import build_recommendations

__all__ = [
    "build_decision_document",
    "load_decision_document",
    "options_mapping",
    "deployment_validation_feedback",
    "build_review_state",
    "confirm_mapping_decisions",
    "evidence_summary",
    "auto_review_results", "decision_evidence",
    "PANAutomationMode", "PANDecisionMode", "PANDecisionReviewState",
    "PANMigrationDecision", "PANMigrationDecisionSet", "PANMigrationOptions",
    "build_decision_set", "make_decision_key", "AutomationPolicy",
    "run_automation_until_stable", "MigrationRuleType", "apply_repeated_zone_action",
    "apply_zone_to_members", "rule_affected_decision_keys", "build_plan_dependency_index",
    "item_key", "build_support_guidance", "reconcile_target_evidence",
    "target_evidence_changed", "target_evidence_identity", "apply_target_intent",
    "export_target_intent", "classify_target_object_reuse", "assess_target_plan",
    "validate_target_plan", "target_device_metadata", "target_devices", "validate_plan",
    "discover_target_candidates", "suggest_from_target", "validate_against_target",
    "build_mapping_requirements", "build_review_context", "build_review_evidence",
    "build_review_workflow", "classify_auto_decisions", "build_recommendations",
]
