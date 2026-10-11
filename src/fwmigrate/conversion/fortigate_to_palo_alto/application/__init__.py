"""Application services for the FortiGate to PAN-OS workflow."""

from .artifact_eligibility import (ArtifactEligibilityError, DESIGN_APPROVAL_TTL_SECONDS, approval_is_current, deployment_serial,
                                   validate_artifact_approval, validate_approved_plan)
from .decision_documents import (
    build_decision_document,
    confirm_mapping_decisions,
    load_decision_document,
    options_mapping,
)
from .deployment_feedback import deployment_validation_feedback
from .review import (
    InterfaceMappingConfirmationError,
    auto_review_results,
    build_review_state,
    confirm_interface_mappings,
    decision_evidence,
    evidence_summary,
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
from ..design.deterministic import approve_draft, build_deterministic_draft, draft_context
from ..pipeline import run_migration_pipeline
from ..decision_propagation import (
    MigrationRuleType,
    apply_repeated_zone_action,
    apply_zone_to_members,
    rule_affected_decision_keys,
)
from ..plan_dependencies import build_plan_dependency_index, item_key
from ..recommendations.support_guidance import build_support_guidance
from ..target.target_evidence import (
    reconcile_target_evidence,
    target_evidence_changed,
    target_evidence_identity,
)
from ..target.target_intent import apply_target_intent, export_target_intent
from ..target.target_object_reuse import classify_target_object_reuse
from ..target.target_plan_validation import assess_target_plan, validate_target_plan
from ..target.target_suggestions import target_device_metadata, target_devices, target_serial
from ..validation import validate_plan
from ..target.target_suggestions import suggest_from_target
from ..target.target_suggestions import discover_target_candidates
from ..target.target_validation import validate_against_target
from ..requirements import build_mapping_requirements
from ..review.review_context import build_review_context
from ..review.review_evidence import build_review_evidence
from ..review.review_workflow import build_review_workflow
from ..auto_decisions import classify_auto_decisions
from .. import build_recommendations

__all__ = [
    "ArtifactEligibilityError", "DESIGN_APPROVAL_TTL_SECONDS", "approval_is_current",
    "deployment_serial", "validate_artifact_approval", "validate_approved_plan", "target_serial",
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
    "run_migration_pipeline", "build_deterministic_draft", "approve_draft",
    "draft_context", "confirm_interface_mappings", "InterfaceMappingConfirmationError",
]
