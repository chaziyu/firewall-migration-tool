"""FortiGate to Palo Alto migration-planning boundary."""

from .models import (
    MigrationIssue,
    MigrationSourceRef,
    PANMigrationPlan,
    PANMigrationStatus,
    PlannedAddress,
    PlannedAddressGroup,
    PlannedNATRule,
    PlannedPANItem,
    PlannedSchedule,
    PlannedSecurityRule,
    PlannedService,
    PlannedServiceGroup,
    PlannedStaticRoute,
    PlannedZone,
)
from .options import InterfaceMapping, PANMigrationOptions, VDOMMapping
from .decisions import (
    PANDecisionMode,
    PANDecisionReviewState,
    PANMigrationDecision,
    PANMigrationDecisionSet,
    build_decision_set,
    make_decision_key,
)
from .planner import FortiGateToPaloAltoPlanner
from .target_validation import PANTargetFinding, validate_against_target
from .support_guidance import PANSupportGuidance, build_support_guidance
from .recommendations import (
    PANMigrationRecommendation,
    PANRecommendationConfidence,
    PANRecommendationMethod,
    PANRecommendationReadiness,
)
from .recommendation_engine import build_recommendations

__all__ = [
    "FortiGateToPaloAltoPlanner",
    "InterfaceMapping",
    "MigrationIssue",
    "MigrationSourceRef",
    "PANMigrationOptions",
    "PANDecisionMode",
    "PANDecisionReviewState",
    "PANMigrationDecision",
    "PANMigrationDecisionSet",
    "PANMigrationPlan",
    "PANMigrationStatus",
    "PlannedAddress",
    "PlannedAddressGroup",
    "PlannedNATRule",
    "PlannedPANItem",
    "PlannedSchedule",
    "PlannedSecurityRule",
    "PlannedService",
    "PlannedServiceGroup",
    "PlannedStaticRoute",
    "PlannedZone",
    "VDOMMapping",
    "build_decision_set",
    "make_decision_key",
    "PANTargetFinding",
    "validate_against_target",
    "PANSupportGuidance",
    "build_support_guidance",
    "PANMigrationRecommendation",
    "PANRecommendationConfidence",
    "PANRecommendationMethod",
    "PANRecommendationReadiness",
    "build_recommendations",
]
