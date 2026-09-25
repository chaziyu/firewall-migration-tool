from types import SimpleNamespace

from fwmigrate.conversion.fortigate_to_palo_alto.decisions import PANMigrationDecisionSet
from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationPlan, PANMigrationStatus, PlannedSecurityRule
from fwmigrate.conversion.fortigate_to_palo_alto.support_guidance import build_support_guidance
from fwmigrate.conversion.fortigate_to_palo_alto.validation import validate_plan


def test_missing_zone_guidance_links_existing_decision():
    item = PlannedSecurityRule(source_vdom="root", source_kind="policy", source_name="42",
                               status=PANMigrationStatus.MANUAL_REVIEW,
                               warnings=("missing target zone mapping for 'wan'",))
    plan = PANMigrationPlan(security_rules=(item,))
    validation = validate_plan(plan)
    decisions = PANMigrationDecisionSet.from_dict({"decisions": [{
        "source_vdom": "root", "source_kind": "interface", "source_name": "wan",
        "target_field": "target_zone", "mode": "REQUIRED", "review_state": "PENDING",
    }]})
    guidance = build_support_guidance(plan, validation, decisions)
    assert guidance[0].resolution_type == "MISSING_MAPPING"
    assert guidance[0].decision_key == decisions.decisions[0].key
