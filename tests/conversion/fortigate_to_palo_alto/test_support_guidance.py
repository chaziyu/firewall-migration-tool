from types import SimpleNamespace

import pytest

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


def test_vip_load_balancing_guidance_requires_manual_target_design():
    item = PlannedSecurityRule(source_vdom="root", source_kind="policy", source_name="42",
                               status=PANMigrationStatus.MANUAL_REVIEW,
                               warnings=("VIP load-balancing semantics unsupported",))
    guidance = build_support_guidance(PANMigrationPlan(security_rules=(item,)), None,
                                      PANMigrationDecisionSet())
    assert guidance[0].resolution_type == "MANUAL_TARGET_DESIGN"


def test_virtual_router_guidance_links_vdom_decision():
    item = SimpleNamespace(source_vdom="root", source_kind="route", source_name="default",
                           status=PANMigrationStatus.MANUAL_REVIEW,
                           warnings=("missing target virtual-router mapping",))
    decisions = PANMigrationDecisionSet.from_dict({"decisions": [{
        "source_vdom": "root", "source_kind": "vdom", "source_name": "root",
        "target_field": "virtual_router", "mode": "REQUIRED", "review_state": "PENDING",
    }]})
    guidance = build_support_guidance(PANMigrationPlan(static_routes=(item,)), None, decisions)
    assert guidance[0].decision_key == decisions.decisions[0].key


def test_converter_feature_guidance_has_no_decision_key():
    item = SimpleNamespace(source_vdom="root", source_kind="service", source_name="dns",
                           status=PANMigrationStatus.UNSUPPORTED,
                           warnings=("Internet Service matching is unsupported",))
    guidance = build_support_guidance(PANMigrationPlan(services=(item,)), None,
                                      PANMigrationDecisionSet())
    assert guidance[0].resolution_type == "CONVERTER_FEATURE"
    assert guidance[0].decision_key is None


@pytest.mark.parametrize(("warning", "code", "resolution"), [
    ("missing target interface mapping for 'wan'", "MISSING_TARGET_INTERFACE", "MISSING_MAPPING"),
    ("multiple possible egress interfaces", "AMBIGUOUS_NAT_EGRESS", "AMBIGUOUS_SOURCE"),
    ("schedule group is unsupported", "SCHEDULE_GROUP_UNSUPPORTED", "CONVERTER_FEATURE"),
    ("service negation is unsupported", "SERVICE_NEGATION_UNSUPPORTED", "CONVERTER_FEATURE"),
    ("unsupported service protocol", "SERVICE_UNSUPPORTED", "CONVERTER_FEATURE"),
    ("Internet Service matching is unsupported", "INTERNET_SERVICE_UNSUPPORTED", "CONVERTER_FEATURE"),
    ("user and group matching is unsupported", "USER_GROUP_UNSUPPORTED", "MANUAL_TARGET_DESIGN"),
    ("inspection settings are unsupported", "INSPECTION_UNSUPPORTED", "MANUAL_TARGET_DESIGN"),
    ("unsupported source or dynamic routing", "ROUTE_SEMANTICS_UNSUPPORTED", "CONVERTER_FEATURE"),
    ("VIP requires explicit mapping", "VIP_MAPPING_REQUIRED", "MISSING_MAPPING"),
])
def test_guidance_classifies_remaining_supported_blockers(warning, code, resolution):
    item = SimpleNamespace(source_vdom="root", source_kind="policy", source_name="42",
                           status=PANMigrationStatus.MANUAL_REVIEW, warnings=(warning,))
    guidance = build_support_guidance(PANMigrationPlan(security_rules=(item,)), None,
                                      PANMigrationDecisionSet())
    assert guidance[0].code == code
    assert guidance[0].resolution_type == resolution
    assert guidance[0].decision_key is None
