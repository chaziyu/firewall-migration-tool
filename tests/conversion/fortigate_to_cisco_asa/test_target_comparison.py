import hashlib

from fwmigrate.conversion.fortigate_to_cisco_asa.planner import FortiGateToCiscoASAPlanner
from fwmigrate.conversion.fortigate_to_cisco_asa.planning.naming import item_key
from fwmigrate.conversion.fortigate_to_cisco_asa.target.comparison import classify_target_reuse
from fwmigrate.conversion.fortigate_to_cisco_asa.target.evidence import build_target_evidence
from fwmigrate.vendors.cisco_asa import CiscoASASourceReporter


COMPLETE = ["interfaces", "objects", "schedules", "routes", "access_rules", "acl_bindings", "nat"]


def evidence(text, *, families=COMPLETE):
    analysis = CiscoASASourceReporter().analyze_source(text)
    return build_target_evidence(analysis, hashlib.sha256(text.encode()).hexdigest(), {
        "context": "single", "version": "9.20", "mode": "routed", "complete_families": families,
    })


def test_exact_interface_reuse_requires_explicit_matching_admin_state(asa_source, asa_options):
    text = """interface GigabitEthernet0/1
 nameif inside
 security-level 100
 ip address 10.0.0.1 255.255.255.0
 no shutdown
"""
    plan = FortiGateToCiscoASAPlanner().plan(asa_source.extracted.config, asa_source.derived, asa_options)
    compared = classify_target_reuse(plan, asa_source.extracted.config, asa_options, evidence(text))
    interface = next(item for item in compared.items if item.key == item_key("root", "interface", "inside"))
    assert interface.target_disposition == "REUSE"
    assert dict(interface.settings)["commands"] == ()

    shut = evidence(text.replace(" no shutdown", " shutdown"))
    compared = classify_target_reuse(plan, asa_source.extracted.config, asa_options, shut)
    interface = next(item for item in compared.items if item.key == item_key("root", "interface", "inside"))
    assert "TARGET_INTERFACE_CONFLICT" in interface.blockers


def test_policy_comparison_requires_acl_binding_and_nat_completeness(asa_source, asa_options):
    plan = FortiGateToCiscoASAPlanner().plan(asa_source.extracted.config, asa_source.derived, asa_options)
    target = evidence("", families=["access_rules", "acl_bindings"])
    compared = classify_target_reuse(plan, asa_source.extracted.config, asa_options, target)
    policy = next(item for item in compared.items if item.family == "policy")
    assert "TARGET_FAMILY_COMPLETENESS_REQUIRED" in policy.blockers
