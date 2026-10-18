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

    for changed in (text.replace("255.255.255.0", "255.255.0.0"),
                    text.replace(" no shutdown", " management-only\n no shutdown")):
        compared = classify_target_reuse(plan, asa_source.extracted.config, asa_options, evidence(changed))
        interface = next(item for item in compared.items if item.key == item_key("root", "interface", "inside"))
        assert "TARGET_INTERFACE_CONFLICT" in interface.blockers


def test_policy_comparison_requires_acl_binding_and_nat_completeness(asa_source, asa_options):
    plan = FortiGateToCiscoASAPlanner().plan(asa_source.extracted.config, asa_source.derived, asa_options)
    target = evidence("", families=["access_rules", "acl_bindings"])
    compared = classify_target_reuse(plan, asa_source.extracted.config, asa_options, target)
    policy = next(item for item in compared.items if item.family == "policy")
    assert "TARGET_FAMILY_COMPLETENESS_REQUIRED" in policy.blockers


def test_exact_address_definition_reuses_but_nat_or_changed_values_do_not(asa_source, asa_options):
    from fwmigrate.conversion.fortigate_to_cisco_asa.rendering.renderer import ASACLIRenderer

    plan = FortiGateToCiscoASAPlanner().plan(asa_source.extracted.config, asa_source.derived, asa_options)
    address = next(item for item in plan.items if item.family == "address" and item.source_name == "clients")
    text = "\n".join(dict(address.settings)["commands"]) + "\n"
    compared = classify_target_reuse(plan, asa_source.extracted.config, asa_options, evidence(text))
    reused = next(item for item in compared.items if item.key == address.key)
    assert reused.target_disposition == "REUSE"
    assert not reused.blockers
    assert f"object network {address.target_name}" not in ASACLIRenderer().render(compared).command_text
    changed = classify_target_reuse(plan, asa_source.extracted.config, asa_options,
                                    evidence(text.replace("10.0.0.0", "10.1.0.0")))
    assert "TARGET_OBJECT_CONFLICT" in next(item for item in changed.items if item.key == address.key).blockers


def test_destination_digest_binds_completeness_metadata(asa_source, asa_options):
    from fwmigrate.conversion.fortigate_to_cisco_asa.application.workflow import build_review

    target = CiscoASASourceReporter().analyze_source("! reviewed target\n")
    metadata = {"context": "single", "version": "9.20", "mode": "routed", "complete_families": COMPLETE}
    first = build_review(asa_source, asa_options, "source", target=target,
                         target_source_text="! reviewed target\n", target_metadata=metadata)
    second = build_review(asa_source, asa_options, "source", target=target,
                          target_source_text="! reviewed target\n", target_metadata={**metadata, "complete_families": ["objects"]})
    assert first["draft"]["target_digest"] != second["draft"]["target_digest"]
