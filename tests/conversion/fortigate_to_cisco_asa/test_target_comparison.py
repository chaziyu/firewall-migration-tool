import hashlib

import pytest

from fwmigrate.conversion.fortigate_to_cisco_asa.planner import FortiGateToCiscoASAPlanner
from fwmigrate.conversion.fortigate_to_cisco_asa.planning.naming import item_key
from fwmigrate.conversion.fortigate_to_cisco_asa.target.comparison import classify_target_reuse
from fwmigrate.conversion.fortigate_to_cisco_asa.target.evidence import build_target_evidence
from fwmigrate.vendors.cisco_asa import CiscoASASourceReporter


COMPLETE = ["interfaces", "objects", "schedules", "routes", "access_rules", "acl_bindings", "nat"]


@pytest.mark.parametrize("text", [
    "object network existing\n subnet 10.0.0.0 255.255.255.0\n nat (inside,outside) dynamic interface\n",
    "object network existing\n subnet 10.0.0.0 255.255.255.0\nnat (inside,outside) source dynamic existing interface\n",
])
def test_existing_nat_blocks_traffic_but_keeps_independent_objects(asa_source, asa_options, text):
    from fwmigrate.conversion.fortigate_to_cisco_asa.application.workflow import build_review

    text = ("interface GigabitEthernet0/1\n nameif inside\n security-level 100\n"
            " ip address 10.0.0.1 255.255.255.0\n no shutdown\n"
            "interface GigabitEthernet0/0\n nameif outside\n security-level 0\n"
            " ip address 198.51.100.1 255.255.255.0\n no shutdown\n" + text)
    target = CiscoASASourceReporter().analyze_source(text)
    review = build_review(asa_source, asa_options, "source", target=target, target_source_text=text,
                          target_metadata={"context": "single", "version": "9.20", "mode": "routed",
                                           "complete_families": COMPLETE})
    for row in review["report"]["items"]:
        if row["family"] in {"policy", "default_behavior", "acl_binding"}:
            assert row["render_disposition"] == "BLOCK"
        elif row["family"] in {"address", "service"}:
            assert row["render_disposition"] == "CREATE"


def test_complete_empty_nat_allows_policy_and_changed_snapshot_revokes_approval(asa_source, asa_options):
    from fwmigrate.conversion.fortigate_to_cisco_asa.application.workflow import approve_design, build_artifact, build_review

    def target(text):
        return {"target": CiscoASASourceReporter().analyze_source(text), "target_source_text": text,
                "target_metadata": {"context": "single", "version": "9.20", "mode": "routed", "complete_families": COMPLETE}}

    review = build_review(asa_source, asa_options, "source", **target(""))
    policy = next(row for row in review["report"]["items"] if row["family"] == "policy")
    assert policy["render_disposition"] == "CREATE"
    approval = approve_design(review, review["draft"], [policy["key"]])
    with pytest.raises(ValueError, match="approval"):
        build_artifact(asa_source, asa_options, "source", approval, **target("! changed target snapshot\n"))


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
