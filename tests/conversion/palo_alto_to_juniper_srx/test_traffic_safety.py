"""Source through approval/export regressions for policy and routing semantics."""

from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import xml.etree.ElementTree as ET

import pytest

from fwmigrate.conversion.palo_alto_to_juniper_srx.application import (
    approve_design, build_artifact, build_review, verify_export_artifact,
)
from fwmigrate.conversion.palo_alto_to_juniper_srx.options import SRXInterfaceMapping, SRXMigrationOptions
from fwmigrate.vendors.palo_alto.source_model import pan_scope_identity
from fwmigrate.vendors.palo_alto.source_report import PaloAltoSourceReporter
from fwmigrate.vendors.juniper_srx.source_report import JuniperSRXSourceReporter


FIXTURE = Path(__file__).parents[2] / "fixtures/palo_alto/ftd_policy_explicit.xml"


def source_tree():
    tree = ET.fromstring(FIXTURE.read_text(encoding="utf-8"))
    rules = tree.find(".//vsys/entry/rulebase/security/rules")
    template = deepcopy(rules[0])
    rules.clear()
    for name, action in (("first-drop", "drop"), ("inactive", "drop"), ("later-allow", "allow")):
        rule = deepcopy(template)
        rule.set("name", name)
        rule.find("action").text = action
        rule.find("from/member").text = "inside"
        rule.find("to/member").text = "outside"
        if name == "inactive":
            rule.find("disabled").text = "yes"
        rules.append(rule)
    return tree


def review_tree(tree, options=None, **target):
    analysis = PaloAltoSourceReporter().analyze_source(ET.tostring(tree, encoding="unicode"))
    scope = pan_scope_identity(next(row for row in analysis.config.scopes if row.kind == "vsys"))
    options = options or SRXMigrationOptions(source_scope=scope,
        interfaces={"ethernet1/1": SRXInterfaceMapping("ge-0/0/0"),
                    "ethernet1/2": SRXInterfaceMapping("ge-0/0/1")},
        zones={"inside": "inside", "outside": "outside"})
    return analysis, options, build_review(analysis, options, "source", **target)


def test_selecting_later_allow_includes_predecessor_and_zone_interface_closure():
    analysis, options, review = review_tree(source_tree())
    before = analysis.config.model_dump_json()
    allow = next(row for row in review["plan"].items if row.source_name == "later-allow")
    approval = approve_design(review, review["draft"], [allow.key])
    artifact = verify_export_artifact(build_artifact(analysis, options, "source", approval))
    selected = [row for row in review["plan"].items if row.key in approval["selected_items"]]
    assert {row.family for row in selected} >= {"interface", "zone", "policy", "address", "service"}
    assert {row.source_name for row in selected if row.family == "policy"} == {"first-drop", "later-allow"}
    assert not any(row.family == "inactive_policy" for row in selected)
    commands = artifact["command_text"]
    assert commands.index("set security zones") < commands.index("policy first-drop") < commands.index("policy later-allow")
    assert "policy first-drop then deny" in commands
    assert "policy later-allow then permit" in commands
    assert analysis.config.model_dump_json() == before
    evidence = dict(allow.settings)["schedule_evidence"]
    assert evidence["origin"] == "PANOS_DEFAULT" and evidence["version"] == "11.1.0"


def test_blocked_interface_blocks_policy_approval_through_zone_dependencies():
    tree = source_tree()
    ET.SubElement(tree.find(".//ethernet/entry/layer3"), "unknown-forwarding-setting").text = "retain"
    _, _, review = review_tree(tree)
    allow = next(row for row in review["plan"].items if row.source_name == "later-allow")
    assert allow.blockers
    with pytest.raises(ValueError, match="blocked"):
        approve_design(review, review["draft"], [allow.key])


@pytest.mark.parametrize("version", [None, "11.0.0", "11.2.0"])
def test_unverified_omitted_schedule_remains_blocked(version):
    tree = source_tree()
    if version is None:
        tree.attrib.pop("version")
    else:
        tree.set("version", version)
    _, _, review = review_tree(tree)
    assert all("POLICY_SCHEDULE_UNSUPPORTED" in row.blockers for row in review["plan"].items if row.family == "policy")


@pytest.mark.parametrize("name", ["always", "office-hours"])
def test_named_schedule_never_becomes_an_unrestricted_policy(name):
    tree = source_tree()
    schedule = ET.SubElement(tree.find(".//vsys/entry"), "schedule")
    entry = ET.SubElement(schedule, "entry", name=name)
    daily = ET.SubElement(ET.SubElement(ET.SubElement(entry, "schedule-type"), "recurring"), "daily")
    ET.SubElement(daily, "member").text = "09:00-17:00"
    ET.SubElement(tree.find(".//security/rules/entry"), "schedule").text = name
    _, _, review = review_tree(tree)
    policies = [row for row in review["plan"].items if row.family == "policy"]
    assert "POLICY_SCHEDULE_UNSUPPORTED" in policies[0].blockers
    assert all(row.blockers for row in policies)
    assert "policy later-allow" not in review["report"]["command_preview"]
    with pytest.raises(ValueError, match="blocked"):
        approve_design(review, review["draft"], [policies[-1].key])


def test_route_preference_survives_approval_native_export_and_exact_reuse():
    tree = source_tree()
    tree.find(".//static-route/entry/admin-dist").text = "100"
    analysis, options, review = review_tree(tree)
    route = next(row for row in review["plan"].items if row.family == "static_route")
    assert not route.blockers
    approval = approve_design(review, review["draft"], [route.key])
    artifact = verify_export_artifact(build_artifact(analysis, options, "source", approval))
    expected = "set routing-options static route 0.0.0.0/0 preference 100"
    assert expected in artifact["command_text"]
    target_text = artifact["command_text"]
    target = JuniperSRXSourceReporter().analyze_source(target_text)
    metadata = {"context": "root", "version": "25.2R1", "mode": "standalone",
                "complete_families": ["static_routes", "interfaces"]}
    compared = build_review(analysis, options, "source", target=target,
                          target_source_text=target_text, target_metadata=metadata)
    reused = next(row for row in compared["plan"].items if row.key == route.key)
    assert reused.target_disposition == "REUSE"
    conflicting_text = target_text.replace("preference 100", "preference 101")
    conflict = build_review(analysis, options, "source",
        target=JuniperSRXSourceReporter().analyze_source(conflicting_text),
        target_source_text=conflicting_text, target_metadata=metadata)
    assert "TARGET_OBJECT_CONFLICT" in next(row for row in conflict["plan"].items if row.key == route.key).blockers


def test_policy_cannot_omit_a_blocked_predecessor_after_an_inactive_rule():
    tree = source_tree()
    tree.find(".//security/rules/entry/application/member").text = "ssl"
    _, _, review = review_tree(tree)
    allow = next(row for row in review["plan"].items if row.source_name == "later-allow")
    assert "EARLIER_POLICY_IN_CONTEXT_UNSUPPORTED" in allow.blockers
    with pytest.raises(ValueError, match="blocked"):
        approve_design(review, review["draft"], [allow.key])


def test_missing_zone_mapping_cannot_be_bypassed_by_policy_selection():
    tree = source_tree()
    _, options, _ = review_tree(tree)
    target_text = "set system host-name target\n"
    _, _, review = review_tree(tree, replace(options, zones={"inside": "inside"}),
        target=JuniperSRXSourceReporter().analyze_source(target_text), target_source_text=target_text,
        target_metadata={"context": "root", "version": "25.2R1", "mode": "standalone",
                         "complete_families": ["addresses", "applications", "interfaces", "zones", "policies", "nat", "static_routes"]})
    allow = next(row for row in review["plan"].items if row.source_name == "later-allow")
    assert allow.blockers
    with pytest.raises(ValueError, match="blocked"):
        approve_design(review, review["draft"], [allow.key])


def test_other_zone_context_does_not_add_unrelated_policy_predecessors():
    tree = source_tree()
    rule = deepcopy(tree.find(".//security/rules/entry"))
    rule.set("name", "separate-context")
    rule.find("from/member").text = "outside"
    rule.find("to/member").text = "inside"
    tree.find(".//security/rules").append(rule)
    _, _, review = review_tree(tree)
    separate = next(row for row in review["plan"].items if row.source_name == "separate-context")
    approval = approve_design(review, review["draft"], [separate.key])
    selected = set(approval["selected_items"])
    assert {row.source_name for row in review["plan"].items if row.key in selected and row.family == "policy"} == {"separate-context"}


def test_legacy_approval_and_artifact_require_fresh_review():
    analysis, options, review = review_tree(source_tree())
    address = next(row for row in review["plan"].items if row.family == "address")
    approval = approve_design(review, review["draft"], [address.key])
    artifact = build_artifact(analysis, options, "source", approval)
    with pytest.raises(ValueError):
        build_artifact(analysis, options, "source", {**approval, "envelope_type": "palo_alto_to_juniper_srx_approval_v1"})
    with pytest.raises(ValueError):
        verify_export_artifact({**artifact, "envelope_type": "palo_alto_to_juniper_srx_artifact_v1"})
