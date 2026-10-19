from dataclasses import replace

import pytest

from fwmigrate.conversion.fortigate_to_cisco_asa.application.workflow import (
    approve_design, build_artifact, build_review,
)
from fwmigrate.conversion.fortigate_to_cisco_asa.planning.naming import item_key
from fwmigrate.conversion.fortigate_to_cisco_asa.rendering.renderer import ASACLIRenderer
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter


@pytest.mark.parametrize("setting", [
    "srcintf", "dstintf", "srcaddr", "dstaddr", "service", "schedule",
    "action", "status", "logtraffic", "srcaddr-negate", "dstaddr-negate",
    "service-negate", "utm-status", "nat", "nat64", "nat46", "natinbound", "natoutbound",
])
def test_missing_policy_evidence_blocks_approval(asa_source_text, asa_options, setting):
    lines = [line for line in asa_source_text.splitlines() if not line.strip().startswith(f"set {setting} ")]
    review = build_review(FortiGateSourceReporter().analyze_source("\n".join(lines)), asa_options, "source")
    policy = next(item for item in review["plan"].items if item.family == "policy")
    assert policy.blockers
    with pytest.raises(ValueError, match="blocked"):
        approve_design(review, review["draft"], [policy.key])


@pytest.mark.parametrize("setting", ["nat64", "nat46", "natinbound", "natoutbound",
    "srcaddr-negate", "dstaddr-negate", "service-negate", "utm-status"])
def test_enabled_policy_semantics_are_blocked(asa_source_text, asa_options, setting):
    text = asa_source_text.replace(f"set {setting} disable", f"set {setting} enable")
    review = build_review(FortiGateSourceReporter().analyze_source(text), asa_options, "source")
    assert next(item for item in review["plan"].items if item.family == "policy").blockers


@pytest.mark.parametrize("field", ["srcintf", "dstintf", "srcaddr", "dstaddr", "service"])
def test_empty_policy_match_lists_are_blocked(asa_source, asa_options, field):
    from fwmigrate.conversion.fortigate_to_cisco_asa.planner import FortiGateToCiscoASAPlanner

    config = asa_source.extracted.config.model_copy(deep=True)
    setattr(config.policies[0], field, [])
    plan = FortiGateToCiscoASAPlanner().plan(config, asa_source.derived, asa_options)
    policy = next(item for item in plan.items if item.family == "policy")
    assert policy.blockers
    assert not dict(policy.settings).get("commands")


@pytest.mark.parametrize("setting", ["set natip 198.51.100.10", "set poolname6 pool6",
    "set ippool enable", "set fixedport enable", "set port-preserve enable"])
def test_typed_translation_controls_are_not_dropped(asa_source_text, asa_options, setting):
    text = asa_source_text.replace("set logtraffic disable", f"{setting}\nset logtraffic disable")
    review = build_review(FortiGateSourceReporter().analyze_source(text), asa_options, "source")
    policy = next(item for item in review["plan"].items if item.family == "policy")
    assert "POLICY_TRANSLATION_CONTROLS_UNSUPPORTED" in policy.blockers


@pytest.fixture
def ordered_source(asa_source_text):
    prefix, _, policies = asa_source_text.partition("config firewall policy\n")
    rule = policies.rsplit("end", 1)[0]
    deny = rule.replace("edit 10", "edit 20").replace("action accept", "action deny")
    return prefix + "config firewall policy\n" + deny + rule + "end\n"


def test_source_order_and_required_deny_survive_partial_approval(ordered_source, asa_options):
    analysis = FortiGateSourceReporter().analyze_source(ordered_source)
    review = build_review(analysis, asa_options, "source")
    deny, permit = [item for item in review["plan"].items if item.family == "policy"]
    assert [deny.source_name, permit.source_name] == ["20", "10"]
    assert deny.key in permit.dependencies
    approval = approve_design(review, review["draft"], [permit.key])
    assert deny.key in approval["selected_items"]
    artifact = build_artifact(analysis, asa_options, "source", approval)
    rules = [line for line in artifact["commands"] if " extended " in line]
    assert " extended deny tcp " in rules[0]
    assert " extended permit tcp " in rules[1]
    with pytest.raises(ValueError, match="dependencies"):
        ASACLIRenderer().render(review["plan"], approved_items={permit.key})


@pytest.mark.parametrize("replacement", [
    'set dstintf "outside"',
    'set dstintf "any"\n        set future-policy-setting enable',
    'set dstintf "any"\n        unset srcintf',
])
def test_blocked_predecessor_blocks_later_permit_and_acl_binding(ordered_source, asa_options, replacement):
    source = ordered_source.replace('set dstintf "any"', replacement, 1)
    analysis = FortiGateSourceReporter().analyze_source(source)
    review = build_review(analysis, asa_options, "source")
    permit = next(item for item in review["report"]["items"]
                  if item["family"] == "policy" and item["source_name"] == "10")
    binding = next(item for item in review["report"]["items"]
                   if item["family"] == "acl_binding" and item["source_name"] == "inside")
    assert permit["render_disposition"] == binding["render_disposition"] == "BLOCK"
    with pytest.raises(ValueError, match="blocked"):
        approve_design(review, review["draft"], [permit["key"]])


def test_translation_predecessor_blocks_later_policy(ordered_source, asa_options):
    text = ordered_source.replace("set nat64 disable", "set nat64 enable", 1)
    review = build_review(FortiGateSourceReporter().analyze_source(text), asa_options, "source")
    policies = [row for row in review["report"]["items"] if row["family"] == "policy"]
    assert all(row["render_disposition"] == "BLOCK" for row in policies)


def test_blocked_rule_does_not_block_an_unrelated_ingress(ordered_source, asa_options):
    source = ordered_source.replace('set dstintf "any"', 'set dstintf "outside"', 1)
    prefix, _, later = source.partition("    edit 10\n")
    source = prefix + "    edit 10\n" + later.replace('set srcintf "inside"', 'set srcintf "outside"')
    analysis = FortiGateSourceReporter().analyze_source(source)
    review = build_review(analysis, asa_options, "source")
    approval = approve_design(review, review["draft"], [item_key("root", "policy", "10")])
    assert item_key("root", "policy", "20") not in approval["selected_items"]
    assert any(" extended permit " in line for line in build_artifact(
        analysis, asa_options, "source", approval,
    )["commands"])


@pytest.mark.parametrize("group", [False, True])
def test_explicit_all_address_keeps_its_restriction_and_dependency(asa_source_text, asa_options, group):
    if group:
        source = asa_source_text.replace('set srcaddr "clients"', 'set srcaddr "all"') + '''config firewall addrgrp
    edit all
        set member clients
        set exclude disable
    next
end
'''
    else:
        source = asa_source_text.replace('"clients"', '"all"')
    analysis = FortiGateSourceReporter().analyze_source(source)
    review = build_review(analysis, asa_options, "source")
    approval = approve_design(review, review["draft"], [item_key("root", "policy", "10")])
    assert item_key("root", "address_group" if group else "address", "all") in approval["selected_items"]
    artifact = build_artifact(analysis, asa_options, "source", approval)
    rule = next(line for line in artifact["commands"] if " extended permit " in line)
    assert "tcp any " not in rule
    assert " subnet 10.0.0.0 255.255.255.0" in artifact["commands"]


def test_explicit_all_service_is_not_an_unrestricted_protocol(asa_source_text, asa_options):
    analysis = FortiGateSourceReporter().analyze_source(asa_source_text.replace('"https"', '"ALL"'))
    review = build_review(analysis, asa_options, "source")
    approval = approve_design(review, review["draft"], [item_key("root", "policy", "10")])
    assert item_key("root", "service", "ALL") in approval["selected_items"]
    artifact = build_artifact(analysis, asa_options, "source", approval)
    assert any(" extended permit tcp " in line and line.endswith("eq 443") for line in artifact["commands"])


@pytest.mark.parametrize("vip_shadow", [False, True])
def test_builtin_all_is_used_only_without_an_explicit_source_object(asa_source_text, asa_options, vip_shadow):
    source = asa_source_text.replace('set dstaddr "web"', 'set dstaddr "all"').replace('set service "https"', 'set service "ALL"')
    if vip_shadow:
        source += '''config firewall vip
    edit all
        set extip 198.51.100.10
        set mappedip 203.0.113.10
        set extintf outside
    next
end
'''
    analysis = FortiGateSourceReporter().analyze_source(source)
    review = build_review(analysis, asa_options, "source")
    policy = next(item for item in review["plan"].items if item.family == "policy")
    if vip_shadow:
        assert policy.blockers
        assert not dict(policy.settings).get("commands")
    else:
        approval = approve_design(review, review["draft"], [policy.key])
        artifact = build_artifact(analysis, asa_options, "source", approval)
        assert any(" extended permit ip " in line and line.endswith(" any") for line in artifact["commands"])


def test_central_snat_blocks_only_the_selected_source_vdom(asa_source_text, asa_options):
    source = asa_source_text + '''config firewall central-snat-map
    edit 1
        set srcintf inside
        set dstintf outside
        set orig-addr clients
        set dst-addr web
        set nat enable
    next
end
'''
    analysis = FortiGateSourceReporter().analyze_source(source)
    review = build_review(analysis, asa_options, "source")
    policy = next(item for item in review["plan"].items if item.family == "policy")
    assert "UNREPRESENTED_CENTRAL_SNAT_BLOCKS_POLICY_EXPORT" in policy.blockers
    assert not dict(policy.settings).get("commands")
    with pytest.raises(ValueError, match="blocked"):
        approve_design(review, review["draft"], [policy.key])

    analysis.extracted.source_objects = [
        replace(row, vdom="other") if row.source_path == "firewall central-snat-map" else row
        for row in analysis.extracted.source_objects
    ]
    review = build_review(analysis, asa_options, "source")
    assert not next(item for item in review["plan"].items if item.family == "policy").blockers
