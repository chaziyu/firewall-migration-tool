from pathlib import Path
from dataclasses import replace
import re

import pytest

from fwmigrate.conversion.fortigate_to_juniper_srx import FortiGateToJuniperSRXPlanner
from fwmigrate.conversion.fortigate_to_juniper_srx.rendering.renderer import JunosSetRenderer
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter


FIXTURE = Path(__file__).parents[2] / "fixtures" / "fortigate" / "multi_vendor_explicit.conf"


def _analysis(source):
    source = source.replace('set interface "lan" "app-vlan"', 'set interface "lan"', 1)
    return FortiGateSourceReporter().analyze_source(source)


def _plan(analysis, options):
    return FortiGateToJuniperSRXPlanner().plan(
        analysis.extracted.config,
        analysis.derived,
        options,
        source_inventory=analysis.extracted.source_objects,
    )


def fixed_pool_source():
    source = FIXTURE.read_text(encoding="utf-8")
    source = re.sub(r'            edit 20\n.*?            next\n', '', source, count=1, flags=re.S)
    source = source.replace('set srcaddr "trusted-clients"', 'set srcaddr "app-host"')
    source = source.replace('set dstaddr "app-host"', 'set dstaddr "all"')
    source = source.replace('set service "application-services"', 'set service "ALL"')
    source = source.replace('set schedule "weekday-hours"', 'set schedule "always"')
    source = source.replace('set nat disable', '''set nat enable
                set ippool enable
                set poolname "fixed-pool"
                set fixedport enable
                set port-preserve enable
                set nat64 disable
                set nat46 disable
                set natinbound disable
                set natoutbound disable''', 1)
    source = source.replace('        config firewall policy', '''        config firewall ippool
            edit "fixed-pool"
                set type one-to-one
                set startip 198.51.100.10
                set endip 198.51.100.10
                set arp-reply disable
            next
        end
        config firewall policy''', 1)
    return source


def test_fixed_host_pool_nat_is_atomic_and_preserves_source_ports(complete_options):
    from fwmigrate.conversion.fortigate_to_juniper_srx.application.workflow import (
        approve_design, build_artifact, build_review,
    )

    analysis = _analysis(fixed_pool_source())
    options = replace(complete_options, nat_return_routing_confirmed=True)
    review = build_review(analysis, options, "source")
    nat = next(item for item in review["plan"].items if item.family == "source_nat")
    assert not nat.blockers, nat.blockers
    approval = approve_design(review, review["draft"], [nat.key])
    artifact = build_artifact(analysis, options, "source", approval)
    assert 'port no-translation' in artifact["command_text"]
    assert 'match source-address 10.10.0.10/32' in artifact["command_text"]
    assert 'then source-nat pool' in artifact["command_text"]
    assert 'then permit' in artifact["command_text"]


@pytest.mark.parametrize("blocked_family", ["policy", "source_nat", "source_nat_pool"])
def test_fixed_pool_target_conflict_blocks_the_entire_group(complete_options, blocked_family):
    from fwmigrate.conversion.fortigate_to_juniper_srx.plan_dependencies import assess_render_disposition

    analysis = _analysis(fixed_pool_source())
    plan = _plan(analysis, replace(complete_options, nat_return_routing_confirmed=True))
    plan = replace(plan, items=tuple(
        replace(item, target_disposition="BLOCK") if item.family == blocked_family else item
        for item in plan.items
    ))
    dispositions = assess_render_disposition(plan)
    assert all(dispositions[item.key] == "BLOCK" for item in plan.items if item.approval_group)
    commands = JunosSetRenderer().render(plan).command_text
    assert 'set security nat source' not in commands
    assert 'then permit' not in commands


def test_existing_target_proxy_arp_blocks_fixed_pool_translation(complete_options):
    from fwmigrate.conversion.fortigate_to_juniper_srx.application.workflow import build_review
    from fwmigrate.vendors.juniper_srx.source_report import JuniperSRXSourceReporter

    text = ('set interfaces ge-0/0/1 unit 0 family inet address 203.0.113.2/24\n'
            'set security nat proxy-arp interface ge-0/0/1.0 address 198.51.100.10/32\n')
    review = build_review(_analysis(fixed_pool_source()),
        replace(complete_options, nat_return_routing_confirmed=True), "source",
        target=JuniperSRXSourceReporter().analyze_source(text), target_source_text=text,
        target_metadata={"context": "root", "version": "25.2R1", "mode": "standalone",
            "complete_families": ["interfaces", "addresses", "applications", "zones", "static_routes", "schedules", "policies", "nat"]})
    nat = next(item for item in review["plan"].items if item.family == "source_nat")
    assert "TARGET_CONFIGURATION_CONFLICT" in nat.blockers
    assert 'then source-nat pool' not in JunosSetRenderer().render(review["plan"]).command_text


@pytest.mark.parametrize("old,new", [("set fixedport enable", "set fixedport disable"),
    ("set port-preserve enable", "set port-preserve disable"),
    ("set arp-reply disable", "set arp-reply enable"),
    ("set type one-to-one", "set type overload")])
def test_fixed_pool_nat_rejects_unproven_port_or_arp_behavior(complete_options, old, new):
    analysis = _analysis(fixed_pool_source().replace(old, new))
    plan = _plan(analysis, replace(complete_options, nat_return_routing_confirmed=True))
    assert 'then source-nat pool' not in JunosSetRenderer().render(plan).command_text


def test_interface_snat_is_linked_to_its_policy_and_stays_blocked(complete_options):
    source = FIXTURE.read_text(encoding="utf-8")
    source = source.replace("set nat disable", "set nat enable", 1)
    analysis = _analysis(source)

    plan = _plan(analysis, complete_options)
    nat = next(item for item in plan.items if item.family == "source_nat")
    policy = next(item for item in plan.items if item.family == "policy" and item.source_name == "allow-app")

    assert nat.approval_group == policy.approval_group
    assert nat.key in policy.dependencies
    assert policy.key not in nat.dependencies
    assert "SOURCE_NAT_PORT_BEHAVIOR_NOT_EXPLICIT" in nat.blockers
    assert "POLICY_SOURCE_NAT_PORT_BEHAVIOR_UNVERIFIED" in policy.blockers
    rendered = JunosSetRenderer().render(plan)
    assert "set security nat source" not in rendered.command_text
    assert "set security policies from-zone" not in rendered.command_text


def test_pool_snat_requires_port_and_return_path_decisions(complete_options):
    source = FIXTURE.read_text(encoding="utf-8")
    source = source.replace(
        "        config firewall policy\n",
        "        config firewall ippool\n"
        "            edit \"public-snat\"\n"
        "                set type overload\n"
        "                set startip 198.51.100.10\n"
        "                set endip 198.51.100.10\n"
        "            next\n"
        "        end\n\n"
        "        config firewall policy\n",
        1,
    )
    source = source.replace(
        "                set nat disable\n",
        "                set nat enable\n                set ippool enable\n                set poolname \"public-snat\"\n",
        1,
    )
    analysis = _analysis(source)

    plan = _plan(analysis, complete_options)
    nat = next(item for item in plan.items if item.family == "source_nat")
    assert dict(nat.settings)["translation_type"] == "ip_pool"
    assert "SOURCE_NAT_POOL_PORT_BEHAVIOR_NOT_EXPLICIT" in nat.blockers
    assert "SOURCE_NAT_POOL_RETURN_ROUTE_OR_PROXY_ARP_REQUIRED" in nat.blockers
    assert not any(command.startswith("set security nat source") for command in JunosSetRenderer().render(plan).commands)


def test_nat_after_an_earlier_permit_is_blocked_for_possible_overlap(complete_options):
    source = FIXTURE.read_text(encoding="utf-8")
    _, second_policy = source.split("            edit 20\n", 1)
    second_policy = "            edit 20\n" + second_policy
    second_policy = second_policy.replace("set action deny", "set action accept", 1)
    second_policy = second_policy.replace("set nat disable", "set nat enable", 1)
    source = source.split("            edit 20\n", 1)[0] + second_policy
    analysis = _analysis(source)

    plan = _plan(analysis, complete_options)
    nat = next(item for item in plan.items if item.family == "source_nat")
    assert dict(nat.settings)["policy_id"] == 20
    assert "SOURCE_NAT_EARLIER_POLICY_MAY_OVERLAP" in nat.blockers


def test_vip_destination_is_visible_and_blocks_the_dependent_policy(complete_options):
    source = FIXTURE.read_text(encoding="utf-8")
    source = source.replace(
        "        config firewall policy\n",
        "        config firewall vip\n"
        "            edit \"public-app\"\n"
        "                set extip 198.51.100.20\n"
        "                set mappedip \"10.30.0.20\"\n"
        "                set extintf \"wan\"\n"
        "            next\n"
        "        end\n\n"
        "        config firewall policy\n",
        1,
    )
    source = source.replace('set dstaddr "app-host"', 'set dstaddr "public-app"', 1)
    analysis = _analysis(source)

    plan = _plan(analysis, complete_options)
    policy = next(item for item in plan.items if item.family == "policy" and item.source_name == "allow-app")
    assert "POLICY_DESTINATION_VIP_DNAT_UNSUPPORTED" in policy.blockers
    assert any(finding.code == "FORTIGATE_NAT_SOURCE_EVIDENCE_REQUIRES_REVIEW" for finding in plan.findings)
    assert not any(command.startswith("set security policies from-zone") for command in JunosSetRenderer().render(plan).commands)


def test_missing_and_multiple_normalized_entries_block_nat(complete_options):
    source = FIXTURE.read_text(encoding="utf-8").replace("set nat disable", "set nat enable", 1)
    analysis = _analysis(source)
    missing = replace(analysis.derived, nat=())
    missing_plan = FortiGateToJuniperSRXPlanner().plan(
        analysis.extracted.config, missing, complete_options,
        source_inventory=analysis.extracted.source_objects,
    )
    missing_nat = next(item for item in missing_plan.items if item.family == "source_nat")
    assert "SOURCE_NAT_TRANSLATION_NOT_NORMALIZED" in missing_nat.blockers

    duplicated = replace(analysis.derived, nat=(*analysis.derived.nat, analysis.derived.nat[0]))
    duplicated_plan = FortiGateToJuniperSRXPlanner().plan(
        analysis.extracted.config, duplicated, complete_options,
        source_inventory=analysis.extracted.source_objects,
    )
    duplicated_nat = next(item for item in duplicated_plan.items if item.family == "source_nat")
    assert "SOURCE_NAT_ENTRY_MISSING_OR_MULTIPLE" in duplicated_nat.blockers


def test_disabled_source_nat_policy_never_activates(complete_options):
    source = FIXTURE.read_text(encoding="utf-8")
    source = source.replace("set nat disable", "set nat enable", 1)
    source = source.replace("set status enable", "set status disable", 1)
    analysis = _analysis(source)
    plan = _plan(analysis, complete_options)

    nat = next(item for item in plan.items if item.family == "source_nat")
    assert "SOURCE_NAT_SOURCE_POLICY_DISABLED" in nat.blockers
    assert not any(command.startswith("set security nat source") for command in JunosSetRenderer().render(plan).commands)


def test_explicit_port_preserve_setting_still_requires_target_equivalence(complete_options):
    source = FIXTURE.read_text(encoding="utf-8")
    source = source.replace(
        "set nat disable\n",
        "set nat enable\n                set port-preserve disable\n",
        1,
    )
    analysis = _analysis(source)
    source_policy = analysis.extracted.config.policies[0]
    assert source_policy.port_preserve == "disable"
    assert "port_preserve" in source_policy.explicit_fields
    assert analysis.derived.nat[0].port_preserve == "disable"

    plan = _plan(analysis, complete_options)
    nat = next(item for item in plan.items if item.family == "source_nat")
    policy = next(item for item in plan.items if item.family == "policy" and item.source_name == "allow-app")
    assert "SOURCE_NAT_PORT_BEHAVIOR_NOT_EXPLICIT" in nat.blockers
    assert "POLICY_SOURCE_NAT_PORT_BEHAVIOR_UNVERIFIED" in policy.blockers
