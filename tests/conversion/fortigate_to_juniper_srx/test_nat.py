from pathlib import Path
from dataclasses import replace

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


def test_unmodeled_port_preserve_setting_stays_unknown(complete_options):
    source = FIXTURE.read_text(encoding="utf-8")
    source = source.replace(
        "set nat disable\n",
        "set nat enable\n                set port-preserve disable\n",
        1,
    )
    analysis = _analysis(source)
    source_policy = analysis.extracted.config.policies[0]
    assert source_policy.raw_extra

    plan = _plan(analysis, complete_options)
    nat = next(item for item in plan.items if item.family == "source_nat")
    policy = next(item for item in plan.items if item.family == "policy" and item.source_name == "allow-app")
    assert "SOURCE_NAT_PORT_BEHAVIOR_NOT_EXPLICIT" in nat.blockers
    assert "POLICY_HAS_UNSUPPORTED_SOURCE_SETTINGS" in policy.blockers
