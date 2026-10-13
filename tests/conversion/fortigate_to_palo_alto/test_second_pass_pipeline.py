import pytest

from fwmigrate.conversion.fortigate_to_palo_alto import FortiGateToPaloAltoPlanner, PANMigrationOptions
from fwmigrate.conversion.fortigate_to_palo_alto.decisions import PANMigrationDecision, PANMigrationDecisionSet
from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer
from fwmigrate.conversion.fortigate_to_palo_alto.validation import validate_plan
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter
from fwmigrate.vendors.fortigate.model.address import FGAddress
from fwmigrate.vendors.fortigate.model.interface import FGInterface
from fwmigrate.vendors.fortigate.model.policy import FGPolicy
from fwmigrate.vendors.fortigate.model.route_static import FGStaticRoute
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.fortigate.model.zone import FGZone
from fwmigrate.vendors.fortigate.model.vip import FGVIP
from fwmigrate.vendors.fortigate.derived import build_derived_views
from fwmigrate.conversion.fortigate_to_palo_alto.planning.routing import _normalize_subnet


BASE = """config system interface
 edit "lan"
 next
 edit "wan"
 next
end
config system zone
 edit "trust"
  set interface "lan"
 next
 edit "untrust"
  set interface "wan"
 next
end
"""


OPTIONS = PANMigrationOptions(
    vdoms={"root": {"vsys": "vsys1", "virtual_router": "default"}},
    interfaces={"root": {"lan": {"target_interface": "ethernet1/1", "target_zone": "trust"},
                         "wan": {"target_interface": "ethernet1/2", "target_zone": "untrust"}}},
    zones={"root": {"trust": {"target_zone": "trust"}, "untrust": {"target_zone": "untrust"}}},
)


def _plan(source, options=OPTIONS):
    analysis = FortiGateSourceReporter().analyze_source(source)
    plan = FortiGateToPaloAltoPlanner().plan(analysis.extracted.config, analysis.derived, options)
    validation = validate_plan(plan)
    return analysis, plan, validation, PANSetRenderer().render(plan, validation)


def _static_vip_config():
    return FGConfig(
        interfaces=[FGInterface(name="lan", ip="10.0.0.1/24"), FGInterface(name="wan", ip="198.51.100.1/24")],
        zones=[FGZone(name="trust", interfaces=["lan"]), FGZone(name="untrust", interfaces=["wan"])],
        vips=[FGVIP(name="web-vip", type="static-nat", extip="198.51.100.10", mappedip=["10.0.0.10"], extintf="wan")],
        policies=[FGPolicy(policy_id=1, name="inbound", srcintf=["wan"], dstintf=["lan"],
            srcaddr=["all"], dstaddr=["web-vip"], service=["ALL"], action="accept", schedule="always")])


@pytest.mark.parametrize("updates", [
    {"type": None}, {"type": "unknown"}, {"portforward": "enable", "extport": "80", "mappedport": "8080"},
    {"extip": "0.0.0.0"}, {"extip": "198.51.100.10-198.51.100.20"}, {"mappedip": ["2001:db8::1"]},
    {"mapped_addr": "server"}, {"nat_source_vip": "enable"}, {"raw_extra": {"src-filter": ["192.0.2.1"]}},
    {"arp_reply": "disable"}, {"status": "disable"},
])
def test_uncertain_vip_blocks_dnat_and_dependent_security_without_mutating_source(updates):
    source = _static_vip_config()
    source.vips[0] = source.vips[0].model_copy(update=updates)
    before = source.model_dump()
    plan = FortiGateToPaloAltoPlanner().plan(source, build_derived_views(source), OPTIONS)
    rendered = PANSetRenderer().render(plan)
    assert not any("rulebase nat" in command or "rulebase security" in command for command in rendered.commands)
    assert source.model_dump() == before
    assert plan.nat_rules[0].warnings


def test_conflicting_vip_post_nat_zones_and_address_names_block_security():
    source = _static_vip_config()
    source.policies.append(source.policies[0].model_copy(update={"policy_id": 2, "name": "conflict", "dstintf": ["wan"]}))
    plan = FortiGateToPaloAltoPlanner().plan(source, build_derived_views(source), OPTIONS)
    assert any("post-NAT destination zones" in warning for warning in plan.nat_rules[0].warnings)
    assert not any("rulebase" in command for command in PANSetRenderer().render(plan).commands)

    source = _static_vip_config()
    source.addresses.append(FGAddress(name="web-vip", subnet="192.0.2.5/32"))
    plan = FortiGateToPaloAltoPlanner().plan(source, build_derived_views(source), OPTIONS)
    assert not any("rulebase security" in command for command in PANSetRenderer().render(plan).commands)
    assert any(issue.code == "duplicate_target_address_name" for issue in validate_plan(plan).issues)


def test_vip_requires_one_confirmed_post_nat_destination_zone():
    source = _static_vip_config()
    source.policies[0] = source.policies[0].model_copy(update={"dstintf": ["lan", "wan"]})
    plan = FortiGateToPaloAltoPlanner().plan(source, build_derived_views(source), OPTIONS)
    assert any("post-NAT destination zone" in warning for warning in plan.nat_rules[0].warnings)
    assert not any("rulebase" in command for command in PANSetRenderer().render(plan).commands)


def test_vip_service_group_match_does_not_reach_pan_nat_service_leaf():
    from fwmigrate.vendors.fortigate.model.service import FGServiceGroup
    source = _static_vip_config()
    source.service_groups.append(FGServiceGroup(name="web-services", members=["HTTP", "HTTPS"]))
    source.policies[0] = source.policies[0].model_copy(update={"service": ["web-services"]})
    plan = FortiGateToPaloAltoPlanner().plan(source, build_derived_views(source), OPTIONS)
    assert any("service-group" in warning for warning in plan.nat_rules[0].warnings)
    assert not any("rulebase" in command for command in PANSetRenderer().render(plan).commands)


def test_vip_nat_target_placement_block_propagates_through_existing_dependency_index():
    from fwmigrate.conversion.fortigate_to_palo_alto.pipeline import run_migration_pipeline
    from fwmigrate.conversion.fortigate_to_palo_alto.plan_dependencies import item_key
    from fwmigrate.conversion.fortigate_to_palo_alto.target.target_plan_validation import PANRenderDisposition
    source = _static_vip_config()

    def classifier(plan, target, device):
        nat = plan.nat_rules[0]
        return ({"status": "ORDER_UNVERIFIED", "family": "nat_rule", "source_name": nat.source_name,
                 "source_vdom": nat.source_vdom, "source_kind": nat.source_kind, "target_vsys": nat.target_vsys},)

    result = run_migration_pipeline(source, build_derived_views(source), options=OPTIONS,
                                   target_object_reuse_classifier=classifier)
    nat_key = item_key(result.plan.nat_rules[0])
    rule_key = item_key(result.plan.security_rules[0])
    assert rule_key in result.dependency_index.dependents_by_item[nat_key]
    assert result.dispositions[rule_key] is PANRenderDisposition.BLOCK
    assert not any("rulebase" in command for command in result.rendered.commands)
    assert result.artifact_status != "READY"


def test_mixed_snat_dnat_and_overlapping_vips_require_precedence_review():
    source = _static_vip_config()
    source.policies.append(FGPolicy(policy_id=2, name="outbound", srcintf=["lan"], dstintf=["wan"],
        srcaddr=["all"], dstaddr=["all"], service=["ALL"], action="accept", schedule="always", nat="enable"))
    plan = FortiGateToPaloAltoPlanner().plan(source, build_derived_views(source), OPTIONS)
    assert len(plan.nat_rules) == 2
    assert all(any("precedence" in warning for warning in rule.warnings) for rule in plan.nat_rules)
    assert not any("rulebase nat" in command for command in PANSetRenderer().render(plan).commands)

    source = _static_vip_config()
    source.vips.append(source.vips[0].model_copy(update={"name": "second-vip"}))
    source.policies.append(source.policies[0].model_copy(update={"policy_id": 2, "name": "second", "dstaddr": ["second-vip"]}))
    plan = FortiGateToPaloAltoPlanner().plan(source, build_derived_views(source), OPTIONS)
    assert all(any("precedence" in warning for warning in rule.warnings) for rule in plan.nat_rules)
    assert not any("rulebase" in command for command in PANSetRenderer().render(plan).commands)


def test_predefined_services_and_subnets_reach_rendered_commands():
    policies = "".join(
        f''' edit {number}
  set name "rule-{name}"
  set srcintf "trust"
  set dstintf "untrust"
  set srcaddr "all"
  set dstaddr "all"
  set service {services}
  set schedule "always"
  set action accept
 next
'''
        for number, (name, services) in enumerate((
            ("all", '"ALL"'), ("http", '"HTTP"'), ("https", '"HTTPS"'),
            ("dns", '"DNS"'), ("ping", '"PING"'), ("mixed", '"CUSTOM" "HTTPS"'),
            ("group", '"web-group"'),
        ), start=1)
    )
    source = BASE + """config firewall address
 edit "net"
  set subnet 10.0.0.0 255.255.255.0
 next
end
config firewall service custom
 edit "CUSTOM"
  set tcp-portrange 8443
 next
end
config firewall service group
 edit "web-group"
  set member "HTTP" "HTTPS"
 next
end
config router static
 edit 1
  set dst 0.0.0.0 0.0.0.0
  set gateway 192.0.2.254
  set device "wan"
 next
end
config firewall policy
""" + policies + "end\n"
    analysis, plan, validation, rendered = _plan(source)
    assert analysis.extracted.config.addresses[0].subnet == "10.0.0.0 255.255.255.0"
    assert analysis.extracted.config.static_routes[0].dst == "0.0.0.0 0.0.0.0"
    assert plan.addresses[0].value == "10.0.0.0/24"
    assert plan.static_routes[0].destination == "0.0.0.0/0"
    assert all(("security_rule", "vsys1", f"rule-{name}") in validation.renderable_item_keys
               for name in ("all", "http", "https", "dns", "ping", "mixed", "group"))
    commands = rendered.commands
    assert "set vsys vsys1 service HTTP protocol tcp port 80" in commands
    assert "set vsys vsys1 service FG-DNS-TCP protocol tcp port 53" in commands
    assert "set vsys vsys1 service FG-DNS-UDP protocol udp port 53" in commands
    assert "set vsys vsys1 service-group web-group members [ HTTP service-https ]" in commands
    assert "set vsys vsys1 rulebase security rules rule-https service [ service-https ]" in commands
    assert "set vsys vsys1 rulebase security rules rule-all service [ any ]" in commands
    assert "set vsys vsys1 rulebase security rules rule-ping application [ ping ]" in commands


def test_vip_uses_original_packet_zone_and_conflicts_fail_closed():
    source = BASE + """config firewall vip
 edit "web-vip"
  set type static-nat
  set extip 198.51.100.10
  set mappedip 10.0.0.10
  set extintf "wan"
 next
end
config firewall policy
 edit 1
  set srcintf "wan"
  set dstintf "lan"
  set srcaddr "all"
  set dstaddr "web-vip"
  set service "ALL"
  set action accept
  set schedule always
 next
end
"""
    analysis, plan, validation, rendered = _plan(source)
    vip = plan.nat_rules[0]
    assert vip.from_zones == ("untrust",)
    assert vip.to_zones == ("untrust",)
    assert ("nat_rule", "vsys1", "web-vip") in validation.renderable_item_keys
    assert any("set vsys vsys1 rulebase nat rules web-vip" in command for command in rendered.commands)
    assert not analysis.extracted.config.addresses
    assert plan.addresses[0].source_kind == "vip"
    assert plan.addresses[0].value == "198.51.100.10/32"
    assert plan.security_rules[0].destinations == ("web-vip",)
    assert plan.security_rules[0].to_zones == ("trust",)
    assert ("security_rule", "vsys1", "1") in validation.renderable_item_keys
    assert "set vsys vsys1 address web-vip ip-netmask 198.51.100.10/32" in rendered.commands

    same_zone = source.replace(
        ' edit 1\n  set srcintf "wan"',
        ' edit 2\n  set srcintf "wan"\n  set dstintf "lan"\n  set srcaddr "all"\n  set service "ALL"\n  set action accept\n  set schedule always\n  set dstaddr "web-vip"\n next\n edit 1\n  set srcintf "wan"',
    )
    _, plan, validation, _ = _plan(same_zone)
    assert plan.nat_rules[0].from_zones == ("untrust",)
    assert ("nat_rule", "vsys1", "web-vip") in validation.renderable_item_keys

    conflicting = source.replace("end\n", "end\n", 1).replace(
        ' edit 1\n  set srcintf "wan"', ' edit 2\n  set srcintf "lan"\n  set dstaddr "web-vip"\n next\n edit 1\n  set srcintf "wan"'
    )
    _, plan, validation, rendered = _plan(conflicting)
    assert plan.nat_rules[0].from_zones == ()
    assert ("nat_rule", "vsys1", "web-vip") not in validation.renderable_item_keys
    assert not any("set vsys vsys1 rulebase nat rules web-vip" in command for command in rendered.commands)
    assert not any("rulebase security" in command for command in rendered.commands)

    unreferenced = source.replace('  set dstaddr "web-vip"\n', '')
    _, plan, validation, _ = _plan(unreferenced)
    assert plan.nat_rules[0].status.value == "MANUAL_REVIEW"
    assert ("nat_rule", "vsys1", "web-vip") not in validation.renderable_item_keys

    _, plan, validation, rendered = _plan(source.replace('  set extintf "wan"\n', ''))
    assert plan.nat_rules[0].to_zones == ()
    assert ("nat_rule", "vsys1", "web-vip") not in validation.renderable_item_keys
    assert not any("set vsys vsys1 rulebase nat rules web-vip" in command for command in rendered.commands)


def test_invalid_subnets_do_not_become_pan_values():
    assert _normalize_subnet("10.0.0.5 255.255.255.255") == "10.0.0.5/32"
    assert _normalize_subnet("10.0.0.0/24") == "10.0.0.0/24"
    assert _normalize_subnet("10.0.0.0 255.0.255.0") is None
    assert _normalize_subnet("10.0.0.0") is None
    source = FGConfig(addresses=[FGAddress(name="invalid", subnet="10.0.0.0 255.0.255.0")],
                      static_routes=[FGStaticRoute(seq_num=1, dst="10.0.0.0", gateway="192.0.2.1")])
    plan = FortiGateToPaloAltoPlanner().plan(source, build_derived_views(source), OPTIONS)
    assert plan.addresses[0].value is None
    assert plan.addresses[0].status.value == "UNSUPPORTED"
    assert plan.static_routes[0].destination is None
    assert plan.static_routes[0].status.value == "MANUAL_REVIEW"
    assert not PANSetRenderer().render(plan).commands


def test_interface_and_zone_decisions_with_same_name_remain_distinct():
    decisions = PANMigrationDecisionSet((
        PANMigrationDecision("root", "interface", "dmz", "target_zone").confirm("interface-zone"),
        PANMigrationDecision("root", "zone", "dmz", "target_zone").confirm("source-zone"),
    ))
    options = decisions.to_options()
    assert options.interfaces["root"]["dmz"].target_zone == "interface-zone"
    assert options.zones["root"]["dmz"].target_zone == "source-zone"
    config = FGConfig(interfaces=[FGInterface(name="dmz")], zones=[FGZone(name="dmz", members=["dmz"])],
                      policies=[FGPolicy(policy_id=1, name="rule", srcintf=["dmz"], dstintf=["dmz"],
                                         srcaddr=["all"], dstaddr=["all"], service=["ALL"], action="accept")],
                      static_routes=[FGStaticRoute(seq_num=1, dst="10.0.0.0 255.255.255.0",
                                                   gateway="192.0.2.1", device="dmz")])
    all_decisions = PANMigrationDecisionSet((*decisions.decisions,
        PANMigrationDecision("root", "vdom", "root", "vsys").confirm("vsys1"),
        PANMigrationDecision("root", "vdom", "root", "virtual_router").confirm("default"),
        PANMigrationDecision("root", "interface", "dmz", "target_interface").confirm("ethernet1/3")))
    plan = FortiGateToPaloAltoPlanner().plan(config, build_derived_views(config), all_decisions.to_options())
    assert plan.zones[0].target_name == "source-zone"
    assert plan.zones[0].interfaces == ("ethernet1/3",)
    assert plan.security_rules[0].from_zones == ("source-zone",)
    assert plan.static_routes[0].interface == "ethernet1/3"
    missing_zone = PANMigrationDecisionSet(tuple(item for item in all_decisions.decisions if item.source_kind != "zone"))
    unresolved = FortiGateToPaloAltoPlanner().plan(config, build_derived_views(config), missing_zone.to_options())
    assert unresolved.zones[0].status.value == "MANUAL_REVIEW"
    assert unresolved.security_rules[0].from_zones == ()
