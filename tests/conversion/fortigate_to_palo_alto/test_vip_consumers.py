from types import SimpleNamespace

import pytest

from fwmigrate.conversion.fortigate_to_palo_alto import PANMigrationOptions, apply_explicit_options, run_migration_pipeline
from fwmigrate.conversion.fortigate_to_palo_alto.decisions import build_decision_set
from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationPlan, PANMigrationStatus, PlannedZone
from fwmigrate.conversion.fortigate_to_palo_alto.planning.nat import plan_nat
from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer
from fwmigrate.conversion.fortigate_to_palo_alto.requirements import build_mapping_requirements
from fwmigrate.vendors.fortigate.derived import build_derived_views
from fwmigrate.vendors.fortigate.model.policy import FGPolicy
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.fortigate.model.vip import FGVIP, FGVIPGroup


def _source(destination="web-group"):
    return FGConfig(
        vips=[FGVIP(name="web", type="static-nat", extip="198.51.100.10",
                    mappedip=["10.0.0.10"], extintf="wan")],
        vip_groups=[FGVIPGroup(name="web-group", members=["web"])],
        policies=[FGPolicy(policy_id=1, srcintf=["outside"], dstintf=["inside"],
                           srcaddr=["all"], dstaddr=[destination], service=["ALL"],
                           action="accept", schedule="always")],
    )


def _options():
    return PANMigrationOptions(vdoms={"root": {"vsys": "vsys1"}}, interfaces={"root": {
        "outside": {"target_zone": "outside"}, "inside": {"target_zone": "inside"},
        "wan": {"target_zone": "untrust"},
    }})


@pytest.mark.parametrize("destination", ["web", "web-group"])
def test_vip_consumers_reach_requirements_and_dnat_renderer(destination):
    source = _source(destination)
    before = source.model_dump()
    derived = build_derived_views(source)
    requirements = build_mapping_requirements(source, derived)
    assert any(item["source_name"] == "wan" and "vip" in item["reasons"]
               for item in requirements["interfaces"])
    decisions = build_decision_set(source, derived, requirements)
    options = apply_explicit_options(source, decisions, _options()).to_options()
    rules = plan_nat(source, derived, options)
    assert rules[0].status is PANMigrationStatus.SUPPORTED
    zones = tuple(PlannedZone(source_object_type="zone", source_name=name, target_name=name,
                             target_vsys="vsys1", status=PANMigrationStatus.SUPPORTED)
                  for name in ("outside", "untrust"))
    rendered = PANSetRenderer().render(PANMigrationPlan(nat_rules=rules, zones=zones))
    assert any("destination-translation translated-address 10.0.0.10" in command
               for command in rendered.commands)
    assert source.model_dump() == before


def test_vip_group_security_coverage_stays_visible_as_manual_work():
    source = _source()
    result = run_migration_pipeline(source, build_derived_views(source), options=_options())
    assert result.plan.nat_rules[0].status is PANMigrationStatus.SUPPORTED
    assert result.artifact_status == "PARTIAL"
    assert any(row["source_kind"] == "vip_group" for row in result.coverage["unplanned"])
    assert not any("rulebase security" in command for command in result.rendered.commands)


@pytest.mark.parametrize("members,extra_groups,warning", [
    (["web", "missing"], [], "unresolved"),
    (["web", "web-group"], [], "circular"),
    (["child"], [FGVIPGroup(name="child", members=["web"])], "nested"),
])
def test_invalid_vip_group_blocks_known_member_translation(members, extra_groups, warning):
    source = _source()
    source.vip_groups[0].members = members
    source.vip_groups.extend(extra_groups)
    rule = plan_nat(source, build_derived_views(source), _options())[0]
    assert rule.status is PANMigrationStatus.MANUAL_REVIEW
    assert any(warning in text for text in rule.warnings)
    assert not rule.destination_translated_address


def test_vip_group_never_resolves_member_from_another_vdom():
    source = _source()
    source.vips[0].vdom = "blue"
    rule = plan_nat(source, build_derived_views(source), _options())[0]
    assert rule.status is PANMigrationStatus.MANUAL_REVIEW
    assert "no referencing" in " ".join(rule.warnings)


def test_vip_multiple_policy_consumers_keep_conflict_guard():
    source = _source()
    source.policies.append(source.policies[0].model_copy(update={"policy_id": 2}))
    assert plan_nat(source, build_derived_views(source), _options())[0].status is PANMigrationStatus.SUPPORTED
    source.policies[1].srcintf = ["inside"]
    rule = plan_nat(source, build_derived_views(source), _options())[0]
    assert any("conflicting source zones" in warning for warning in rule.warnings)


def test_group_interface_and_unknown_semantics_require_manual_review():
    source = _source()
    source.vip_groups[0].interface = "other"
    source.vip_groups[0].raw_extra = {"future-match": "enable"}
    rule = plan_nat(source, build_derived_views(source), _options())[0]
    assert rule.status is PANMigrationStatus.MANUAL_REVIEW
    assert any("interface" in warning for warning in rule.warnings)
    assert any("future-match" in warning for warning in rule.warnings)


def test_vip_discovery_supports_existing_minimal_derived_callers():
    source = _source("web")
    assert plan_nat(source, SimpleNamespace(), _options())[0].status is PANMigrationStatus.SUPPORTED


def test_vip_address_namespace_collision_requires_manual_review():
    from fwmigrate.vendors.fortigate.model.address import FGAddress

    source = _source("web")
    source.addresses = [FGAddress(name="web", subnet="192.0.2.1/32")]
    rule = plan_nat(source, build_derived_views(source), _options())[0]
    assert rule.status is PANMigrationStatus.MANUAL_REVIEW
    assert any("ambiguous" in text for text in rule.warnings)


def test_independent_group_interfaces_are_checked_only_for_their_members():
    source = _source()
    source.vip_groups[0].interface = "wan"
    source.vip_groups.append(FGVIPGroup(name="other-group", interface="wan2", members=["other"]))
    source.vips.append(source.vips[0].model_copy(update={"name": "other", "extintf": "wan2", "extip": "198.51.100.11"}))
    source.policies[0].dstaddr.append("other-group")
    options = _options()
    options.interfaces["root"]["wan2"] = options.interfaces["root"]["wan"]
    assert all(rule.status is PANMigrationStatus.SUPPORTED
               for rule in plan_nat(source, build_derived_views(source), options))


@pytest.mark.parametrize("updates,warning", [
    ({"status": "unknown"}, "state"),
    ({"ippool": "disable"}, "IP-pool"),
])
def test_source_nat_uncertain_policy_controls_block_conversion(updates, warning):
    from fwmigrate.vendors.fortigate.model.interface import FGInterface
    from fwmigrate.vendors.fortigate.model.ippool import FGIPPool

    source = _source("web")
    source.vips = []
    source.vip_groups = []
    source.interfaces = [FGInterface(name="inside", ip="10.0.0.1/24")]
    source.ip_pools = [FGIPPool(name="pool", type="overload", startip="203.0.113.1",
                              endip="203.0.113.1", explicit_fields={"type", "startip", "endip"})]
    source.policies[0] = source.policies[0].model_copy(update={
        "nat": "enable", "ippool": "enable", "poolname": ["pool"], "dstaddr": ["all"],
    })
    options = PANMigrationOptions(vdoms={"root": {"vsys": "vsys1"}}, interfaces={"root": {
        "outside": {"target_zone": "outside"},
        "inside": {"target_zone": "inside", "target_interface": "ethernet1/1"},
    }})
    assert plan_nat(source, build_derived_views(source), options)[0].status is PANMigrationStatus.SUPPORTED
    source.policies[0] = source.policies[0].model_copy(update=updates)
    rule = plan_nat(source, build_derived_views(source), options)[0]
    assert rule.status is PANMigrationStatus.MANUAL_REVIEW
    assert any(warning in text for text in rule.warnings)


@pytest.mark.parametrize("value", ["invalid", "203.0.113.10-203.0.113.1", "2001:db8::1"])
def test_invalid_snat_translated_address_is_not_rendered(value):
    from fwmigrate.conversion.fortigate_to_palo_alto.models import PlannedNATRule

    rule = PlannedNATRule(source_object_type="nat_rule", source_kind="source_nat", source_name="snat",
                          target_vsys="vsys1", status=PANMigrationStatus.SUPPORTED,
                          from_zones=("any",), to_zones=("any",), source_addresses=("any",),
                          destination_addresses=("any",), service="any", to_interface="ethernet1/1",
                          source_translation_type="dynamic-ip-and-port", translated_addresses=(value,))
    assert PANSetRenderer().render(PANMigrationPlan(nat_rules=(rule,))).commands == ()
