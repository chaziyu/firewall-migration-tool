from pathlib import Path

from fwmigrate.vendors.checkpoint.extraction import CheckPointSourceRecord
from fwmigrate.vendors.checkpoint.source_report import extract_checkpoint_source
from fwmigrate.vendors.checkpoint.model.policy import CPAccessRule
from fwmigrate.vendors.checkpoint.model.source import CPApplication, CheckPointConfig
from fwmigrate.vendors.checkpoint.relationships.references import collect_broken_references
from fwmigrate.vendors.checkpoint.model.address import CPGroupWithExclusion
from fwmigrate.vendors.checkpoint.model.identity import CPAccessRole
from fwmigrate.vendors.checkpoint.model.service import CPService
from fwmigrate.vendors.checkpoint.model.schedule import CPTime
from fwmigrate.vendors.checkpoint.model.zone import CPSecurityZone
from fwmigrate.vendors.checkpoint.model.vpn import CPVPNCommunity
from fwmigrate.vendors.checkpoint.model.gateway import CPGateway
from fwmigrate.vendors.checkpoint.model.policy import CPAccessRule
from fwmigrate.vendors.checkpoint.model.source import CPApplication, CheckPointConfig
from fwmigrate.vendors.checkpoint.relationships.references import collect_broken_references
from fwmigrate.vendors.checkpoint.model.address import CPGroupWithExclusion
from fwmigrate.vendors.checkpoint.model.identity import CPAccessRole
from fwmigrate.vendors.checkpoint.model.service import CPService
from fwmigrate.vendors.checkpoint.model.schedule import CPTime
from fwmigrate.vendors.checkpoint.model.zone import CPSecurityZone
from fwmigrate.vendors.checkpoint.model.vpn import CPVPNCommunity
from fwmigrate.vendors.checkpoint.model.gateway import CPGateway


def test_reference_views_are_derived_and_source_records_remain_unchanged():
    source = (Path(__file__).parents[2] / "fixtures" / "checkpoint" / "r81_golden_matrix.json").read_text()
    result = extract_checkpoint_source(source)
    assert isinstance(result.derived.broken_references, tuple)
    assert result.config.hosts
    assert all(not isinstance(item, CheckPointSourceRecord) for item in result.derived.references.by_uid.values())
    assert result.derived.references.by_name
    assert result.derived.by_uid is result.derived.references.by_uid
    assert result.derived.by_name is result.derived.references.by_name
    assert result.derived.package_layers == result.derived.policy_structure.package_layer_map
    assert result.derived.inline_layers == result.derived.policy_structure.inline_layer_map
    expected_memberships = {}
    for edge in result.derived.references.memberships:
        owner = edge.owner
        key = owner.uid or f"{owner.domain_uid or owner.domain or 'global'}:{owner.name}"
        expected_memberships.setdefault(key, []).append(edge.member_reference)
    assert result.derived.group_memberships == {
        key: tuple(values) for key, values in expected_memberships.items()
    }
    assert len(result.derived.unresolved_references) == len(result.derived.broken_references)


def test_access_rule_reference_kinds_include_applications_roles_zones_and_exclusions():
    config = CheckPointConfig(
        applications=[CPApplication(uid="app", name="App")],
        access_roles=[CPAccessRole(uid="role", name="Role")],
        security_zones=[CPSecurityZone(uid="zone", name="Zone")],
        groups_with_exclusion=[CPGroupWithExclusion(uid="group", name="ExcludedGroup")],
        services=[CPService(uid="service", name="Service")],
        times=[CPTime(uid="time", name="Time")],
        vpn_communities=[CPVPNCommunity(uid="vpn", name="VPN")],
        gateways=[CPGateway(uid="gateway", name="Gateway")],
        access_rules=[CPAccessRule(uid="rule", name="Rule", source=["zone", "role", "group"],
          destination=["role"], services_and_applications=["app", "service"], time=["time"], vpn=["vpn"], install_on=["gateway"])],
    )
    assert collect_broken_references(config) == ()


def test_access_rule_reference_kinds_include_applications_roles_zones_and_exclusions():
    config = CheckPointConfig(
        applications=[CPApplication(uid="app", name="App")],
        access_roles=[CPAccessRole(uid="role", name="Role")],
        security_zones=[CPSecurityZone(uid="zone", name="Zone")],
        groups_with_exclusion=[CPGroupWithExclusion(uid="group", name="ExcludedGroup")],
        services=[CPService(uid="service", name="Service")],
        times=[CPTime(uid="time", name="Time")],
        vpn_communities=[CPVPNCommunity(uid="vpn", name="VPN")],
        gateways=[CPGateway(uid="gateway", name="Gateway")],
        access_rules=[CPAccessRule(uid="rule", name="Rule", source=["zone", "role", "group"],
          destination=["role"], services_and_applications=["app", "service"], time=["time"], vpn=["vpn"], install_on=["gateway"])],
    )
    assert collect_broken_references(config) == ()
