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
from fwmigrate.vendors.checkpoint.model.address import CPGroup, CPHost
from fwmigrate.vendors.checkpoint.model.common import CheckPointObjectReference
from fwmigrate.vendors.checkpoint.model.service import CPService, CPServiceGroup
from fwmigrate.vendors.checkpoint.relationships.references import CPReferenceKind, build_memberships, build_reference_index


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


def test_uid_and_domain_scoped_name_resolution():
    a = CPHost(uid="a", name="same", domain_uid="d1")
    b = CPHost(uid="b", name="same", domain_uid="d2")
    index = build_reference_index(CheckPointConfig(hosts=[a, b]))
    assert index.resolve("a", expected_kinds=(CPReferenceKind.HOST,)).target is a
    assert index.resolve("same", owner=CPHost(domain_uid="d1"), expected_kinds=(CPReferenceKind.HOST,)).target is a
    assert index.resolve("same", owner=CPHost(domain_uid="d2"), expected_kinds=(CPReferenceKind.HOST,)).target is b
    assert index.resolve("same", owner=CPHost(domain_uid="d3"), expected_kinds=(CPReferenceKind.HOST,)).status == "cross_scope"
    assert index.resolve("a", expected_kinds=(CPReferenceKind.SERVICE,)).status == "wrong_type"


def test_group_edges_keep_source_field_provenance():
    host = CPHost(uid="h", name="host")
    group = CPGroup(uid="g", name="group", members=[CheckPointObjectReference(uid="h")])
    excluded = CPGroupWithExclusion(uid="x", name="excluded", include="g", **{"except": "h"})
    service = CPService(uid="s", name="svc")
    services = CPServiceGroup(uid="sg", name="services", members=["s"])
    config = CheckPointConfig(hosts=[host], groups=[group], groups_with_exclusion=[excluded], services=[service], service_groups=[services])
    edges = build_memberships(config, build_reference_index(config))
    assert {(edge.owner.uid, edge.source_field, edge.resolved_target.uid if edge.resolved_target else None) for edge in edges} >= {
        ("g", "members", "h"), ("x", "include", "g"), ("x", "except_", "h"), ("sg", "members", "s")
    }
