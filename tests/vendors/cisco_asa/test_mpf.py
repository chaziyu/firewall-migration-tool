from fwmigrate.vendors.cisco_asa.parser import CiscoASAParser

from fwmigrate.vendors.cisco_asa.relationships.mpf import build_mpf_relationships

from fwmigrate.vendors.cisco_asa.relationships.references import build_asa_reference_index

from types import SimpleNamespace

from fwmigrate.vendors.cisco_asa.model import CiscoIPsecProfile, CiscoNATRule

from fwmigrate.vendors.cisco_asa.model.acl import CiscoACLEndpoint, CiscoAccessRule

from fwmigrate.vendors.cisco_asa.model.service import CiscoPortSpec

from fwmigrate.vendors.cisco_asa.relationships.acl import build_acl_relationships

from fwmigrate.vendors.cisco_asa.relationships.identity import build_identity_relationships

from fwmigrate.vendors.cisco_asa.relationships.nat import build_nat_relationships

from fwmigrate.vendors.cisco_asa.relationships.references import ASAReferenceIndex, ASAReferenceKind

from fwmigrate.vendors.cisco_asa.relationships.routing import build_routing_relationships

from fwmigrate.vendors.cisco_asa.relationships.vpn import build_vpn_relationships

from copy import deepcopy

from fwmigrate.vendors.cisco_asa.derived import build_asa_derived_views

from fwmigrate.vendors.cisco_asa.model import CiscoASAConfig, CiscoInterface, CiscoNetworkObject

from fwmigrate.vendors.cisco_asa.relationships.references import (
    ASAReferenceKind,
    ASAReferenceStatus,
    build_asa_reference_index,
)

from fwmigrate.vendors.cisco_asa.source_report import extract_cisco_asa_source

def test_ips_sensor_is_external_source_reference():
    config = CiscoASAParser("""class-map inspection_default
 match default-inspection-traffic
policy-map global_policy
 class inspection_default
  ips inline fail-close sensor edge_sensor
""").parse_raw()
    action = config.policy_maps[0].classes[0].ips_actions[0]
    assert (action.mode, action.failure_mode, action.sensor) == ("inline", "fail-close", "edge_sensor")
    result = build_mpf_relationships(config, build_asa_reference_index(config))
    assert result.external_ips_actions[0][2] is action
    assert not any("sensor" in issue.reference_name for issue in result.issues)

def test_mpf_keeps_class_map_to_policy_map_chain():
    acl = "ACL-1"
    class_map = SimpleNamespace(name="CM", source_context="ctx", matches=[SimpleNamespace(match_type="access_list", acl_name=acl, class_map_name=None)])
    section = SimpleNamespace(class_name="CM", tcp_map="TCP", inspect_actions=[])
    policy = SimpleNamespace(name="PM", source_context="ctx", classes=[section], inspection_sections=[])
    config = SimpleNamespace(class_maps=[class_map], policy_maps=[policy], service_policies=[])
    refs = ASAReferenceIndex(); refs.register("ctx", ASAReferenceKind.ACL, acl, acl)
    refs.register("ctx", ASAReferenceKind.CLASS_MAP, "CM", class_map)
    tcp = SimpleNamespace(name="TCP"); refs.register("ctx", ASAReferenceKind.TCP_MAP, "TCP", tcp)

    graph = build_mpf_relationships(config, refs)

    assert graph.class_maps[0].targets == (acl,)
    assert graph.policy_maps[0].classes == ((section, class_map),)
    assert graph.policy_maps[0].tcp_maps == ((section, tcp),)
    assert not graph.issues

def test_relationship_building_does_not_mutate_mpf_source_fields():
    config = extract_cisco_asa_source(
        "class-map CM\n match access-list MISSING\n"
        "policy-map PM\n class MISSING-CLASS\n inspect dns\n"
    ).config
    before = deepcopy(config)

    build_asa_derived_views(config)

    assert config == before
    match = config.class_maps[0].matches[0]
    assert "resolved" not in type(match).model_fields
    assert match.review_reasons == []
