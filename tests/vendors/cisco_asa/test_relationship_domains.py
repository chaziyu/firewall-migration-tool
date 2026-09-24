from types import SimpleNamespace

from fwmigrate.vendors.cisco_asa.model import CiscoNATRule
from fwmigrate.vendors.cisco_asa.relationships.acl import build_acl_relationships
from fwmigrate.vendors.cisco_asa.relationships.identity import build_identity_relationships
from fwmigrate.vendors.cisco_asa.relationships.mpf import build_mpf_relationships
from fwmigrate.vendors.cisco_asa.relationships.nat import build_nat_relationships
from fwmigrate.vendors.cisco_asa.relationships.references import ASAReferenceIndex, ASAReferenceKind
from fwmigrate.vendors.cisco_asa.relationships.routing import build_routing_relationships
from fwmigrate.vendors.cisco_asa.relationships.vpn import build_vpn_relationships


def test_acl_global_binding_keeps_scope_separate_and_preserves_rule_order():
    first = SimpleNamespace(acl_name="OUT", source_order=2)
    second = SimpleNamespace(acl_name="OUT", source_order=3)
    binding = SimpleNamespace(acl_name="OUT", source_context=None, interface=None, direction="in")
    config = SimpleNamespace(access_rules=[first, second], acl_bindings=[binding])
    refs = ASAReferenceIndex(); refs.register(None, ASAReferenceKind.ACL, "OUT", "OUT")

    relation = build_acl_relationships(config, refs).bindings[0]

    assert relation.scope == "global" and relation.interface is None
    assert relation.rules == (first, second)
    assert not relation.issues


def test_nat_address_operand_can_resolve_to_network_group():
    rule = CiscoNATRule(name="manual-1", source_context="ctx", real_source="WEB-GROUP", mapped_source="interface")
    rule = rule.model_copy(update={"source_interface": "inside", "destination_interface": "outside"})
    config = SimpleNamespace(nat_rules=[rule])
    refs = ASAReferenceIndex()
    group = SimpleNamespace(name="WEB-GROUP")
    inside = SimpleNamespace(name="GigabitEthernet0/1")
    outside = SimpleNamespace(name="GigabitEthernet0/2")
    refs.register("ctx", ASAReferenceKind.NETWORK_GROUP, "WEB-GROUP", group)
    refs.register("ctx", ASAReferenceKind.INTERFACE, "inside", inside)
    refs.register("ctx", ASAReferenceKind.INTERFACE, "outside", outside)

    relation = build_nat_relationships(config, refs).rules[0]

    assert relation.real_source is group
    assert relation.source_interface is inside and relation.destination_interface is outside
    assert not relation.issues


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


def test_routing_keeps_route_track_sla_edges_context_scoped():
    route = SimpleNamespace(source_context="ctx", raw_line="route inside", interface="inside", track_id=1)
    track = SimpleNamespace(name="track:1", source_context="ctx", track_id=1, sla_id=5)
    sla = SimpleNamespace(name="sla:5", source_context="ctx", sla_id=5, interface=None)
    config = SimpleNamespace(static_routes=[route], tracks=[track], sla_monitors=[sla], route_maps=[], interfaces=[])
    interface = SimpleNamespace(name="inside"); track_ref = SimpleNamespace(track_id=1); sla_ref = SimpleNamespace(sla_id=5)
    refs = ASAReferenceIndex()
    refs.register("ctx", ASAReferenceKind.INTERFACE, "inside", interface)
    refs.register("ctx", ASAReferenceKind.TRACK, "1", track_ref)
    refs.register("ctx", ASAReferenceKind.SLA_MONITOR, "5", sla_ref)

    graph = build_routing_relationships(config, refs)

    assert graph.static_routes[0].interface is interface and graph.static_routes[0].track is track_ref
    assert graph.tracks[0].sla_monitor is sla_ref
    assert not graph.issues


def test_unmatched_identity_selector_is_source_selector_not_missing_local_user():
    rule = SimpleNamespace(name="auth", source_context="ctx", group_name=None, server_group=None,
                           interface=None, acl_reference=None, user_identity="remote-user")
    config = SimpleNamespace(aaa_server_hosts=[], aaa_authentication_rules=[rule],
                             aaa_authorization_rules=[], aaa_accounting_rules=[])

    relation = build_identity_relationships(config, ASAReferenceIndex()).relationships[0]

    assert relation.local_user is None and relation.user_group is None
    assert relation.selector_status == "SOURCE_SELECTOR"
    assert not build_identity_relationships(config, ASAReferenceIndex()).issues


def test_vpn_resolves_crypto_acl_peer_and_keeps_vti_profile_source_only():
    crypto = SimpleNamespace(name="CMAP", sequence=10, source_context="ctx", acl_name="VPN-ACL",
                             transform_sets=[], ikev2_proposals=[], interface_attachment=None,
                             dynamic_map=None, peers=["203.0.113.5"], peer=None)
    tunnel = SimpleNamespace(name="203.0.113.5", source_context="ctx", peer_address="203.0.113.5")
    interface = SimpleNamespace(name="Tunnel1", source_context="ctx", ipsec_profile="PROFILE")
    config = SimpleNamespace(crypto_maps=[crypto], tunnel_groups=[tunnel], group_policies=[], interfaces=[interface])
    refs = ASAReferenceIndex(); refs.register("ctx", ASAReferenceKind.ACL, "VPN-ACL", "VPN-ACL")
    refs.register("ctx", ASAReferenceKind.TUNNEL_GROUP, tunnel.name, tunnel)

    graph = build_vpn_relationships(config, refs)

    crypto_rel = next(item for item in graph.relationships if item.source is crypto)
    vti_rel = next(item for item in graph.relationships if item.source is interface)
    assert dict(crypto_rel.targets)["crypto-acl"] == "VPN-ACL"
    assert dict(crypto_rel.targets)["peer"] is tunnel
    assert vti_rel.source_only == ("ipsec-profile",)
    assert not graph.issues
