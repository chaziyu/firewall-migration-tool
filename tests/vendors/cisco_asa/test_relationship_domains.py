from types import SimpleNamespace

from fwmigrate.vendors.cisco_asa.model import CiscoIPsecProfile, CiscoNATRule
from fwmigrate.vendors.cisco_asa.model.acl import CiscoACLEndpoint, CiscoAccessRule
from fwmigrate.vendors.cisco_asa.model.service import CiscoPortSpec
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


def test_acl_rule_relationships_resolve_endpoints_services_protocol_time_and_identity():
    rule = CiscoAccessRule(
        id="ACL:1", acl_name="ACL", source_context="ctx", protocol="object-group", protocol_object="PROTO",
        source_endpoint=CiscoACLEndpoint(type="object", value="SRC", raw="object SRC"),
        destination_endpoint=CiscoACLEndpoint(type="object-group", value="DST", raw="object-group DST"),
        source_port=CiscoPortSpec(operator="object", object_name="SRC-SVC"),
        destination_port=CiscoPortSpec(operator="object-group", object_name="DST-SVC"),
        time_range="HOURS", user="alice", user_group="REMOTE", source_security_group_type="object-group",
        source_security_group_value="SGT",
    )
    refs = ASAReferenceIndex()
    targets = {
        (ASAReferenceKind.PROTOCOL_GROUP, "PROTO"): object(),
        (ASAReferenceKind.NETWORK_OBJECT, "SRC"): object(),
        (ASAReferenceKind.NETWORK_GROUP, "DST"): object(),
        (ASAReferenceKind.SERVICE_OBJECT, "SRC-SVC"): object(),
        (ASAReferenceKind.SERVICE_GROUP, "DST-SVC"): object(),
        (ASAReferenceKind.TIME_RANGE, "HOURS"): object(),
        (ASAReferenceKind.LOCAL_USER, "alice"): object(),
        (ASAReferenceKind.USER_GROUP, "REMOTE"): object(),
        (ASAReferenceKind.SECURITY_GROUP, "SGT"): object(),
    }
    for (kind, name), target in targets.items():
        refs.register("ctx", kind, name, target)
    config = SimpleNamespace(access_rules=[rule], acl_bindings=[])

    relationship = build_acl_relationships(config, refs).rules[0]

    assert dict(relationship.references) == {
        "protocol": targets[(ASAReferenceKind.PROTOCOL_GROUP, "PROTO")],
        "source": targets[(ASAReferenceKind.NETWORK_OBJECT, "SRC")],
        "destination": targets[(ASAReferenceKind.NETWORK_GROUP, "DST")],
        "source-service": targets[(ASAReferenceKind.SERVICE_OBJECT, "SRC-SVC")],
        "destination-service": targets[(ASAReferenceKind.SERVICE_GROUP, "DST-SVC")],
        "time-range": targets[(ASAReferenceKind.TIME_RANGE, "HOURS")],
        "user": targets[(ASAReferenceKind.LOCAL_USER, "alice")],
        "user-group": targets[(ASAReferenceKind.USER_GROUP, "REMOTE")],
        "source-security-group": targets[(ASAReferenceKind.SECURITY_GROUP, "SGT")],
    }
    assert not relationship.issues


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


def test_vpn_resolves_crypto_acl_peer_and_reports_missing_vti_profile():
    crypto = SimpleNamespace(name="CMAP", sequence=10, source_context="ctx", acl_name="VPN-ACL",
                             transform_sets=[], ikev2_proposals=[], interface_attachment=None,
                             dynamic_map=None, peers=["203.0.113.5"], peer=None)
    tunnel = SimpleNamespace(name="203.0.113.5", source_context="ctx", peer_address="203.0.113.5")
    interface = SimpleNamespace(name="Tunnel1", source_context="ctx", ipsec_profile="PROFILE")
    config = SimpleNamespace(crypto_maps=[crypto], tunnel_groups=[tunnel], group_policies=[], interfaces=[interface], ipsec_profiles=[])
    refs = ASAReferenceIndex(); refs.register("ctx", ASAReferenceKind.ACL, "VPN-ACL", "VPN-ACL")
    refs.register("ctx", ASAReferenceKind.TUNNEL_GROUP, tunnel.name, tunnel)

    graph = build_vpn_relationships(config, refs)

    crypto_rel = next(item for item in graph.relationships if item.source is crypto)
    vti_rel = next(item for item in graph.relationships if item.source is interface)
    assert dict(crypto_rel.targets)["crypto-acl"] == "VPN-ACL"
    assert dict(crypto_rel.targets)["peer"] is tunnel
    assert vti_rel.source_only == ()
    assert len(vti_rel.issues) == 1 and vti_rel.issues[0].reference_name == "PROFILE"
    assert len(graph.issues) == 1


def test_vti_ipsec_profile_and_selector_acl_resolve():
    profile = CiscoIPsecProfile(name="VTI-PROFILE", source_context="ctx", ikev1_transform_sets=["TS"],
                                ikev2_ipsec_proposals=["P2"], pfs="group14", sa_lifetime_seconds=3600,
                                trustpoint="TP", responder_only=True)
    interface = SimpleNamespace(name="Tunnel1", source_context="ctx", ipsec_profile="VTI-PROFILE",
                                ipsec_policy_acl="VTI-ACL")
    config = SimpleNamespace(crypto_maps=[], tunnel_groups=[], group_policies=[], interfaces=[interface],
                             ipsec_profiles=[profile])
    refs = ASAReferenceIndex()
    transform = SimpleNamespace(name="TS"); proposal = SimpleNamespace(name="P2"); trustpoint = SimpleNamespace(name="TP")
    refs.register("ctx", ASAReferenceKind.IPSEC_PROFILE, profile.name, profile)
    refs.register("ctx", ASAReferenceKind.IPSEC_TRANSFORM_SET, "TS", transform)
    refs.register("ctx", ASAReferenceKind.IKEV2_PROPOSAL, "P2", proposal)
    refs.register("ctx", ASAReferenceKind.TRUSTPOINT, "TP", trustpoint)
    refs.register("ctx", ASAReferenceKind.ACL, "VTI-ACL", "VTI-ACL")

    graph = build_vpn_relationships(config, refs)

    profile_rel = next(item for item in graph.relationships if item.source is profile)
    vti_rel = next(item for item in graph.relationships if item.source is interface)
    assert dict(profile_rel.targets) == {"ikev1-transform-set": transform, "ikev2-ipsec-proposal": proposal, "trustpoint": trustpoint}
    assert dict(vti_rel.targets) == {"ipsec-profile": profile, "ipsec-policy-acl": "VTI-ACL"}
    assert not graph.issues


def test_parser_extracts_ipsec_profile_and_vti_selector():
    from fwmigrate.vendors.cisco_asa import extract_cisco_asa_source
    result = extract_cisco_asa_source(
        "crypto ipsec profile VTI-PROFILE\n"
        " set ikev1 transform-set TS1 TS2\n"
        " set ikev2 ipsec-proposal P2\n"
        " set pfs group14\n"
        " set security-association lifetime seconds 3600\n"
        " set security-association lifetime kilobytes 100000\n"
        " set trustpoint TP\n"
        " responder-only\n"
        "interface Tunnel1\n tunnel source outside\n tunnel destination 203.0.113.10\n"
        " tunnel protection ipsec profile VTI-PROFILE\n"
        " tunnel protection ipsec policy VTI-ACL\n"
    )
    profile = result.config.ipsec_profiles[0]
    interface = result.config.interfaces[0]
    assert profile.ikev1_transform_sets == ["TS1", "TS2"]
    assert profile.ikev2_ipsec_proposals == ["P2"]
    assert (profile.pfs, profile.sa_lifetime_seconds, profile.sa_lifetime_kilobytes) == ("group14", 3600, 100000)
    assert (profile.trustpoint, profile.responder_only) == ("TP", True)
    assert (interface.ipsec_profile, interface.ipsec_policy_acl) == ("VTI-PROFILE", "VTI-ACL")
