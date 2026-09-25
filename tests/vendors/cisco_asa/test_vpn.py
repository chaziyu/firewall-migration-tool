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

from copy import deepcopy

from fwmigrate.vendors.cisco_asa import extract_cisco_asa_source

from fwmigrate.vendors.cisco_asa.source_report import extract_cisco_asa_source

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

def test_vti_profile_without_a_definition_is_partial():
    result = extract_cisco_asa_source("interface Tunnel1\n tunnel source outside\n tunnel destination 203.0.113.5\n"
                                     " tunnel protection ipsec profile PROFILE\n")
    row = next(item for item in result.derived.vpn.topologies if item.topology_type == "vti")
    assert (row.tunnel_interface, row.tunnel_source, row.tunnel_destination) == ("Tunnel1", "outside", "203.0.113.5")
    assert (row.ipsec_profile, row.resolution_status) == ("PROFILE", "PARTIAL")

def test_vti_topology_follows_profile_and_exposes_selector_acl():
    result = extract_cisco_asa_source(
        "access-list SELECTOR extended permit ip any any\n"
        "crypto ipsec ikev1 transform-set TS esp-aes esp-sha-hmac\n"
        "crypto ipsec ikev2 ipsec-proposal P2\n protocol esp encryption aes-256\n"
        "crypto ca trustpoint TP\n enrollment self\n"
        "crypto ipsec profile VTI\n set ikev1 transform-set TS\n set ikev2 ipsec-proposal P2\n set trustpoint TP\n"
        "interface Tunnel1\n tunnel source outside\n tunnel destination 203.0.113.5\n"
        " tunnel protection ipsec profile VTI\n tunnel protection ipsec policy SELECTOR\n"
    )
    row = next(item for item in result.derived.vpn.ipsec_topologies if item.topology_type == "vti")
    assert row.transform_sets[0].name == "TS"
    assert row.ikev2_proposals[0].name == "P2"
    assert row.trustpoint.name == "TP"
    assert row.selector_acl == "SELECTOR"
    assert row.resolution_status == "RESOLVED"

def test_vti_resolved_profile_with_missing_selector_is_partial():
    result = extract_cisco_asa_source(
        "crypto ipsec ikev1 transform-set TS esp-aes esp-sha-hmac\n"
        "crypto ipsec profile VTI\n set ikev1 transform-set TS\n"
        "interface Tunnel1\n tunnel protection ipsec profile VTI\n"
        " tunnel protection ipsec policy MISSING\n"
    )
    row = next(item for item in result.derived.vpn.ipsec_topologies if item.topology_type == "vti")
    assert row.transform_sets[0].name == "TS"
    assert row.selector_acl is None
    assert row.resolution_status == "PARTIAL"

def test_policy_vpn_chain_resolves_to_context_local_source_objects():
    result = extract_cisco_asa_source(
        "access-list CRYPTO extended permit ip any any\n"
        "crypto ipsec ikev1 transform-set TS esp-aes esp-sha-hmac\n"
        "crypto ipsec ikev2 ipsec-proposal P2\n protocol esp encryption aes-256\n"
        "crypto map VPN 10 match address CRYPTO\n"
        "crypto map VPN 10 set peer 192.0.2.1\n"
        "crypto map VPN 10 set transform-set TS\n"
        "crypto map VPN 10 set ikev2 ipsec-proposal P2\n"
        "crypto map VPN interface outside\n"
        "interface Ethernet0/0\n nameif outside\n"
        "tunnel-group 192.0.2.1 type ipsec-l2l\n"
        "tunnel-group 192.0.2.1 general-attributes\n default-group-policy GP\n"
        "group-policy GP internal\n"
    )
    relationships = result.derived.vpn_relationships
    crypto = next(row for row in relationships.relationships if row.source.name == "VPN")
    targets = dict(crypto.targets)

    assert getattr(targets["crypto-acl"], "acl_name", targets["crypto-acl"]) == "CRYPTO"
    assert targets["transform-set"].name == "TS"
    assert targets["ikev2-proposal"].name == "P2"
    assert targets["interface"].nameif == "outside"
    assert targets["peer"].name == "192.0.2.1"
    tunnel_group = next(row for row in relationships.relationships if row.source.name == "192.0.2.1")
    assert dict(tunnel_group.targets)["group-policy"].name == "GP"
    assert not relationships.issues
    assert crypto.source.name == "VPN"
