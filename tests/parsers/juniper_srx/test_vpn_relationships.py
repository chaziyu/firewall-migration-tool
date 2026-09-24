from fwmigrate.vendors.juniper_srx.derived import build_juniper_derived_views
from fwmigrate.vendors.juniper_srx.parser import JuniperSRXParser


def test_vpn_graph_keeps_explicit_ike_ipsec_and_interface_edges():
    config = JuniperSRXParser("\n".join([
        "set security ike proposal P1 encryption-algorithm aes-256-cbc",
        "set security ike policy I1 proposals P1",
        "set security ike gateway G1 ike-policy I1",
        "set security ipsec proposal ESP1 encryption-algorithm aes-256-cbc",
        "set security ipsec policy IP1 proposals ESP1",
        "set security ipsec vpn V1 ike gateway G1",
        "set security ipsec vpn V1 ike ipsec-policy IP1",
        "set security ipsec vpn V1 bind-interface st0.1",
        "set security ipsec vpn V1 vpn-monitor source-interface lo0.0",
        "set interfaces st0 unit 1 family inet address 192.0.2.1/32",
        "set interfaces lo0 unit 0 family inet address 192.0.2.2/32",
        "set security policies from-zone trust to-zone untrust policy P then permit tunnel ipsec-vpn V1",
    ])).extract_source()
    derived = build_juniper_derived_views(config)
    edges = derived.vpn_graph
    assert {(edge["source_type"], edge["relationship"], edge["target_name"]) for edge in edges} >= {
        ("ike-gateway", "IKE_POLICY", "I1"),
        ("ike-policy", "IKE_PROPOSAL", "P1"),
        ("ipsec-vpn", "IKE_GATEWAY", "G1"),
        ("ipsec-vpn", "IPSEC_POLICY", "IP1"),
        ("ipsec-policy", "IPSEC_PROPOSAL", "ESP1"),
        ("ipsec-vpn", "BIND_INTERFACE", "st0.1"),
        ("vpn-monitor", "SOURCE_INTERFACE", "lo0.0"),
    }
    assert all(edge["resolved"] for edge in edges if edge["relationship"] != "CERTIFICATE_REFERENCE")
    assert any(edge["relationship"] == "EXPLICIT_VPN_REFERENCE" and edge["target_name"] == "V1"
               for policy in derived.policy_relationships for edge in policy["edges"])


def test_missing_vpn_references_remain_unresolved_without_placeholder_objects():
    config = JuniperSRXParser("\n".join([
        "set security ipsec vpn V1 ike gateway MISSING-GW",
        "set security ipsec vpn V1 ike ipsec-policy MISSING-POLICY",
        "set security ipsec vpn V1 bind-interface st0.99",
    ])).extract_source()
    context = config.get_context()
    derived = build_juniper_derived_views(config)
    missing = [edge for edge in derived.vpn_graph if edge["resolved"] is False]
    assert {edge["target_name"] for edge in missing} >= {"MISSING-GW", "MISSING-POLICY", "st0.99"}
    assert set(context.vpn.ike_gateways) == set()
    assert set(context.vpn.ipsec_policies) == set()
    assert "st0" not in context.interfaces
