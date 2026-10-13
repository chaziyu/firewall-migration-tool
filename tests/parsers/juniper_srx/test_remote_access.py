from copy import deepcopy

from fwmigrate.vendors.juniper_srx.derived import build_juniper_derived_views
from fwmigrate.vendors.juniper_srx.parser import JuniperSRXParser
from fwmigrate.vendors.juniper_srx.validation import validate_juniper_config


def test_secure_connect_stays_separate_from_dynamic_vpn_and_resolves_explicit_names():
    config = JuniperSRXParser("\n".join([
        "set access profile AUTH client alice firewall-user",
        "set security ike proposal IKE-P encryption-algorithm aes-256-cbc",
        "set security ike policy IKE-POL proposal IKE-P",
        "set security ike gateway GW ike-policy IKE-POL",
        "set security ipsec policy IPSEC-POL perfect-forward-secrecy keys group14",
        "set security ipsec vpn VPN ike gateway GW",
        "set security ipsec vpn VPN bind-interface st0.1",
        "set interfaces st0 unit 1 family inet address 192.0.2.1/32",
        "set security dynamic-vpn access-profile LEGACY",
        "set security remote-access profile RA access-profile AUTH",
        "set security remote-access profile RA client-config CLIENTS",
        "set security remote-access profile RA ipsec-vpn VPN",
        "set security remote-access profile RA options multi-access",
        "set security remote-access client-config CLIENTS application-bypass term WEB domain-name example.com",
        "set security remote-access client-config CLIENTS application-bypass term WEB protocol tcp",
    ])).extract_source()
    context = next(iter(config.iter_contexts()))
    profile = context.remote_access.profiles["RA"]
    assert (profile.access_profile, profile.client_config, profile.ipsec_vpn, profile.multi_access) == ("AUTH", "CLIENTS", "VPN", True)
    assert context.remote_access.client_configs["CLIENTS"].application_bypass_terms["WEB"].domain_names == ["example.com"]
    assert context.remote_access.client_configs["CLIENTS"].application_bypass_terms["WEB"].protocols == ["tcp"]
    assert "RA" not in context.dynamic_vpns
    before = deepcopy(config)
    derived = build_juniper_derived_views(config)
    profile_edges = [edge for edge in derived.secure_connect_graph if edge["source_type"] == "remote-access-profile"]
    assert {(edge["relationship"], edge["target_name"], edge["resolved"]) for edge in profile_edges} >= {
        ("ACCESS_PROFILE", "AUTH", True), ("CLIENT_CONFIG", "CLIENTS", True), ("IPSEC_VPN", "VPN", True)
    }
    assert not [item for item in derived.dependencies if item.result == "UNRESOLVED"]
    validate_juniper_config(config, derived)
    assert config == before


def test_missing_secure_connect_dependencies_report_without_synthesizing_targets():
    config = JuniperSRXParser("set security remote-access profile RA access-profile MISSING").extract_source()
    context = next(iter(config.iter_contexts()))
    derived = build_juniper_derived_views(config)
    result = validate_juniper_config(config, derived)
    assert "MISSING" not in context.access_profiles
    assert any("MISSING" in issue.message for issue in result.issues)


def test_secure_connect_zone_adjacency_does_not_label_policy_authorization():
    config = JuniperSRXParser("\n".join([
        "set interfaces st0 unit 1 family inet address 192.0.2.1/32",
        "set security zones security-zone vpn interfaces st0.1",
        "set security policies from-zone vpn to-zone untrust policy P then permit",
        "set security ipsec vpn V bind-interface st0.1",
        "set security remote-access profile RA ipsec-vpn V",
    ])).extract_source()
    edges = build_juniper_derived_views(config).secure_connect_graph
    zone_edge = next(edge for edge in edges if edge["relationship"] == "TUNNEL_INTERFACE_ZONE")
    assert zone_edge["target_name"] == ("vpn",)
    assert any(edge["relationship"] == "ZONE_ASSOCIATED_POLICY" and edge["target_name"] == "P" for edge in edges)
    assert not any("authorization" in edge["relationship"].lower() or
                   "remote-access policy" in edge["relationship"].lower() for edge in edges)
