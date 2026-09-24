from fwmigrate.vendors.juniper_srx.derived import build_juniper_derived_views
from fwmigrate.vendors.juniper_srx.parser import JuniperSRXParser


def test_policy_views_keep_zone_pair_and_global_order_separate():
    config = JuniperSRXParser("\n".join([
        "set security zones security-zone vpn interfaces st0.1",
        "set security policies from-zone vpn to-zone untrust policy P1 match source-identity alice",
        "set security policies from-zone vpn to-zone untrust policy P1 then permit",
        "set security policies from-zone vpn to-zone untrust policy P2 then deny",
        "set security policies global policy G1 then permit",
        "set security policies global policy G2 then deny",
    ])).extract_source()
    derived = build_juniper_derived_views(config)
    view = derived.policy_relationships[0]
    pair = view["zone_policy_sets"][0]
    assert (pair["from_zone"], pair["to_zone"]) == ("vpn", "untrust")
    assert [(item["name"], item["order"]) for item in pair["policies"]] == [("P1", 0), ("P2", 1)]
    assert [(item["name"], item["order"]) for item in view["global_policies"]] == [("G1", 0), ("G2", 1)]
    assert pair["policies"][0]["source_identities"] == ("alice",)
    assert not [edge for edge in view["edges"] if edge["relationship"] == "EXPLICIT_VPN_REFERENCE"]


def test_policy_view_resolves_named_addresses_applications_and_scheduler():
    config = JuniperSRXParser("\n".join([
        "set security address-book global address SRC 10.0.0.1/32",
        "set applications application WEB protocol tcp",
        "set schedulers scheduler S daily 12:00-13:00",
        "set security policies from-zone trust to-zone untrust policy P match source-address SRC",
        "set security policies from-zone trust to-zone untrust policy P match application WEB",
        "set security policies from-zone trust to-zone untrust policy P scheduler-name S",
    ])).extract_source()
    view = build_juniper_derived_views(config).policy_relationships[0]
    assert all(edge["resolved"] for edge in view["edges"])
