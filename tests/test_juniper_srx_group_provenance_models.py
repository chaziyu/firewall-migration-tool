from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_remaining_structured_domains_expose_one_history_contract():
    cfg = JuniperSRXParser("""
set security zones security-zone z description zone
set schedulers scheduler s description schedule
set security policies from-zone z to-zone z policy p description policy
set routing-options static route 10.0.0.0/8 preference 5
set security nat source pool pool address 203.0.113.1/32
set security ike proposal ike authentication-algorithm sha256
""").parse_raw().contexts["root"]
    objects = [cfg.zones["z"], cfg.schedulers["s"], cfg.policies[0], cfg.routes[0], cfg.nat.source_pools["pool"], cfg.vpn.ike_proposals["ike"]]
    assert all(hasattr(obj, "field_candidate_history") and hasattr(obj, "member_candidate_history") for obj in objects)
