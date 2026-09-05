from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_route_scalar_override_and_next_hop_member_history():
    cfg = JuniperSRXParser("""
set groups G1 routing-options static route 10.0.0.0/8 next-hop 192.0.2.1
set groups G1 routing-options static route 10.0.0.0/8 preference 20
set apply-groups G1
set routing-options static route 10.0.0.0/8 next-hop 192.0.2.1
set routing-options static route 10.0.0.0/8 preference 10
""").parse_raw()
    route = cfg.contexts["root"].routes[0]
    assert route.preference == 10
    assert len(route.next_hops) == 1
    assert len(route.member_candidate_history["next_hops"]) == 2
    assert route.field_candidate_history["preference"][0].shadowed
