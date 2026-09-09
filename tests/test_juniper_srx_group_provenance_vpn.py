from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_vpn_scalar_and_proposal_member_history():
    cfg = JuniperSRXParser("""
set groups G1 security ike proposal p authentication-algorithm sha1
set groups G1 security ike policy ip proposals [ p q ]
set apply-groups G1
set security ike proposal p authentication-algorithm sha256
set security ike policy ip proposals [ p q ]
""").parse_raw()
    context = cfg.contexts["root"]
    proposal = context.vpn.ike_proposals["p"]
    policy = context.vpn.ike_policies["ip"]
    assert proposal.authentication_algorithm == "sha256"
    assert proposal.field_candidate_history["authentication_algorithm"][0].shadowed
    assert [c.value for c in policy.member_candidate_history["proposals"] if c.effective] == ["p", "q"]
