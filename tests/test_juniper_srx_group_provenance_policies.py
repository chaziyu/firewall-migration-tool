from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_policy_members_coexist_and_action_shadows():
    cfg = JuniperSRXParser("""
set groups G1 security policies from-zone trust to-zone untrust policy p match source-address A
set groups G1 security policies from-zone trust to-zone untrust policy p then deny
set apply-groups G1
set security policies from-zone trust to-zone untrust policy p match source-address A
set security policies from-zone trust to-zone untrust policy p match source-address B
set security policies from-zone trust to-zone untrust policy p then permit
""").parse_raw()
    policy = cfg.contexts["root"].policies[0]
    assert policy.source_addresses == ["A", "B"]
    assert policy.action == "permit"
    assert [c.status.value for c in policy.field_candidate_history["action"]] == ["SHADOWED", "EFFECTIVE"]
    assert sum(c.effective for c in policy.member_candidate_history["source_addresses"]) == 2
