from fwmigrate.parsers.juniper_srx.coverage import assert_no_silent_loss
from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_ike_proposal_supported_children_lifetime_and_child_deactivation():
    content = """
    set version 21.4R1.12
    set security ike proposal ike1 description "IKE test"
    set security ike proposal ike1 authentication-method ecdsa-signatures-521
    set security ike proposal ike1 dh-group group14
    set security ike proposal ike1 authentication-algorithm sha-384
    set security ike proposal ike1 encryption-algorithm aes-256-cbc
    set security ike proposal ike1 digital-signature-scheme ecdsa
    set security ike proposal ike1 prf-algorithm prf-hmac-sha2-256
    set security ike proposal ike1 signature-hash-algorithm sha-256
    set security ike proposal ike1 lifetime-seconds 3600
    set security ike proposal bad lifetime-seconds not-a-number
    deactivate security ike proposal ike1 encryption-algorithm
    """
    result = JuniperSRXParser(content).extract()
    config = JuniperSRXParser(content).parse_raw()

    proposal = config.contexts["root"].vpn.ike_proposals["ike1"]
    assert proposal.description == "IKE test"
    assert proposal.lifetime_seconds == 3600
    assert proposal.source_attributes["disabled_children"] == [["encryption-algorithm"]]
    assert config.contexts["root"].vpn.ike_proposals["bad"].lifetime_seconds is None
    assert_no_silent_loss(result, total_input_commands=12)
