from fwmigrate.parsers.cisco_asa.parser import CiscoASAParser


def test_asa_management_commands_and_icmp_reach_local_in_without_fake_profiles():
    ir = CiscoASAParser("""
ssh 10.0.0.0 255.255.255.0 inside
http 192.0.2.0 255.255.255.0 outside
telnet 198.51.100.10 255.255.255.255 management
management-access inside
icmp permit any echo outside
icmp deny host 192.0.2.10 outside
""").transform_to_ir()

    assert len(ir.policies) == 0
    assert [rule.source_attributes["origin"] for rule in ir.local_in_policies] == [
        "asa-management-command", "asa-management-command", "asa-management-command",
        "asa-management-access", "asa-icmp-management", "asa-icmp-management",
    ]
    assert ir.local_in_policies[0].interface == "inside"
    assert ir.local_in_policies[0].service == ["ssh"]
    assert ir.local_in_policies[3].interface == "inside"
    assert ir.local_in_policies[4].action == "permit"
    assert ir.local_in_policies[5].action == "deny"
    assert all(not rule.source_attributes.get("application") for rule in ir.local_in_policies)
