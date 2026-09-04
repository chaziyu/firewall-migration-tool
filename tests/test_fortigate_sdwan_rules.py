from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config


def test_sdwan_service_expanded_fields_and_provenance():
    result = extract_fortigate_config('''
config system sdwan
    config service
        edit 10
            set name "rule 10"
            set addr-mode ipv6
            set src6 "SRC6"
            set dst6 "DST6"
            set groups "VPN Users"
            set users "alice"
            set input-device "port1"
            set input-zone "inside"
            set priority-members 2 1
            set priority-zone "virtual-wan-link"
            set internet-service-custom "custom-app"
            set protocol 17
            set start-port 100
            set end-port 200
            set start-src-port 300
            set end-src-port 400
            set tos 0x10
            set tos-mask 0xff
            set dscp-forward-tag 10101010
            set hash-mode source-ip-based
            set link-cost-factor jitter
        next
    end
end
''')
    rule = result.canonical_ir.sdwans[0].rules[0]
    assert rule.source_id == 10
    assert rule.name == "rule 10"
    assert rule.address_mode == "ipv6"
    assert rule.source_addresses6 == ["SRC6"]
    assert rule.destination_addresses6 == ["DST6"]
    assert rule.user_groups == ["VPN Users"]
    assert rule.users == ["alice"]
    assert rule.input_devices == ["port1"]
    assert rule.input_zones == ["inside"]
    assert rule.priority_member_ids == [2, 1]
    assert rule.priority_zones == ["virtual-wan-link"]
    assert rule.internet_service_custom == ["custom-app"]
    assert rule.protocol == 17
    assert (rule.destination_port_start, rule.destination_port_end) == (100, 200)
    assert (rule.source_port_start, rule.source_port_end) == (300, 400)
    assert rule.tos == "0x10"
    assert rule.tos_mask == "0xff"
    assert rule.dscp_forward_tag == "10101010"
    assert rule.hash_mode == "source-ip-based"
    assert rule.link_cost_factor == "jitter"
    assert rule.migration_status == "EXTRACT_ONLY"
    assert rule.requires_manual_review is True
    assert "name" in rule.source_explicit_fields
