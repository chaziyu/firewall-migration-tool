from fwmigrate.parsers.cisco_asa.parser import CiscoASAParser


def test_typed_object_groups_and_network_services_are_not_collapsed():
    parser = CiscoASAParser("""
object-group protocol TUNNELS
 protocol-object gre
object-group icmp-type PING
 icmp-object echo
object-group user PEOPLE
 user-object DOMAIN\\user
object-group security TRUSTED
 security-group name TRUSTED-SGT
object network-service HTTPS_SITE
 domain example.com
 service tcp destination eq 443
object-group network-service WEB_SITES
 network-service-member object HTTPS_SITE
""")
    parser.parse_raw()
    assert parser.config.protocol_groups[0].name == "TUNNELS"
    assert parser.config.icmp_type_groups[0].name == "PING"
    assert parser.config.user_groups[0].name == "PEOPLE"
    assert parser.config.security_groups[0].name == "TRUSTED"
    assert parser.config.network_service_objects[0].members == ["domain example.com", "service tcp destination eq 443"]
    assert parser.config.network_service_groups[0].members == ["network-service-member object HTTPS_SITE"]
    assert all(item.requires_manual_review for item in [
        parser.config.protocol_groups[0], parser.config.icmp_type_groups[0],
        parser.config.user_groups[0], parser.config.security_groups[0],
        parser.config.network_service_objects[0], parser.config.network_service_groups[0],
    ])


def test_network_service_acl_endpoint_is_preserved_and_policy_is_withheld():
    parser = CiscoASAParser("""
interface Gi0/0
 nameif inside
object-group network-service WEB_SITES
 network-service-member domain example.com service tcp destination eq 443
access-list A extended permit ip any object-group-network-service WEB_SITES
access-group A in interface inside
""")
    ir = parser.transform_to_ir()
    assert parser.config.access_rules[0].destination_endpoint.type == "object-group-network-service"
    assert ir.policies[0].destination == []
    assert ir.policies[0].requires_manual_review


def test_network_group_preserves_member_types_and_detects_cycles():
    parser = CiscoASAParser("""
object network HOST
 host 10.0.0.1
object-group network OUTER
 network-object object HOST
 group-object INNER
object-group network INNER
 group-object OUTER
""")
    parser.transform_to_ir()
    outer = parser.config.network_groups[0]
    assert [entry["type"] for entry in outer.member_entries] == ["network_object", "network_group"]
    assert outer.requires_manual_review
    assert "Cyclic nested network-group reference" in outer.source_attributes["reference_validation"]


def test_network_object_conflicting_addresses_do_not_use_last_value():
    parser = CiscoASAParser("""
object network WEB
 host 10.0.0.1
 host 10.0.0.2
""")
    parser.parse_raw()
    obj = parser.config.network_objects[0]
    assert obj.value == "10.0.0.1"
    assert obj.migration_status == "PARSE_ERROR"
    assert obj.source_attributes["conflicting_definitions"] == ["host 10.0.0.2"]


def test_network_group_member_entries_cover_supported_typed_forms():
    parser = CiscoASAParser("""
object network HOST4
 host 10.0.0.1
object-group network G
 description preserved
 network-object host 192.0.2.1
 network-object host 2001:db8::1
 network-object 198.51.100.0 255.255.255.0
 network-object 2001:db8:1::/64
 network-object object HOST4
 group-object LATER
object-group network LATER
 network-object object HOST4
""")
    group = parser.parse_raw().network_groups[0]
    assert [entry.type for entry in group.member_entries] == [
        "host", "host", "inline_network", "inline_network", "network_object", "network_group",
    ]
    assert [entry.address_family for entry in group.member_entries] == [
        "ipv4", "ipv6", "ipv4", "ipv6", "ipv4", "ipv4",
    ]
    assert group.member_entries[0].value == "192.0.2.1"
    assert group.member_entries[2].value == "198.51.100.0/24"
    assert group.member_entries[4].resolved and group.member_entries[5].resolved
    assert group.member_entries[0].raw == "network-object host 192.0.2.1"
    assert group.members[0].startswith("asa_inline_host_")


def test_malformed_network_group_members_are_diagnostics_and_do_not_stop_parse():
    parser = CiscoASAParser("""
object-group network BAD
 network-object host 999.0.0.1
 network-object 10.0.0.0 255.0.255.0
 network-object 2001:db8::/129
 network-object object
object-group network GOOD
 network-object host 192.0.2.10
""")
    config = parser.parse_raw()
    bad, good = config.network_groups
    assert bad.migration_status == "PARSE_ERROR"
    assert bad.member_entries == []
    assert good.member_entries[0].type == "host"
    assert [item.raw_line for item in config.diagnostics] == [
        "network-object host 999.0.0.1",
        "network-object 10.0.0.0 255.0.255.0",
        "network-object 2001:db8::/129",
        "network-object object",
    ]
