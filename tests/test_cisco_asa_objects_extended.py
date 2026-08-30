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
