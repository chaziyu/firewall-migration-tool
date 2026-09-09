from fwmigrate.parsers.cisco_asa.net_utils import parse_ipv4_netmask
from fwmigrate.parsers.cisco_asa.parser import CiscoASAParser


def test_strict_ipv4_masks_never_fall_back_to_32():
    assert parse_ipv4_netmask("255.255.255.0") == 24
    assert parse_ipv4_netmask("0.0.0.0") == 0
    assert parse_ipv4_netmask("255.0.255.0") is None
    assert parse_ipv4_netmask("setroute") is None


def test_invalid_values_do_not_invent_addresses_zones_or_protocols():
    ir = CiscoASAParser("""
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.0.255.0
object network Broken
 subnet 10.0.0.0 255.0.255.0
object service Empty
 description no service clause
access-list A extended permit madeup any any
access-group A in interface GigabitEthernet0/0
route GigabitEthernet0/0 10.0.0.0 badmask 192.0.2.1
""").transform_to_ir()

    assert ir.interfaces[0].zone is None
    assert ir.interfaces[0].ip is None
    assert all(zone.name != "untrust" for zone in ir.zones)
    assert all(address.name != "Broken" for address in ir.addresses)
    assert all(service.name != "Empty" for service in ir.services)
    policy = ir.policies[0]
    assert policy.service == []
    assert policy.requires_manual_review
    assert policy.from_zone == []
    assert ir.routes[0].destination is None
    assert ir.routes[0].requires_manual_review


def test_incomplete_nat_does_not_become_any():
    ir = CiscoASAParser("nat (inside,outside) source static ONLY_REAL").transform_to_ir()
    nat = ir.nat_rules[0]
    assert nat.source == ["ONLY_REAL"]
    assert nat.translated_sources == []
    assert nat.destination == []
    assert nat.requires_manual_review

