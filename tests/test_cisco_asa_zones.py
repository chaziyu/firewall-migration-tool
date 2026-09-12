from fwmigrate.parsers.cisco_asa.parser import CiscoASAParser


def test_asa_traffic_zone_membership_is_distinct_from_nameif():
    parser = CiscoASAParser("""
zone WAN
interface GigabitEthernet0/0
 nameif outside
 zone-member WAN
access-list WAN_IN extended permit tcp any any eq 443
access-group WAN_IN in interface outside
""")
    config = parser.parse_raw()
    assert config.interfaces[0].nameif == "outside"
    assert config.interfaces[0].traffic_zone_members == ["WAN"]
    assert [zone.name for zone in config.traffic_zones] == ["WAN"]

    ir = parser.transform_to_ir()
    assert [(zone.name, zone.interfaces) for zone in ir.zones] == [("WAN", ["GigabitEthernet0/0"])]
    assert ir.interfaces[0].zone == "WAN"
    policy = ir.policies[0]
    assert policy.source_from_interfaces == ["outside"]
    assert policy.from_zone == ["WAN"]


def test_asa_zone_definition_resolves_members_and_does_not_use_nameif():
    parser = CiscoASAParser("""
zone name WAN
 interface GigabitEthernet0/0
interface GigabitEthernet0/0
 nameif outside
access-list WAN_IN extended permit ip any any
access-group WAN_IN in interface outside
""")
    config = parser.parse_raw()
    assert config.traffic_zones[0].members == ["GigabitEthernet0/0"]
    assert not [issue for issue in config.reference_issues if not issue["resolved"]]
    ir = parser.transform_to_ir()
    assert ir.zones[0].name == "WAN"
    assert ir.policies[0].from_zone == ["WAN"]


def test_asa_external_zone_mapping_is_opt_in():
    ir = CiscoASAParser("""
interface GigabitEthernet0/0
 nameif outside
access-list A extended permit ip any any
access-group A in interface outside
""", zone_mapping={"GigabitEthernet0/0": "WAN"}).transform_to_ir()
    assert [zone.name for zone in ir.zones] == ["WAN"]
    assert ir.interfaces[0].zone == "WAN"
    assert ir.policies[0].from_zone == ["WAN"]
