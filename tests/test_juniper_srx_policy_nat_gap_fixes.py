from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_nested_application_set_is_preserved_as_service_group_member():
    content = """
set applications application web protocol tcp
set applications application web destination-port 443
set applications application-set child application web
set applications application-set parent application-set child
set security policies from-zone trust to-zone untrust policy allow-web match source-address any
set security policies from-zone trust to-zone untrust policy allow-web match destination-address any
set security policies from-zone trust to-zone untrust policy allow-web match application parent
set security policies from-zone trust to-zone untrust policy allow-web then permit
"""

    ir = JuniperSRXParser(content).extract().canonical_ir

    parent = next(group for group in ir.service_groups if group.name == "parent")
    assert parent.members == ["child"]
    assert parent.source_attributes["nested_application_sets"] == ["child"]

    policy = next(policy for policy in ir.policies if policy.name == "allow-web")
    assert policy.service == ["parent"]


def test_nat_rule_preserves_interface_routing_instance_and_port_protocol_context():
    content = """
set security nat source rule-set RS from interface ge-0/0/0.0
set security nat source rule-set RS to routing-instance RI-OUT
set security nat source rule-set RS rule R1 match source-address 10.0.0.0/24
set security nat source rule-set RS rule R1 match destination-address 198.51.100.0/24
set security nat source rule-set RS rule R1 match protocol tcp
set security nat source rule-set RS rule R1 match source-port 1024-65535
set security nat source rule-set RS rule R1 match destination-port 443
set security nat source rule-set RS rule R1 then source-nat interface
"""

    ir = JuniperSRXParser(content).extract().canonical_ir
    rule = next(rule for rule in ir.nat_rules if rule.name == "R1")

    context = rule.source_attributes["junos_rule_set_context"]
    assert context["from"]["interfaces"] == ["ge-0/0/0.0"]
    assert context["to"]["routing_instances"] == ["RI-OUT"]

    match = rule.source_attributes["junos_match"]
    assert match["protocols"] == ["tcp"]
    assert match["source_ports"] == ["1024-65535"]
    assert match["destination_ports"] == ["443"]
    assert rule.requires_manual_review is True
    assert rule.protocol_name == "tcp"
    assert [(port.start, port.end) for port in rule.original_source_ports] == [(1024, 65535)]
    assert [(port.start, port.end) for port in rule.original_destination_ports] == [(443, None)]


def test_static_nat_same_line_mapped_port_and_routing_instance_are_not_dropped():
    content = """
set security nat static rule-set STATIC from zone untrust
set security nat static rule-set STATIC rule R1 match destination-address 203.0.113.10/32
set security nat static rule-set STATIC rule R1 then static-nat prefix 10.10.10.10/32 mapped-port 8443
set security nat static rule-set STATIC rule R1 then static-nat prefix routing-instance VR-INTERNAL
"""

    result = JuniperSRXParser(content).extract()
    raw = JuniperSRXParser(content).parse_raw()
    source_rule = raw.contexts["root"].nat.static_rule_sets["STATIC"].rules[0]

    assert source_rule.action["type"] == "static_prefix"
    assert source_rule.action["prefix"] == "10.10.10.10/32"
    assert source_rule.action["mapped_port"] == "8443"
    assert source_rule.action["routing_instance"] == "VR-INTERNAL"

    ir_rule = next(rule for rule in result.canonical_ir.nat_rules if rule.name == "R1")
    action = ir_rule.source_attributes["junos_nat_action"]
    assert action["prefix"] == "10.10.10.10/32"
    assert action["mapped_port"] == "8443"
    assert action["routing_instance"] == "VR-INTERNAL"
    assert ir_rule.requires_manual_review is True
    assert ir_rule.type.value == "destination"
    assert ir_rule.translated_sources == []
    assert ir_rule.translated_destinations == ["10.10.10.10/32"]
