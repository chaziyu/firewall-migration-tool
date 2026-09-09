from fwmigrate.parsers.juniper_srx import JuniperSRXParser


def rule(text):
    config = JuniperSRXParser(text).parse_raw()
    return config.contexts["root"].nat.static_rule_sets["rs"].rules[0]


def test_static_nat_prefix_and_children():
    assert rule(
        "set security nat static rule-set rs rule r then static-nat prefix 192.0.2.0/24"
    ).action["prefix"] == "192.0.2.0/24"
    assert rule(
        "set security nat static rule-set rs rule r then static-nat prefix mapped-port 80"
    ).action["mapped_port_start"] == "80"
    assert rule(
        "set security nat static rule-set rs rule r then static-nat prefix mapped-port 80 to 90"
    ).action["mapped_port_end"] == "90"
    assert rule(
        "set security nat static rule-set rs rule r then static-nat prefix routing-instance RI"
    ).action["routing_instance"] == "RI"


def test_static_nat_prefix_name_and_children():
    assert rule(
        "set security nat static rule-set rs rule r then static-nat prefix-name TARGET"
    ).action["prefix_name"] == "TARGET"
    assert rule(
        "set security nat static rule-set rs rule r then static-nat prefix-name mapped-port 443"
    ).action["mapped_port_end"] == "443"
    assert rule(
        "set security nat static rule-set rs rule r then static-nat prefix-name routing-instance RI"
    ).action["routing_instance"] == "RI"


def test_static_nat_children_compose_and_preserve_prefix():
    r = rule("""
        set security nat static rule-set rs rule r then static-nat prefix 192.0.2.0/24
        set security nat static rule-set rs rule r then static-nat prefix mapped-port 80 to 90
        set security nat static rule-set rs rule r then static-nat prefix routing-instance RI
    """)
    assert r.action == {
        "type": "static_prefix",
        "prefix": "192.0.2.0/24",
        "mapped_port": "80-90",
        "mapped_port_start": "80",
        "mapped_port_end": "90",
        "routing_instance": "RI",
    }
    assert len(r.field_candidate_history["static_prefix"]) == 1
    assert len(r.field_candidate_history["mapped_port"]) == 1
    assert len(r.field_candidate_history["routing_instance"]) == 1


def test_static_nat_sibling_mapped_port_does_not_mutate_action():
    r = rule("""
        set security nat static rule-set rs rule r then static-nat prefix 192.0.2.0/24
        set security nat static rule-set rs rule r then static-nat mapped-port 80
        set security nat static rule-set rs rule r then static-nat prefix
    """)
    assert r.action == {"type": "static_prefix", "prefix": "192.0.2.0/24"}


def test_static_nat_group_mapped_port_local_override_keeps_prefix_provenance():
    config = JuniperSRXParser("""
        set groups G security nat static rule-set rs rule r then static-nat prefix 192.0.2.0/24
        set groups G security nat static rule-set rs rule r then static-nat prefix mapped-port 80
        set apply-groups G
        set security nat static rule-set rs rule r then static-nat prefix mapped-port 443
    """).parse_raw()
    r = config.contexts["root"].nat.static_rule_sets["rs"].rules[0]
    assert r.action["prefix"] == "192.0.2.0/24"
    assert r.action["mapped_port"] == "443"
    assert r.field_candidate_history["static_prefix"][0].effective
    assert r.field_candidate_history["mapped_port"][0].shadowed
    assert r.field_candidate_history["mapped_port"][1].effective
