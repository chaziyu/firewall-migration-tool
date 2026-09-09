from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_rpm_and_chassis_are_preserved_as_source_inventory():
    cfg = JuniperSRXParser("""
    set services rpm probe WAN test ping target address 192.0.2.1
    set services rpm probe WAN test ping probe-count 3
    set services rpm probe WAN test ping traps test-failure
    set chassis aggregated-devices ethernet device-count 2
    set virtual-chassis preprovisioned-naming member 0 serial-number ABC
    """).parse_raw()
    ctx = cfg.contexts["root"]
    probe = ctx.rpm_probes["WAN:WAN"]
    assert probe.tests["ping"].target == "192.0.2.1"
    assert probe.tests["ping"].probe_count == 3
    assert probe.tests["ping"].traps == ["test-failure"]
    assert len(ctx.chassis) == 2


def test_policy_name_is_scoped_by_zone_pair():
    cfg = JuniperSRXParser("""
    set security policies from-zone trust to-zone untrust policy same match source-address any
    set security policies from-zone trust to-zone untrust policy same match destination-address any
    set security policies from-zone trust to-zone untrust policy same match application any
    set security policies from-zone trust to-zone untrust policy same then permit
    set security policies from-zone dmz to-zone untrust policy same match source-address any
    set security policies from-zone dmz to-zone untrust policy same match destination-address any
    set security policies from-zone dmz to-zone untrust policy same match application any
    set security policies from-zone dmz to-zone untrust policy same then deny
    """).parse_raw()
    policies = cfg.contexts["root"].policies
    assert len(policies) == 2
    assert {p.from_zone for p in policies} == {"trust", "dmz"}


def test_nat_actions_and_ranges_are_not_overwritten():
    cfg = JuniperSRXParser("""
    set security nat source pool p address 203.0.113.10/32
    set security nat source pool p address-range 203.0.113.11 203.0.113.12
    set security nat source rule-set rs from zone trust
    set security nat source rule-set rs rule r then source-nat pool p persistent-nat permit any-remote-host
    set security nat static rule-set st from zone untrust
    set security nat static rule-set st rule s then static-nat mapped-port 8443
    set security nat static rule-set st rule s then static-nat prefix 10.0.0.10/32
    """).parse_raw()
    ctx = cfg.contexts["root"]
    assert ctx.nat.source_pools["p"].address_ranges == [{"start": "203.0.113.11", "end": "203.0.113.12"}]
    assert ctx.nat.source_rule_sets["rs"].rules[0].action["pool_name"] == "p"
    assert ctx.nat.source_rule_sets["rs"].rules[0].action["persistent_nat"]
    action = ctx.nat.static_rule_sets["st"].rules[0].action
    assert action["prefix"] == "10.0.0.10/32" and action["mapped_port"] == "8443"


def test_deactivated_host_inbound_child_is_preserved():
    cfg = JuniperSRXParser("""
    set security zones security-zone trust host-inbound-traffic system-services ssh
    deactivate security zones security-zone trust host-inbound-traffic system-services ssh
    """).parse_raw()
    assert cfg.contexts["root"].zones["trust"].disabled_host_inbound == {"*:system-services": ["ssh"]}
