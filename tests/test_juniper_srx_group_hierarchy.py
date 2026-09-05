from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser
from fwmigrate.parsers.juniper_srx.group_resolver import resolve_group_commands
from fwmigrate.parsers.juniper_srx.tokenizer import JuniperSetTokenizer


def parse(text):
    return JuniperSRXParser(text).parse_raw()


def test_group_tree_and_single_group():
    cfg = parse("set groups G1 interfaces <*> mtu 1500\nset apply-groups G1\nset interfaces ge-0/0/0")
    group = cfg.configuration_groups["G1"]
    assert group.root_node.children["interfaces"].children["<*>"] .wildcard
    assert cfg.contexts["root"].interfaces["ge-0/0/0"].mtu == 1500


def test_first_group_wins_and_local_override():
    cfg = parse("""
set groups G1 system host-name first
set groups G2 system host-name second
set apply-groups [ G1 G2 ]
set system host-name local
""")
    assert cfg.hostname == "local"
    cfg = parse("""
set groups G1 system host-name first
set groups G2 system host-name second
set apply-groups [ G1 G2 ]
""")
    assert cfg.hostname == "first"


def test_nested_target_has_priority_over_outer_group():
    cfg = parse("""
set groups G1 interfaces ge-0/0/0 description outer
set groups G2 interfaces ge-0/0/0 description inner
set apply-groups G1
set interfaces ge-0/0/0 apply-groups G2
""")
    assert cfg.contexts["root"].interfaces["ge-0/0/0"].description == "inner"


def test_exclusion_is_limited_to_subtree():
    cfg = parse("""
set groups G1 interfaces <*> mtu 1500
set apply-groups G1
set interfaces ge-0/0/0 apply-groups-except G1
set interfaces ge-0/0/1 description local
""")
    assert cfg.contexts["root"].interfaces["ge-0/0/1"].mtu == 1500


def test_root_group_does_not_bleed_into_logical_system():
    cfg = parse("""
set groups G1 interfaces ge-0/0/0 description root
set logical-systems LS1 apply-groups G1
set logical-systems LS1 interfaces ge-0/0/0 description local
""")
    assert cfg.contexts["LS1"].interfaces["ge-0/0/0"].description == "local"


def test_explicit_logical_system_group_keeps_context():
    cfg = parse("""
set groups G1 logical-systems LS1 interfaces ge-0/0/0 description inherited
set logical-systems LS1 apply-groups G1
""")
    assert cfg.contexts["LS1"].interfaces["ge-0/0/0"].description == "inherited"


def test_inactive_apply_group_is_not_effective():
    cfg = parse("""
deactivate apply-groups G1
set groups G1 system host-name inherited
set apply-groups G1
""")
    assert cfg.hostname is None


def test_group_provenance_is_preserved_on_synthetic_command():
    commands = JuniperSetTokenizer().tokenize("set groups G1 system host-name inherited\nset apply-groups G1")
    inherited = resolve_group_commands(commands)[0]
    assert inherited.source_group == "G1"
    assert inherited.source_group_path == ("system", "host-name", "inherited")


def test_nested_group_application_is_relative_to_group_node():
    cfg = parse("""
set groups G1 interfaces ge-0/0/0 apply-groups G2
set groups G2 mtu 1500
set apply-groups G1
set interfaces ge-0/0/0
""")
    assert cfg.contexts["root"].interfaces["ge-0/0/0"].mtu == 1500


def test_group_node_application_is_not_replayed_at_prefixes():
    commands = JuniperSetTokenizer().tokenize("""
set groups G1 system host-name bad
set groups G1 interfaces ge-0/0/0 apply-groups G2
set groups G2 system host-name nested
set apply-groups G1
""")
    inherited = resolve_group_commands(commands)
    assert [c.tokens for c in inherited if c.synthetic] == [
        ["set", "interfaces", "ge-0/0/0", "system", "host-name", "nested"],
        ["set", "system", "host-name", "bad"],
    ]


def test_interface_candidate_history_keeps_shadowed_group_value():
    cfg = parse("""
set groups G1 interfaces ge-0/0/0 mtu 1500
set apply-groups G1
set interfaces ge-0/0/0 mtu 1600
""")
    history = cfg.contexts["root"].interfaces["ge-0/0/0"].field_candidate_history["mtu"]
    assert [candidate.value for candidate in history] == [1500, 1600]
    assert history[0].shadowed and history[1].effective
