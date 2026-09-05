from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def _history(text, field, path=None):
    cfg = JuniperSRXParser(text).parse_raw()
    if path is None:
        history = cfg.field_candidate_history[field]
        value = cfg.hostname
    else:
        interface = cfg.contexts["root"].interfaces[path]
        history = interface.field_candidate_history[field]
        value = getattr(interface, field)
    return value, [(c.value, c.status.value, c.effective, c.shadowed) for c in history]


def test_outer_and_inner_application_order_is_semantic():
    lines = [
        "set groups G1 interfaces ge-0/0/0 description outer",
        "set groups G2 interfaces ge-0/0/0 description inner",
        "set apply-groups G1",
        "set interfaces ge-0/0/0 apply-groups G2",
    ]
    expected = _history("\n".join(lines), "description", "ge-0/0/0")
    assert _history("\n".join(reversed(lines)), "description", "ge-0/0/0") == expected
    assert expected == ("inner", [("outer", "SHADOWED", False, True),
                                   ("inner", "EFFECTIVE", True, False)])


def test_local_and_inherited_order_is_semantic():
    lines = [
        "set groups G1 system host-name inherited",
        "set apply-groups G1",
        "set system host-name local",
    ]
    expected = _history("\n".join(lines), "hostname")
    assert _history("\n".join(reversed(lines)), "hostname") == expected
    assert expected[0] == "local"
    assert [item[1:] for item in expected[1]] == [
        ("SHADOWED", False, True), ("EFFECTIVE", True, False)
    ]


def test_first_group_in_apply_groups_list_wins_regardless_of_definition_order():
    lines = [
        "set groups G1 system host-name first",
        "set groups G2 system host-name second",
        "set apply-groups [ G1 G2 ]",
    ]
    expected = _history("\n".join(lines), "hostname")
    assert _history("\n".join(reversed(lines)), "hostname") == expected
    assert expected[0] == "first"
    assert [item[1:] for item in expected[1]] == [
        ("SHADOWED", False, True), ("EFFECTIVE", True, False)
    ]


def test_precedence_metadata_keeps_list_and_application_depth_distinct():
    cfg = JuniperSRXParser("""
set groups G1 interfaces ge-0/0/0 description outer
set groups G2 interfaces ge-0/0/0 description inner
set apply-groups [ G1 G2 ]
""").parse_raw()
    history = cfg.contexts["root"].interfaces["ge-0/0/0"].field_candidate_history["description"]
    assert [(c.value, c.provenance.group_list_priority,
             c.provenance.group_application_depth,
             c.provenance.group_recursion_depth) for c in history] == [
        ("inner", 1, 0, 1), ("outer", 0, 0, 1)
    ]

    cfg = JuniperSRXParser("""
set groups G1 interfaces ge-0/0/0 description outer
set groups G2 interfaces ge-0/0/0 description inner
set apply-groups G1
set interfaces ge-0/0/0 apply-groups G2
""").parse_raw()
    history = cfg.contexts["root"].interfaces["ge-0/0/0"].field_candidate_history["description"]
    assert [(c.value, c.provenance.group_application_depth) for c in history] == [
        ("outer", 0), ("inner", 2)
    ]


def test_parent_group_statement_beats_recursive_child_regardless_of_line_order():
    lines = [
        "set groups G1 apply-groups G2",
        "set groups G1 system host-name parent",
        "set groups G2 system host-name child",
        "set apply-groups G1",
    ]
    expected = _history("\n".join(lines), "hostname")
    assert _history("\n".join(reversed(lines)), "hostname") == expected
    assert expected == ("parent", [("child", "SHADOWED", False, True),
                                    ("parent", "EFFECTIVE", True, False)])
