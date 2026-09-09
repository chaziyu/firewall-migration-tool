from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_applied_group_is_inherited_and_local_value_wins():
    content = """
    set groups baseline system host-name inherited
    set groups baseline interfaces ge-0/0/0 description inherited-interface
    set apply-groups baseline
    set system host-name local
    """
    cfg = JuniperSRXParser(content).parse_raw()
    assert cfg.hostname == "local"
    assert cfg.contexts["root"].interfaces["ge-0/0/0"].description == "inherited-interface"
    assert cfg.configuration_groups["baseline"]
