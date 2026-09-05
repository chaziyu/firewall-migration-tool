from fwmigrate.parsers.juniper_srx.model import JuniperConfigContext, JuniperContextType
from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_logical_system_context_identity_and_normalized_path():
    parser = JuniperSRXParser(
        "set interfaces ge-0/0/0 description root\n"
        "set logical-systems LS1 interfaces ge-0/0/0 description ls1\n"
        "set logical-systems LS2 interfaces ge-0/0/0 description ls2\n"
    )
    result = parser.extract()

    assert parser.config.contexts["root"].context == JuniperConfigContext(JuniperContextType.ROOT)
    assert parser.config.contexts["LS1"].context == JuniperConfigContext(
        JuniperContextType.LOGICAL_SYSTEM, "LS1"
    )
    assert parser.config.contexts["LS2"].context == JuniperConfigContext(
        JuniperContextType.LOGICAL_SYSTEM, "LS2"
    )
    commands = [command for item in result.inventory_items for command in item.commands]
    assert any(command.source_context == "LS1" for command in commands)


def test_malformed_logical_system_prefix_is_visible_parse_error():
    result = JuniperSRXParser("set logical-systems LS1").extract()

    assert result.unsupported_items[0].reason == "Malformed logical-systems context prefix"
    assert result.unsupported_items[0].raw_capture == "set logical-systems LS1"


def test_logical_system_unsupported_command_keeps_context():
    result = JuniperSRXParser(
        "set logical-systems LS1 protocols ospf area 0.0.0.0 interface ge-0/0/0.0"
    ).extract()

    assert result.unsupported_items[0].source_context == "LS1"


def test_child_deactivation_is_context_isolated():
    parser = JuniperSRXParser(
        "set logical-systems LS1 interfaces ge-0/0/0 unit 0 family inet address 10.1.1.1/24\n"
        "set logical-systems LS2 interfaces ge-0/0/0 unit 0 family inet address 10.2.2.1/24\n"
        "deactivate logical-systems LS1 interfaces ge-0/0/0 unit 0\n"
    )
    parser.extract()

    assert parser.config.contexts["LS1"].interfaces["ge-0/0/0"].units["0"].disabled
    assert not parser.config.contexts["LS2"].interfaces["ge-0/0/0"].units["0"].disabled
