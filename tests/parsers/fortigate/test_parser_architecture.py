import pytest

from fwmigrate.parsers.fortigate.command_evaluator import (
    evaluate_commands,
    evaluate_section_commands,
)
from fwmigrate.parsers.fortigate.parser import FortiGateParser
from fwmigrate.parsers.fortigate.section_registry import (
    get_section_parser_capability,
    get_section_spec,
)
from fwmigrate.parsers.fortigate.source_tree import FGSourceCommand
from fwmigrate.parsers.fortigate.tokenizer import (
    FortiGateTokenizer,
    TokenType,
    TokenizerError,
)


def test_tokenizer_preserves_syntax_values_order_and_lines():
    source = '''# config edit set unset append next end
config future feature
    edit "object one"
        set unknown-key "quoted value" tail
        append unknown-key again
        unset unused value
        set certificate "line one
line two"
        mystery "unknown value"
    next
end
'''

    tokens = list(FortiGateTokenizer(source).tokenize())

    assert [(token.type, token.value, token.line_number) for token in tokens] == [
        (TokenType.COMMENT, "# config edit set unset append next end", 1),
        (TokenType.CONFIG, "config", 2),
        (TokenType.STRING, "future", 2),
        (TokenType.STRING, "feature", 2),
        (TokenType.EDIT, "edit", 3),
        (TokenType.STRING, "object one", 3),
        (TokenType.SET, "set", 4),
        (TokenType.STRING, "unknown-key", 4),
        (TokenType.STRING, "quoted value", 4),
        (TokenType.STRING, "tail", 4),
        (TokenType.APPEND, "append", 5),
        (TokenType.STRING, "unknown-key", 5),
        (TokenType.STRING, "again", 5),
        (TokenType.UNSET, "unset", 6),
        (TokenType.STRING, "unused", 6),
        (TokenType.STRING, "value", 6),
        (TokenType.SET, "set", 7),
        (TokenType.STRING, "certificate", 7),
        (TokenType.STRING, "line one\nline two", 7),
        (TokenType.STRING, "mystery", 9),
        (TokenType.STRING, "unknown value", 9),
        (TokenType.NEXT, "next", 10),
        (TokenType.END, "end", 11),
    ]


def test_tokenizer_retains_empty_and_malformed_values_but_rejects_select():
    tokens = list(FortiGateTokenizer('set empty\nset broken "unterminated').tokenize())
    assert [(token.type, token.value) for token in tokens] == [
        (TokenType.SET, "set"),
        (TokenType.STRING, "empty"),
        (TokenType.SET, "set"),
        (TokenType.STRING, "broken"),
        (TokenType.STRING, '"unterminated'),
    ]
    with pytest.raises(TokenizerError):
        list(FortiGateTokenizer("select 1").tokenize())


def test_source_tree_preserves_nested_operations_unknown_commands_and_provenance():
    parser = FortiGateParser(FortiGateTokenizer('''config future feature
edit "object one"
set members a
append members b
unset stale
config nested block
edit 1
set arbitrary "two words"
next
end
mystery "raw value"
next
end
'''))
    parser.parse()

    config_root = parser.structured_source_objects[0].root
    root = config_root.children[0]
    nested = next(child for child in root.children if child.node_type == "config")
    assert root.node_type == "edit"
    assert [(command.operation, command.key, command.values) for command in root.commands] == [
        ("set", "members", ["a"]),
        ("append", "members", ["b"]),
        ("unset", "stale", []),
        ("unknown", "mystery", ["raw value"]),
    ]
    assert root.start_line_number == 3
    assert root.end_line_number == 12
    assert nested.name == "nested block"
    assert nested.children[0].commands[0].values == ["two words"]


def test_shared_command_evaluator_applies_operations_and_preserves_bad_values():
    commands = [
        FGSourceCommand(operation="set", key="members", values=["a"]),
        FGSourceCommand(operation="append", key="members", values=["b", "a"]),
        FGSourceCommand(operation="set", key="timeout", values=["bad"]),
        FGSourceCommand(operation="set", key="unknown-field", values=["kept"]),
        FGSourceCommand(operation="append", key="scalar", values=["not-applied"]),
        FGSourceCommand(operation="unset", key="unknown-field"),
    ]

    result = evaluate_commands(
        commands,
        list_fields={"members"},
        integer_fields={"timeout"},
        scalar_fields={"scalar"},
        explicit_fields={"members", "timeout"},
    )

    assert result.attributes == {"members": ["a", "b", "a"]}
    assert result.explicit_fields == {"members", "timeout"}
    assert result.extra_settings == {
        "unparsed_timeout": "bad",
        "unparsed_append_scalar": "not-applied",
    }

    section_result = evaluate_section_commands(
        "firewall address",
        [
            FGSourceCommand(operation="set", key="color", values=["bad"]),
            FGSourceCommand(operation="set", key="future-field", values=["kept"]),
        ],
        get_section_spec("firewall address"),
        initial={"name": "address-one"},
    )
    assert section_result.attributes == {
        "name": "address-one",
        "future_field": "kept",
    }
    assert section_result.extra_settings == {
        "unparsed_color": "bad",
        "future_field": "kept",
    }


def test_registry_reports_parser_capability_from_active_section_spec():
    FortiGateParser(FortiGateTokenizer(""))
    capability = get_section_parser_capability("firewall address")

    assert capability["known_section"] is True
    assert capability["model"] == "FGAddress"
    assert "color" in capability["integer_fields"]
    assert get_section_parser_capability(
        "firewall address", {"color", "future_field"}
    )["unknown_fields"] == ["future_field"]
    assert get_section_parser_capability("future feature")["classification"] == "unknown"


def test_migration_critical_sections_keep_objects_and_unknown_fields():
    config = FortiGateParser(FortiGateTokenizer('''config firewall address
edit a
set subnet 10.0.0.1 255.255.255.255
set cache-ttl invalid
set future-field kept
next
end
config firewall service custom
edit svc
set tcp-portrange 443
set future-service-field kept
next
end
config system interface
edit port1
set ip 192.0.2.1 255.255.255.0
set future-interface-field kept
next
end
config router static
edit 1
set dst 198.51.100.0 255.255.255.0
set gateway 192.0.2.254
set future-route-field kept
next
end
''')).parse()

    assert len(config.addresses) == len(config.services) == len(config.interfaces) == len(config.static_routes) == 1
    assert config.addresses[0].extra_settings["future_field"] == "kept"
    assert config.addresses[0].extra_settings["unparsed_cache_ttl"] == "invalid"
    assert config.services[0].extra_settings["future_service_field"] == "kept"
    assert config.interfaces[0].source_attributes["future_interface_field"] == "kept"
    assert config.static_routes[0].extra_settings["future_route_field"] == "kept"


@pytest.mark.parametrize("section_path", ["router static", "router static6"])
def test_static_route_dstaddr_is_scalar(section_path):
    spec = get_section_spec(section_path)
    assert spec is not None
    assert "dstaddr" not in spec.list_fields
    assert "dstaddr" in spec.scalar_fields

    config = FortiGateParser(FortiGateTokenizer(f'''config {section_path}
edit 1
set dstaddr YAPPK_remote
next
end
''')).parse()

    assert config.static_routes[0].dstaddr == "YAPPK_remote"
