import pytest

from fwmigrate.parsers.fortigate.command_evaluator import (
    evaluate_commands,
    evaluate_section_commands,
)
from fwmigrate.parsers.fortigate.builders import build_model as build_section
from fwmigrate.parsers.fortigate.model import (
    FGAddress,
    FGAddressGroup,
    FGAddressGroupTaggingEntry,
    FGConfig,
)
from fwmigrate.parsers.fortigate.parser import (
    CONTEXTUAL_MODEL_SECTIONS,
    SECTION_EXPLICIT_FIELDS,
    SOURCE_ONLY_RULE_FAMILIES,
    FortiGateParser,
)
from fwmigrate.parsers.fortigate.section_registry import (
    get_section_parser_capability,
    get_section_spec,
    SECTION_REGISTRY,
)
from fwmigrate.parsers.fortigate.source_tree import FGSourceCommand
from fwmigrate.ir.extensions import IRFortiOSExtensions
from fwmigrate.parsers.fortigate.tokenizer import (
    FortiGateTokenizer,
    TokenType,
    TokenizerError,
)


DROPPED_SECTION_PATHS = frozenset({
    "system dhcp server", "system dhcp server ip-range",
    "system dhcp server exclude-range", "system dhcp server reserved-address",
    "system dhcp server options", "system dhcp6 server",
    "system dhcp6 server ip-range", "system dhcp6 server prefix-range",
    "system dhcp6 server option", "system dhcp6 server options",
    "firewall shaping-policy", "firewall shaper traffic-shaper",
    "firewall shaper per-ip-shaper", "firewall ipv6-eh-filter",
    "firewall address6-template", "firewall service category",
    "firewall proxy-address", "system dns-server", "system dns64",
    "firewall multicast-policy", "firewall multicast-policy6",
    "firewall network-service-dynamic", "system sdn-connector",
    "system switch-interface", "system pppoe-interface",
    "authentication scheme", "authentication rule", "system admin",
    "system accprofile", "user fortitoken", "system session-helper",
    "system session-ttl", "system session-ttl port",
    "vpn ssl web host-check-software", "firewall sniffer",
    "endpoint-control fctems", "firewall local-in-policy",
    "firewall local-in-policy6", "firewall proxy-policy",
    "firewall ssh local-key", "firewall ssh local-ca", "web-proxy global",
    "firewall access-proxy", "firewall access-proxy6",
    "firewall access-proxy-virtual-host", "firewall access-proxy-ssh-client-cert",
    "endpoint-control fctems-override", "vpn ssl web realm",
    "vpn ssl web user-bookmark", "vpn ssl web group-bookmark",
    "vpn ipsec manualkey", "vpn ipsec manualkey-interface",
})


def test_dropped_sections_are_not_parser_registered():
    for path in DROPPED_SECTION_PATHS:
        assert path not in SECTION_EXPLICIT_FIELDS
        assert path not in SOURCE_ONLY_RULE_FAMILIES
        assert path not in CONTEXTUAL_MODEL_SECTIONS
        spec = SECTION_REGISTRY.get(path)
        assert spec is None or (spec.model is None and spec.destination_collection is None)


def test_dropped_sections_are_not_consumed_by_builders():
    parser = FortiGateParser(FortiGateTokenizer(""))
    before = parser.config.model_dump()

    for path in (
        "firewall address6-template",
        "firewall shaper traffic-shaper",
        "system admin",
        "system accprofile",
        "user fortitoken",
        "vpn ssl web host-check-software",
        "firewall sniffer",
        "system session-helper",
        "system session-ttl port",
        "system dhcp server",
        "system dns64",
        "firewall local-in-policy",
        "firewall local-in-policy6",
        "firewall proxy-policy",
        "firewall shaping-policy",
        "system dhcp6 server",
        "firewall ssh local-key",
        "firewall ssh local-ca",
        "authentication scheme",
    ):
        assert build_section(parser, path, {"id": 1, "name": "dropped"}) is False

    assert parser.config.model_dump() == before


def test_fg_config_exposes_only_migration_boundary_collections():
    fields = set(FGConfig.model_fields)
    assert fields.isdisjoint({
        "traffic_shapers",
        "dhcp_servers",
        "dns64_settings",
        "administrators",
        "fortitokens",
        "access_proxies",
        "topology_objects",
    })
    assert {
        "addresses",
        "address_groups",
        "services",
        "service_groups",
        "schedules",
        "policies",
        "static_routes",
        "phase1_interfaces",
        "phase2_interfaces",
    } <= fields
    assert "structured_source_objects" not in fields
    assert "source_only_rules" not in fields
    assert "source_only_rules" not in IRFortiOSExtensions.model_fields


def test_unknown_source_stops_at_parser_inventory():
    parser = FortiGateParser(FortiGateTokenizer('''config future feature
    edit "one"
        set unknown value
    next
end
'''))
    config = parser.parse()

    assert "structured_source_objects" not in FGConfig.model_fields
    assert "source_only_rules" not in FGConfig.model_fields
    assert any(item.source_path == "future feature" for item in parser.source_inventory_items)
    assert config.model_dump().get("future_feature") is None


def test_fg_address_model_fields_are_explicitly_bounded():
    assert set(FGAddress.model_fields) == {
        "source_context",
        "nested_configs",
        "name",
        "uuid",
        "type",
        "subnet",
        "start_ip",
        "end_ip",
        "fqdn",
        "wildcard",
        "wildcard_fqdn",
        "associated_interface",
        "comment",
        "ip6",
        "is_ipv6",
        "is_multicast",
        "extra_settings",
    }


def test_fg_address_group_preserves_raw_source_fields():
    group = FGAddressGroup(
        name="servers",
        member=["web", "db"],
        exclude="blocked",
        exclude_member=["legacy"],
        comment="Server group",
        uuid="group-uuid",
        allow_routing="enable",
        category="default",
        color=6,
        fabric_object="enable",
        type="static",
        tagging=[FGAddressGroupTaggingEntry(name="environment", tags=["prod"])],
        extra_settings={"future-setting": "kept"},
    )

    assert group.member == ["web", "db"]
    assert group.exclude_member == ["legacy"]
    assert group.exclude == "blocked"
    assert (
        group.comment,
        group.uuid,
        group.allow_routing,
        group.category,
        group.color,
        group.fabric_object,
        group.type,
    ) == (
        "Server group",
        "group-uuid",
        "enable",
        "default",
        6,
        "enable",
        "static",
    )
    assert isinstance(group.tagging[0], FGAddressGroupTaggingEntry)
    assert group.extra_settings == {"future-setting": "kept"}
    assert "dynamic_filter" not in FGAddressGroup.model_fields
    assert "filter" not in FGAddressGroup.model_fields


def test_address_group_parser_preserves_fields_without_dynamic_filter_alias():
    source = '''
config firewall addrgrp
    edit "servers"
        set member "A" "B"
        set exclude enable
        set exclude-member "C" "D"
        set comment "Server group"
        set uuid "group-uuid"
        set allow-routing enable
        set color 6
        set category default
        set type static
        set fabric-object enable
        set filter legacy-filter
        config tagging
            edit "environment"
                set category "environment"
                set tags "prod" "critical"
                set future-tagging kept
            next
        end
    next
end
config firewall addrgrp6
    edit "v6-servers"
        set member "V6-A"
    next
end
'''

    config = FortiGateParser(FortiGateTokenizer(source)).parse()
    group, group6 = config.address_groups

    assert group.member == ["A", "B"]
    assert group.exclude == "enable"
    assert group.exclude_member == ["C", "D"]
    assert (
        group.comment,
        group.uuid,
        group.allow_routing,
        group.color,
        group.category,
        group.type,
        group.fabric_object,
    ) == (
        "Server group",
        "group-uuid",
        "enable",
        6,
        "default",
        "static",
        "enable",
    )
    assert group.extra_settings == {"filter": "legacy-filter"}
    assert len(group.tagging) == 1
    assert group.tagging[0].name == "environment"
    assert group.tagging[0].category == "environment"
    assert group.tagging[0].tags == ["prod", "critical"]
    assert group.tagging[0].extra_settings == {"future_tagging": "kept"}
    assert not hasattr(group, "dynamic_filter")
    assert group6.is_ipv6 is True
    assert group6.member == ["V6-A"]


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


def test_tokenizer_keeps_service_values_as_uninterpreted_strings():
    tokens = list(FortiGateTokenizer('''config firewall service custom
edit svc1
set protocol TCP/UDP/SCTP
set tcp-portrange "443:1024-65535"
next
end
''').tokenize())

    assert [(token.type, token.value) for token in tokens] == [
        (TokenType.CONFIG, "config"),
        (TokenType.STRING, "firewall"),
        (TokenType.STRING, "service"),
        (TokenType.STRING, "custom"),
        (TokenType.EDIT, "edit"),
        (TokenType.STRING, "svc1"),
        (TokenType.SET, "set"),
        (TokenType.STRING, "protocol"),
        (TokenType.STRING, "TCP/UDP/SCTP"),
        (TokenType.SET, "set"),
        (TokenType.STRING, "tcp-portrange"),
        (TokenType.STRING, "443:1024-65535"),
        (TokenType.NEXT, "next"),
        (TokenType.END, "end"),
    ]


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


def test_command_evaluator_applies_set_append_and_unset_in_source_order():
    result = evaluate_commands(
        [
            FGSourceCommand(operation="set", key="member", values=["A"]),
            FGSourceCommand(operation="append", key="member", values=["B"]),
            FGSourceCommand(operation="unset", key="member"),
        ],
        list_fields={"member"},
    )

    assert result.attributes == {}
    assert result.extra_settings == {}


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


def test_system_fsso_polling_has_a_static_typed_section_spec():
    spec = get_section_spec("system fsso-polling")
    assert spec is not None
    assert spec.model.__name__ == "FGSystemFSSOPolling"
    assert "listening_port" in spec.integer_fields
    assert get_section_parser_capability("system fsso-polling")["classification"] == "typed"


def test_migration_critical_sections_keep_objects_and_unknown_fields():
    config = FortiGateParser(FortiGateTokenizer('''config firewall address
edit a
set subnet 10.0.0.1 255.255.255.255
set color 3
set fabric-object enable
set sdn-tag abc
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
    assert config.addresses[0].extra_settings["color"] == 3
    assert config.addresses[0].extra_settings["fabric_object"] == "enable"
    assert config.addresses[0].extra_settings["sdn_tag"] == "abc"
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
