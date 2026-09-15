from pathlib import Path

from fwmigrate.parsers.fortigate import extract_fortigate_config
from fwmigrate.parsers.fortigate.command_evaluator import evaluate_commands
from fwmigrate.parsers.fortigate.parser import FortiGateParser
from fwmigrate.parsers.fortigate.section_registry import (
    get_section_parser_capability,
    get_section_spec,
)
from fwmigrate.parsers.fortigate.source_tree import FGSourceCommand
from fwmigrate.parsers.fortigate.tokenizer import FortiGateTokenizer


def test_fortigate_syntax_evaluation_and_critical_sections_are_lossless():
    assert all(
        getattr(FortiGateParser, name).__module__ == "fwmigrate.parsers.fortigate.parser"
        for name in (
            "__init__", "parse", "parse_config_contents", "parse_edit_attributes",
            "build_model", "_build_structured_typed_parents",
        )
    )
    assert get_section_parser_capability("firewall address")["classification"] == "typed"
    assert get_section_parser_capability("router bgp")["classification"] == "preserved source-only"
    assert get_section_parser_capability("future feature")["classification"] == "unknown"

    evaluation = evaluate_commands(
        [
            FGSourceCommand(operation="set", key="members", values=["a"]),
            FGSourceCommand(operation="append", key="members", values=["b"]),
            FGSourceCommand(operation="set", key="timeout", values=["bad"]),
            FGSourceCommand(operation="set", key="future-field", values=["kept"]),
            FGSourceCommand(operation="unset", key="future-field"),
            FGSourceCommand(operation="future-op", key="other", values=["raw"]),
        ],
        list_fields={"members"},
        integer_fields={"timeout"},
        explicit_fields={"members", "timeout"},
    )
    assert evaluation.attributes == {"members": ["a", "b"]}
    assert evaluation.explicit_fields == {"members", "timeout"}
    assert evaluation.extra_settings == {
        "unparsed_timeout": "bad",
        "unparsed_operation_future_op_other": "raw",
    }

    source = Path("tests/fixtures/fortigate/fortios_7_4_6_critical.conf").read_text(
        encoding="utf-8"
    )
    config = FortiGateParser(FortiGateTokenizer(source)).parse()

    assert config.source_version == "7.4.6"
    assert len(config.addresses) == len(config.address_groups) == 1
    assert len(config.services) == len(config.service_groups) == 1
    assert len(config.policies) == len(config.static_routes) == 1
    assert len(config.interfaces) == 2
    assert len(config.system_zones) == len(config.vips) == len(config.vip_groups) == 1
    assert len(config.ip_pools) == len(config.central_snat_rules) == 1
    assert config.addresses[0].extra_settings["future_field"] == "kept"
    assert config.addresses[0].extra_settings["unparsed_cache_ttl"] == "invalid"
    assert config.services[0].extra_settings["future_service_field"] == "kept"
    assert config.interfaces[0].source_attributes["future_interface_field"] == "kept"
    assert config.static_routes[0].extra_settings["future_route_field"] == "kept"

    extraction = extract_fortigate_config(source)
    critical = {
        "system interface", "system zone", "firewall address", "firewall addrgrp",
        "firewall service custom", "firewall service group", "firewall policy",
        "firewall vip", "firewall vipgrp", "firewall ippool",
        "firewall central-snat-map", "router static",
    }
    sections = {section.path: section for section in extraction.source_sections}
    assert critical <= sections.keys()
    assert all(
        sections[path].object_count_source == sections[path].object_count_parsed
        and sections[path].status
        for path in critical
    )
    assert all(item.commands or item.children for item in extraction.inventory_items)


def test_local_user_passwd_time_uses_scalar_evaluation_and_reaches_ir():
    spec = get_section_spec("user local")
    assert spec is not None
    assert spec.model.__name__ == "FGLocalUser"
    assert "passwd_time" in spec.scalar_fields

    timestamp_source = """\
config user local
    edit timestamp-user
        set status enable
        set passwd-time 2021-03-25 14:02:05
    next
end
"""
    config = FortiGateParser(FortiGateTokenizer(timestamp_source)).parse()
    timestamp_user = next(
        user for user in config.local_users if user.name == "timestamp-user"
    )
    assert timestamp_user.passwd_time == "2021-03-25 14:02:05"

    extraction = extract_fortigate_config(timestamp_source)
    ir_user = next(
        user
        for user in extraction.canonical_ir.local_users
        if user.name == "timestamp-user"
    )
    assert ir_user.source_passwd_time == "2021-03-25 14:02:05"

    for value, expected in (
        ("2021-03-25 14:02:05", "2021-03-25 14:02:05"),
        ("1720000000", "1720000000"),
        (None, None),
    ):
        command = f"set passwd-time {value}" if value else "unset passwd-time"
        source = f"""\
config user local
    edit test-user
        {command}
    next
end
"""
        config = FortiGateParser(FortiGateTokenizer(source)).parse()
        assert config.local_users[0].passwd_time == expected
