import importlib
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


def test_ipv4_addresses_preserve_only_explicit_type_and_subnet_values():
    source = '''
config firewall address
    edit "explicit"
        set type ipmask
        set subnet 10.0.0.1 255.255.255.255
    next
    edit "missing-type"
        set subnet 10.0.0.2 255.255.255.255
    next
    edit "missing-subnet"
        set type ipmask
    next
end
'''

    config = FortiGateParser(FortiGateTokenizer(source)).parse()
    addresses = {address.name: address for address in config.addresses}

    assert (addresses["explicit"].type, addresses["explicit"].subnet) == (
        "ipmask",
        "10.0.0.1 255.255.255.255",
    )
    assert (addresses["missing-type"].type, addresses["missing-type"].subnet) == (
        None,
        "10.0.0.2 255.255.255.255",
    )
    assert (addresses["missing-subnet"].type, addresses["missing-subnet"].subnet) == (
        "ipmask",
        None,
    )
    assert all("source_effective_defaults" not in address.extra_settings for address in addresses.values())
    assert all(not hasattr(address, "source_effective_defaults") for address in addresses.values())


def test_local_user_passwd_time_uses_scalar_evaluation_and_reaches_ir():
    spec = get_section_spec("user local")
    assert spec is not None
    assert spec.model.__name__ == "FGLocalUser"
    assert "passwd_time" in spec.scalar_fields
    assert "passwd_time" not in spec.list_fields

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


def test_user_group_member_uses_list_evaluation_and_ordered_operations():
    spec = get_section_spec("user group")
    assert spec is not None
    assert "member" in spec.list_fields
    assert "member" not in spec.scalar_fields

    source = Path("tests/fixtures/fortigate/identity_authentication_full.conf").read_text(
        encoding="utf-8"
    )
    config = FortiGateParser(FortiGateTokenizer(source)).parse()
    groups = {group.name: group for group in config.user_groups}

    assert groups["single-member"].member == ["itsec1"]
    assert groups["multi-member"].member == ["itsec1", "itsec2"]
    assert groups["append-member"].member == ["itsec1", "itsec2"]
    assert groups["unset-member"].member == []


def test_structured_profile_builders_preserve_declared_cardinality():
    source = Path("tests/fixtures/fortigate/security_profiles_full.conf").read_text(
        encoding="utf-8"
    )
    config = FortiGateParser(FortiGateTokenizer(source)).parse()

    antivirus = config.antivirus_profiles[0]
    assert antivirus.external_blocklist == ["av-one"]
    assert antivirus.protocols[0].settings["archive_block"] == ["exe"]
    assert antivirus.protocols[0].settings["archive_log"] == ["enable"]

    webfilter = config.webfilter_profiles[0]
    assert webfilter.options == ["block-invalid-url"]
    assert webfilter.ftgd_wf.options == ["web-one"]
    assert webfilter.categories[0].auth_usr_grp == ["itsec"]

    dnsfilter = config.dnsfilter_profiles[0]
    assert dnsfilter.external_ip_blocklist == ["dns-one"]
    assert dnsfilter.ftgd_dns.options == ["dns-one"]

    application = config.application_lists[0]
    entry = application.entries[0]
    assert application.options == ["app-one"]
    assert entry.application == [16091]
    assert entry.application_id == 16091
    assert entry.category == [15, 16]
    assert entry.exclusion == [21]
    assert entry.risk == [3]
    assert entry.popularity == [2]

    ssl_profile = config.ssl_ssh_profiles[0]
    assert ssl_profile.server_cert == ["cert-one"]
    assert ssl_profile.protocols[0].ports == ["443"]

    assert extract_fortigate_config(source).canonical_ir is not None


def test_system_fsso_polling_is_static_typed_source_only_and_redacts_password():
    source = """\
config system fsso-polling
    set status enable
    set listening-port malformed
    set authentication password
    set auth-password super-secret
    set future-setting future-value
end
"""

    parser = FortiGateParser(FortiGateTokenizer(source))
    config = parser.parse()

    polling = config.system_fsso_polling
    assert polling is not None
    assert polling.status == "enable"
    assert polling.listening_port is None
    assert polling.extra_settings["unparsed_listening_port"] == "malformed"
    assert polling.extra_settings["future_setting"] == "future-value"
    assert polling.has_auth_password is True
    assert "super-secret" not in polling.model_dump_json()
    assert FortiGateParser.__init__.__module__ == "fwmigrate.parsers.fortigate.parser"

    extraction = extract_fortigate_config(source)
    section = next(
        item for item in extraction.source_sections
        if item.path == "system fsso-polling"
    )
    assert section.status.value == "EXTRACT_ONLY"
    assert "TYPED_EXTRACT_ONLY" in " ".join(section.notes)


def test_canonical_models_keep_dns_authentication_and_session_semantics():
    source = """\
config system dns
    set server-hostname dns-one dns-two
end
config system global
    set tcp-halfclose-timer malformed
end
config authentication scheme
    edit scheme-one
        set method basic unsupported
        set fsso-guest invalid
    next
end
config firewall service custom
    edit web
        set session-ttl never
        set tcp-halfopen-timer malformed
        set tcp-portrange 443:1024-1025
    next
end
"""

    config = FortiGateParser(FortiGateTokenizer(source)).parse()

    assert config.dns.server_hostname == ["dns-one", "dns-two"]
    assert config.system_global.tcp_halfclose_timer is None
    assert config.system_global.extra_settings["unparsed_tcp_halfclose_timer"] == "malformed"
    assert config.authentication_schemes[0].method == ["basic"]
    assert config.authentication_schemes[0].extra_settings["unparsed_method"] == ["unsupported"]
    assert config.authentication_schemes[0].extra_settings["unparsed_fsso_guest"] == "invalid"
    service = config.services[0]
    assert service.session_ttl == "never"
    assert service.extra_settings["unparsed_tcp_halfopen_timer"] == "malformed"
    assert service.tcp_port_ranges[0].source_start == 1024
    assert service.tcp_port_ranges[0].source_end == 1025


def test_repeated_system_fsso_imports_do_not_mutate_parser_methods():
    methods = {
        name: getattr(FortiGateParser, name)
        for name in ("__init__", "parse", "build_model", "_build_structured_typed_parents")
    }
    module = importlib.import_module("fwmigrate.parsers.fortigate.system_fsso")
    importlib.import_module("fwmigrate.parsers.fortigate.system_fsso")
    importlib.reload(module)

    assert all(getattr(FortiGateParser, name) is method for name, method in methods.items())
