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
        set subnet 10.0.0.2 255.255.255.0
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
        "10.0.0.2 255.255.255.0",
    )
    assert (addresses["missing-subnet"].type, addresses["missing-subnet"].subnet) == (
        "ipmask",
        None,
    )
    assert all("source_effective_defaults" not in address.extra_settings for address in addresses.values())
    assert all(not hasattr(address, "source_effective_defaults") for address in addresses.values())

    ir_addresses = {
        address.name: address
        for address in extract_fortigate_config(source).canonical_ir.addresses
    }
    assert (ir_addresses["explicit"].type.value, ir_addresses["explicit"].value) == (
        "network",
        "10.0.0.1/32",
    )
    assert (ir_addresses["missing-type"].type.value, ir_addresses["missing-type"].value) == (
        "network",
        "10.0.0.2/24",
    )


def test_firewall_address_builder_preserves_unknown_and_nested_values():
    source = '''
config firewall address
    edit "server"
        set subnet 10.0.0.1 255.255.255.0
        set color 6
        set sdn-tag "prod"
        set future-field kept
        config list
            edit "member1"
            next
        end
        config tagging
            edit "tag1"
                set category "environment"
                set tags "prod"
            next
        end
    next
end
'''

    address = FortiGateParser(FortiGateTokenizer(source)).parse().addresses[0]

    assert address.type is None
    assert address.subnet == "10.0.0.1 255.255.255.0"
    assert address.color == 6
    assert address.sdn_tag == "prod"
    assert address.extra_settings == {"future_field": "kept"}
    assert [entry.name for entry in address.address_list] == ["member1"]
    assert address.tagging[0].model_dump() == {
        "name": "tag1",
        "category": "environment",
        "tags": ["prod"],
        "extra_settings": {},
    }


def test_fortigate_address_forms_preserve_source_and_ir_semantics():
    source = """
config system interface
    edit "port1"
    next
end
config firewall address
    edit "RANGE"
        set type iprange
        set start-ip 10.0.2.1
        set end-ip 10.0.2.10
    next
    edit "FQDN"
        set type fqdn
        set fqdn app.example.test
    next
    edit "WILDCARD"
        set type wildcard
        set wildcard 10.0.0.0 0.0.0.255
    next
    edit "METADATA"
        set type ipmask
        set subnet 10.0.3.0 255.255.255.0
        set uuid uuid-1
        set comment "Address comment"
        set associated-interface "port1"
        set future-field abc
    next
end
"""

    config = FortiGateParser(FortiGateTokenizer(source)).parse()
    parser_values = {
        address.name: (
            values["type"],
            values["subnet"],
            values["start_ip"],
            values["end_ip"],
            values["fqdn"],
            values["wildcard"],
            values["uuid"],
            values["comment"],
            values["associated_interface"],
            values["extra_settings"],
        )
        for address in config.addresses
        for values in [address.model_dump()]
    }
    assert parser_values == {
        "RANGE": (
            "iprange", None, "10.0.2.1", "10.0.2.10", None, None,
            None, None, None, {},
        ),
        "FQDN": (
            "fqdn", None, None, None, "app.example.test", None,
            None, None, None, {},
        ),
        "WILDCARD": (
            "wildcard", None, None, None, None, "10.0.0.0 0.0.0.255",
            None, None, None, {},
        ),
        "METADATA": (
            "ipmask", "10.0.3.0 255.255.255.0", None, None, None, None,
            "uuid-1", "Address comment", "port1", {"future_field": "abc"},
        ),
    }

    ir_addresses = {
        address.name: address
        for address in extract_fortigate_config(source).canonical_ir.addresses
    }
    assert {
        name: (
            address.type.value,
            address.value,
            address.source_uuid,
            address.description,
            address.associated_interface,
            address.source_attributes.get("future_field"),
        )
        for name, address in ir_addresses.items()
    } == {
        "RANGE": ("range", "10.0.2.1-10.0.2.10", None, None, None, None),
        "FQDN": ("fqdn", "app.example.test", None, None, None, None),
        "WILDCARD": (
            "wildcard_mask", "10.0.0.0 0.0.0.255", None, None, None, None,
        ),
        "METADATA": (
            "network", "10.0.3.0/24", "uuid-1", "Address comment", "port1", "abc",
        ),
    }


def test_wildcard_fqdn_uses_its_dedicated_source_model():
    source = """
config firewall wildcard-fqdn custom
    edit "WILDCARD_FQDN"
        set wildcard-fqdn *.example.test
    next
end
"""

    config = FortiGateParser(FortiGateTokenizer(source)).parse()
    assert config.wildcard_fqdns[0].model_dump() == {
        "source_context": "root",
        "nested_configs": [],
        "name": "WILDCARD_FQDN",
        "wildcard_fqdn": "*.example.test",
        "comment": None,
        "uuid": None,
        "extra_settings": {},
    }

    address = extract_fortigate_config(source).canonical_ir.addresses[0]
    assert (address.type.value, address.value, address.source_section, address.source_type) == (
        "wildcard",
        "*.example.test",
        "firewall wildcard-fqdn custom",
        "wildcard-fqdn",
    )


def test_ipv6_and_multicast_address_paths_preserve_current_behavior():
    source = """
config firewall address6
    edit "V6_DEFAULT_TYPE"
        set ip6 2001:db8:100::/64
    next
end
config firewall multicast-address
    edit "MCAST4_RANGE"
        set start-ip 239.1.1.1
        set end-ip 239.1.1.255
    next
end
config firewall multicast-address6
    edit "MCAST6_RANGE"
        set ip6 ff05::/16
    next
end
    """

    config = FortiGateParser(FortiGateTokenizer(source)).parse()
    parser_values = {
        address.name: (
            values["type"],
            values["subnet"],
            values["start_ip"],
            values["end_ip"],
            values["ip6"],
            values["is_ipv6"],
            values["is_multicast"],
            values["address_list"],
            values["tagging"],
            values["extra_settings"],
        )
        for address in config.addresses
        for values in [address.model_dump()]
    }

    assert parser_values == {
        "V6_DEFAULT_TYPE": (
            "ipprefix", None, None, None, "2001:db8:100::/64", True, False, [], [],
            {"source_effective_defaults": {"type": "ipprefix"}},
        ),
        "MCAST4_RANGE": (
            "multicastrange", None, "239.1.1.1", "239.1.1.255", None, False, True,
            [], [],
            {"source_effective_defaults": {"type": "multicastrange"}},
        ),
        "MCAST6_RANGE": (
            None, None, None, None, "ff05::/16", True, True, [], [], {},
        ),
    }

    extraction = extract_fortigate_config(source)
    ir_values = {
        address.name: (
            address.type.value,
            address.address_family,
            address.is_ipv6,
            address.is_multicast,
            address.source_section,
            address.migration_status,
            address.requires_manual_review,
        )
        for address in extraction.canonical_ir.addresses
    }
    assert ir_values == {
        "V6_DEFAULT_TYPE": (
            "network", "ipv6", True, False, "firewall address6", "NORMALIZED", False,
        ),
        "MCAST4_RANGE": (
            "range", "ipv4", False, True, "firewall multicast-address", "NORMALIZED", False,
        ),
        "MCAST6_RANGE": (
            "network", "ipv6", True, True, "firewall multicast-address6", "NORMALIZED", False,
        ),
    }

    sections = {
        section.path: section
        for section in extraction.source_sections
        if section.path in {
            "firewall address6",
            "firewall multicast-address",
            "firewall multicast-address6",
        }
    }
    assert {
        path: (section.object_count_source, section.object_count_parsed, section.status.value)
        for path, section in sections.items()
    } == {
        "firewall address6": (1, 1, "PARTIALLY_NORMALIZED"),
        "firewall multicast-address": (1, 1, "PARTIALLY_NORMALIZED"),
        "firewall multicast-address6": (1, 1, "PARTIALLY_NORMALIZED"),
    }
    assert len(extraction.canonical_ir.addresses) == 3
    assert not extraction.requires_manual_review
    assert extraction.generation_safe
    assert extraction.blocking_reasons == []


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
