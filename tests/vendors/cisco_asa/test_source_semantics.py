from io import BytesIO

from openpyxl import load_workbook

from fwmigrate.vendors.cisco_asa.export.excel import export_asa_excel

from fwmigrate.vendors.cisco_asa.source_report import extract_cisco_asa_source

from .helpers import assert_source_unchanged, snapshot_source

from fwmigrate.vendors.cisco_asa.parser import CiscoASAParser

from pathlib import Path

from fwmigrate.vendors.cisco_asa import extract_cisco_asa_source

from fwmigrate.vendors.cisco_asa.model import CiscoInterface, CiscoNATRule, CiscoStaticRoute

from fwmigrate.vendors.cisco_asa.web_report import build_asa_preview

def test_nat_optional_flags_distinguish_absent_from_explicit():
    result = extract_cisco_asa_source(
        "nat (inside,outside) source static 10.0.0.1 192.0.2.1\n"
        "nat (inside,outside) source static 10.0.0.2 192.0.2.2 dns no-proxy-arp route-lookup unidirectional inactive\n"
    )
    absent, explicit = result.config.nat_rules
    for field in ("dns", "no_proxy_arp", "route_lookup", "unidirectional", "inactive"):
        assert getattr(absent, field) is False and field not in absent.explicit_fields
        assert getattr(explicit, field) is True and field in explicit.explicit_fields

def test_service_object_keeps_last_specification_and_flags_prior_conflict():
    config = CiscoASAParser(
        "object service APP\n"
        " service tcp destination eq 443\n"
        " service udp destination eq 53\n"
    ).parse_raw()
    service = config.service_objects[0]

    assert [(item.protocol, item.destination.values) for item in service.ports] == [("udp", ["53"])]
    assert service.extraction_status == "PARTIAL"
    assert "Multiple service specifications in one service object" in [item.reason for item in config.diagnostics]
    assert service.raw_extra["superseded_service_commands"] == ["service tcp destination eq 443"]

def test_missing_hostname_remains_unconfigured():
    config = extract_cisco_asa_source("interface Ethernet0/0\n").config
    assert config.hostname is None
    assert config.system_settings.hostname is None
    assert "hostname" not in config.explicit_fields

def test_explicit_hostname_is_tracked():
    config = extract_cisco_asa_source("hostname edge\n").config
    assert config.hostname == config.system_settings.hostname == "edge"
    assert "hostname" in config.explicit_fields
    assert "hostname" in config.system_settings.explicit_fields

def test_interface_without_shutdown_has_no_effective_state():
    interface = extract_cisco_asa_source("interface Ethernet0/0\n").config.interfaces[0]
    assert interface.shutdown is None
    assert interface.administrative_state is None
    assert "shutdown" not in interface.explicit_fields

def test_shutdown_and_no_shutdown_remain_distinct_explicit_source():
    config = extract_cisco_asa_source(
        "interface Ethernet0/0\n shutdown\ninterface Ethernet0/1\n no shutdown\n"
    ).config
    down, up = config.interfaces
    assert (down.shutdown, down.administrative_state) == (True, "down")
    assert (up.shutdown, up.administrative_state) == (False, "up")
    assert {"shutdown", "administrative_state"} <= set(down.explicit_fields)
    assert {"shutdown", "administrative_state"} <= set(up.explicit_fields)

def test_explicit_no_command_is_distinct_from_missing_field():
    config = extract_cisco_asa_source(
        "interface Ethernet0/0\n no nameif\ninterface Ethernet0/1\n"
    ).config
    explicit_no, missing = config.interfaces
    assert explicit_no.nameif is missing.nameif is None
    assert "nameif" in explicit_no.explicit_fields
    assert "nameif" not in missing.explicit_fields

def test_route_without_distance_does_not_store_default():
    route = extract_cisco_asa_source("route outside 192.0.2.0 255.255.255.0 192.0.2.1\n").config.static_routes[0]
    assert route.administrative_distance is None
    assert not hasattr(route, "effective_administrative_distance")

def test_explicit_route_distance_is_preserved():
    route = extract_cisco_asa_source("route outside 192.0.2.0 255.255.255.0 192.0.2.1 7\n").config.static_routes[0]
    assert route.administrative_distance == 7
    assert "administrative_distance" in route.explicit_fields

def test_nat_model_contains_only_source_order():
    fixture = Path("tests/fixtures/cisco_asa/nat_pipeline_conformance.txt").read_text()
    rules = extract_cisco_asa_source(fixture).config.nat_rules
    assert [rule.source_order for rule in rules] == sorted(rule.source_order for rule in rules)
    assert all(rule.section in {"manual", "object", "after-auto"} for rule in rules)
    assert not {"effective_source_order", "object_nat_precedence", "object_nat_specificity", "effective_order_inputs"} & set(CiscoNATRule.model_fields)

def test_unknown_source_evidence_is_preserved_in_raw_extra():
    config = extract_cisco_asa_source(
        "interface Ethernet0/0\n vendor-knob keep-me\n"
        "route outside 192.0.2.0 255.255.255.0 192.0.2.1 unknown-route-option\n"
        "nat (inside,outside) source static 10.0.0.1 192.0.2.1 vendor-nat-option\n"
    ).config
    assert "vendor-knob keep-me" in config.interfaces[0].raw_extra["unmodeled_lines"]
    assert "unknown-route-option" in config.static_routes[0].raw_extra["unparsed_options"]
    assert "vendor-nat-option" in config.nat_rules[0].raw_extra["unparsed_tokens"]

def test_safe_unknown_source_survives_preview_without_becoming_a_model_field():
    result = extract_cisco_asa_source(
        "interface Ethernet0/0\n future-interface-option alpha beta\n"
        "object network WEB\n host 10.0.0.1\n future-object-option one two\n"
    )
    before = result.config.interfaces[0].raw_extra["unmodeled_lines"][:]
    assert "future-interface-option alpha beta" in before
    assert result.config.network_objects[0].raw_lines[-1] == "future-object-option one two"
    assert not hasattr(result.config.interfaces[0], "future_interface_option")


def test_absent_and_explicit_no_values_remain_distinct_in_source():
    result = extract_cisco_asa_source(
        "interface Ethernet0/0\n ip address 192.0.2.1 255.255.255.0\n"
        "interface Ethernet0/1\n no shutdown\n no nameif\n no security-level\n no ip address\n"
        "route outside 192.0.2.0 255.255.255.0 192.0.2.1\n"
        "route outside 198.51.100.0 255.255.255.0 192.0.2.1 10\n"
    )
    missing, explicit_no = result.config.interfaces
    assert missing.shutdown is None and "shutdown" not in missing.explicit_fields
    assert explicit_no.shutdown is False and "shutdown" in explicit_no.explicit_fields
    assert explicit_no.nameif is None and "nameif" in explicit_no.explicit_fields
    assert explicit_no.security_level is None and "security_level" in explicit_no.explicit_fields
    assert explicit_no.ip is None and "ip" in explicit_no.explicit_fields
    assert [route.administrative_distance for route in result.config.static_routes] == [None, 10]
