from pathlib import Path

import pytest

import fwmigrate.parsers  # noqa: F401 - registers Palo Alto plugins
from fwmigrate.core.registry import PluginRegistry
from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.ir.enums import PolicyAction


FIXTURE = Path(__file__).parent / "fixtures" / "palo_alto" / "phase13_conformance.xml"


@pytest.fixture(scope="module")
def result():
    return PluginRegistry.get_parser("palo_alto").extract(FIXTURE.read_text(encoding="utf-8"))


def _section(result, path):
    return next(section for section in result.source_sections if section.path == path)


def _inventory(result, *, domain=None, name=None, source_path=None):
    return [
        item for item in result.inventory_items
        if (domain is None or item.domain == domain)
        and (name is None or item.name == name)
        and (source_path is None or item.source_path == source_path)
    ]


def test_phase13_canonical_matrix(result):
    ir = result.canonical_ir
    assert ir.metadata.hostname == "phase13-fw"
    assert ir.metadata.source_vendor == "palo_alto"
    assert {interface.name for interface in ir.interfaces} == {"ethernet1/1", "ethernet1/2"}
    assert {interface.name: interface.zone for interface in ir.interfaces} == {
        "ethernet1/1": "trust", "ethernet1/2": "untrust",
    }
    assert {address.name for address in ir.addresses} == {"phase13-inside", "phase13-public"}
    assert [service.name for service in ir.services] == ["phase13-https"]
    assert [route.name for route in ir.routes] == ["phase13-default"]
    assert ir.routes[0].destination == "0.0.0.0/0"
    assert ir.routes[0].metric == 10
    assert [policy.name for policy in ir.policies] == ["phase13-security"]
    assert [rule.name for rule in ir.nat_rules] == ["phase13-snat"]


def test_phase13_policy_and_management_semantics_are_not_widened(result):
    policy = result.canonical_ir.policies[0]
    assert policy.from_zone == ["trust"]
    assert policy.to_zone == ["untrust"]
    assert policy.source == ["phase13-inside"]
    assert policy.destination == ["phase13-public"]
    assert policy.action == PolicyAction.ALLOW
    settings = policy.source_extra_settings
    assert settings["pan_rule_type"] == "interzone"
    assert settings["pan_rule_type_valid"] is True
    assert settings["pan_qos_marking_type"] == "ip-dscp"
    assert settings["pan_qos_ip_dscp"] == "af31"
    assert policy.review_reasons == ["rule-type-interzone", "qos-marking"]

    interface = next(item for item in result.canonical_ir.interfaces if item.name == "ethernet1/1")
    assert interface.management_profile == "phase13-mgmt"
    assert interface.management_access == ["https", "ping", "ssh"]
    assert set(interface.source_attributes["pan_effective_management_services"]) >= {
        "http", "https", "ping", "ssh", "telnet", "snmp",
    }
    assert interface.source_attributes["pan_effective_management_permitted_ips"] == [
        "192.0.2.10", "2001:db8:13::/64",
    ]


def test_phase13_source_only_domains_do_not_leak_into_canonical_ir(result):
    pbf = _inventory(result, domain="policy:pbf", name="phase13-pbf")
    assert len(pbf) == 1
    assert pbf[0].status == ExtractionStatus.EXTRACT_ONLY
    assert pbf[0].source_attributes["pan_pbf_next_hop"] == "198.51.100.253"
    assert not result.canonical_ir.policies[0].name == "phase13-pbf"
    assert [route.next_hop for route in result.canonical_ir.routes] == ["198.51.100.254"]

    assert not any(item.domain == "management_access" and item.name in {
        "http", "https", "ssh", "ping",
    } for item in result.inventory_items)
    assert {address.name for address in result.canonical_ir.addresses} == {
        "phase13-inside", "phase13-public",
    }
    assert "198.51.100.1" not in {route.next_hop for route in result.canonical_ir.routes}


def test_phase13_source_accounting_and_terminal_ownership(result):
    assert len({item.source_record_id for item in result.inventory_items}) == len(result.inventory_items)
    owners = {
        (item.domain, item.name, item.source_path)
        for item in result.inventory_items
    }
    assert sum(item.domain == "policies" and item.name == "phase13-security" for item in result.inventory_items) == 1
    assert sum(item.domain == "policy:pbf" and item.name == "phase13-pbf" for item in result.inventory_items) == 1
    assert sum(item.domain == "management_access" and item.name == "phase13-mgmt" for item in result.inventory_items) == 1
    assert sum(item.domain == "management_access" and item.source_path == "deviceconfig/system/service" for item in result.inventory_items) == 1
    assert sum(item.domain == "management_access" and item.source_path == "deviceconfig/system/permitted-ip" for item in result.inventory_items) == 1
    assert sum(item.domain == "deviceconfig" and item.source_path == "deviceconfig/system/future-system-setting" for item in result.inventory_items) == 1
    assert not any(item.domain == "policy:security" and item.name == "phase13-security" for item in result.inventory_items)
    assert not any(item.domain == "deviceconfig" and item.source_path == "deviceconfig/system/service" for item in result.inventory_items)
    assert not any(item.domain == "deviceconfig" and item.source_path == "deviceconfig/system/permitted-ip" for item in result.inventory_items)
    assert not any(item.domain == "deviceconfig" and item.source_path.startswith("network/profiles/interface-management-profile") for item in result.inventory_items)
    assert owners

    expected = {
        "network/profiles/interface-management-profile": (1, 1, 0, ExtractionStatus.EXTRACT_ONLY),
        "deviceconfig/system/service": (1, 1, 0, ExtractionStatus.EXTRACT_ONLY),
        "deviceconfig/system/permitted-ip": (1, 1, 0, ExtractionStatus.EXTRACT_ONLY),
        "rulebase/security/rules": (1, 1, 0, ExtractionStatus.PARTIALLY_NORMALIZED),
        "rulebase/pbf/rules": (1, 1, 0, ExtractionStatus.EXTRACT_ONLY),
        "rulebase/nat/rules": (1, 1, 0, ExtractionStatus.PARTIALLY_NORMALIZED),
        "deviceconfig/system/future-system-setting": (1, 1, 0, ExtractionStatus.EXTRACT_ONLY_UNKNOWN),
    }
    for path, (source, parsed, normalized, status) in expected.items():
        section = _section(result, path)
        assert (section.object_count_source, section.object_count_parsed,
                section.object_count_normalized, section.status) == (source, parsed, normalized, status)


def test_phase13_safety_and_valid_input_contract(result):
    assert result.requires_manual_review is True
    assert result.migration_complete is False
    assert result.generation_safe is False
    assert not any(item.status == ExtractionStatus.PARSE_ERROR for item in result.inventory_items)
    future = _inventory(result, domain="deviceconfig", source_path="deviceconfig/system/future-system-setting")
    assert len(future) == 1
    assert future[0].status == ExtractionStatus.UNSUPPORTED
    assert "retain-phase13-system" in str(future[0].source_attributes)
