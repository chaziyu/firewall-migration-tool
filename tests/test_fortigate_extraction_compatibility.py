from fwmigrate.extraction.models import (
    ExtractionResult,
    ExtractionStatus,
    SourceCommand,
    SourceInventoryItem,
    SourceSectionResult,
    UnsupportedItem,
)
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import FortiGateParser
from fwmigrate.parsers.fortigate.tokenizer import FortiGateTokenizer
from tests.fixture_paths import (
    FORTIGATE_P0_EDGE_CASES_FIXTURE,
    FORTIGATE_P0_MIGRATION_CRITICAL_FIXTURE,
)


def _read_fixture(path):
    return path.read_text(encoding="utf-8")


def _names(items):
    return {item.name for item in items}


def test_source_command_backward_compatibility():
    """Verify SourceCommand default field values work with legacy 3-arg constructor."""
    cmd = SourceCommand(operation="set", key="subnet", values=["192.168.1.0", "255.255.255.0"])
    assert cmd.operation == "set"
    assert cmd.key == "subnet"
    assert cmd.values == ["192.168.1.0", "255.255.255.0"]
    assert cmd.line_number is None
    assert cmd.status is None
    assert cmd.parser_handler is None
    assert cmd.requires_manual_review is False


def test_source_command_extended_fields():
    """Verify SourceCommand supports new granular accounting fields."""
    cmd = SourceCommand(
        operation="set",
        key="address",
        values=["10.0.0.1/32"],
        line_number=42,
        status=ExtractionStatus.NORMALIZED,
        parser_handler="interfaces",
        requires_manual_review=False,
    )
    assert cmd.line_number == 42
    assert cmd.status == ExtractionStatus.NORMALIZED
    assert cmd.parser_handler == "interfaces"
    assert cmd.requires_manual_review is False


def test_fortigate_extraction_pipeline_compatibility():
    """Verify extract_fortigate_config runs cleanly and populates ExtractionResult."""
    fgt_config = """
    config firewall address
        edit "web_server"
            set subnet 10.1.1.100 255.255.255.255
        next
    end
    """
    result = extract_fortigate_config(fgt_config)
    assert isinstance(result, ExtractionResult)
    assert len(result.canonical_ir.addresses) >= 1
    assert any(addr.name == "web_server" for addr in result.canonical_ir.addresses)


def test_fortigate_p0_migration_critical_fixture_freezes_current_behavior():
    """Freeze migration-critical FortiOS 7.4.6 extraction and dependency behavior."""
    result = extract_fortigate_config(
        _read_fixture(FORTIGATE_P0_MIGRATION_CRITICAL_FIXTURE)
    )
    ir = result.canonical_ir

    assert ir.metadata.source_version == "FortiOS 7.4.6"
    assert {"port1", "port2", "vlan100"} <= _names(ir.interfaces)
    assert "LAN_ZONE" in _names(ir.zones)
    assert {"USER_NET", "WEB_SERVER", "V6_NET"} <= _names(ir.addresses)
    assert {"INTERNAL_NETS", "V6_GROUP"} <= _names(ir.address_groups)
    assert {"TCP_443", "TCP_8443"} <= _names(ir.services)
    assert "WEB_SERVICES" in _names(ir.service_groups)
    assert {"WORK_HOURS", "MAINT_WINDOW"} <= _names(ir.schedules)
    assert "BUSINESS_SCHEDULES" in _names(ir.schedule_groups)
    assert {"SNAT_POOL", "SNAT6_POOL"} <= _names(ir.ip_pools)
    assert "VIP_WEB" in _names(ir.virtual_ips)
    assert "VIP_SERVERS" in _names(ir.virtual_ip_groups)
    assert {"OUTBOUND_WEB", "INBOUND_WEB"} <= _names(ir.policies)
    assert ir.routes

    section_counts = {
        section.path: section.object_count_source
        for section in result.source_sections
    }
    assert section_counts["system interface"] == 3
    assert section_counts["system zone"] == 1
    assert section_counts["firewall address"] == 2
    assert section_counts["firewall address6"] == 1
    assert section_counts["firewall addrgrp"] == 1
    assert section_counts["firewall addrgrp6"] == 1
    assert section_counts["firewall service custom"] == 2
    assert section_counts["firewall service group"] == 1
    assert section_counts["firewall schedule recurring"] == 1
    assert section_counts["firewall schedule onetime"] == 1
    assert section_counts["firewall schedule group"] == 1
    assert section_counts["firewall ippool"] == 1
    assert section_counts["firewall ippool6"] == 1
    assert section_counts["firewall vip"] == 1
    assert section_counts["firewall vipgrp"] == 1
    assert section_counts["firewall policy"] == 2
    assert section_counts["router static"] == 1

    critical_paths = {
        "firewall policy",
        "firewall vip",
        "firewall vipgrp",
        "router static",
    }
    assert not [
        dependency
        for dependency in result.dependencies
        if dependency.result == "UNRESOLVED"
        and dependency.source_path in critical_paths
    ]

    pool_dependency = next(
        dependency
        for dependency in result.dependencies
        if dependency.source_path == "firewall policy"
        and dependency.source_field == "poolname"
        and dependency.reference == "SNAT_POOL"
    )
    assert pool_dependency.result == "RESOLVED"

    vip_group_dependency = next(
        dependency
        for dependency in result.dependencies
        if dependency.source_path == "firewall policy"
        and dependency.source_field == "dstaddr"
        and dependency.reference == "VIP_SERVERS"
    )
    assert vip_group_dependency.result == "RESOLVED"
    assert vip_group_dependency.target_path == "firewall vipgrp"


def test_fortigate_p0_edge_fixture_freezes_lossless_and_fail_closed_behavior():
    """Freeze unknown-value preservation, command ordering, and dependency safety."""
    text = _read_fixture(FORTIGATE_P0_EDGE_CASES_FIXTURE)

    parser = FortiGateParser(FortiGateTokenizer(text))
    config = parser.parse()

    edge_src = next(address for address in config.addresses if address.name == "EDGE_SRC")
    assert edge_src.extra_settings["future_address_field"] == "kept"
    assert edge_src.extra_settings["unparsed_cache_ttl"] == "invalid"

    edge_service = next(service for service in config.services if service.name == "EDGE_SERVICE")
    assert edge_service.extra_settings["future_service_field"] == "kept"
    assert edge_service.extra_settings["unparsed_protocol_number"] == "invalid"

    edge_group = next(
        group for group in config.address_groups if group.name == "EDGE_GROUP"
    )
    assert edge_group.member == ["EDGE_DST"]

    group_inventory = next(
        item
        for item in parser.source_inventory_items
        if item.source_path == "firewall addrgrp" and item.name == "EDGE_GROUP"
    )
    assert [
        (command.operation, command.key, command.values)
        for command in group_inventory.commands
        if command.key == "member"
    ] == [
        ("set", "member", ["EDGE_SRC"]),
        ("append", "member", ["EDGE_DST"]),
        ("unset", "member", []),
        ("set", "member", ["EDGE_DST"]),
    ]

    result = extract_fortigate_config(text)
    missing_reference = next(
        dependency
        for dependency in result.dependencies
        if dependency.source_path == "firewall policy"
        and dependency.source_field == "dstaddr"
        and dependency.reference == "MISSING_ADDRESS"
    )
    assert missing_reference.result == "UNRESOLVED"
    assert result.requires_manual_review is True
    assert result.generation_safe is False
    assert any(
        "MISSING_ADDRESS" in reason
        for reason in result.blocking_reasons
    )

    section_counts = {
        section.path: section.object_count_source
        for section in result.source_sections
    }
    assert section_counts["firewall central-snat-map"] == 1
    assert section_counts["firewall ip-translation"] == 1
