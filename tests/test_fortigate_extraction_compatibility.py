from fwmigrate.extraction.models import (
    ExtractionResult,
    ExtractionStatus,
    MigrationImpact,
    SourceCommand,
    SourceInventoryItem,
    SourceSectionResult,
    UnsupportedItem,
)
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.coverage import fortigate_generation_impact
from fwmigrate.parsers.fortigate.model import (
    FGAddressGroup,
    FGAddressGroupTaggingEntry,
)
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


def test_removed_fortigate_families_remain_inventory_only():
    paths = [
        "firewall multicast-policy", "firewall multicast-policy6",
        "firewall local-in-policy", "firewall local-in-policy6",
        "system dhcp server", "system dhcp6 server",
        "firewall address6-template", "authentication scheme",
        "authentication rule", "firewall access-proxy",
        "firewall access-proxy6", "firewall access-proxy-virtual-host",
        "firewall access-proxy virtual-host", "firewall access-proxy6 virtual-host",
        "firewall access-proxy realservers", "firewall access-proxy6 realservers",
        "firewall network-service-dynamic", "system sdn-connector",
        "firewall shaper traffic-shaper", "firewall shaper per-ip-shaper",
        "firewall shaping-profile", "firewall shaping-policy", "firewall proxy-policy",
        "system global",
    ]
    blocks = []
    for path in paths:
        if path == "system global":
            blocks.append("config system global\n    set hostname dropped\nend")
            continue
        blocks.append(
            f"config {path}\n"
            "    edit dropped\n"
            "        set value dropped\n"
            "    next\n"
            "end"
        )

    result = extract_fortigate_config("\n".join(blocks))
    sections = {section.path: section for section in result.source_sections}
    inventory = {item.source_path: item for item in result.inventory_items}

    assert set(sections) == set(paths)
    assert all(
        sections[path].status == ExtractionStatus.IGNORED_BY_POLICY
        and sections[path].migration_impact == MigrationImpact.NONE
        for path in paths
    )
    assert set(inventory) == set(paths)
    assert not result.dependencies
    assert result.blocking_reasons == []
    assert result.generation_safe is True
    fortios = result.canonical_ir.vendor_extensions.fortios
    assert not hasattr(fortios, "source_only_rules")
    assert fortios.authentication_profiles == []
    assert fortios.authentication_policies == []
    assert fortios.traffic_shapers == []


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


def test_security_profile_references_preserve_profile_context():
    source = '''
config antivirus profile
    edit "av"
        set comment "test"
    next
end
config firewall policy
    edit 1
        set name "policy"
        set srcintf "any"
        set dstintf "any"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
        set av-profile "av"
    next
end
'''

    result = extract_fortigate_config(source)

    policy = result.canonical_ir.policies[0]
    assert policy.security_profile_reference_statuses["av_profile"] == "resolved"


def test_fortigate_addrgrp_parser_preserves_typed_and_unknown_fields():
    source = """
config firewall addrgrp
    edit "GROUP-A"
        set member "ADDR-A" "ADDR-B" "GROUP-C"
        set exclude enable
        set exclude-member "ADDR-X" "ADDR-Y"
        set comment "Address group"
        set uuid "group-uuid"
        set allow-routing enable
        set color 6
        set category location
        set type static
        set fabric-object enable
        set filter "legacy-filter"
        set future-setting "value"
        config tagging
            edit "tag-entry"
                set category location
                set tags "prod" "dmz"
            next
        end
    next
end
"""

    config = FortiGateParser(FortiGateTokenizer(source)).parse()
    group = config.address_groups[0]

    assert group.member == ["ADDR-A", "ADDR-B", "GROUP-C"]
    assert group.exclude_member == ["ADDR-X", "ADDR-Y"]
    assert (
        group.exclude,
        group.comment,
        group.uuid,
        group.allow_routing,
        group.color,
        group.category,
        group.type,
        group.fabric_object,
    ) == (
        "enable",
        "Address group",
        "group-uuid",
        "enable",
        6,
        "location",
        "static",
        "enable",
    )
    assert group.extra_settings == {
        "filter": "legacy-filter",
        "future_setting": "value",
    }
    assert len(group.tagging) == 1
    assert isinstance(group.tagging[0], FGAddressGroupTaggingEntry)
    assert group.tagging[0].name == "tag-entry"
    assert group.tagging[0].category == "location"
    assert group.tagging[0].tags == ["prod", "dmz"]
    assert "dynamic_filter" not in FGAddressGroup.model_fields
    assert not hasattr(group, "dynamic_filter")


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
    v6_group = next(
        group for group in ir.address_groups if group.name == "V6_GROUP"
    )
    assert v6_group.address_family == "ipv6"
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


def test_administrative_unsupported_section_is_preserved_without_blocking_generation():
    source = """
config system interface
    edit port1
    next
    edit port2
    next
end
config firewall policy
    edit 1
        set srcintf port1
        set dstintf port2
        set srcaddr all
        set dstaddr all
        set service ALL
        set action accept
    next
end
config system accprofile
    edit admin-profile
        config utmgrp-permission
            set cli-read enable
        end
    next
end
"""

    result = extract_fortigate_config(source)

    assert result.generation_safe is True
    assert result.blocking_reasons == []
    nested_section = next(
        section
        for section in result.source_sections
        if section.path == "system accprofile utmgrp-permission"
    )
    inventory = next(
        item for item in result.inventory_items if item.source_path == "system accprofile"
    )
    assert nested_section.migration_impact == MigrationImpact.NONE
    assert inventory.migration_impact == MigrationImpact.NONE
    assert inventory.status == ExtractionStatus.IGNORED_BY_POLICY
    assert not any(
        item.source_path == "system accprofile utmgrp-permission"
        for item in result.unsupported_items
    )
    assert result.requires_manual_review is False


def test_unsupported_traffic_section_still_blocks_generation():
    result = extract_fortigate_config("""
config firewall unknown-policy
    edit policy-1
        set future-field value
    next
end
""")

    assert result.generation_safe is False
    assert any("firewall unknown-policy" in reason for reason in result.blocking_reasons)


def test_administrative_and_traffic_unsupported_sections_keep_only_traffic_blocking():
    result = extract_fortigate_config("""
config system accprofile
    edit admin-profile
        config utmgrp-permission
            set cli-read enable
        end
    next
end
config firewall unknown-policy
    edit policy-1
        set future-field value
    next
end
""")

    assert result.generation_safe is False
    assert any("firewall unknown-policy" in reason for reason in result.blocking_reasons)
    assert not any("system accprofile" in reason for reason in result.blocking_reasons)


def test_fortigate_generation_impact_matrix():
    cases = [
        ("system accprofile", ExtractionStatus.EXTRACT_ONLY, False),
        ("system accprofile utmgrp-permission", ExtractionStatus.UNSUPPORTED, False),
        ("system admin", ExtractionStatus.EXTRACT_ONLY, False),
        ("log fortianalyzer setting", ExtractionStatus.EXTRACT_ONLY, False),
        ("system snmp community", ExtractionStatus.UNSUPPORTED, False),
        ("firewall policy", ExtractionStatus.UNSUPPORTED, True),
        ("firewall central-snat-map", ExtractionStatus.EXTRACT_ONLY, True),
        ("unknown source section", ExtractionStatus.UNSUPPORTED, False),
        ("firewall policy", ExtractionStatus.PARSE_ERROR, True),
    ]

    for path, status, blocking in cases:
        impact = fortigate_generation_impact(path, status)
        assert (impact == MigrationImpact.BLOCKING) is blocking, (path, status, impact)


def test_unreferenced_user_source_only_object_is_review_only():
    result = extract_fortigate_config("""
config user ldap
    edit LDAP1
        set server ldap.example.test
    next
end
""")

    assert result.generation_safe is True
    item = next(item for item in result.inventory_items if item.source_path == "user ldap")
    assert item.migration_impact == MigrationImpact.REVIEW
    assert result.blocking_reasons == []
