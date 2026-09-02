import io

from openpyxl import load_workbook

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import FortiGateParser
from fwmigrate.parsers.fortigate.tokenizer import FortiGateTokenizer
from fwmigrate.report.excel_exporter import IRExcelExporter


def test_typed_operational_parents_keep_context_and_redact_credentials() -> None:
    content = """config vdom
edit "root"
    config system sdn-connector
        edit "sdn1"
            set type aws
            set server "10.0.0.10"
            set api-key "SDN_SECRET"
        next
    end
    config firewall network-service-dynamic
        edit "dynamic1"
            set filter "cloud"
            set sdn "sdn1"
        next
    end
    config user radius
        edit "radius1"
            set server "10.0.0.20"
            set secret "RADIUS_SECRET"
        next
    end
    config user tacacs+
        edit "tacacs1"
            set server "10.0.0.30"
            set secondary-server "10.0.0.31"
            set tertiary-server "10.0.0.32"
            set port 49
            set authen-type pap
            set authorization enable
            set source-ip "10.0.0.5"
            set interface-select-method specify
            set interface "mgmt"
            set key-string "TACACS_SECRET"
        next
    end
    config system link-monitor
        edit "wan-monitor"
            set srcintf "wan1"
            set server "1.1.1.1" "1.0.0.1"
            set update-static-route enable
        next
    end
    config vpn ipsec manualkey-interface
        edit "manual1"
            set interface "wan1"
            set encryption-key "ENC_SECRET"
            set authentication-key "AUTH_SECRET"
        next
    end
next
end
"""

    parser = FortiGateParser(FortiGateTokenizer(content))
    parsed = parser.parse()

    assert parsed.sdn_connectors[0].source_context == "root"
    assert parsed.sdn_connectors[0].server == "10.0.0.10"
    assert parsed.sdn_connectors[0].has_secret is True
    assert parsed.radius_servers[0].has_secret is True
    assert parsed.tacacs_servers[0].has_secret is True
    assert parsed.link_monitors[0].server == ["1.1.1.1", "1.0.0.1"]
    assert parsed.manualkey_interfaces[0].has_encryption_key is True
    assert parsed.manualkey_interfaces[0].has_authentication_key is True

    serialized = parsed.model_dump_json()
    for secret in ("SDN_SECRET", "RADIUS_SECRET", "TACACS_SECRET", "ENC_SECRET", "AUTH_SECRET"):
        assert secret not in serialized
    result = extract_fortigate_config(content)
    tacacs = result.canonical_ir.user_tacacs_servers[0]
    assert (
        tacacs.server, tacacs.secondary_server, tacacs.tertiary_server,
        tacacs.port, tacacs.authentication_type, tacacs.authorization,
        tacacs.interface,
    ) == ("10.0.0.30", "10.0.0.31", "10.0.0.32", 49, "pap", "enable", "mgmt")
    workbook = load_workbook(
        io.BytesIO(IRExcelExporter(result.canonical_ir, result).generate())
    )
    tacacs_sheet = workbook["TACACS+ Servers"]
    tacacs_headers = {cell.value: cell.column for cell in tacacs_sheet[3]}
    assert tacacs_sheet.cell(4, tacacs_headers["Secret Configured"]).value == "Yes"
    assert "TACACS_SECRET" not in "\n".join(
        str(cell.value)
        for row in tacacs_sheet.iter_rows()
        for cell in row
        if cell.value is not None
    )


def test_dynamic_service_dependencies_are_resolved_within_source_context() -> None:
    content = """config firewall network-service-dynamic
    edit "dynamic1"
        set sdn "sdn1"
    next
end
config system sdn-connector
    edit "sdn1"
        set type aws
    next
end
config firewall policy
    edit 1
        set srcintf "wan1"
        set dstintf "lan"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
        set network-service-dynamic "dynamic1"
    next
end
"""

    result = extract_fortigate_config(content)
    dependency_pairs = {
        (dependency.source_path, dependency.source_field, dependency.reference, dependency.result)
        for dependency in result.dependencies
    }
    assert (
        "firewall network-service-dynamic",
        "sdn",
        "sdn1",
        "RESOLVED",
    ) in dependency_pairs
    assert (
        "firewall policy",
        "network-service-dynamic",
        "dynamic1",
        "RESOLVED",
    ) in dependency_pairs


def test_identity_dependency_chain_reaches_radius_source_inventory() -> None:
    content = """config user radius
    edit "radius1"
        set server "10.0.0.20"
        set secret "RADIUS_SECRET"
    next
end
config user group
    edit "vpn-users"
        set member "radius1"
    next
end
config firewall policy
    edit 1
        set srcintf "any"
        set dstintf "any"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
        set groups "vpn-users"
    next
end
"""

    result = extract_fortigate_config(content)
    chain = [
        dependency for dependency in result.dependencies
        if dependency.reference in {"vpn-users", "radius1"}
    ]
    assert {(dependency.source_path, dependency.reference, dependency.result) for dependency in chain} == {
        ("firewall policy", "vpn-users", "RESOLVED"),
        ("user group", "radius1", "RESOLVED"),
    }


def test_profile_group_nested_security_dependencies_are_inventory_resolvable() -> None:
    content = """config firewall profile-group
    edit "secure"
        set ssh-filter-profile "ssh-prod"
        config ssh-filter
            edit "ssh-prod"
                set status enable
            next
        end
    next
end
config firewall policy
    edit 1
        set srcintf "any"
        set dstintf "any"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
        set profile-group "secure"
    next
end
"""

    result = extract_fortigate_config(content)
    assert any(
        dependency.source_path == "firewall profile-group"
        and dependency.reference == "ssh-prod"
        and dependency.result == "RESOLVED"
        and dependency.target_path == "firewall profile-group ssh-filter"
        for dependency in result.dependencies
    )


def test_unresolved_reference_is_partial_and_reported_without_broadening_policy() -> None:
    content = """config firewall policy
    edit 1
        set srcintf "missing-interface"
        set dstintf "any"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
    next
end
"""

    result = extract_fortigate_config(content)
    unresolved = [dependency for dependency in result.dependencies if dependency.result == "UNRESOLVED"]
    assert len(unresolved) == 1
    assert unresolved[0].reference == "missing-interface"
    assert result.generation_safe is False
    policy_section = next(section for section in result.source_sections if section.path == "firewall policy")
    assert policy_section.status == ExtractionStatus.PARTIALLY_NORMALIZED
    assert policy_section.unresolved_dependencies == 1
    assert any("missing-interface" in entry.message for entry in result.canonical_ir.audit_entries)

    workbook = load_workbook(
        io.BytesIO(IRExcelExporter(result.canonical_ir, result).generate())
    )
    assert "Unresolved References" in workbook.sheetnames
    unresolved_sheet = workbook["Unresolved References"]
    values = "\n".join(
        str(cell.value)
        for row in unresolved_sheet.iter_rows()
        for cell in row
        if cell.value is not None
    )
    assert "missing-interface" in values


def test_dns_source_semantics_are_partial_even_when_typed_vendor_fields_exist() -> None:
    content = """config system dns
    set primary 1.1.1.1
    set secondary 8.8.8.8
    set protocol dot
    set server-select-method failover
    set domain example.com
end
"""

    result = extract_fortigate_config(content)
    dns_section = next(section for section in result.source_sections if section.path == "system dns")
    assert dns_section.status == ExtractionStatus.PARTIALLY_NORMALIZED
    assert {"protocol", "server_select_method", "domain"} <= set(dns_section.semantic_unknowns)
    assert result.canonical_ir.dns_settings.primary == "1.1.1.1"
    assert result.canonical_ir.dns_settings.secondary == "8.8.8.8"


def test_dos_policy_identity_includes_address_family() -> None:
    content = """config firewall DoS-policy
    edit 1
        set status enable
        set interface "wan4"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
    next
end
config firewall DoS-policy6
    edit 1
        set status enable
        set interface "wan6"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
    next
end
"""

    result = extract_fortigate_config(content)
    assert [(policy.source_id, policy.address_family, policy.interface) for policy in result.canonical_ir.dos_policies] == [
        (1, "ipv4", "wan4"),
        (1, "ipv6", "wan6"),
    ]


def test_unknown_migration_relevant_sections_are_recursively_captured() -> None:
    content = """config firewall future-policy
    edit "future1"
        set action accept
        set api-key "FUTURE_SECRET"
        config nested-setting
            edit "child1"
                set value preserved
            next
        end
    next
end
"""

    result = extract_fortigate_config(content)
    section = result.source_sections[0]
    assert section.status == ExtractionStatus.EXTRACT_ONLY_UNKNOWN
    assert result.generation_safe is False
    root = next(item for item in result.inventory_items if item.source_path == "firewall future-policy")
    assert root.name == "future1"
    assert root.children[0].children[0].name == "child1"
    serialized = result.model_dump_json()
    assert "FUTURE_SECRET" not in serialized


def test_webfilter_url_sections_are_structured_extract_only_including_empty() -> None:
    content = """config webfilter search-engine
    edit "search"
        set safe-search enable
    next
end
config webfilter ips-urlfilter-setting
end
config webfilter ips-urlfilter-setting6
    edit "ipv6"
        set status enable
    next
end
"""

    result = extract_fortigate_config(content)
    sections = {section.path: section for section in result.source_sections}
    assert {
        path: sections[path].status
        for path in (
            "webfilter search-engine",
            "webfilter ips-urlfilter-setting",
            "webfilter ips-urlfilter-setting6",
        )
    } == {
        path: ExtractionStatus.EXTRACT_ONLY
        for path in (
            "webfilter search-engine",
            "webfilter ips-urlfilter-setting",
            "webfilter ips-urlfilter-setting6",
        )
    }
    assert any(
        item.source_path == "webfilter ips-urlfilter-setting"
        for item in result.inventory_items
    )
