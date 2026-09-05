import io

from openpyxl import load_workbook

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import FortiGateParser
from fwmigrate.parsers.fortigate.tokenizer import FortiGateTokenizer
from fwmigrate.report.excel_exporter import IRExcelExporter


def test_dhcp_v4_coverage_is_typed_extract_only_with_exact_child_counts() -> None:
    result = extract_fortigate_config("""
config system dhcp server
    edit 1
        config ip-range
            edit 3
            next
            edit 1
            next
        end
        config exclude-range
            edit 2
            next
        end
        config reserved-address
            edit 4
            next
        end
        config options
            edit 5
            next
            edit 6
            next
        end
    next
end
""")
    sections = {section.path: section for section in result.source_sections}
    for path, count in {
        "system dhcp server": 1,
        "system dhcp server ip-range": 2,
        "system dhcp server exclude-range": 1,
        "system dhcp server reserved-address": 1,
        "system dhcp server options": 2,
    }.items():
        assert sections[path].status == ExtractionStatus.EXTRACT_ONLY
        assert sections[path].object_count_source == count
        assert sections[path].object_count_parsed == count
        assert sections[path].object_count_normalized == count


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
            set secondary-server "10.0.0.21"
            set tertiary-server "10.0.0.22"
            set auth-type ms_chap_v2
            set nas-ip "192.0.2.20"
            set source-ip "192.0.2.21"
            set radius-port 1812
            set acct-interim-interval 300
            set secret "RADIUS_SECRET"
            set username-case-sensitive enable
            config accounting-server
                edit "1"
                    set status enable
                    set server "10.0.0.23"
                    set port 1813
                    set source-ip "192.0.2.22"
                    set secret "ACCOUNTING_SECRET"
                next
            end
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
            set status-ttl 300
            set secondary-key "TACACS_SECONDARY_SECRET"
            set tertiary-key "TACACS_TERTIARY_SECRET"
            set key-string "TACACS_SECRET"
        next
    end
    config system link-monitor
        edit "wan-monitor"
            set srcintf "wan1" "wan2"
            set server "1.1.1.1" "1.0.0.1"
            set protocol ping http
            set gateway-ip 192.0.2.1
            set source-ip 192.0.2.2
            set port 443
            set timeout 500
            set update-static-route enable
            set update-policy-route disable
            set update-cascade-interface enable
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
    assert parsed.link_monitors[0].srcintf == ["wan1", "wan2"]
    assert parsed.link_monitors[0].protocol == ["ping", "http"]
    assert (
        parsed.link_monitors[0].gateway_ip,
        parsed.link_monitors[0].source_ip,
        parsed.link_monitors[0].port,
        parsed.link_monitors[0].timeout,
    ) == ("192.0.2.1", "192.0.2.2", 443, 500)
    assert (
        parsed.link_monitors[0].update_static_route,
        parsed.link_monitors[0].update_policy_route,
        parsed.link_monitors[0].update_cascade_interface,
    ) == ("enable", "disable", "enable")
    assert parsed.manualkey_interfaces[0].has_encryption_key is True
    assert parsed.manualkey_interfaces[0].has_authentication_key is True

    serialized = parsed.model_dump_json()
    for secret in (
        "SDN_SECRET", "RADIUS_SECRET", "TACACS_SECRET",
        "TACACS_SECONDARY_SECRET", "TACACS_TERTIARY_SECRET",
        "ENC_SECRET", "AUTH_SECRET",
    ):
        assert secret not in serialized
    result = extract_fortigate_config(content)
    radius = result.canonical_ir.user_radius_servers[0]
    assert (
        radius.server, radius.secondary_server, radius.tertiary_server,
        radius.auth_type, radius.port, radius.acct_interim_interval,
        radius.nas_ip, radius.source_ip,
    ) == (
        "10.0.0.20", "10.0.0.21", "10.0.0.22", "ms_chap_v2", 1812,
        300, "192.0.2.20", "192.0.2.21",
    )
    assert radius.accounting_servers[0].server == "10.0.0.23"
    assert radius.accounting_servers[0].port == 1813
    assert radius.accounting_servers[0].has_secret is True
    radius_section = next(section for section in result.source_sections if section.path == "user radius")
    assert (
        radius_section.parser_handler,
        radius_section.object_count_parsed,
        radius_section.object_count_normalized,
    ) == ("FortiGateParser.build_model", 1, 1)
    tacacs = result.canonical_ir.user_tacacs_servers[0]
    assert (
        tacacs.server, tacacs.secondary_server, tacacs.tertiary_server,
        tacacs.port, tacacs.authentication_type, tacacs.authorization,
        tacacs.interface, tacacs.status_ttl,
    ) == ("10.0.0.30", "10.0.0.31", "10.0.0.32", 49, "pap", "enable", "mgmt", 300)
    tacacs_section = next(section for section in result.source_sections if section.path == "user tacacs+")
    assert (
        tacacs_section.parser_handler,
        tacacs_section.object_count_parsed,
        tacacs_section.object_count_normalized,
    ) == ("FortiGateParser.build_model", 1, 1)
    workbook = load_workbook(
        io.BytesIO(IRExcelExporter(result.canonical_ir, result).generate())
    )
    tacacs_sheet = workbook["TACACS+ Servers"]
    tacacs_headers = {cell.value: cell.column for cell in tacacs_sheet[3]}
    assert tacacs_sheet.cell(4, tacacs_headers["Secret Configured"]).value == "Yes"
    assert tacacs_sheet.cell(4, tacacs_headers["Status TTL"]).value == 300
    assert all(secret not in "\n".join(
        str(cell.value)
        for row in tacacs_sheet.iter_rows()
        for cell in row
        if cell.value is not None
    ) for secret in ("TACACS_SECRET", "TACACS_SECONDARY_SECRET", "TACACS_TERTIARY_SECRET"))
    radius_sheet = workbook["RADIUS Servers"]
    radius_headers = {cell.value: cell.column for cell in radius_sheet[3]}
    assert radius_sheet.cell(4, radius_headers["Accounting Interim Interval"]).value == 300
    accounting_sheet = workbook["RADIUS Accounting Servers"]
    accounting_headers = {cell.value: cell.column for cell in accounting_sheet[3]}
    assert accounting_sheet.cell(4, accounting_headers["Server"]).value == "10.0.0.23"
    assert accounting_sheet.cell(4, accounting_headers["Secret Configured"]).value == "Yes"
    assert "ACCOUNTING_SECRET" not in "\n".join(
        str(cell.value)
        for row in accounting_sheet.iter_rows()
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


def test_coverage_reports_semantic_tiers_for_typed_and_structured_sections() -> None:
    result = extract_fortigate_config('''
config user local
    edit "alice"
        set status enable
        set passwd-time 123
    next
end
config user radius
    edit "radius"
        set server "192.0.2.1"
        set obscure-setting value
    next
end
config ips sensor
    edit "IPS1"
        config entries
            edit 1
                set action block
            next
        end
    next
end
config webfilter profile
    edit "WF1"
        config web
            set feature enable
        end
    next
end
''')
    sections = {section.path: section for section in result.source_sections}
    assert any("Semantic support level: TYPED_EXTRACT_ONLY" in note for note in sections["user local"].notes)
    assert any("Semantic support level: TYPED_EXTRACT_ONLY" in note for note in sections["user radius"].notes)
    assert any("Semantic support level: TYPED_EXTRACT_ONLY" in note for note in sections["ips sensor"].notes)
    assert any("Support level: STRUCTURED_EXTRACT_ONLY" in note for note in sections["webfilter profile"].notes)


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
