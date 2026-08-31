import io

from openpyxl import load_workbook

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer
from fwmigrate.report.excel_exporter import IRExcelExporter


PRIMARY_IPV6_CONFIG = """
config system interface
    edit "v6-only"
        config ipv6
            set ip6-address 2001:0DB8:0:0::1/64
            set ip6-allowaccess ping https ssh
            set ip6-mode static
            set ip6-send-adv enable
            set ip6-manage-flag enable
            set ip6-other-flag disable
        end
    next
end
"""


def _interface(config, name):
    return next(item for item in config.interfaces if item.name == name)


def test_primary_ipv6_values_are_typed_and_source_preserved():
    interface = _interface(parse_fortigate_config(PRIMARY_IPV6_CONFIG), "v6-only")

    assert interface.ip6_address == "2001:0DB8:0:0::1/64"
    assert interface.ip6_allowaccess == ["ping", "https", "ssh"]
    assert interface.ip6_mode == "static"
    assert interface.ip6_send_adv == "enable"
    assert interface.ip6_manage_flag == "enable"
    assert interface.ip6_other_flag == "disable"
    assert interface.ipv6_source_settings == {
        "ip6_address": "2001:0DB8:0:0::1/64",
        "ip6_allowaccess": ["ping", "https", "ssh"],
        "ip6_mode": "static",
        "ip6_send_adv": "enable",
        "ip6_manage_flag": "enable",
        "ip6_other_flag": "disable",
    }


def test_ipv6_only_interface_is_retained_and_normalized():
    result = extract_fortigate_config(PRIMARY_IPV6_CONFIG)
    interface = result.canonical_ir.interfaces[0]

    assert interface.ip is None
    assert interface.ipv6_address == "2001:db8::1/64"
    assert interface.source_ipv6_address == "2001:0DB8:0:0::1/64"
    assert interface.source_ipv6_management_access == ["ping", "https", "ssh"]
    assert interface.requires_manual_review is False
    assert interface.migration_status == "NORMALIZED"
    assert interface.review_reasons == []
    assert result.generation_safe is True


def test_simple_ipv6_interface_does_not_get_generic_nested_review():
    ir = FGToIRTransformer(parse_fortigate_config(PRIMARY_IPV6_CONFIG)).transform()
    interface = ir.interfaces[0]

    assert [node.name for node in interface.nested_source_configs] == ["ipv6"]
    assert not any("nested" in reason.lower() for reason in interface.review_reasons)
    assert not any(
        entry.category == "Interface Nested Configuration"
        for entry in ir.audit_entries
    )


def test_nested_ipv6_tree_preserves_additional_addresses_and_order():
    config = """
config system interface
    edit "port1"
        config ipv6
            set ip6-address 2001:db8:1::1/64
            config ip6-extra-addr
                edit 2001:db8:1::2/64
                next
                edit 2001:db8:1::3/64
                next
            end
            config ip6-prefix-list
                edit 2001:db8:1::/64
                    set autonomous-flag enable
                next
            end
        end
    next
end
"""
    interface = _interface(parse_fortigate_config(config), "port1")
    ipv6 = next(node for node in interface.nested_configs if node.name == "ipv6")

    extra_addresses = next(
        child for child in ipv6.children if child.name == "ip6-extra-addr"
    )
    assert [child.name for child in extra_addresses.children] == [
        "2001:db8:1::2/64",
        "2001:db8:1::3/64",
    ]
    assert [child.name for child in ipv6.children] == [
        "ip6-extra-addr",
        "ip6-prefix-list",
    ]


def test_complex_ipv6_interface_is_partially_normalized_and_reviewed():
    config = """
config system interface
    edit "port1"
        config ipv6
            set ip6-address 2001:db8::1/64
            config ip6-prefix-list
                edit 2001:db8::/64
                    set autonomous-flag enable
                next
            end
        end
    next
end
"""
    interface = FGToIRTransformer(parse_fortigate_config(config)).transform().interfaces[0]

    assert interface.ipv6_address == "2001:db8::1/64"
    assert interface.migration_status == "PARTIALLY_NORMALIZED"
    assert interface.requires_manual_review is True
    assert interface.review_reasons == [
        "FortiGate IPv6 interface contains source-specific behavior requiring target-platform review"
    ]


def test_vrrp6_is_preserved_and_reviewed():
    config = """
config system interface
    edit "port1"
        config ipv6
            set ip6-address 2001:db8::1/64
        end
        config vrrp6
            edit 1
                set vrip6 2001:db8::fe/64
            next
        end
    next
end
"""
    ir = FGToIRTransformer(parse_fortigate_config(config)).transform()
    interface = ir.interfaces[0]

    assert any(node.name == "vrrp6" for node in interface.nested_source_configs)
    assert interface.migration_status == "PARTIALLY_NORMALIZED"
    assert interface.requires_manual_review is True
    assert any(
        "vrrp6" in reason.lower()
        for reason in interface.review_reasons
    )


def test_malformed_ipv6_address_is_retained_without_repair():
    config = """
config system interface
    edit "broken-v6"
        config ipv6
            set ip6-address not-an-ipv6/64
        end
    next
end
"""
    result = extract_fortigate_config(config)
    interface = result.canonical_ir.interfaces[0]

    assert interface.ipv6_address is None
    assert interface.source_ipv6_address == "not-an-ipv6/64"
    assert interface.ipv6_source_settings["ip6_address"] == "not-an-ipv6/64"
    assert interface.parse_errors
    assert "ipv6-address" in interface.parse_errors[0]
    assert interface.requires_manual_review is True
    assert result.generation_safe is False

    section = next(
        item for item in result.source_sections if item.path == "system interface"
    )
    assert section.status == ExtractionStatus.PARTIALLY_NORMALIZED


def test_ipv6_fields_are_visible_in_excel_interface_inventory():
    result = extract_fortigate_config(PRIMARY_IPV6_CONFIG)
    workbook = load_workbook(
        io.BytesIO(IRExcelExporter(result.canonical_ir, result).generate())
    )
    sheet = workbook["Interfaces"]
    headers = [cell.value for cell in sheet[3]]
    values = [cell.value for cell in sheet[4]]
    values_by_header = dict(zip(headers, values))

    assert {
        "IPv6 Address",
        "IPv6 Management Access",
        "Migration Status",
        "Manual Review",
        "Review Reasons",
    }.issubset(headers)
    assert values_by_header["IPv6 Address"] == "2001:db8::1/64"
    assert values_by_header["IPv6 Source Address"] == "2001:0DB8:0:0::1/64"
    assert values_by_header["IPv6 Management Access"] == "ping\nhttps\nssh"
    assert values_by_header["Migration Status"] == "NORMALIZED"
    assert values_by_header["Manual Review"] == "FALSE"
    assert values_by_header["Review Reasons"] is None
