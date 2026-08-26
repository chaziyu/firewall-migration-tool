import io

from openpyxl import load_workbook

from fwmigrate.ir.enums import AddressType
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer
from fwmigrate.report.excel_exporter import IRExcelExporter


ADDRESS_CONFIG = """
config firewall address
    edit "normal-net"
        set uuid 11111111-1111-1111-1111-111111111111
        set subnet 192.168.10.0 255.255.255.0
        set allow-routing enable
        set associated-interface "port6"
        set color 9
        set cache-ttl 300
        set password "must-not-be-retained"
    next

    edit "geo"
        set type geography
        set country "MY"
    next

    edit "geo-missing-country"
        set type geography
    next

    edit "ems"
        set type dynamic
        set sub-type ems-tag
        set dirty clean
        set obj-tag "Deleum_ADUser"
        set tag-type "zero_trust"
        set obj-type mac
    next

    edit "mac-source"
        set uuid 33333333-3333-3333-3333-333333333333
        set type mac
        set macaddr "00:11:22:33:44:55"
        set associated-interface "port7"
        set comment "Unsupported MAC inventory"
    next
end

config firewall address6
    edit "SSLVPN_TUNNEL_IPv6_ADDR1"
        set uuid 17523864-65a4-51e9-c45e-65c6367ea4e3
        set ip6 fdff:ffff::/120
    next
    edit "ipv6-test"
        set uuid 22222222-2222-2222-2222-222222222222
        set ip6 fdff:ffff::/120
        set fabric-object enable
    next
    edit "all"
        set uuid aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
    next
    edit "none"
        set uuid bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb
        set ip6 ::/128
    next
end


config firewall multicast-address
    edit "multicast-test"
        set start-ip 239.1.1.1
        set end-ip 239.1.1.2
        set visibility enable
    next
end

config firewall multicast-address6
    edit "all"
        set ip6 ff00::/8
        set visibility enable
    next
end

config firewall wildcard-fqdn custom
    edit "cdn-apple"
        set uuid cccccccc-cccc-cccc-cccc-cccccccccccc
        set wildcard-fqdn "*.cdn-apple.com"
        set cache-ttl 60
    next
    edit "google-play"
        set uuid dddddddd-dddd-dddd-dddd-dddddddddddd
        set wildcard-fqdn "*play.google.com"
    next
end
"""


def _by_name(items):
    return {item.name: item for item in items}


def test_fortigate_address_parser_preserves_typed_and_unknown_settings():
    config = parse_fortigate_config(ADDRESS_CONFIG)
    addresses = _by_name(config.addresses)

    normal = addresses["normal-net"]
    assert normal.uuid == "11111111-1111-1111-1111-111111111111"
    assert normal.associated_interface == "port6"
    assert normal.allow_routing == "enable"
    assert normal.color == 9
    assert normal.extra_settings == {
        "cache_ttl": "300",
        "password": "[REDACTED]",
    }

    assert addresses["geo"].country == "MY"

    ems = addresses["ems"]
    assert ems.sub_type == "ems-tag"
    assert ems.obj_tag == "Deleum_ADUser"
    assert ems.tag_type == "zero_trust"
    assert ems.obj_type == "mac"
    assert ems.dirty == "clean"

    ipv6 = addresses["ipv6-test"]
    assert ipv6.ip6 == "fdff:ffff::/120"
    assert ipv6.is_ipv6 is True
    assert ipv6.extra_settings == {"fabric_object": "enable"}

    sslvpn_ipv6 = addresses["SSLVPN_TUNNEL_IPv6_ADDR1"]
    assert sslvpn_ipv6.uuid == "17523864-65a4-51e9-c45e-65c6367ea4e3"
    assert sslvpn_ipv6.ip6 == "fdff:ffff::/120"
    assert sslvpn_ipv6.is_ipv6 is True

    multicast6 = [
        item
        for item in config.addresses
        if item.name == "all" and item.is_multicast
    ][0]
    assert multicast6.ip6 == "ff00::/8"
    assert multicast6.is_ipv6 is True
    assert multicast6.is_multicast is True
    assert multicast6.extra_settings == {"visibility": "enable"}

    wildcard = _by_name(config.wildcard_fqdns)
    assert wildcard["cdn-apple"].uuid == "cccccccc-cccc-cccc-cccc-cccccccccccc"
    assert wildcard["cdn-apple"].extra_settings == {"cache_ttl": "60"}

    multicast = addresses["multicast-test"]
    assert multicast.is_multicast is True
    assert multicast.extra_settings == {"visibility": "enable"}


def test_fortigate_address_transform_preserves_semantics_and_source_metadata():
    ir = FGToIRTransformer(
        parse_fortigate_config(ADDRESS_CONFIG)
    ).transform()
    addresses = _by_name(ir.addresses)
    groups = _by_name(ir.address_groups)

    normal = addresses["normal-net"]
    assert normal.type == AddressType.NETWORK
    assert normal.value == "192.168.10.0/24"
    assert normal.source_uuid == "11111111-1111-1111-1111-111111111111"
    assert normal.associated_interface == "port6"
    assert normal.allow_routing is True
    assert normal.source_color == 9
    assert normal.source_attributes == {
        "cache_ttl": "300",
        "password": "[REDACTED]",
    }

    geo = addresses["geo"]
    assert geo.type == AddressType.GEO
    assert geo.geo_code == "MY"

    missing_geo = addresses["geo-missing-country"]
    assert missing_geo.value == ""
    assert missing_geo.parse_error is not None
    assert missing_geo.requires_manual_review is True
    assert "unknown" not in (missing_geo.raw_value or "")

    ems = groups["ems"]
    assert ems.dynamic_filter == "'Deleum_ADUser'"
    assert ems.source_sub_type == "ems-tag"
    assert ems.source_obj_tag == "Deleum_ADUser"
    assert ems.source_tag_type == "zero_trust"
    assert ems.source_obj_type == "mac"
    assert ems.source_dirty == "clean"

    ipv6 = addresses["ipv6-test"]
    assert ipv6.type == AddressType.NETWORK
    assert ipv6.value == "fdff:ffff::/120"
    assert ipv6.is_ipv6 is True
    assert ipv6.source_uuid == "22222222-2222-2222-2222-222222222222"
    assert ipv6.source_attributes == {"fabric_object": "enable"}

    sslvpn_ipv6 = addresses["SSLVPN_TUNNEL_IPv6_ADDR1"]
    assert sslvpn_ipv6.value == "fdff:ffff::/120"
    assert sslvpn_ipv6.is_ipv6 is True
    assert sslvpn_ipv6.source_uuid == "17523864-65a4-51e9-c45e-65c6367ea4e3"

    assert "all" not in addresses
    assert "none" not in addresses
    audit_messages = "\n".join(
        entry.message for entry in ir.audit_entries
    )
    assert "firewall address6:all" in {
        entry.id for entry in ir.audit_entries
    }
    assert "firewall address6:none" in {
        entry.id for entry in ir.audit_entries
    }
    assert "firewall multicast-address6:all" in {
        entry.id for entry in ir.audit_entries
    }
    assert "ff00::/8" in audit_messages

    cdn_apple = addresses["cdn-apple"]
    assert cdn_apple.value == "*.cdn-apple.com"
    assert cdn_apple.source_uuid == "cccccccc-cccc-cccc-cccc-cccccccccccc"
    assert cdn_apple.source_attributes == {"cache_ttl": "60"}
    assert addresses["google-play"].value == "*play.google.com"

    multicast = addresses["multicast-test"]
    assert multicast.type == AddressType.RANGE
    assert multicast.is_multicast is True
    assert multicast.source_attributes == {"visibility": "enable"}

    mac = addresses["mac-source"]
    assert mac.type == AddressType.MAC
    assert mac.mac == "00:11:22:33:44:55"
    assert mac.value == "00:11:22:33:44:55"
    assert mac.requires_manual_review is False
    assert mac.source_uuid == "33333333-3333-3333-3333-333333333333"
    assert mac.associated_interface == "port7"


def test_fortigate_address_excel_exposes_source_metadata():
    ir = FGToIRTransformer(
        parse_fortigate_config(ADDRESS_CONFIG)
    ).transform()
    workbook = load_workbook(
        io.BytesIO(IRExcelExporter(ir).generate())
    )
    sheet = workbook["Addresses"]
    headers = {
        cell.value: cell.column
        for cell in sheet[3]
    }

    assert list(headers) == [
        "Name",
        "Source UUID",
        "Type",
        "Value",
        "IPv6",
        "Multicast",
        "Associated Interface",
        "Allow Routing",
        "Source Color",
        "EMS Sub-Type",
        "EMS Object Tag",
        "EMS Tag Type",
        "EMS Object Type",
        "EMS Dirty",
        "Tags",
        "Manual Review",
        "Audit Note",
        "Parse Error",
        "Additional Settings",
        "Description",
    ]

    row_by_name = {
        sheet.cell(row, headers["Name"]).value: row
        for row in range(4, sheet.max_row + 1)
    }
    normal_row = row_by_name["normal-net"]
    assert sheet.cell(normal_row, headers["Source UUID"]).value == (
        "11111111-1111-1111-1111-111111111111"
    )
    assert sheet.cell(normal_row, headers["Associated Interface"]).value == "port6"
    assert sheet.cell(normal_row, headers["Allow Routing"]).value == "TRUE"
    assert sheet.cell(normal_row, headers["Source Color"]).value == 9
    assert sheet.cell(normal_row, headers["Additional Settings"]).value == (
        "cache-ttl=300; password=******"
    )

    ipv6_row = row_by_name["ipv6-test"]
    assert sheet.cell(ipv6_row, headers["Value"]).value == "fdff:ffff::/120"
    assert sheet.cell(ipv6_row, headers["IPv6"]).value == "Yes"

    sslvpn_row = row_by_name["SSLVPN_TUNNEL_IPv6_ADDR1"]
    assert sheet.cell(sslvpn_row, headers["Value"]).value == "fdff:ffff::/120"
    assert sheet.cell(sslvpn_row, headers["Source UUID"]).value == (
        "17523864-65a4-51e9-c45e-65c6367ea4e3"
    )
    google_play_row = row_by_name["google-play"]
    assert sheet.cell(google_play_row, headers["Value"]).value == "*play.google.com"

    mac_row = row_by_name["mac-source"]
    assert sheet.cell(mac_row, headers["Type"]).value == "mac"
    assert sheet.cell(mac_row, headers["Value"]).value == "00:11:22:33:44:55"


def test_fortigate_invalid_and_missing_mac_values_are_not_replaced():
    ir = FGToIRTransformer(
        parse_fortigate_config(
            """
config firewall address
    edit "invalid-mac"
        set type mac
        set macaddr "not-a-mac"
    next
    edit "missing-mac"
        set type mac
    next
end
"""
        )
    ).transform()
    addresses = _by_name(ir.addresses)

    invalid = addresses["invalid-mac"]
    assert invalid.type == AddressType.MAC
    assert invalid.value == "not-a-mac"
    assert invalid.requires_manual_review is True
    assert invalid.parse_error is not None

    missing = addresses["missing-mac"]
    assert missing.type == AddressType.MAC
    assert missing.value == ""
    assert missing.requires_manual_review is True
    assert missing.parse_error is not None

    assert all(
        not address.value.startswith(("198.18.", "198.19."))
        for address in (invalid, missing)
    )
