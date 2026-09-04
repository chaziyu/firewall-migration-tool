from io import BytesIO

import pytest

from fwmigrate.parsers.fortigate.parser import (
    parse_fortigate_config,
)
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.transformer import (
    FGToIRTransformer,
)
from fwmigrate.report.excel_exporter import (
    IRExcelExporter,
)


FORTIGATE_CONFIG = """
config system global
    set hostname "FG-DHCP-TEST"
end

config system dhcp server
    edit 1
        set default-gateway 192.168.100.99
        set netmask 255.255.255.0
        set interface "mgmt"
        config ip-range
            edit 1
                set start-ip 192.168.100.110
                set end-ip 192.168.100.210
            next
        end
        set timezone-option default
        set dns-server1 8.8.8.8
    next

    edit 2
        set lease-time 28800
        set default-gateway 10.10.10.1
        set netmask 255.255.254.0
        set interface "port6"
        config ip-range
            edit 1
                set start-ip 10.10.10.50
                set end-ip 10.10.11.250
            next
        end
        config reserved-address
            edit 1
                set ip 10.10.10.58
                set mac bc:d7:13:80:ac:bb
            next
        end
        set dns-server1 8.8.8.8
        set dns-server2 9.9.9.9
    next
end
"""


def test_dhcp_parser():
    fg = parse_fortigate_config(
        FORTIGATE_CONFIG
    )

    assert len(fg.dhcp_servers) == 2

    server = fg.dhcp_servers[1]

    assert server.id == 2
    assert server.interface == "port6"
    assert server.lease_time == 28800
    assert len(server.ip_ranges) == 1
    assert len(server.reserved_addresses) == 1

    assert (
        server.ip_ranges[0].start_ip
        == "10.10.10.50"
    )

    assert (
        server.reserved_addresses[0].mac
        == "bc:d7:13:80:ac:bb"
    )


def test_dhcp_transformer():
    fg = parse_fortigate_config(
        FORTIGATE_CONFIG
    )

    ir = FGToIRTransformer(
        fg
    ).transform()

    assert len(ir.dhcp_servers) == 2

    server = ir.dhcp_servers[1]

    assert server.interface == "port6"
    assert server.lease_time_seconds == 28800

    assert server.dns_servers == [
        "8.8.8.8",
        "9.9.9.9",
    ]

    assert len(server.ip_ranges) == 1
    assert len(server.reservations) == 1


def test_dhcp_excel():
    openpyxl = pytest.importorskip(
        "openpyxl"
    )

    fg = parse_fortigate_config(
        FORTIGATE_CONFIG
    )

    ir = FGToIRTransformer(
        fg
    ).transform()

    workbook_bytes = IRExcelExporter(
        ir
    ).generate()

    workbook = openpyxl.load_workbook(
        BytesIO(workbook_bytes)
    )

    assert "DHCP Servers" in workbook.sheetnames
    assert "DHCP IP Ranges" in workbook.sheetnames
    assert "DHCP Reservations" in workbook.sheetnames

    summary = workbook["Summary"]
    summary_values = {
        summary.cell(row, 1).value: summary.cell(row, 2).value
        for row in range(1, summary.max_row + 1)
    }

    assert summary_values["DHCP Servers"] == 2
    assert summary_values["DHCP IP Ranges"] == 2
    assert summary_values["DHCP Reservations"] == 1

    servers = workbook["DHCP Servers"]
    ranges = workbook["DHCP IP Ranges"]
    reservations = workbook[
        "DHCP Reservations"
    ]

    assert servers["A4"].value == 1
    assert servers["B4"].value == "mgmt"

    assert ranges["D4"].value == "192.168.100.110"
    assert ranges["E4"].value == "192.168.100.210"

    assert reservations["A4"].value == 2
    assert reservations["D4"].value == "10.10.10.58"
    assert (
        reservations["E4"].value
        == "bc:d7:13:80:ac:bb"
    )


def test_dhcp_v4_complete_typed_source_and_ir_mapping():
    config = """
config system dhcp server
    edit 1
        set status disable
        set interface "port1"
        set default-gateway 10.0.0.1
        set netmask 255.255.255.0
        set lease-time 604800
        set auto-configuration enable
        set auto-managed-status enable
        set conflicted-ip-timeout 60
        set ddns-auth tsig
        set ddns-key "ENC DHCP_SECRET"
        set ddns-keyname "dhcp-key"
        set ddns-server-ip 10.0.0.2
        set ddns-ttl 60
        set ddns-update enable
        set ddns-update-override disable
        set ddns-zone "example.test"
        set dhcp-settings-from-fortiipam enable
        set dns-service specify
        set dns-server1 1.1.1.1
        set dns-server2 8.8.8.8
        set dns-server3 9.9.9.9
        set dns-server4 4.4.4.4
        set domain "example.test"
        set filename "bootfile"
        set forticlient-on-net-status enable
        set ip-mode range
        set ipsec-lease-hold 0
        set mac-acl-default-action assign
        set next-server 10.0.0.3
        set ntp-server1 10.0.0.4
        set ntp-service specify
        set relay-agent 10.0.0.5
        set server-type regular
        set shared-subnet disable
        append tftp-server 10.0.0.6
        set timezone "US/Eastern"
        set timezone-option specify
        set vci-match enable
        append vci-string "PXE"
        set wifi-ac-service specify
        set wifi-ac1 10.0.0.7
        set wins-server1 10.0.0.8
        config ip-range
            edit 20
                set start-ip 10.0.0.20
                set end-ip 10.0.0.30
                set lease-time 300
                set uci-match enable
                set uci-string "uci-a"
                set vci-match enable
                set vci-string "vci-a"
            next
        end
        config exclude-range
            edit 10
                set start-ip 10.0.0.10
                set end-ip 10.0.0.12
            next
        end
        config reserved-address
            edit 30
                set action reserved
                set type mac
                set ip 10.0.0.40
                set mac aa:bb:cc:dd:ee:ff
                set description "MAC reservation"
            next
            edit 5
                set type option82
                set circuit-id "circuit"
                set circuit-id-type hex
                set remote-id "remote"
                set remote-id-type string
            next
        end
        config options
            edit 8
                set code 60
                set type string
                set value "PXEClient"
                set uci-match enable
                set uci-string "uci-opt"
                set vci-match enable
                set vci-string "vci-opt"
            next
            edit 2
                set code 66
                set type ip
                set ip 10.0.0.6 10.0.0.7
            next
        end
    next
end
"""
    fg = parse_fortigate_config(config)
    server = fg.dhcp_servers[0]
    assert server.dns_server4 == "4.4.4.4"
    assert server.has_ddns_key and server.ddns_key_format == "encrypted"
    assert server.ddns_keyname == "dhcp-key"
    assert server.tftp_server == ["10.0.0.6"]
    assert server.source_explicit_fields >= {
        "status", "lease_time", "ddns_auth", "ddns_keyname", "dns_server4",
        "vci_match", "vci_string",
    }
    assert server.ip_ranges[0].source_explicit_fields >= {"lease_time", "uci_string"}
    assert [item.id for item in server.reserved_addresses] == [30, 5]
    assert server.options[1].ips == ["10.0.0.6", "10.0.0.7"]
    assert server.options[1].ip is None

    result = extract_fortigate_config(config)
    ir_server = result.canonical_ir.dhcp_servers[0]
    assert ir_server.dns_servers == ["1.1.1.1", "8.8.8.8", "9.9.9.9", "4.4.4.4"]
    assert ir_server.exclude_ranges[0].source_id == 10
    assert ir_server.options[1].ips == ["10.0.0.6", "10.0.0.7"]
    assert ir_server.reservations[1].reservation_type == "option82"
    assert result.generation_safe is False
    assert any("DHCP servers are extract-only" in reason for reason in result.blocking_reasons)
    serialized = result.model_dump_json()
    assert "DHCP_SECRET" not in serialized
    assert "dhcp-key" in serialized


def test_dhcp_defaults_unset_and_malformed_numeric_values_are_safe():
    config = """
config system dhcp server
    edit 1
        set lease-time 300
        unset lease-time
        set status disable
        unset status
        set ntp-service local
        unset ntp-service
        set conflicted-ip-timeout invalid
        config options
            edit 1
                set code invalid
            next
        end
    next
end
"""
    fg = parse_fortigate_config(config)
    server = fg.dhcp_servers[0]
    assert server.lease_time == 604800
    assert server.status == "enable"
    assert server.ntp_service == "specify"
    assert "lease_time" not in server.source_explicit_fields
    assert "status" not in server.source_explicit_fields
    assert "ntp_service" not in server.source_explicit_fields
    assert server.extra_settings["unparsed_conflicted_ip_timeout"] == "invalid"
    assert server.options[0].extra_settings["unparsed_code"] == "invalid"


def test_dhcp_unknown_values_and_malformed_ids_remain_inventory_evidence():
    config = """
config system dhcp server
    edit 1
        set future-parent-value "keep-me"
        config exclude-range
            edit "bad-child-id"
                set future-child-value "keep-child"
            next
        end
    next
    edit "bad-server-id"
        set future-server-value "keep-server"
    next
end
"""
    result = extract_fortigate_config(config)
    assert len(result.canonical_ir.dhcp_servers) == 1
    assert result.canonical_ir.dhcp_servers[0].source_attributes["future_parent_value"] == "keep-me"
    assert any(
        item.name == "bad-server-id"
        and item.source_record_id == "bad-server-id"
        and any("malformed DHCP edit identifier" in note for note in item.notes)
        for item in result.inventory_items
    )
    assert "bad-child-id" in result.model_dump_json()


def test_dhcp_v4_vdom_scope_and_child_order_are_preserved():
    result = extract_fortigate_config("""
config vdom
    edit "blue"
        config system interface
            edit "port1"
            next
        end
        config system dhcp server
            edit 1
                set interface "port1"
                config ip-range
                    edit 9
                    next
                    edit 2
                    next
                end
            next
        end
    next
    edit "green"
        config system interface
            edit "port1"
            next
        end
        config system dhcp server
            edit 1
                set interface "port1"
            next
        end
    next
end
""")

    servers = result.canonical_ir.dhcp_servers
    assert [(server.source_context, server.source_id) for server in servers] == [
        ("blue", 1), ("green", 1)
    ]
    assert [item.source_id for item in servers[0].ip_ranges] == [9, 2]
    assert [item.source_context for item in servers[0].ip_ranges] == ["blue", "blue"]
    assert [
        (dependency.source_context, dependency.reference, dependency.result)
        for dependency in result.dependencies
        if dependency.source_path == "system dhcp server"
    ] == [("blue", "port1", "RESOLVED"), ("green", "port1", "RESOLVED")]


def test_dhcp_v4_invalid_values_are_preserved_and_reviewed():
    result = extract_fortigate_config("""
config system dhcp server
    edit 1
        set default-gateway 999.0.0.1
        set netmask 255.0.255.0
        set lease-time 1
        set conflicted-ip-timeout 1
        set ddns-auth future
        set vci-match future
        config ip-range
            edit 1
                set start-ip 10.0.0.20
                set end-ip 10.0.0.10
                set uci-match enable
            next
        end
        config options
            edit 1
                set code 256
                set type ip
                set ip 999.0.0.1
            next
        end
    next
end
""")

    server = result.canonical_ir.dhcp_servers[0]
    reasons = " ".join(server.review_reasons + server.ip_ranges[0].review_reasons + server.options[0].review_reasons)
    assert server.default_gateway == "999.0.0.1"
    assert server.netmask == "255.0.255.0"
    assert server.options[0].code == 256
    assert "invalid IPv4" in reasons
    assert "invalid contiguous IPv4" in reasons
    assert "outside 300..8640000" in reasons
    assert "outside 60..8640000" in reasons
    assert "unknown value 'future'" in reasons
    assert "start_ip is greater than end_ip" in reasons
    assert "enabled without matching strings" in reasons
    assert "outside 0..255" in reasons
