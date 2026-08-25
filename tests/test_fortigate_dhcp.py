from io import BytesIO

import pytest

from fwmigrate.parsers.fortigate.parser import (
    parse_fortigate_config,
)
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