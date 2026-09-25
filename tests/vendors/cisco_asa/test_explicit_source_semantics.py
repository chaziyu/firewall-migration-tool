from io import BytesIO

from openpyxl import load_workbook

from fwmigrate.vendors.cisco_asa.export.excel import export_asa_excel
from fwmigrate.vendors.cisco_asa.source_report import extract_cisco_asa_source

from .helpers import assert_source_unchanged, snapshot_source


def test_absent_and_explicit_no_interface_values_survive_all_report_stages():
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
    before = snapshot_source(result.config)

    output = BytesIO()
    export_asa_excel(result, output)

    assert_source_unchanged(result.config, before)
    workbook = load_workbook(BytesIO(output.getvalue()), read_only=True)
    assert workbook["Routes"]["A2"].value == "outside"


def test_null0_route_keeps_gateway_absent():
    route = extract_cisco_asa_source("route null0 192.168.2.0 255.255.255.0\n").config.static_routes[0]
    assert (route.interface, route.destination, route.mask, route.gateway) == (
        "null0", "192.168.2.0", "255.255.255.0", None
    )
    assert "gateway" not in route.explicit_fields


def test_nat_optional_flags_distinguish_absent_from_explicit():
    result = extract_cisco_asa_source(
        "nat (inside,outside) source static 10.0.0.1 192.0.2.1\n"
        "nat (inside,outside) source static 10.0.0.2 192.0.2.2 dns no-proxy-arp route-lookup unidirectional inactive\n"
    )
    absent, explicit = result.config.nat_rules
    for field in ("dns", "no_proxy_arp", "route_lookup", "unidirectional", "inactive"):
        assert getattr(absent, field) is False and field not in absent.explicit_fields
        assert getattr(explicit, field) is True and field in explicit.explicit_fields
