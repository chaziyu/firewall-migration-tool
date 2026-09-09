from io import BytesIO

import pytest

from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer
from fwmigrate.report.excel_exporter import IRExcelExporter


def _parse_interface(vrf_line=None):
    setting = f"        set vrf {vrf_line}\n" if vrf_line is not None else ""
    return parse_fortigate_config(
        """
config system interface
    edit "port1"
        set ip 192.0.2.1 255.255.255.0
"""
        + setting
        + """    next
end
"""
    )


def _transform_interface(vrf_line=None):
    return FGToIRTransformer(_parse_interface(vrf_line)).transform()


@pytest.mark.parametrize("vrf, expected", [("0", 0), ("10", 10)])
def test_parser_typed_interface_vrf(vrf, expected):
    parsed = _parse_interface(vrf)

    interface = parsed.interfaces[0]
    assert interface.vrf == expected
    assert isinstance(interface.vrf, int)
    assert interface.source_attributes["vrf"] == expected


def test_parser_omitted_interface_vrf_remains_unset():
    interface = _parse_interface().interfaces[0]

    assert interface.vrf is None
    assert "vrf" not in interface.source_attributes


def test_transformer_default_interface_vrf_is_preserved_without_vrf_review():
    interface = _transform_interface("0").interfaces[0]

    assert interface.source_vrf == 0
    assert interface.migration_status == "NORMALIZED"
    assert interface.requires_manual_review is False
    assert not any("VRF" in reason for reason in interface.review_reasons)


def test_transformer_non_default_interface_vrf_requires_review():
    interface = _transform_interface("10").interfaces[0]

    assert interface.source_vrf == 10
    assert interface.migration_status == "PARTIALLY_NORMALIZED"
    assert interface.requires_manual_review is True
    assert (
        "FortiGate interface uses non-default VRF and requires routing-instance "
        "migration review"
    ) in interface.review_reasons


def test_malformed_interface_vrf_is_preserved_and_does_not_crash():
    parsed = _parse_interface("not-an-integer")
    source_interface = parsed.interfaces[0]

    assert source_interface.vrf is None
    assert source_interface.source_attributes["unparsed_vrf"] == "not-an-integer"

    interface = FGToIRTransformer(parsed).transform().interfaces[0]
    assert interface.source_vrf is None
    assert interface.migration_status == "PARTIALLY_NORMALIZED"
    assert interface.requires_manual_review is True
    assert any("could not be parsed as an integer" in reason for reason in interface.review_reasons)
    assert any(error.startswith("vrf:") for error in interface.parse_errors)


def test_out_of_range_interface_vrf_is_preserved_and_requires_review():
    interface = _transform_interface("300").interfaces[0]

    assert interface.source_vrf == 300
    assert interface.requires_manual_review is True
    assert interface.migration_status == "PARTIALLY_NORMALIZED"
    assert any("outside the valid range 0-251" in reason for reason in interface.review_reasons)


def test_interface_and_route_vrf_values_remain_separately_preserved():
    ir = FGToIRTransformer(
        parse_fortigate_config(
            """
config system interface
    edit "port1"
        set vrf 10
    next
end
config router static
    edit 1
        set dst 198.51.100.0 255.255.255.0
        set device "port1"
        set vrf 10
    next
end
"""
        )
    ).transform()

    assert ir.interfaces[0].source_vrf == 10
    assert ir.routes[0].vrf == 10
    assert ir.routes[0].interface == "port1"


def test_excel_interfaces_expose_vrf_column():
    openpyxl = pytest.importorskip("openpyxl")
    workbook = openpyxl.load_workbook(
        BytesIO(IRExcelExporter(_transform_interface("10")).generate())
    )

    interfaces = workbook["Interfaces"]
    headers = {cell.value: cell.column for cell in interfaces[3]}
    assert "VRF" in headers
    assert interfaces.cell(4, headers["VRF"]).value == 10
