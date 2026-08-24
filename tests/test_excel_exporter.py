import io

from openpyxl import load_workbook

from fwmigrate.ir.core import (
    IRAddress,
    IRAddressGroup,
    IRAuditEntry,
    IRConfig,
    IRInterface,
    IRMetadata,
    IRNATRule,
    IRPolicy,
    IRRoute,
    IRSecurityProfileGroup,
    IRService,
    IRServiceGroup,
    IRServicePort,
    IRVPNTunnel,
    IRZone,
)
from fwmigrate.ir.enums import (
    AddressType,
    MigrationConfidence,
    NATType,
    PolicyAction,
    ServiceProtocol,
)
from fwmigrate.report.excel_exporter import IRExcelExporter
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer


def _sample_ir() -> IRConfig:
    return IRConfig(
        metadata=IRMetadata(
            hostname="HQ-FW-東京",
            source_vendor="fortigate",
            input_type="Configuration File",
            source_version="7.4.x",
            source_context="root",
        ),
        interfaces=[IRInterface(name="port1", zone="trust", ip="10.0.0.1/24")],
        zones=[IRZone(name="trust", interfaces=["port1"])],
        addresses=[
            IRAddress(name="Users", type=AddressType.NETWORK, subnet="10.0.0.0/24"),
            IRAddress(
                name="=HYPERLINK(\"https://invalid.example\")",
                type=AddressType.FQDN,
                fqdn="app.example.test",
                description="Unicode ✓ " + ("x" * 40000),
            ),
        ],
        address_groups=[IRAddressGroup(name="User Group", members=["Users", "Remote Users"])],
        services=[
            IRService(
                name="Web",
                ports=[
                    IRServicePort(protocol=ServiceProtocol.TCP, port="443"),
                    IRServicePort(protocol=ServiceProtocol.UDP, port="443"),
                ],
            )
        ],
        service_groups=[IRServiceGroup(name="Web Group", members=["Web"])],
        policies=[
            IRPolicy(
                name="Allow-Web",
                from_zone=["trust"],
                to_zone=["untrust"],
                source=["Users", "Remote Users"],
                destination=["any"],
                service=["Web"],
                action=PolicyAction.ALLOW,
            )
        ],
        nat_rules=[
            IRNATRule(
                name="Outbound-NAT",
                type=NATType.SOURCE,
                source=["Users"],
                destination=["any"],
                translated_source="203.0.113.10",
            )
        ],
        vpn_tunnels=[
            IRVPNTunnel(
                name="VPN-HQ",
                peer_address="192.0.2.1",
                local_interface="port1",
                psk="do-not-export-this-secret",
            )
        ],
        routes=[IRRoute(name="default", destination="0.0.0.0/0", next_hop="10.0.0.254")],
        security_profile_groups=[IRSecurityProfileGroup(name="strict", antivirus="default")],
        audit_entries=[
            IRAuditEntry(
                id="warn-1",
                category="Reference",
                message="Unresolved object requires review",
                confidence=MigrationConfidence.PARTIAL,
            ),
            IRAuditEntry(
                id="unsupported-1",
                category="router bgp",
                message="No IR mapping implemented; token=super-secret-value",
                confidence=MigrationConfidence.UNSUPPORTED,
            ),
        ],
    )


def test_excel_exporter_generates_complete_safe_workbook():
    workbook_bytes = IRExcelExporter(_sample_ir()).generate()
    workbook = load_workbook(io.BytesIO(workbook_bytes), data_only=False)

    assert workbook.sheetnames == list(IRExcelExporter.SHEET_ORDER)
    assert workbook["Addresses"].max_row == 5  # title, note, header, and exactly two objects
    assert workbook["Addresses"]["A4"].value == "Users"
    assert workbook["Addresses"]["A5"].value.startswith("'")
    assert workbook["Addresses"]["A5"].data_type == "s"
    assert len(workbook["Addresses"]["J5"].value) <= 32767
    assert workbook["Address Groups"]["B4"].value == "Users\nRemote Users"
    assert workbook["Policies"]["E4"].value == "Users\nRemote Users"
    assert workbook["VPN Tunnels"]["E4"].value == "Configured / Redacted"
    assert workbook["Extraction Coverage"]["A4"].value == "Interfaces"

    all_text = "\n".join(
        str(cell.value)
        for sheet in workbook.worksheets
        for row in sheet.iter_rows()
        for cell in row
        if cell.value is not None
    )
    assert "do-not-export-this-secret" not in all_text
    assert "super-secret-value" not in all_text
    assert "HQ-FW-東京" in all_text


def test_excel_exporter_marks_missing_parser_coverage_as_unknown():
    ir = IRConfig(metadata=IRMetadata(hostname="minimal", source_vendor="juniper_srx"))
    workbook = load_workbook(io.BytesIO(IRExcelExporter(ir).generate()))
    coverage = workbook["Extraction Coverage"]

    assert coverage["D4"].value == "Not reported"
    assert coverage["E4"].value == "Empty / unknown"
    assert "awaits ExtractionResult" in coverage["F4"].value


def test_fortigate_interface_source_settings_are_exported():
    config = """
config system interface
    edit "x1"
        set vdom "root"
        set mode dhcp
        set allowaccess ping
        set type physical
        set lldp-reception disable
        set role wan
        set snmp-index 3
    next
end
    """
    ir = FGToIRTransformer(parse_fortigate_config(config)).transform()
    workbook = load_workbook(io.BytesIO(IRExcelExporter(ir).generate()))

    interfaces = workbook["Interfaces"]
    headers = {cell.value: cell.column for cell in interfaces[3]}
    assert interfaces.cell(4, headers["Name"]).value == "x1"
    assert interfaces.cell(4, headers["Source VDOM"]).value == "root"
    assert interfaces.cell(4, headers["Interface Type"]).value == "physical"
    assert interfaces.cell(4, headers["Role"]).value == "wan"
    assert interfaces.cell(4, headers["Addressing Mode"]).value == "dhcp"
    assert interfaces.cell(4, headers["DHCP Client"]).value == "Yes"
    assert interfaces.cell(4, headers["Management Access"]).value == "ping"

    settings = workbook["Interface Source Settings"]
    extracted = {
        settings.cell(row, 3).value: settings.cell(row, 4).value
        for row in range(4, settings.max_row + 1)
    }
    assert extracted["lldp-reception"] == "disable"
    assert extracted["snmp-index"] == "3"
