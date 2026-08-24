import io

from openpyxl import load_workbook

from fwmigrate.ir.core import (
    IRAddress,
    IRAddressGroup,
    IRAuditEntry,
    IRConfig,
    IRInterface,
    IRIPPool,
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
                source_rule_id="25",
                source_uuid="0819b852-ebb4-51eb-210e-517744c1e41b",
                source_from_interfaces=["LAN"],
                source_to_interfaces=["WAN"],
                source_log_setting="all",
                nat_enabled=True,
                nat_pool_enabled=True,
                nat_pool_names=["PUBLIC_POOL"],
                from_zone=["trust"],
                to_zone=["untrust"],
                source=["Users", "Remote Users"],
                destination=["any"],
                service=["Web"],
                action=PolicyAction.ALLOW,
            )
        ],
        ip_pools=[
            IRIPPool(
                name="PUBLIC_POOL",
                pool_type="overload",
                start_ip="203.0.113.10",
                end_ip="203.0.113.20",
                associated_interface="wan1",
                arp_reply=True,
                permit_any_host=False,
                excluded_ips=["203.0.113.11", "203.0.113.12"],
                description="Internet SNAT pool",
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
    assert workbook["Policies"]["I4"].value == "Users\nRemote Users"
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


def test_excel_exporter_exposes_source_policy_audit_fields():
    workbook = load_workbook(io.BytesIO(IRExcelExporter(_sample_ir()).generate()))
    policies = workbook["Policies"]

    assert [cell.value for cell in policies[3]] == [
        "Rule #", "Source Policy ID", "Source UUID", "Name", "Source Interface", "From Zone",
        "Destination Interface", "To Zone", "Source", "Destination", "Service",
        "Action", "Schedule", "Disabled", "Log Setting", "Log Start", "Log End",
        "NAT Enabled", "IP Pool Enabled", "NAT Pool", "Applications",
        "Internet Services", "Security Profile Group", "Antivirus", "IPS Sensor",
        "Web Filter", "Application List", "SSL/SSH Profile", "Description",
    ]
    assert policies["A4"].value == 1
    assert policies["B4"].value == "25"
    assert policies["C4"].value == "0819b852-ebb4-51eb-210e-517744c1e41b"
    assert policies["E4"].value == "LAN"
    assert policies["G4"].value == "WAN"
    assert policies["O4"].value == "all"
    assert policies["R4"].value == "TRUE"
    assert policies["S4"].value == "TRUE"
    assert policies["T4"].value == "PUBLIC_POOL"


def test_excel_exporter_includes_ip_pool_inventory_and_existing_nat_output():
    workbook = load_workbook(io.BytesIO(IRExcelExporter(_sample_ir()).generate()))
    pools = workbook["IP Pools"]

    assert [cell.value for cell in pools[3]] == [
        "Name", "Type", "Start IP", "End IP", "Source Start IP",
        "Source End IP", "Start Port", "End Port", "Associated Interface",
        "ARP Reply", "ARP Interface", "Permit Any Host", "Excluded IPs",
        "Block Size", "Blocks Per User", "PBA Timeout", "Ports Per User",
        "NAT64", "TCP Session Quota", "UDP Session Quota",
        "ICMP Session Quota", "Description",
    ]
    assert pools["A4"].value == "PUBLIC_POOL"
    assert pools["B4"].value == "overload"
    assert pools["C4"].value == "203.0.113.10"
    assert pools["D4"].value == "203.0.113.20"
    assert pools["I4"].value == "wan1"
    assert pools["J4"].value == "TRUE"
    assert pools["L4"].value == "FALSE"
    assert pools["M4"].value == "203.0.113.11\n203.0.113.12"
    assert pools["V4"].value == "Internet SNAT pool"

    summary_counts = {
        workbook["Summary"].cell(row, 1).value: workbook["Summary"].cell(row, 2).value
        for row in range(1, workbook["Summary"].max_row + 1)
    }
    assert summary_counts["IP Pools"] == 1

    coverage_rows = {
        workbook["Extraction Coverage"].cell(row, 1).value:
            workbook["Extraction Coverage"].cell(row, 3).value
        for row in range(4, workbook["Extraction Coverage"].max_row + 1)
    }
    assert coverage_rows["IP Pools"] == 1
    assert workbook["NAT Rules"]["A4"].value == "Outbound-NAT"
    assert workbook["NAT Rules"]["H4"].value == "203.0.113.10"


def test_excel_exporter_marks_missing_parser_coverage_as_unknown():
    ir = IRConfig(metadata=IRMetadata(hostname="minimal", source_vendor="juniper_srx"))
    workbook = load_workbook(io.BytesIO(IRExcelExporter(ir).generate()))
    coverage = workbook["Extraction Coverage"]

    assert coverage["D4"].value == "Not reported"
    assert coverage["E4"].value == "Empty / unknown"
    assert "awaits ExtractionResult" in coverage["F4"].value
