import io

from openpyxl import load_workbook

from fwmigrate.ir.enums import ServiceProtocol
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer
from fwmigrate.report.excel_exporter import IRExcelExporter


SERVICE_CONFIG = """
config firewall service category
    edit "General"
        set comment "General services."
        set color 1
    next
    edit "Web Access"
    next
    edit "File Access"
    next
    edit "Email"
    next
    edit "Network Services"
    next
    edit "Authentication"
    next
    edit "Remote Access"
    next
    edit "Tunneling"
    next
    edit "VoIP, Messaging & Other Applications"
    next
    edit "Web Proxy"
    next
end
config firewall service custom
    edit "ALL"
        set uuid 00000000-0000-0000-0000-000000000001
        set category "General"
        set protocol IP
    next
    edit "FTP"
        set uuid 00000000-0000-0000-0000-000000000002
        set category "File Access"
        set tcp-portrange 21
        set helper ftp
    next
    edit "DNS"
        set category "Network Services"
        set tcp-portrange 53
        set udp-portrange 53
    next
    edit "KERBEROS"
        set category "Authentication"
        set tcp-portrange 88 464
        set udp-portrange 88 464
    next
    edit "ALL_ICMP"
        set protocol ICMP
    next
    edit "ALL_ICMP6"
        set protocol ICMP6
    next
    edit "GRE"
        set protocol IP
        set protocol-number 47
    next
    edit "PING"
        set protocol ICMP
        set icmptype 8
    next
    edit "PING6"
        set protocol ICMP6
        set icmptype 128
    next
    edit "RLOGIN"
        set tcp-portrange 513:512-1023
    next
    edit "RSH"
        set tcp-portrange 514:512-1023
    next
    edit "NONE"
        set tcp-portrange 0
    next
    edit "webproxy"
        set uuid 00000000-0000-0000-0000-000000000013
        set proxy enable
        set category "Web Proxy"
        set protocol ALL
        set tcp-portrange 0-65535:0-65535
    next
end
config firewall service group
    edit "Web Access"
        set uuid 00000000-0000-0000-0000-000000000014
        set member "DNS" "FTP"
        set color 4
    next
end
"""


def _by_name(items):
    return {item.name: item for item in items}


def test_service_parser_preserves_source_metadata_and_categories():
    parsed = parse_fortigate_config(SERVICE_CONFIG)
    categories = _by_name(parsed.service_categories)
    services = _by_name(parsed.services)
    groups = _by_name(parsed.service_groups)

    assert len(categories) == 10
    assert categories["General"].comment == "General services."
    assert categories["General"].extra_settings == {"color": "1"}
    assert services["FTP"].uuid == "00000000-0000-0000-0000-000000000002"
    assert services["FTP"].category == "File Access"
    assert services["FTP"].extra_settings == {"helper": "ftp"}
    assert services["webproxy"].proxy == "enable"
    assert groups["Web Access"].uuid == "00000000-0000-0000-0000-000000000014"
    assert groups["Web Access"].extra_settings == {"color": "4"}


def test_service_semantics_are_preserved_without_permissive_rewriting():
    ir = FGToIRTransformer(
        parse_fortigate_config(SERVICE_CONFIG)
    ).transform()
    services = _by_name(ir.services)

    assert services["ALL"].ports[0].protocol == ServiceProtocol.ANY
    assert services["ALL"].source_protocol == "IP"

    assert services["FTP"].source_uuid == "00000000-0000-0000-0000-000000000002"
    assert services["FTP"].source_category == "File Access"
    assert services["FTP"].source_protocol == "tcp/udp/sctp"
    assert services["FTP"].ports[0].port == "21"
    assert services["FTP"].source_attributes == {"helper": "ftp"}

    assert {port.protocol for port in services["DNS"].ports} == {
        ServiceProtocol.TCP,
        ServiceProtocol.UDP,
    }
    assert [port.port for port in services["KERBEROS"].ports] == [
        "88", "464", "88", "464"
    ]

    assert services["ALL_ICMP"].ports[0].protocol == ServiceProtocol.ICMP
    assert services["ALL_ICMP6"].ports[0].protocol == ServiceProtocol.ICMPV6
    assert services["GRE"].ports[0].protocol == ServiceProtocol.IP
    assert services["GRE"].ports[0].port == "47"
    assert services["PING"].ports[0].icmptype == 8
    assert services["PING6"].ports[0].protocol == ServiceProtocol.ICMPV6
    assert services["PING6"].ports[0].icmptype == 128

    rlogin = services["RLOGIN"].ports[0]
    assert rlogin.port == "513"
    assert rlogin.source_port == "512-1023"
    assert rlogin.raw_source_value == "513:512-1023"
    rsh = services["RSH"].ports[0]
    assert rsh.port == "514"
    assert rsh.source_port == "512-1023"

    none = services["NONE"]
    assert none.ports[0].port == "0"
    assert none.ports[0].port != "1-65535"
    assert none.requires_manual_review is True
    assert none.migration_status == "PARTIALLY_NORMALIZED"

    webproxy = services["webproxy"]
    assert webproxy.ports[0].port == "0-65535"
    assert webproxy.ports[0].source_port == "0-65535"
    assert webproxy.source_proxy is True
    assert webproxy.source_protocol == "ALL"
    assert webproxy.requires_manual_review is True
    assert webproxy.migration_status == "PARTIALLY_NORMALIZED"

    group = ir.service_groups[0]
    assert group.members == ["DNS", "FTP"]
    assert group.source_uuid == "00000000-0000-0000-0000-000000000014"
    assert group.source_attributes == {"color": "4"}


def test_service_inventory_reaches_excel():
    ir = FGToIRTransformer(
        parse_fortigate_config(SERVICE_CONFIG)
    ).transform()
    workbook = load_workbook(
        io.BytesIO(IRExcelExporter(ir).generate())
    )

    categories = workbook["Service Categories"]
    assert categories.max_row == 13
    assert categories["A4"].value == "General"
    assert categories["C4"].value == "EXTRACT_ONLY"
    assert categories["D4"].value == "color=1"

    services = workbook["Services"]
    headers = {cell.value: cell.column for cell in services[3]}
    rows = {
        services.cell(row, headers["Name"]).value: row
        for row in range(4, services.max_row + 1)
    }

    ftp_row = rows["FTP"]
    assert services.cell(ftp_row, headers["Source UUID"]).value == (
        "00000000-0000-0000-0000-000000000002"
    )
    assert services.cell(ftp_row, headers["Category"]).value == "File Access"
    assert services.cell(ftp_row, headers["Source Protocol"]).value == "tcp/udp/sctp"
    assert services.cell(ftp_row, headers["Protocol / Destination Port"]).value == "tcp/21"

    rlogin_row = rows["RLOGIN"]
    assert services.cell(rlogin_row, headers["Protocol / Destination Port"]).value == "tcp/513"
    assert services.cell(rlogin_row, headers["Source Port Constraint"]).value == "512-1023"

    none_row = rows["NONE"]
    assert services.cell(none_row, headers["Protocol / Destination Port"]).value == "tcp/0"
    assert "1-65535" not in services.cell(none_row, headers["Protocol / Destination Port"]).value

    proxy_row = rows["webproxy"]
    assert services.cell(proxy_row, headers["Protocol / Destination Port"]).value == "tcp/0-65535"
    assert services.cell(proxy_row, headers["Source Port Constraint"]).value == "0-65535"
    assert services.cell(proxy_row, headers["Proxy"]).value == "TRUE"
    assert services.cell(proxy_row, headers["Manual Review"]).value == "TRUE"

    groups = workbook["Service Groups"]
    group_headers = {cell.value: cell.column for cell in groups[3]}
    assert groups.cell(4, group_headers["Source UUID"]).value == (
        "00000000-0000-0000-0000-000000000014"
    )
    assert groups.cell(4, group_headers["Additional Settings"]).value == "color=4"

    summary = {
        workbook["Summary"].cell(row, 1).value:
            workbook["Summary"].cell(row, 2).value
        for row in range(1, workbook["Summary"].max_row + 1)
    }
    assert summary["Service Categories"] == 10


def test_target_generators_do_not_flatten_source_port_or_proxy_semantics():
    from fwmigrate.generators.checkpoint.cli_generator import CheckPointCLIGenerator
    from fwmigrate.generators.cisco_asa.cli_generator import CiscoASACLIGenerator
    from fwmigrate.generators.fortigate.cli_generator import FortiGateCLIGenerator
    from fwmigrate.generators.juniper_srx.cli_generator import JuniperSRXCLIGenerator
    from fwmigrate.generators.palo_alto.terraform_generator import PANOSTerraformGenerator
    from fwmigrate.generators.palo_alto.xml_generator import PANOSXMLGenerator

    ir = FGToIRTransformer(
        parse_fortigate_config(SERVICE_CONFIG)
    ).transform()

    fortigate_output = FortiGateCLIGenerator().generate(ir)[0].content
    assert "set tcp-portrange 513:512-1023" in fortigate_output
    assert "set tcp-portrange 0-65535:0-65535" in fortigate_output
    assert "set proxy enable" in fortigate_output

    for output in (
        CiscoASACLIGenerator().generate(ir),
        CheckPointCLIGenerator().generate(ir),
        JuniperSRXCLIGenerator().generate(ir),
    ):
        assert "Service RLOGIN withheld" in output
        assert "Service webproxy withheld" in output

    panos_xml = PANOSXMLGenerator().generate(ir)[0].content
    assert '<entry name="RLOGIN">' not in panos_xml
    assert '<entry name="webproxy">' not in panos_xml

    panos_tf = "\n".join(
        artifact.content
        for artifact in PANOSTerraformGenerator().generate(ir)
    )
    assert "Service RLOGIN withheld" in panos_tf
    assert "Service webproxy withheld" in panos_tf
