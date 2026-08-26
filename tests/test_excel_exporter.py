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
    IRServiceCategory,
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
from fwmigrate.ir.version import IR_SCHEMA_VERSION
from fwmigrate.report.excel_exporter import IRExcelExporter
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config


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
        address_groups=[
            IRAddressGroup(
                name="User Group",
                members=["Users", "Remote Users"],
                source_uuid="address-group-uuid",
                allow_routing=True,
                source_color=25,
                source_category="ztna-ems-tag",
                source_attributes={"visibility": "enable"},
            )
        ],
        service_categories=[
            IRServiceCategory(
                name="Web Access",
                description="Web access.",
                source_attributes={"color": "1"},
            )
        ],
        services=[
            IRService(
                name="Web",
                source_uuid="service-uuid",
                source_category="Web Access",
                source_protocol="tcp/udp/sctp",
                ports=[
                    IRServicePort(
                        protocol=ServiceProtocol.TCP,
                        port="443",
                        source_port="1024-65535",
                        raw_source_value="443:1024-65535",
                    ),
                    IRServicePort(protocol=ServiceProtocol.UDP, port="443"),
                ],
                source_proxy=False,
                source_attributes={"helper": "https"},
            )
        ],
        service_groups=[
            IRServiceGroup(
                name="Web Group",
                members=["Web"],
                source_uuid="service-group-uuid",
                source_attributes={"color": "4"},
            )
        ],
        policies=[
            IRPolicy(
                name="Allow-Web",
                source_rule_id="25",
                source_uuid="0819b852-ebb4-51eb-210e-517744c1e41b",
                source_from_interfaces=["LAN"],
                source_to_interfaces=["WAN"],
                source_user_groups=["SSLVPN Users", "Domain_Users"],
                source_users=["alice", "bob.smith"],
                source_log_setting="all",
                source_inspection_mode="proxy",
                source_ztna_status="enable",
                source_ztna_ems_tags=["TAG_A", "TAG B"],
                source_extra_settings={
                    "timeout_send_rst": "enable",
                    "port_preserve": "disable",
                },
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
                type=NATType.TWICE,
                source_policy_reference="25",
                source_policy_uuid="nat-policy-uuid",
                enabled=False,
                source_from_interfaces=["LAN"],
                source_to_interfaces=["WAN"],
                from_zone=["trust"],
                to_zone=["untrust"],
                source=["Users"],
                destination=["any"],
                services=["Web", "HTTPS"],
                internet_services=["Microsoft-Office365"],
                source_translation_mode="pool",
                source_pool_references=["PUBLIC_POOL"],
                translated_sources=["203.0.113.10"],
                source_vip_reference="VIP_WEB",
                source_vip_group_reference="VIP_GROUP",
                translated_destinations=["10.0.0.10"],
                original_destination_port="8443",
                translated_port="443",
                requires_manual_review=True,
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
    address_headers = {
        cell.value: cell.column
        for cell in workbook["Addresses"][3]
    }
    assert len(
        workbook["Addresses"].cell(
            5,
            address_headers["Description"],
        ).value
    ) <= 32767
    assert workbook["Address Groups"]["C4"].value == "Users\nRemote Users"
    assert workbook["Address Groups"]["B4"].value == "address-group-uuid"
    assert workbook["Service Categories"]["A4"].value == "Web Access"
    services = workbook["Services"]
    service_headers = {cell.value: cell.column for cell in services[3]}
    assert services.cell(4, service_headers["Source UUID"]).value == "service-uuid"
    assert services.cell(4, service_headers["Category"]).value == "Web Access"
    assert services.cell(4, service_headers["Source Port Constraint"]).value == "1024-65535"
    assert services.cell(4, service_headers["Additional Settings"]).value == "helper=https"
    service_groups = workbook["Service Groups"]
    group_headers = {cell.value: cell.column for cell in service_groups[3]}
    assert service_groups.cell(4, group_headers["Source UUID"]).value == "service-group-uuid"
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
        "Destination Interface", "To Zone", "Source", "Destination", "User Groups", "Users", "Service",
        "Action", "Schedule", "Disabled", "Log Setting", "Log Start", "Log End",
        "NAT Enabled", "IP Pool Enabled", "NAT Pool", "Applications",
        "Internet Services", "Security Profile Group", "Antivirus", "IPS Sensor",
        "Web Filter", "Application List", "SSL/SSH Profile", "Inspection Mode",
        "ZTNA Status", "ZTNA EMS Tags", "Additional Settings", "Description",
    ]
    assert policies["A4"].value == 1
    assert policies["B4"].value == "25"
    assert policies["C4"].value == "0819b852-ebb4-51eb-210e-517744c1e41b"
    assert policies["E4"].value == "LAN"
    assert policies["G4"].value == "WAN"
    assert policies["K4"].value == "SSLVPN Users\nDomain_Users"
    assert policies["L4"].value == "alice\nbob.smith"
    assert policies["Q4"].value == "all"
    assert policies["T4"].value == "TRUE"
    assert policies["U4"].value == "TRUE"
    assert policies["V4"].value == "PUBLIC_POOL"
    headers = {cell.value: cell.column for cell in policies[3]}
    assert policies.cell(4, headers["Inspection Mode"]).value == "proxy"
    assert policies.cell(4, headers["ZTNA Status"]).value == "enable"
    assert policies.cell(4, headers["ZTNA EMS Tags"]).value == "TAG_A\nTAG B"
    additional = policies.cell(4, headers["Additional Settings"]).value
    assert "timeout-send-rst=enable" in additional
    assert "port-preserve=disable" in additional


def test_excel_exporter_leaves_empty_policy_identity_selectors_blank():
    ir = IRConfig(
        metadata=IRMetadata(hostname="minimal", source_vendor="fortigate"),
        policies=[IRPolicy(name="No_Identity", action=PolicyAction.DENY)],
    )
    workbook = load_workbook(io.BytesIO(IRExcelExporter(ir).generate()))

    assert workbook["Policies"]["K4"].value is None
    assert workbook["Policies"]["L4"].value is None


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
    assert summary_counts["IR Schema Version"] == IR_SCHEMA_VERSION

    coverage_rows = {
        workbook["Extraction Coverage"].cell(row, 1).value:
            workbook["Extraction Coverage"].cell(row, 3).value
        for row in range(4, workbook["Extraction Coverage"].max_row + 1)
    }
    assert coverage_rows["IP Pools"] == 1
    nat_rules = workbook["NAT Rules"]
    assert [cell.value for cell in nat_rules[3]] == [
        "Rule #", "Name", "Type", "Source Policy ID", "Source Policy UUID",
        "Enabled", "Source Interface", "From Zone", "Destination Interface",
        "To Zone", "Original Source", "Original Destination", "Services",
        "Internet Services", "Source Translation Mode", "IP Pool",
        "Translated Source", "VIP", "VIP Group", "Translated Destination",
        "Original Destination Port", "Translated Port", "Manual Review", "Description",
    ]
    headers = {cell.value: cell.column for cell in nat_rules[3]}
    assert nat_rules.cell(4, headers["Name"]).value == "Outbound-NAT"
    assert nat_rules.cell(4, headers["Source Policy ID"]).value == "25"
    assert nat_rules.cell(4, headers["Source Policy UUID"]).value == "nat-policy-uuid"
    assert nat_rules.cell(4, headers["Enabled"]).value == "FALSE"
    assert nat_rules.cell(4, headers["Source Interface"]).value == "LAN"
    assert nat_rules.cell(4, headers["Destination Interface"]).value == "WAN"
    assert nat_rules.cell(4, headers["Services"]).value == "Web\nHTTPS"
    assert nat_rules.cell(4, headers["Internet Services"]).value == "Microsoft-Office365"
    assert nat_rules.cell(4, headers["Source Translation Mode"]).value == "pool"
    assert nat_rules.cell(4, headers["IP Pool"]).value == "PUBLIC_POOL"
    assert nat_rules.cell(4, headers["Translated Source"]).value == "203.0.113.10"
    assert nat_rules.cell(4, headers["VIP"]).value == "VIP_WEB"
    assert nat_rules.cell(4, headers["VIP Group"]).value == "VIP_GROUP"
    assert nat_rules.cell(4, headers["Translated Destination"]).value == "10.0.0.10"
    assert nat_rules.cell(4, headers["Translated Port"]).value == "443"
    assert nat_rules.cell(4, headers["Manual Review"]).value == "TRUE"


def test_excel_exporter_marks_missing_parser_coverage_as_unknown():
    ir = IRConfig(metadata=IRMetadata(hostname="minimal", source_vendor="juniper_srx"))
    workbook = load_workbook(io.BytesIO(IRExcelExporter(ir).generate()))
    coverage = workbook["Extraction Coverage"]

    assert coverage["D4"].value == "Not reported"
    assert coverage["E4"].value == "Empty / unknown"
    assert "awaits ExtractionResult" in coverage["F4"].value


def test_excel_exporter_uses_extraction_result_source_evidence():
    config = """config application list
    edit "inventory-only"
        set comment "retained"
    next
end
config switch-controller global
end
config system unknown-feature
    edit "x"
    next
end
"""
    extraction = extract_fortigate_config(config)
    workbook = load_workbook(
        io.BytesIO(
            IRExcelExporter(
                extraction.canonical_ir,
                extraction_result=extraction,
            ).generate()
        )
    )

    coverage = workbook["Extraction Coverage"]
    headers = {cell.value: cell.column for cell in coverage[3]}
    rows = {
        coverage.cell(row, headers["Source Section"]).value: row
        for row in range(4, coverage.max_row + 1)
    }
    assert coverage.cell(
        rows["application list"], headers["Status"]
    ).value == "EXTRACT_ONLY"
    assert coverage.cell(
        rows["switch-controller global"], headers["Status"]
    ).value == "IGNORED_BY_POLICY"
    assert coverage.cell(
        rows["system unknown-feature"], headers["Status"]
    ).value == "UNSUPPORTED"
    assert coverage.cell(
        rows["system unknown-feature"], headers["Line Start"]
    ).value == 8
    assert "unavailable" not in coverage["A2"].value

    unsupported = workbook["Unsupported"]
    assert unsupported["A4"].value == "system unknown-feature"
    assert unsupported["C4"].value == "UNSUPPORTED"
    assert unsupported["E4"].value == "Yes"


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


def test_fortigate_tunnel_remote_ip_is_exported_with_source_evidence():
    config = """
config system interface
    edit "Tunnel_With_IP"
        set vdom "root"
        set ip 10.255.0.1 255.255.255.255
        set type tunnel
        set remote-ip 10.255.0.2 255.255.255.255
        set interface "port1"
    next
    edit "Tunnel_No_IP"
        set type tunnel
        set interface "port1"
    next
end
    """
    ir = FGToIRTransformer(parse_fortigate_config(config)).transform()
    workbook = load_workbook(io.BytesIO(IRExcelExporter(ir).generate()))

    interfaces = workbook["Interfaces"]
    headers = {cell.value: cell.column for cell in interfaces[3]}
    rows = {
        interfaces.cell(row, headers["Name"]).value: row
        for row in range(4, interfaces.max_row + 1)
    }

    with_ip_row = rows["Tunnel_With_IP"]
    assert interfaces.cell(with_ip_row, headers["IP / Prefix"]).value == "10.255.0.1/32"
    assert interfaces.cell(with_ip_row, headers["Remote IP / Prefix"]).value == "10.255.0.2/32"
    assert interfaces.cell(with_ip_row, headers["Interface Type"]).value == "tunnel"
    assert interfaces.cell(
        with_ip_row, headers["Parent / Underlay Interface"]
    ).value == "port1"

    no_ip_row = rows["Tunnel_No_IP"]
    assert interfaces.cell(no_ip_row, headers["IP / Prefix"]).value is None
    assert interfaces.cell(no_ip_row, headers["Remote IP / Prefix"]).value is None
    assert interfaces.cell(no_ip_row, headers["Interface Type"]).value == "tunnel"
    assert interfaces.cell(
        no_ip_row, headers["Parent / Underlay Interface"]
    ).value == "port1"

    settings = workbook["Interface Source Settings"]
    remote_ip_rows = [
        row for row in range(4, settings.max_row + 1)
        if settings.cell(row, 1).value == "Tunnel_With_IP"
        and settings.cell(row, 3).value == "remote-ip"
    ]
    assert len(remote_ip_rows) == 1
    remote_ip_row = remote_ip_rows[0]
    assert settings.cell(remote_ip_row, 4).value == "10.255.0.2 255.255.255.255"
    assert settings.cell(remote_ip_row, 5).value == "EXTRACT_ONLY"


def test_unresolved_interface_zone_exports_as_blank():
    ir = IRConfig(
        metadata=IRMetadata(hostname="edge-fw", source_vendor="fortigate"),
        interfaces=[IRInterface(name="port1", role="wan", zone=None)],
    )
    workbook = load_workbook(io.BytesIO(IRExcelExporter(ir).generate()))
    interfaces = workbook["Interfaces"]
    headers = {cell.value: cell.column for cell in interfaces[3]}

    assert interfaces.cell(4, headers["Name"]).value == "port1"
    assert interfaces.cell(4, headers["Zone"]).value is None
    assert interfaces.cell(4, headers["Role"]).value == "wan"


def test_invalid_route_source_and_parse_error_are_visible_in_excel():
    ir = IRConfig(
        metadata=IRMetadata(hostname="edge-fw", source_vendor="fortigate"),
        routes=[
            IRRoute(
                name="route_20",
                destination=None,
                source_destination="10.20.30.0 255.0.255.0",
                next_hop="192.0.2.1",
                requires_manual_review=True,
                parse_error="Invalid IPv4 network",
                source_attributes={"priority": "7"},
            )
        ],
    )
    workbook = load_workbook(io.BytesIO(IRExcelExporter(ir).generate()))
    routes = workbook["Routes"]
    headers = {cell.value: cell.column for cell in routes[3]}

    assert routes.cell(4, headers["Destination"]).value is None
    assert routes.cell(4, headers["Source Destination"]).value == (
        "10.20.30.0 255.0.255.0"
    )
    assert routes.cell(4, headers["Manual Review"]).value == "Yes"
    assert routes.cell(4, headers["Parse Error"]).value == "Invalid IPv4 network"


def test_route_excel_keeps_administrative_distance_separate_from_metric():
    ir = IRConfig(
        metadata=IRMetadata(hostname="edge-fw", source_vendor="fortigate"),
        routes=[
            IRRoute(
                name="route_10",
                source_route_id=10,
                destination="10.10.0.0/16",
                source_destination="10.10.0.0 255.255.0.0",
                administrative_distance=5,
                metric=None,
                priority=20,
                blackhole=False,
                enabled=False,
                sdwan_zone="virtual-wan-link",
            )
        ],
    )
    workbook = load_workbook(io.BytesIO(IRExcelExporter(ir).generate()))
    routes = workbook["Routes"]
    headers = {cell.value: cell.column for cell in routes[3]}

    assert routes.cell(4, headers["Source Route ID"]).value == 10
    assert routes.cell(4, headers["Administrative Distance"]).value == 5
    assert routes.cell(4, headers["Metric"]).value is None
    assert routes.cell(4, headers["Priority"]).value == 20
    assert routes.cell(4, headers["Blackhole"]).value == "No"
    assert routes.cell(4, headers["Enabled"]).value == "No"
    assert routes.cell(4, headers["SD-WAN Zone"]).value == "virtual-wan-link"
    assert routes.cell(4, headers["Migration Status"]).value == "NORMALIZED"
