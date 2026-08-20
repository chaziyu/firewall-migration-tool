import pytest
from pathlib import Path
from click.testing import CliRunner

from fwmigrate.ir.core import (
    IRConfig, IRMetadata, IRZone, IRInterface, IRAddress, AddressType,
    IRAddressGroup, IRService, IRServicePort, ServiceProtocol, IRServiceGroup,
    IRPolicy, PolicyAction, IRNATRule, NATType, IRRoute
)
from fwmigrate.generators.palo_alto.terraform_generator import PANOSTerraformGenerator
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer
from fwmigrate.main import cli


def test_sanitize_names():
    gen = PANOSTerraformGenerator()
    
    # Terraform identifier sanitization
    assert gen.sanitize_tf_name("10.0.0.1/24") == "obj_10_0_0_1_24"
    assert gen.sanitize_tf_name("Web-Server_DMZ") == "Web-Server_DMZ"
    assert gen.sanitize_tf_name("my service / port 80") == "my_service___port_80"
    assert gen.sanitize_tf_name("___") == "unnamed"
    assert gen.sanitize_tf_name("") == "unnamed"
    
    # PAN-OS object name sanitization (max 63 chars, alphanumeric start)
    assert gen.sanitize_panos_name("_hidden_obj") == "o_hidden_obj"
    assert gen.sanitize_panos_name("normal-name.123_456") == "normal-name.123_456"
    assert len(gen.sanitize_panos_name("a" * 100)) == 63
    assert gen.sanitize_panos_name("") == "unnamed"


def test_address_objects_generation():
    ir = IRConfig(
        metadata=IRMetadata(hostname="fw-test"),
        addresses=[
            IRAddress(name="LAN_Subnet", type=AddressType.NETWORK, value="192.168.1.0/24", description="Internal LAN"),
            IRAddress(name="DHCP_Pool", type=AddressType.RANGE, value="10.0.0.100-10.0.0.200"),
            IRAddress(name="Web_FQDN", type=AddressType.FQDN, value="api.example.com"),
            IRAddress(name="Wildcard_Web", type=AddressType.WILDCARD_FQDN, value="*.example.com"),
            IRAddress(name="EMS_Tag", type=AddressType.DYNAMIC, value="ems-tag-1")
        ]
    )

    gen = PANOSTerraformGenerator()
    artifacts = gen.generate(ir)
    
    main_tf = next(a.content for a in artifacts if a.filename == "main.tf")
    
    assert 'resource "panos_address_object" "addr_LAN_Subnet"' in main_tf
    assert 'value       = "192.168.1.0/24"' in main_tf
    assert 'type        = "ip-netmask"' in main_tf
    assert 'description = "Internal LAN"' in main_tf

    assert 'resource "panos_address_object" "addr_DHCP_Pool"' in main_tf
    assert 'value       = "10.0.0.100-10.0.0.200"' in main_tf
    assert 'type        = "ip-range"' in main_tf

    assert 'resource "panos_address_object" "addr_Web_FQDN"' in main_tf
    assert 'value       = "api.example.com"' in main_tf
    assert 'type        = "fqdn"' in main_tf

    # Wildcard FQDN promoted to custom URL category
    assert 'resource "panos_custom_url_category" "url_Wildcard_Web"' in main_tf
    assert 'sites       = ["*.example.com"]' in main_tf

    assert 'resource "panos_address_object" "addr_EMS_Tag"' in main_tf


def test_address_groups_generation_with_dependencies():
    ir = IRConfig(
        metadata=IRMetadata(hostname="fw-test"),
        addresses=[
            IRAddress(name="Host_A", type=AddressType.HOST, value="10.1.1.1/32"),
            IRAddress(name="Host_B", type=AddressType.HOST, value="10.1.1.2/32"),
        ],
        address_groups=[
            # Group_Parent depends on Group_Child
            IRAddressGroup(name="Group_Parent", members=["Group_Child", "Host_A"]),
            IRAddressGroup(name="Group_Child", members=["Host_B"]),
        ]
    )

    gen = PANOSTerraformGenerator()
    artifacts = gen.generate(ir)
    main_tf = next(a.content for a in artifacts if a.filename == "main.tf")

    # Verify topological ordering: Group_Child should appear before Group_Parent
    child_pos = main_tf.find('resource "panos_address_group" "grp_Group_Child"')
    parent_pos = main_tf.find('resource "panos_address_group" "grp_Group_Parent"')
    assert child_pos != -1 and parent_pos != -1
    assert child_pos < parent_pos

    assert "panos_address_object.addr_Host_B.name" in main_tf
    assert "panos_address_group.grp_Group_Child.name" in main_tf
    assert "depends_on" in main_tf


def test_service_objects_and_groups():
    ir = IRConfig(
        metadata=IRMetadata(hostname="fw-test"),
        services=[
            IRService(name="HTTPS_Custom", ports=[IRServicePort(protocol=ServiceProtocol.TCP, port="8443")]),
            IRService(name="DNS_Dual", ports=[
                IRServicePort(protocol=ServiceProtocol.TCP, port="53"),
                IRServicePort(protocol=ServiceProtocol.UDP, port="53")
            ])
        ],
        service_groups=[
            IRServiceGroup(name="Web_Services", members=["HTTPS_Custom", "DNS_Dual"])
        ]
    )

    gen = PANOSTerraformGenerator()
    artifacts = gen.generate(ir)
    main_tf = next(a.content for a in artifacts if a.filename == "main.tf")

    assert 'resource "panos_service_object" "svc_HTTPS_Custom"' in main_tf
    assert 'destination_port = "8443"' in main_tf
    assert 'protocol         = "tcp"' in main_tf

    assert 'resource "panos_service_object" "svc_DNS_Dual"' in main_tf
    assert 'resource "panos_service_object" "svc_DNS_Dual_udp"' in main_tf

    assert 'resource "panos_service_group" "sgrp_Web_Services"' in main_tf
    assert 'panos_service_object.svc_HTTPS_Custom.name' in main_tf


def test_zones_and_routes():
    ir = IRConfig(
        metadata=IRMetadata(hostname="fw-test"),
        zones=[
            IRZone(name="trust", interfaces=["ethernet1/2"]),
            IRZone(name="untrust", interfaces=["ethernet1/1"])
        ],
        routes=[
            IRRoute(name="Default_Route", destination="0.0.0.0/0", next_hop="192.168.1.254", interface="ethernet1/1", metric=10)
        ]
    )

    gen = PANOSTerraformGenerator()
    artifacts = gen.generate(ir)
    main_tf = next(a.content for a in artifacts if a.filename == "main.tf")

    assert 'resource "panos_zone" "zone_trust"' in main_tf
    assert 'interfaces  = ["ethernet1/2"]' in main_tf

    assert 'resource "panos_static_route_ipv4" "route_Default_Route"' in main_tf
    assert 'destination    = "0.0.0.0/0"' in main_tf
    assert 'nexthop        = "192.168.1.254"' in main_tf


def test_security_policies_and_nat_rules():
    ir = IRConfig(
        metadata=IRMetadata(hostname="fw-test"),
        zones=[
            IRZone(name="trust", interfaces=["ethernet1/2"]),
            IRZone(name="untrust", interfaces=["ethernet1/1"])
        ],
        addresses=[
            IRAddress(name="Internal_LAN", type=AddressType.NETWORK, value="10.0.0.0/24"),
            IRAddress(name="1.2.3.100", type=AddressType.HOST, value="1.2.3.100/32")
        ],
        services=[
            IRService(name="Web", ports=[IRServicePort(protocol=ServiceProtocol.TCP, port="80")])
        ],
        policies=[
            IRPolicy(
                name="Allow_Outbound",
                from_zone=["trust"],
                to_zone=["untrust"],
                source=["Internal_LAN"],
                destination=["all"],
                service=["Web"],
                action=PolicyAction.ALLOW,
                description="Allow outbound web traffic"
            ),
            IRPolicy(
                name="Deny_All",
                from_zone=["any"],
                to_zone=["any"],
                source=["all"],
                destination=["all"],
                service=["all"],
                action=PolicyAction.DENY
            )
        ],
        nat_rules=[
            IRNATRule(
                name="SNAT_Outbound",
                type=NATType.SOURCE,
                from_zone=["trust"],
                to_zone=["untrust"],
                source=["Internal_LAN"],
                destination=["any"],
                translated_source="1.2.3.4-1.2.3.10"
            ),
            IRNATRule(
                name="DNAT_Web",
                type=NATType.DESTINATION,
                from_zone=["untrust"],
                to_zone=["trust"],
                source=["any"],
                destination=["1.2.3.100"],
                translated_destination="10.0.0.100"
            )
        ]
    )

    gen = PANOSTerraformGenerator()
    artifacts = gen.generate(ir)
    main_tf = next(a.content for a in artifacts if a.filename == "main.tf")

    # Security Rules
    assert 'resource "panos_security_rule_group" "security_rules"' in main_tf
    assert 'name                  = "Allow_Outbound"' in main_tf
    assert 'action                = "allow"' in main_tf
    assert 'source_zones          = ["trust"]' in main_tf
    assert 'destination_zones     = ["untrust"]' in main_tf
    assert 'name                  = "Deny_All"' in main_tf
    assert 'action                = "deny"' in main_tf

    # NAT Rules
    assert 'resource "panos_nat_rule_group" "nat_rules"' in main_tf
    assert 'name                  = "SNAT_Outbound"' in main_tf
    assert 'translated_addresses = ["1.2.3.4-1.2.3.10"]' in main_tf
    assert 'name                  = "DNAT_Web"' in main_tf
    assert 'address = "10.0.0.100"' in main_tf


def test_full_example_migration_terraform(tmp_path):
    example_conf = Path("examples/example_fortigate.conf")
    assert example_conf.exists()

    with open(example_conf, "r", encoding="utf-8") as f:
        conf_text = f.read()

    fg_config = parse_fortigate_config(conf_text)
    transformer = FGToIRTransformer(fg_config)
    ir_config = transformer.transform()

    gen = PANOSTerraformGenerator()
    artifacts = gen.generate(ir_config)

    filenames = {a.filename for a in artifacts}
    assert filenames == {"provider.tf", "variables.tf", "terraform.tfvars.example", "main.tf"}

    main_artifact = next(a for a in artifacts if a.filename == "main.tf")
    assert "panos_address_object" in main_artifact.content
    assert "panos_security_rule_group" in main_artifact.content


def test_cli_migrate_terraform(tmp_path):
    runner = CliRunner()
    out_dir = tmp_path / "tf_output"
    report_file = out_dir / "report.md"

    result = runner.invoke(cli, [
        "migrate",
        "-i", "examples/example_fortigate.conf",
        "-o", str(out_dir),
        "--format", "terraform",
        "--report", str(report_file)
    ])

    assert result.exit_code == 0
    assert (out_dir / "provider.tf").exists()
    assert (out_dir / "variables.tf").exists()
    assert (out_dir / "main.tf").exists()
    assert (out_dir / "terraform.tfvars.example").exists()
    assert report_file.exists()
