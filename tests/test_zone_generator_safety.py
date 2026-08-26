from fwmigrate.generators.cisco_asa.cli_generator import CiscoASACLIGenerator
from fwmigrate.generators.fortigate.cli_generator import FortiGateCLIGenerator
from fwmigrate.generators.fortigate.terraform_generator import FortiGateTerraformGenerator
from fwmigrate.generators.juniper_srx.cli_generator import JuniperSRXCLIGenerator
from fwmigrate.generators.palo_alto.terraform_generator import PANOSTerraformGenerator
from fwmigrate.generators.palo_alto.transformer import IRToPANOSTransformer
from fwmigrate.ir.core import IRConfig, IRMetadata, IRPolicy, IRRoute
from fwmigrate.ir.enums import PolicyAction


def _ir_with_unresolved_policy_zones() -> IRConfig:
    return IRConfig(
        metadata=IRMetadata(hostname="edge-fw", source_vendor="fortigate"),
        policies=[
            IRPolicy(
                name="Unresolved_Zone_Rule",
                source_from_interfaces=["port1"],
                source_to_interfaces=["port2"],
                source=["<IR_ANY>"],
                destination=["<IR_ANY>"],
                service=["<IR_ANY>"],
                action=PolicyAction.ALLOW,
            )
        ],
    )


def test_generators_withhold_policies_with_unresolved_canonical_zones():
    ir = _ir_with_unresolved_policy_zones()

    cisco = CiscoASACLIGenerator().generate(ir)
    juniper = JuniperSRXCLIGenerator().generate(ir)
    fortigate = next(
        artifact.content
        for artifact in FortiGateTerraformGenerator().generate(ir)
        if artifact.filename == "main.tf"
    )
    panos = next(
        artifact.content
        for artifact in PANOSTerraformGenerator().generate(ir)
        if artifact.filename == "main.tf"
    )

    assert "access-list global_access_in" not in cisco
    assert "nat (inside,outside)" not in cisco
    assert "from-zone any to-zone any" not in juniper
    assert 'resource "fortios_firewall_policy"' not in fortigate
    assert 'source_zones          = ["any"]' not in panos
    assert all("withheld" in output for output in (cisco, juniper, fortigate))
    assert any(
        entry.category == "PAN-OS Terraform Policy"
        and entry.confidence.value == "manual"
        for entry in ir.audit_entries
    )


def test_generators_withhold_routes_without_canonical_destinations():
    ir = IRConfig(
        metadata=IRMetadata(hostname="edge-fw", source_vendor="fortigate"),
        routes=[
            IRRoute(
                name="route_20",
                destination=None,
                source_destination="10.20.30.0 255.0.255.0",
                requires_manual_review=True,
                parse_error="Invalid IPv4 network",
            )
        ],
    )

    cisco = CiscoASACLIGenerator().generate(ir)
    juniper = JuniperSRXCLIGenerator().generate(ir)
    fortigate = FortiGateCLIGenerator().generate(ir)
    panos_tf = next(
        artifact.content
        for artifact in PANOSTerraformGenerator().generate(ir)
        if artifact.filename == "main.tf"
    )
    panos_model = IRToPANOSTransformer(ir).transform()

    assert "route outside 0.0.0.0 0.0.0.0" not in cisco
    assert "static route None" not in juniper
    assert all("set dst" not in artifact.content for artifact in fortigate)
    assert 'resource "panos_static_route_ipv4"' not in panos_tf
    assert panos_model.routes == []
    assert any(
        entry.category == "PAN-OS Route" and "withheld" in entry.message
        for entry in ir.audit_entries
    )
