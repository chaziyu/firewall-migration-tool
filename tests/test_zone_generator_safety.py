from fwmigrate.generators.cisco_asa.cli_generator import CiscoASACLIGenerator
from fwmigrate.generators.checkpoint.cli_generator import CheckPointCLIGenerator
from fwmigrate.generators.fortigate.cli_generator import FortiGateCLIGenerator
from fwmigrate.generators.fortigate.terraform_generator import FortiGateTerraformGenerator
from fwmigrate.generators.juniper_srx.cli_generator import JuniperSRXCLIGenerator
from fwmigrate.generators.palo_alto.terraform_generator import PANOSTerraformGenerator
from fwmigrate.generators.palo_alto.transformer import IRToPANOSTransformer
from fwmigrate.ir.core import IRConfig, IRMetadata, IRNATRule, IRPolicy, IRRoute, IRZone, IRAddress
from fwmigrate.ir.enums import NATType, PolicyAction, AddressType


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


def test_generators_use_central_route_safety_contract():
    unsafe_routes = [
        IRRoute(
            name="object-route",
            source_destination_reference="REMOTE_NET",
            requires_manual_review=True,
            review_reasons=["Destination object reference"],
        ),
        IRRoute(
            name="dynamic-route",
            destination="10.1.0.0/16",
            dynamic_gateway="enable",
            migration_status="PARTIALLY_NORMALIZED",
            requires_manual_review=True,
            review_reasons=["Dynamic gateway"],
        ),
        IRRoute(
            name="source-route",
            destination="10.2.0.0/16",
            source_prefix="192.0.2.0 255.255.255.0",
            migration_status="PARTIALLY_NORMALIZED",
            requires_manual_review=True,
            review_reasons=["Source-specific route"],
        ),
        IRRoute(
            name="multi-sdwan-route",
            destination="10.3.0.0/16",
            sdwan_zones=["A", "B"],
            migration_status="PARTIALLY_NORMALIZED",
            requires_manual_review=True,
            review_reasons=["Multiple SD-WAN zones"],
        ),
        IRRoute(
            name="unmodeled-route",
            destination="10.4.0.0/16",
            migration_status="PARTIALLY_NORMALIZED",
            requires_manual_review=True,
            review_reasons=["Unmodeled semantics"],
            source_attributes={"future_option": "enabled"},
        ),
    ]
    safe_route = IRRoute(
        name="safe-route",
        destination="10.99.0.0/16",
        interface="wan1",
        next_hop="192.0.2.1",
    )
    ir = IRConfig(
        metadata=IRMetadata(hostname="edge-fw", source_vendor="fortigate"),
        routes=[*unsafe_routes, safe_route],
    )

    cisco = CiscoASACLIGenerator().generate(ir)
    juniper = JuniperSRXCLIGenerator().generate(ir)
    fortigate = "\n".join(
        artifact.content for artifact in FortiGateCLIGenerator().generate(ir)
    )
    panos_tf = next(
        artifact.content
        for artifact in PANOSTerraformGenerator().generate(ir)
        if artifact.filename == "main.tf"
    )
    panos_model = IRToPANOSTransformer(ir).transform()

    for destination in ("10.1.0.0", "10.2.0.0", "10.3.0.0", "10.4.0.0"):
        assert destination not in cisco
        assert destination not in juniper
        assert destination not in fortigate
        assert destination not in panos_tf
    assert "10.99.0.0" in cisco
    assert "10.99.0.0/16" in juniper
    assert "10.99.0.0" in fortigate
    assert "10.99.0.0/16" in panos_tf
    assert [route.name for route in panos_model.routes] == ["safe-route"]


def test_generators_withhold_ipsec_and_manual_review_policies():
    ir = IRConfig(
        metadata=IRMetadata(hostname="edge-fw", source_vendor="fortigate"),
        policies=[
            IRPolicy(
                name="Policy_Based_IPsec",
                from_zone=["inside"],
                to_zone=["outside"],
                source=["any"],
                destination=["any"],
                service=["any"],
                action=PolicyAction.IPSEC,
                requires_manual_review=True,
            )
        ],
    )

    cisco = CiscoASACLIGenerator().generate(ir)
    checkpoint = CheckPointCLIGenerator().generate(ir)
    juniper = JuniperSRXCLIGenerator().generate(ir)
    fortigate_cli = "\n".join(
        artifact.content for artifact in FortiGateCLIGenerator().generate(ir)
    )
    fortigate_tf = next(
        artifact.content
        for artifact in FortiGateTerraformGenerator().generate(ir)
        if artifact.filename == "main.tf"
    )
    panos_tf = next(
        artifact.content
        for artifact in PANOSTerraformGenerator().generate(ir)
        if artifact.filename == "main.tf"
    )
    panos_model = IRToPANOSTransformer(ir).transform()

    assert "access-list inside_access_in" not in cisco
    assert "mgmt_cli add access-rule" not in checkpoint
    assert "policy Policy_Based_IPsec match" not in juniper
    assert 'edit "Policy_Based_IPsec"' not in fortigate_cli
    assert 'resource "fortios_firewall_policy"' not in fortigate_tf
    assert 'rule_name             = "Policy_Based_IPsec"' not in panos_tf
    assert panos_model.vsys.security_rules == []


def test_nat_generators_require_normalized_status_and_no_review_reasons():
    ir = IRConfig(
        metadata=IRMetadata(hostname="edge-fw", source_vendor="fortigate"),
        nat_rules=[
            IRNATRule(
                name="Partial_Status_NAT",
                type=NATType.SOURCE,
                from_zone=["inside"],
                to_zone=["outside"],
                source=["any"],
                destination=["any"],
                services=["any"],
                translated_sources=["203.0.113.10"],
                migration_status="PARTIALLY_NORMALIZED",
            ),
            IRNATRule(
                name="Review_Reason_NAT",
                type=NATType.SOURCE,
                from_zone=["inside"],
                to_zone=["outside"],
                source=["any"],
                destination=["any"],
                services=["any"],
                translated_sources=["203.0.113.11"],
                review_reasons=["source restriction requires review"],
            ),
        ],
    )

    cisco = CiscoASACLIGenerator().generate(ir)
    panos_tf = next(
        artifact.content
        for artifact in PANOSTerraformGenerator().generate(ir)
        if artifact.filename == "main.tf"
    )
    panos_model = IRToPANOSTransformer(ir).transform()

    assert "203.0.113.10" not in cisco
    assert "203.0.113.11" not in cisco
    assert "Partial_Status_NAT" not in panos_tf
    assert "Review_Reason_NAT" not in panos_tf
    assert panos_model.vsys.nat_rules == []


def test_generators_withhold_deactivated_zones_and_referencing_policies():
    ir = IRConfig(
        metadata=IRMetadata(hostname="edge-fw", source_vendor="juniper_srx"),
        zones=[
            IRZone(name="trust", interfaces=["ge-0/0/0.0"]),
            IRZone(
                name="dmz_deactivated",
                interfaces=["ge-0/0/1.0"],
                disabled=True,
                requires_manual_review=True,
                migration_status="PARTIALLY_NORMALIZED",
                review_reasons=["Zone deactivated in source"],
            ),
        ],
        addresses=[
            IRAddress(name="10.0.0.1/32", type=AddressType.HOST, value="10.0.0.1/32"),
            IRAddress(name="10.0.0.2/32", type=AddressType.HOST, value="10.0.0.2/32"),
        ],
        policies=[
            IRPolicy(
                name="Safe_Policy",
                from_zone=["trust"],
                to_zone=["trust"],
                source=["10.0.0.1/32"],
                destination=["10.0.0.2/32"],
                service=["any"],
                action=PolicyAction.ALLOW,
                schedule="always",
            ),
            IRPolicy(
                name="Unsafe_Zone_Policy",
                from_zone=["trust"],
                to_zone=["dmz_deactivated"],
                source=["10.0.0.1/32"],
                destination=["10.0.0.3/32"],
                service=["any"],
                action=PolicyAction.ALLOW,
                schedule="always",
            ),
        ],
    )

    cisco = CiscoASACLIGenerator().generate(ir)
    checkpoint = CheckPointCLIGenerator().generate(ir)
    juniper = JuniperSRXCLIGenerator().generate(ir)
    fortigate_cli = "\n".join(
        artifact.content for artifact in FortiGateCLIGenerator().generate(ir)
    )
    fortigate_tf = next(
        artifact.content
        for artifact in FortiGateTerraformGenerator().generate(ir)
        if artifact.filename == "main.tf"
    )
    panos_tf = next(
        artifact.content
        for artifact in PANOSTerraformGenerator().generate(ir)
        if artifact.filename == "main.tf"
    )
    panos_model = IRToPANOSTransformer(ir).transform()

    # Zone definition assertions
    assert "set security zones security-zone dmz_deactivated" not in juniper
    assert 'resource "panos_zone" "zone_dmz_deactivated"' not in panos_tf
    assert all(z.name != "dmz_deactivated" for z in panos_model.vsys.zones)

    # Policy referencing deactivated zone assertions: active rules withheld
    assert "10.0.0.3" not in cisco
    assert 'name "Unsafe_Zone_Policy"' not in checkpoint
    assert "policy Unsafe_Zone_Policy match" not in juniper
    assert 'set name "Unsafe_Zone_Policy"' not in fortigate_cli
    assert 'name     = "Unsafe_Zone_Policy"' not in fortigate_tf
    assert 'name                  = "Unsafe_Zone_Policy"' not in panos_tf
    assert all(r.name != "Unsafe_Zone_Policy" for r in panos_model.vsys.security_rules)

    # Safe policy is generated
    assert "access-list trust_access_in extended permit" in cisco
    assert 'name "Safe_Policy"' in checkpoint
    assert "policy Safe_Policy match" in juniper
    assert 'set name "Safe_Policy"' in fortigate_cli
    assert 'name     = "Safe_Policy"' in fortigate_tf
    assert any(r.name == "Safe_Policy" for r in panos_model.vsys.security_rules)
