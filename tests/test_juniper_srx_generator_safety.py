from fwmigrate.core.registry import PluginRegistry
from fwmigrate.generators.juniper_srx.cli_generator import JuniperSRXCLIGenerator
from fwmigrate.ir.core import (
    IRAddress,
    IRConfig,
    IRMetadata,
    IRNATRule,
    IRPolicy,
    IRRoute,
    IRSecurityProfileGroup,
    IRService,
    IRServicePort,
    IRZone,
)
from fwmigrate.ir.enums import AddressType, NATTranslationMode, NATType, PolicyAction, ServiceProtocol


def test_target_generators_withhold_unsafe_objects():
    ir = IRConfig(
        metadata=IRMetadata(hostname="SRX-Safety", source_vendor="juniper_srx"),
        zones=[
            IRZone(name="trust", interfaces=["ge-0/0/0.0"]),
            IRZone(name="untrust", interfaces=["ge-0/0/1.0"]),
        ],
        addresses=[
            IRAddress(name="valid_ipv4_host", type=AddressType.HOST, subnet="10.1.1.1/32"),
            IRAddress(name="valid_ipv6_host", type=AddressType.HOST, subnet="2001:db8::1/128"),
            IRAddress(
                name="unsafe_addr",
                type=AddressType.HOST,
                subnet="10.2.2.2/32",
                requires_manual_review=True,
            ),
            IRAddress(
                name="stub_no_value",
                type=AddressType.STUB_UNSUPPORTED,
                stub_value=None,
            ),
            IRAddress(
                name="stub_with_value",
                type=AddressType.STUB_UNSUPPORTED,
                stub_value="198.19.255.254/32",
            ),
        ],
        policies=[
            IRPolicy(
                name="Valid_Policy",
                from_zone=["trust"],
                to_zone=["untrust"],
                source=["valid_ipv4_host", "any-ipv4"],
                destination=["any-ipv6"],
                service=["any"],
                action=PolicyAction.ALLOW,
            ),
            IRPolicy(
                name="Unsafe_Policy_Manual_Review",
                from_zone=["trust"],
                to_zone=["untrust"],
                source=["valid_ipv4_host"],
                destination=["any"],
                service=["any"],
                action=PolicyAction.ALLOW,
                requires_manual_review=True,
            ),
            IRPolicy(
                name="Incomplete_Policy_Missing_Dest",
                from_zone=["trust"],
                to_zone=["untrust"],
                source=["valid_ipv4_host"],
                destination=[],
                service=["any"],
                action=PolicyAction.ALLOW,
            ),
        ],
        routes=[
            IRRoute(name="valid_route", destination="0.0.0.0/0", next_hop="198.51.100.1"),
            IRRoute(
                name="unsafe_route_no_nexthop",
                destination="10.0.0.0/8",
                next_hop=None,
            ),
        ],
        security_profile_groups=[
            IRSecurityProfileGroup(
                name="Missing_AV_PG",
                url_filtering="web-filter-1",
                antivirus=None,
                requires_manual_review=False,
                migration_status="NORMALIZED",
            ),
            IRSecurityProfileGroup(
                name="Missing_URL_PG",
                antivirus="av-profile-1",
                url_filtering=None,
                requires_manual_review=False,
                migration_status="NORMALIZED",
            ),
            IRSecurityProfileGroup(
                name="Valid_Explicit_PG",
                antivirus="av-profile-1",
                url_filtering="web-filter-1",
                requires_manual_review=False,
                migration_status="NORMALIZED",
            ),
        ],
    )

    generator = PluginRegistry.get_generator("juniper_srx")
    artifacts = generator.generate(ir)

    cli_art = next(a for a in artifacts if a.filename == "junos_srx_config.set")
    tf_main = next(a for a in artifacts if a.filename == "main.tf")

    # CLI generator assertions
    assert "set security address-book global address valid_ipv4_host 10.1.1.1/32" in cli_art.content
    assert "set security address-book global address valid_ipv6_host 2001:db8::1/128" in cli_art.content
    assert "# Address unsafe_addr withheld: source semantics require manual review" in cli_art.content

    # STUB_UNSUPPORTED withholding assertions
    assert "198.19.255.254" not in cli_art.content
    assert "# Address stub_no_value withheld: unsupported source address semantics require manual review" in cli_art.content
    assert "# Address stub_with_value withheld: unsupported source address semantics require manual review" in cli_art.content

    # Policy assertions
    assert "set security policies from-zone trust to-zone untrust policy Valid_Policy match source-address any-ipv4" in cli_art.content
    assert "set security policies from-zone trust to-zone untrust policy Valid_Policy match destination-address any-ipv6" in cli_art.content
    assert "set security policies from-zone trust to-zone untrust policy Valid_Policy then permit" in cli_art.content
    assert "# Policy Unsafe_Policy_Manual_Review withheld" in cli_art.content
    assert "# Policy Incomplete_Policy_Missing_Dest withheld" in cli_art.content

    # Route assertions
    assert "192.168.1.1" not in cli_art.content  # No fake fallback!
    assert "# Route unsafe_route_no_nexthop withheld: missing next hop" in cli_art.content

    # UTM assertions
    assert "# Security profile group Missing_AV_PG withheld: antivirus profile missing" in cli_art.content
    assert "# Security profile group Missing_URL_PG withheld: url filtering profile missing" in cli_art.content
    assert "set security utm utm-policy Valid_Explicit_PG anti-virus http-profile av-profile-1" in cli_art.content
    assert "set security utm utm-policy Valid_Explicit_PG web-filtering http-profile web-filter-1" in cli_art.content

    # Terraform generator assertions
    assert "valid_ipv4_host" in tf_main.content
    assert "valid_ipv6_host" in tf_main.content
    assert "unsafe_addr" not in tf_main.content


def test_generator_withholds_partial_services_and_manual_review_routes():
    cli_gen = JuniperSRXCLIGenerator()
    ir = IRConfig(
        metadata=IRMetadata(hostname="SRX-Test", source_vendor="juniper_srx"),
        services=[
            IRService(
                name="partial_svc",
                ports=[IRServicePort(protocol=ServiceProtocol.TCP, port="8080")],
                requires_manual_review=True,
                migration_status="PARTIALLY_NORMALIZED",
            ),
        ],
        routes=[
            IRRoute(
                name="routing_instance_rt",
                destination="172.16.0.0/16",
                next_hop="172.16.0.1",
                requires_manual_review=True,
                migration_status="PARTIALLY_NORMALIZED",
            ),
        ],
    )
    output = cli_gen.generate(ir)
    assert "# Service partial_svc withheld: source/proxy port semantics require manual review" in output
    assert "# Route routing_instance_rt withheld: source semantics require manual review" in output
    assert "set routing-options static route 172.16.0.0/16" not in output

