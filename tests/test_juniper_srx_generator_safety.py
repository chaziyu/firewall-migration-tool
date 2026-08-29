from fwmigrate.core.registry import PluginRegistry
from fwmigrate.ir.core import (
    IRAddress,
    IRConfig,
    IRMetadata,
    IRPolicy,
    IRRoute,
    IRService,
    IRServicePort,
    IRZone,
)
from fwmigrate.ir.enums import AddressType, PolicyAction, ServiceProtocol

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
        ],
        policies=[
            IRPolicy(
                name="Valid_Policy",
                from_zone=["trust"],
                to_zone=["untrust"],
                source=["valid_ipv4_host"],
                destination=["any"],
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
        ],
        routes=[
            IRRoute(name="valid_route", destination="0.0.0.0/0", next_hop="198.51.100.1"),
            IRRoute(
                name="unsafe_route_no_nexthop",
                destination="10.0.0.0/8",
                next_hop=None,
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
    assert "unsafe_addr" not in cli_art.content or "# Address unsafe_addr withheld" in cli_art.content
    assert "set security policies from-zone trust to-zone untrust policy Valid_Policy then permit" in cli_art.content
    assert "Unsafe_Policy_Manual_Review" not in cli_art.content or "# Policy Unsafe_Policy_Manual_Review withheld" in cli_art.content
    assert "192.168.1.1" not in cli_art.content  # No fake 192.168.1.1 fallback!
    assert "# Route unsafe_route_no_nexthop withheld" in cli_art.content

    # Terraform generator assertions
    assert "valid_ipv4_host" in tf_main.content
    assert "valid_ipv6_host" in tf_main.content
    assert "unsafe_addr" not in tf_main.content
