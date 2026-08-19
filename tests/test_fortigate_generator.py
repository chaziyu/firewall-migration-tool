from fwmigrate.core.registry import PluginRegistry
from fwmigrate.ir.core import (
    IRConfig, IRMetadata, IRZone, IRAddress, IRAddressGroup,
    IRService, IRServicePort, IRPolicy, IRRoute
)
from fwmigrate.ir.enums import AddressType, ServiceProtocol, PolicyAction

def test_fortigate_target_generator():
    ir = IRConfig(
        metadata=IRMetadata(hostname="test-fw", source_vendor="cisco_asa"),
        zones=[IRZone(name="trust"), IRZone(name="untrust")],
        addresses=[
            IRAddress(name="h_web", type=AddressType.HOST, value="10.1.1.10/32"),
            IRAddress(name="fqdn_api", type=AddressType.FQDN, value="api.example.com"),
            IRAddress(name="rng_pool", type=AddressType.RANGE, value="10.1.1.50-10.1.1.60"),
        ],
        address_groups=[
            IRAddressGroup(name="grp_web", members=["h_web", "fqdn_api"])
        ],
        services=[
            IRService(name="svc_http", ports=[IRServicePort(protocol=ServiceProtocol.TCP, port="80")]),
            IRService(name="svc_https", ports=[IRServicePort(protocol=ServiceProtocol.TCP, port="443")]),
        ],
        policies=[
            IRPolicy(
                name="Allow_Web",
                from_zone=["trust"],
                to_zone=["untrust"],
                source=["h_web"],
                destination=["all"],
                service=["svc_https"],
                action=PolicyAction.ALLOW
            )
        ],
        routes=[
            IRRoute(name="default_gw", destination="0.0.0.0/0", next_hop="192.168.1.1")
        ]
    )

    generator = PluginRegistry.get_generator("fortigate")
    artifacts = generator.generate(ir)

    filenames = [a.filename for a in artifacts]
    assert "fortigate_config.conf" in filenames
    assert "provider.tf" in filenames
    assert "variables.tf" in filenames
    assert "main.tf" in filenames

    # Check CLI content
    cli_art = next(a for a in artifacts if a.filename == "fortigate_config.conf")
    assert 'edit "h_web"' in cli_art.content
    assert 'set fqdn "api.example.com"' in cli_art.content
    assert 'config firewall policy' in cli_art.content
    assert 'set action accept' in cli_art.content

    # Check Terraform content
    main_tf = next(a for a in artifacts if a.filename == "main.tf")
    assert 'resource "fortios_firewall_address" "h_web"' in main_tf.content
    assert 'resource "fortios_firewall_policy"' in main_tf.content
