from fwmigrate.core.registry import PluginRegistry
from fwmigrate.ir.core import (
    IRConfig, IRMetadata, IRAddress, IRAddressGroup, IRService, IRServicePort, IRPolicy, IRRoute
)
from fwmigrate.ir.enums import AddressType, ServiceProtocol, PolicyAction

def test_cisco_asa_target_generator():
    ir = IRConfig(
        metadata=IRMetadata(hostname="ASA-Target", source_vendor="fortigate"),
        addresses=[
            IRAddress(name="h_web", type=AddressType.HOST, value="10.1.1.10/32"),
            IRAddress(name="net_lan", type=AddressType.NETWORK, value="10.1.0.0/16"),
            IRAddress(name="rng_dhcp", type=AddressType.RANGE, value="10.1.2.10-10.1.2.20"),
            IRAddress(name="fqdn_ext", type=AddressType.FQDN, value="api.test.com"),
        ],
        address_groups=[
            IRAddressGroup(name="grp_internal", members=["h_web", "net_lan"])
        ],
        services=[
            IRService(name="svc_web", ports=[IRServicePort(protocol=ServiceProtocol.TCP, port="8080")]),
        ],
        policies=[
            IRPolicy(
                name="Allow_Outbound",
                from_zone=["inside"],
                to_zone=["outside"],
                source=["grp_internal"],
                destination=["all"],
                service=["svc_web"],
                action=PolicyAction.ALLOW
            )
        ],
        routes=[
            IRRoute(name="default_gw", destination="0.0.0.0/0", next_hop="192.168.1.1", interface="outside")
        ]
    )

    generator = PluginRegistry.get_generator("cisco_asa")
    artifacts = generator.generate(ir)

    filenames = [a.filename for a in artifacts]
    assert "cisco_asa_config.cfg" in filenames
    assert "provider.tf" in filenames
    assert "variables.tf" in filenames
    assert "main.tf" in filenames

    # Check CLI content
    cli_art = next(a for a in artifacts if a.filename == "cisco_asa_config.cfg")
    assert "object network h_web" in cli_art.content
    assert "host 10.1.1.10" in cli_art.content
    assert "object-group network grp_internal" in cli_art.content
    assert "access-list inside_access_in extended permit" in cli_art.content
    assert "route outside 0.0.0.0 0.0.0.0 192.168.1.1 1" in cli_art.content
