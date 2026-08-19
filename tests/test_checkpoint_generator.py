from fwmigrate.core.registry import PluginRegistry
from fwmigrate.ir.core import (
    IRConfig, IRMetadata, IRAddress, IRAddressGroup, IRService, IRServicePort, IRPolicy
)
from fwmigrate.ir.enums import AddressType, ServiceProtocol, PolicyAction

def test_checkpoint_target_generator():
    ir = IRConfig(
        metadata=IRMetadata(hostname="CP-Target", source_vendor="cisco_asa"),
        addresses=[
            IRAddress(name="h_db", type=AddressType.HOST, value="192.168.10.5/32"),
            IRAddress(name="net_dmz", type=AddressType.NETWORK, value="192.168.20.0/24"),
            IRAddress(name="rng_pool", type=AddressType.RANGE, value="192.168.10.100-192.168.10.200"),
        ],
        address_groups=[
            IRAddressGroup(name="grp_dmz_hosts", members=["h_db"])
        ],
        services=[
            IRService(name="svc_custom_9443", ports=[IRServicePort(protocol=ServiceProtocol.TCP, port="9443")]),
        ],
        policies=[
            IRPolicy(
                name="Allow_To_DMZ",
                from_zone=["internal"],
                to_zone=["dmz"],
                source=["all"],
                destination=["grp_dmz_hosts"],
                service=["svc_custom_9443"],
                action=PolicyAction.ALLOW
            )
        ]
    )

    generator = PluginRegistry.get_generator("checkpoint")
    artifacts = generator.generate(ir)

    filenames = [a.filename for a in artifacts]
    assert "checkpoint_mgmt_cli.sh" in filenames
    assert "provider.tf" in filenames
    assert "variables.tf" in filenames
    assert "main.tf" in filenames

    # Check CLI content
    cli_art = next(a for a in artifacts if a.filename == "checkpoint_mgmt_cli.sh")
    assert 'mgmt_cli add host name "h_db" ip-address "192.168.10.5"' in cli_art.content
    assert 'mgmt_cli add network name "net_dmz"' in cli_art.content
    assert 'mgmt_cli add group name "grp_dmz_hosts"' in cli_art.content
    assert 'mgmt_cli add service-tcp name "svc_custom_9443" port "9443"' in cli_art.content
    assert 'mgmt_cli add access-rule layer "Network"' in cli_art.content
