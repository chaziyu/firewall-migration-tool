from fwmigrate.core.registry import PluginRegistry
from fwmigrate.ir.core import (
    IRConfig, IRMetadata, IRZone, IRAddress, IRAddressGroup, IRService, IRServicePort, IRPolicy, IRRoute
)
from fwmigrate.ir.enums import AddressType, ServiceProtocol, PolicyAction

def test_juniper_srx_target_generator():
    ir = IRConfig(
        metadata=IRMetadata(hostname="SRX-Target", source_vendor="checkpoint"),
        zones=[
            IRZone(name="trust", interfaces=["ge-0/0/0.0"]),
            IRZone(name="untrust", interfaces=["ge-0/0/1.0"])
        ],
        addresses=[
            IRAddress(name="srv_app", type=AddressType.HOST, value="10.200.1.10/32"),
            IRAddress(name="net_office", type=AddressType.NETWORK, value="10.200.0.0/16"),
            IRAddress(name="fqdn_cloud", type=AddressType.FQDN, value="login.microsoft.com"),
        ],
        address_groups=[
            IRAddressGroup(name="grp_app_stack", members=["srv_app", "net_office"])
        ],
        services=[
            IRService(name="app_tls_8443", ports=[IRServicePort(protocol=ServiceProtocol.TCP, port="8443")]),
        ],
        policies=[
            IRPolicy(
                name="Allow_Trust_To_Untrust",
                from_zone=["trust"],
                to_zone=["untrust"],
                source=["grp_app_stack"],
                destination=["fqdn_cloud"],
                service=["app_tls_8443"],
                action=PolicyAction.ALLOW,
                log_end=True
            )
        ],
        routes=[
            IRRoute(name="default_gw", destination="0.0.0.0/0", next_hop="198.51.100.1")
        ]
    )

    generator = PluginRegistry.get_generator("juniper_srx")
    artifacts = generator.generate(ir)

    filenames = [a.filename for a in artifacts]
    assert "junos_srx_config.set" in filenames
    assert "provider.tf" in filenames
    assert "variables.tf" in filenames
    assert "main.tf" in filenames

    # Check Set CLI content
    cli_art = next(a for a in artifacts if a.filename == "junos_srx_config.set")
    assert "set system host-name SRX-Target" in cli_art.content
    assert "set security zones security-zone trust interfaces ge-0/0/0.0" in cli_art.content
    assert "set security address-book global address srv_app 10.200.1.10/32" in cli_art.content
    assert "set security address-book global address fqdn_cloud dns-name login.microsoft.com" in cli_art.content
    assert "set security address-book global address-set grp_app_stack address srv_app" in cli_art.content
    assert "set security policies from-zone trust to-zone untrust policy Allow_Trust_To_Untrust match application app_tls_8443" in cli_art.content
    assert "set routing-options static route 0.0.0.0/0 next-hop 198.51.100.1" in cli_art.content
