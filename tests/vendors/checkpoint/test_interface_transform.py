from fwmigrate.vendors.checkpoint.derived import build_checkpoint_derived_views
from fwmigrate.vendors.checkpoint.model.gaia import CPGaiaInterface
from fwmigrate.vendors.checkpoint.model.gateway import CPGateway, CPGatewayInterface
from fwmigrate.vendors.checkpoint.model.source import CheckPointConfig
from fwmigrate.vendors.checkpoint.model.zone import CPSecurityZone


def test_interface_view_uses_topology_and_keeps_unmatched_gaia_separate():
    zone = CPSecurityZone(uid="z", name="inside")
    gateway_interface = CPGatewayInterface(name="eth0", ipv4_address="192.0.2.1", zone="z")
    gateway = CPGateway(uid="g", name="gateway", interfaces=[gateway_interface])
    gaia_interface = CPGaiaInterface(name="eth0", ipv4_address="192.0.2.2")
    config = CheckPointConfig(
        security_zones=[zone], gateways=[gateway], gaia_interfaces=[gaia_interface],
    )
    before = config.model_dump()

    result = build_checkpoint_derived_views(config).interface_views

    assert len(result.views) == 2
    management, gaia = result.views
    assert management.resolved_zone_uid == "z"
    assert management.management_source is gateway_interface and management.gaia_source is None
    assert management.management_source_present and not management.gaia_source_present
    assert gaia.device_uid is None and gaia.gaia_source is gaia_interface and gaia.management_source is None
    assert gaia.gaia_source_present and not gaia.management_source_present
    assert gaia.issues and "without correlation" in gaia.issues[0].message
    assert config.model_dump() == before


def test_unresolved_zone_and_unmatched_gaia_identity_stay_unknown():
    gateway_interface = CPGatewayInterface(name="eth9", zone="missing-zone")
    gateway = CPGateway(uid="g", name="gateway", interfaces=[gateway_interface])
    gaia_interface = CPGaiaInterface(name="eth9")
    config = CheckPointConfig(gateways=[gateway], gaia_interfaces=[gaia_interface])
    before = config.model_dump()

    views = build_checkpoint_derived_views(config).interface_views.views

    management, gaia = views
    assert management.resolved_zone_uid is None and management.resolved_zone_name is None
    assert management.issues and "missing" in management.issues[0].message
    assert gaia.device_uid is None and gaia.device_name is None
    assert gaia.management_source is None and gaia.gaia_source is gaia_interface
    assert config.model_dump() == before
