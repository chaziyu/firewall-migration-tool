from fwmigrate.vendors.checkpoint.model.gateway import CPGateway, CPGatewayInterface
from fwmigrate.vendors.checkpoint.model.source import CheckPointConfig
from fwmigrate.vendors.checkpoint.model.zone import CPSecurityZone
from fwmigrate.vendors.checkpoint.relationships.interface_topology import build_interface_topology


def test_interface_zone_relationship_does_not_mutate_zone():
    zone = CPSecurityZone(uid="z", name="inside")
    gateway = CPGateway(uid="g", name="gateway", interfaces=[CPGatewayInterface(name="eth0", zone="z")])
    config = CheckPointConfig(security_zones=[zone], gateways=[gateway])
    before = config.model_dump()
    topology = build_interface_topology(config)
    assert topology.interfaces[0].resolved_zone is zone
    assert config.model_dump() == before and not hasattr(zone, "members")

