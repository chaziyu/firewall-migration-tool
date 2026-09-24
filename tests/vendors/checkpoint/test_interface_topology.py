from fwmigrate.vendors.checkpoint.model.gateway import CPGateway, CPGatewayInterface
from fwmigrate.vendors.checkpoint.model.source import CheckPointConfig
from fwmigrate.vendors.checkpoint.model.zone import CPSecurityZone
from fwmigrate.vendors.checkpoint.relationships.interface_topology import build_interface_topology
from fwmigrate.vendors.checkpoint.extraction import extract_checkpoint_config
from fwmigrate.vendors.checkpoint.models import CheckPointExportBundle


def test_interface_zone_relationship_does_not_mutate_zone():
    zone = CPSecurityZone(uid="z", name="inside")
    gateway = CPGateway(uid="g", name="gateway", interfaces=[CPGatewayInterface(name="eth0", zone="z")])
    config = CheckPointConfig(security_zones=[zone], gateways=[gateway])
    before = config.model_dump()
    topology = build_interface_topology(config)
    assert topology.interfaces[0].resolved_zone is zone
    assert config.model_dump() == before and not hasattr(zone, "members")


def test_native_security_zone_field_reaches_interface_relationship():
    bundle = CheckPointExportBundle.model_validate({"responses": [
        {"command": "show-security-zones", "data": {"objects": [{"uid": "z", "name": "inside", "type": "security-zone"}]}},
        {"command": "show-gateways-and-servers", "data": {"objects": [{"uid": "g", "name": "gateway", "type": "gateway",
          "interfaces": [{"name": "eth0", "security-zone": {"uid": "z", "name": "inside"}}]}]}},
    ]})
    config = extract_checkpoint_config(bundle).config
    relation = build_interface_topology(config).interfaces[0]
    assert relation.resolved_zone.name == "inside"
