from fwmigrate.vendors.checkpoint.extraction import extract_checkpoint_config
from fwmigrate.vendors.checkpoint.models import CheckPointExportBundle
from fwmigrate.vendors.checkpoint.derived import build_checkpoint_derived_views
from fwmigrate.vendors.checkpoint.model.gaia import CPGaiaInterface
from fwmigrate.vendors.checkpoint.model.gateway import CPGateway, CPGatewayInterface
from fwmigrate.vendors.checkpoint.model.source import CheckPointConfig
from fwmigrate.vendors.checkpoint.model.zone import CPSecurityZone
from fwmigrate.vendors.checkpoint.relationships.interface_topology import build_interface_topology
from fwmigrate.vendors.checkpoint.validation import validate_checkpoint_config

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
    assert relation.assignment_source is None

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

def test_gaia_interface_correlates_only_from_explicit_gateway_identity():
    management_interface = CPGatewayInterface(name="eth0", ipv4_address="192.0.2.1")
    gateway = CPGateway(uid="g", name="gateway", interfaces=[management_interface])
    gaia_interface = CPGaiaInterface(
        name="eth0", gateway="g", ipv4_address="192.0.2.2", explicit_fields=("gateway",),
    )
    config = CheckPointConfig(gateways=[gateway], gaia_interfaces=[gaia_interface])
    before = config.model_dump()

    view, = build_checkpoint_derived_views(config).interface_views.views

    assert view.device_uid == "g"
    assert view.management_source is management_interface and view.gaia_source is gaia_interface
    assert view.management_source_present and view.gaia_source_present
    assert config.model_dump() == before

def test_gaia_interface_keeps_device_association_when_interface_name_is_unknown():
    gateway = CPGateway(uid="g", name="gateway")
    source = CPGaiaInterface(name="eth9", gateway="g", explicit_fields=("gateway",))
    view, = build_checkpoint_derived_views(CheckPointConfig(gateways=[gateway], gaia_interfaces=[source])).interface_views.views

    assert view.device_uid == "g" and view.device_kind == "gateway"
    assert view.management_source is None and view.gaia_source is source

def test_gaia_interface_ambiguous_gateway_identity_is_a_structured_finding():
    config = CheckPointConfig(
        gateways=[CPGateway(uid="g1", name="gateway"), CPGateway(uid="g2", name="gateway")],
        gaia_interfaces=[CPGaiaInterface(name="eth0", gateway="gateway", explicit_fields=("gateway",))],
    )
    derived = build_checkpoint_derived_views(config)

    assert any(issue.source_field == "gateway" and issue.status == "ambiguous"
               for issue in derived.interface_topology.issues)
    assert any(issue.code == "interface_correlation_ambiguous"
               for issue in validate_checkpoint_config(config, derived).issues)
