from fwmigrate.vendors.checkpoint.model.address import CPHost
from fwmigrate.vendors.checkpoint.model.gaia import CPVTI
from fwmigrate.vendors.checkpoint.model.gateway import CPGateway, CPGatewayInterface
from fwmigrate.vendors.checkpoint.model.policy import CPAccessLayer, CPAccessRule, CPPolicyPackage
from fwmigrate.vendors.checkpoint.model.source import CheckPointConfig
from fwmigrate.vendors.checkpoint.model.vpn import CPVPNCommunity
from fwmigrate.vendors.checkpoint.models import CheckPointCollectionDiagnostic, CollectionStatus
from fwmigrate.vendors.checkpoint.derived import build_checkpoint_derived_views


def test_derived_build_populates_views_and_preserves_source_and_collection():
    layer = CPAccessLayer(uid="layer", name="Layer", package_uid="package")
    package = CPPolicyPackage(uid="package", name="Package", access_layers=["layer"])
    rule = CPAccessRule(uid="rule", name="Rule", layer_uid="layer", inline_layer="missing-layer")
    gateway = CPGateway(
        uid="gateway", name="Gateway",
        interfaces=[CPGatewayInterface(name="eth0", zone="missing-zone")],
    )
    host = CPHost(uid="host", name="Host", nat_settings={"auto-rule": True})
    community = CPVPNCommunity(
        uid="community", name="Community", community_type="star",
        participating_gateways=["missing-gateway"],
    )
    vti = CPVTI(uid="vti", name="vti0", gateway="missing-gateway")
    config = CheckPointConfig(
        policy_packages=[package], access_layers=[layer], access_rules=[rule],
        gateways=[gateway], hosts=[host], vpn_communities=[community], vtis=[vti],
    )
    before = config.model_dump()
    diagnostic = CheckPointCollectionDiagnostic(
        command="show-hosts", source_plane="management", status=CollectionStatus.API_ERROR,
        complete=False, error="collection failed",
    )
    derived = build_checkpoint_derived_views(config, (diagnostic,))

    assert derived.references.by_uid and derived.references.by_name
    assert derived.policy_structure.package_layers
    assert derived.interface_topology.interfaces
    assert derived.vpn_topology.communities and derived.vpn_topology.vtis
    assert derived.nat.views and derived.policy_traversal.entries
    assert derived.interface_views.views and derived.vpn_views.views
    assert derived.policy_traversal.issues
    assert derived.interface_views.issues
    assert derived.vpn_views.issues
    assert derived.nat.issues
    assert derived.collection_incomplete == (diagnostic,)
    assert config.model_dump() == before
