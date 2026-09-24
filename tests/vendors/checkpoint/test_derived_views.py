from unittest.mock import patch

from fwmigrate.vendors.checkpoint import derived as derived_module
from fwmigrate.vendors.checkpoint.model.address import CPHost
from fwmigrate.vendors.checkpoint.model.gaia import CPVTI
from fwmigrate.vendors.checkpoint.model.gateway import CPGateway, CPGatewayInterface
from fwmigrate.vendors.checkpoint.model.policy import CPAccessLayer, CPAccessRule, CPPolicyPackage
from fwmigrate.vendors.checkpoint.model.source import CheckPointConfig
from fwmigrate.vendors.checkpoint.model.vpn import CPVPNCommunity
from fwmigrate.vendors.checkpoint.models import CheckPointCollectionDiagnostic, CollectionStatus
from fwmigrate.vendors.checkpoint.relationships.references import build_reference_index


def test_derived_build_reuses_reference_index_and_preserves_source_and_collection():
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
    created_indexes = []

    def make_index(source):
        index = build_reference_index(source)
        created_indexes.append(index)
        return index

    with patch.object(derived_module, "build_reference_index", side_effect=make_index) as build_index:
        derived = derived_module.build_checkpoint_derived_views(config, (diagnostic,))

    build_index.assert_called_once_with(config)
    assert len(created_indexes) == 1
    assert derived.references is created_indexes[0]
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
    assert "collection_incomplete" not in type(config).model_fields
    assert config.model_dump() == before
