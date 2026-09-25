import json
from fwmigrate.vendors.checkpoint.derived import build_checkpoint_derived_views
from fwmigrate.vendors.checkpoint.model.gateway import CPCluster, CPGateway, CPInteroperableDevice
from fwmigrate.vendors.checkpoint.model.vpn import CPVPNCommunity, CPVPNDomain
from fwmigrate.vendors.checkpoint.model.gaia import CPVTI
from fwmigrate.vendors.checkpoint.model.source import CheckPointConfig
from fwmigrate.vendors.checkpoint.relationships.vpn_topology import build_vpn_topology
from fwmigrate.vendors.checkpoint.relationships.references import CPReferenceKind, CPResolvedReference
from fwmigrate.vendors.checkpoint.source_report import extract_checkpoint_source

def test_vpn_members_and_vti_peer_are_derived():
    gateway = CPGateway(uid="g", name="gateway")
    peer = CPCluster(uid="c", name="cluster")
    community = CPVPNCommunity(uid="comm", name="star", participating_gateways=["g", "c"], center=["g"], satellites=["c"])
    vti = CPVTI(name="vti", gateway="g", peer="c")
    topology = build_vpn_topology(CheckPointConfig(gateways=[gateway], clusters=[peer], vpn_communities=[community], vtis=[vti]))
    assert topology.communities[0].centers == (gateway,) and topology.communities[0].satellites == (peer,)
    assert topology.vtis[0].owning_gateway is gateway and topology.vtis[0].peer is peer

def test_live_community_commands_enter_derived_vpn_topology():
    responses = [
        {"command": "show-gateways-and-servers", "data": {"objects": [{"uid": "g", "name": "gateway", "type": "gateway"}]}},
        {"command": "show-simple-clusters", "data": {"objects": [{"uid": "c", "name": "cluster", "type": "cluster"}]}},
        {"command": "show-vpn-communities-star", "data": {"objects": [{"uid": "star", "name": "star", "participating-gateways": ["g"], "center": ["g"]}]}},
        {"command": "show-vpn-communities-meshed", "data": {"objects": [{"uid": "mesh", "name": "mesh", "participating-gateways": ["g", "c"], "community-type": "mesh"}]}},
        {"command": "show-vpn-communities-remote-access", "data": {"objects": [{"uid": "ra", "name": "remote", "participating-gateways": ["g"]}]}},
    ]
    result = extract_checkpoint_source(json.dumps({"responses": responses}))
    assert {item.uid for item in result.config.vpn_communities} == {"star", "mesh", "ra"}
    assert result.derived.vpn_topology.communities
    star = next(item for item in result.derived.vpn_topology.communities if item.community.uid == "star")
    assert star.centers[0].uid == "g"
    assert star.community.command == "show-vpn-communities-star"
    mesh = next(item for item in result.derived.vpn_topology.communities if item.community.uid == "mesh")
    assert {item.uid for item in mesh.members} == {"g", "c"}

def test_vpn_migration_view_retains_checkpoint_sources_and_shared_relationships():
    gateway = CPGateway(uid="g", name="gateway", vpn={"ike": "source setting"})
    cluster = CPCluster(uid="c", name="cluster")
    interoperable = CPInteroperableDevice(uid="d", name="peer")
    domain = CPVPNDomain(uid="domain", name="network-domain", members=["g", "c", "d"])
    community = CPVPNCommunity(
        uid="community", name="star", community_type="star",
        participating_gateways=["g", "c", "d"], center=["g"], satellites=["c", "d"],
        vpn_domain="domain", ike_properties={"source": "ike"}, ipsec_properties={"source": "ipsec"},
    )
    meshed = CPVPNCommunity(
        uid="mesh-community", name="mesh", community_type="meshed",
        participating_gateways=["g"],
    )
    vti = CPVTI(uid="vti", name="vti0", gateway="g", peer="c")
    config = CheckPointConfig(
        gateways=[gateway], clusters=[cluster], interoperable_devices=[interoperable],
        vpn_domains=[domain], vpn_communities=[community, meshed], vtis=[vti],
    )
    before = config.model_dump()

    derived = build_checkpoint_derived_views(config)
    view = derived.vpn_views.views[0]

    resolved_gateway = derived.references.resolve("g", expected_kinds=(CPReferenceKind.GATEWAY,))
    assert isinstance(resolved_gateway, CPResolvedReference) and resolved_gateway.target is gateway
    assert view.community_source is community
    assert view.member_gateways == (gateway,)
    assert view.member_clusters == (cluster,)
    assert view.member_interoperable_devices == (interoperable,)
    assert view.vpn_domains == (domain,)
    assert view.vtis == (vti,) and view.route_based is True
    assert view.vti_topology[0].owning_gateway is gateway
    assert view.vti_topology[0].vti is vti
    assert view.vti_topology[0].matching_communities == (community,)
    assert view.gateway_vpn_sources == (gateway,)
    assert view.center_members == (gateway,)
    assert view.satellite_members == (cluster, interoperable)
    assert [item.community_type for item in derived.vpn_views.views] == ["star", "meshed"]
    assert isinstance(view.vti_topology[0].vti, CPVTI)
    assert view.ike_properties == community.ike_properties
    assert not hasattr(view, "phase1") and not hasattr(view, "phase2")
    assert derived.references is not None and isinstance(derived.broken_references, tuple)
    assert config.model_dump() == before

def test_multiple_vti_community_candidates_remain_ambiguous():
    gateway = CPGateway(uid="g", name="gateway")
    peer = CPGateway(uid="p", name="peer")
    communities = [
        CPVPNCommunity(uid="star", name="star", community_type="star", participating_gateways=["g", "p"]),
        CPVPNCommunity(uid="mesh", name="mesh", community_type="meshed", participating_gateways=["g", "p"]),
    ]
    vti = CPVTI(uid="vti", name="vti0", gateway="g", peer="p")

    derived = build_checkpoint_derived_views(CheckPointConfig(
        gateways=[gateway, peer], vpn_communities=communities, vtis=[vti],
    ))

    relation = derived.vpn_topology.vtis[0]
    assert relation.vti is vti
    assert relation.matching_communities == tuple(communities)
    assert all(
        any(issue.relationship_status == "ambiguous" for issue in view.issues)
        for view in derived.vpn_views.views
    )

def test_explicit_vti_claims_route_based_vpn_even_when_owner_is_unresolved():
    derived = build_checkpoint_derived_views(CheckPointConfig(vtis=[CPVTI(uid="v", name="vti0")]))
    assert derived.vpn_views.views[0].route_based is True
    assert derived.vpn_views.views[0].vti_topology[0].owning_gateway is None
