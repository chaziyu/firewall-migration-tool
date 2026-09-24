from fwmigrate.vendors.checkpoint.model.gateway import CPGateway, CPCluster
from fwmigrate.vendors.checkpoint.model.source import CheckPointConfig
from fwmigrate.vendors.checkpoint.model.vpn import CPVPNCommunity
from fwmigrate.vendors.checkpoint.model.gaia import CPVTI
from fwmigrate.vendors.checkpoint.relationships.vpn_topology import build_vpn_topology
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
import json
