from fwmigrate.vendors.checkpoint.model.gateway import CPGateway, CPCluster
from fwmigrate.vendors.checkpoint.model.source import CheckPointConfig
from fwmigrate.vendors.checkpoint.model.vpn import CPVPNCommunity
from fwmigrate.vendors.checkpoint.model.gaia import CPVTI
from fwmigrate.vendors.checkpoint.relationships.vpn_topology import build_vpn_topology


def test_vpn_members_and_vti_peer_are_derived():
    gateway = CPGateway(uid="g", name="gateway")
    peer = CPCluster(uid="c", name="cluster")
    community = CPVPNCommunity(uid="comm", name="star", participating_gateways=["g", "c"], center=["g"], satellites=["c"])
    vti = CPVTI(name="vti", gateway="g", peer="c")
    topology = build_vpn_topology(CheckPointConfig(gateways=[gateway], clusters=[peer], vpn_communities=[community], vtis=[vti]))
    assert topology.communities[0].centers == (gateway,) and topology.communities[0].satellites == (peer,)
    assert topology.vtis[0].owning_gateway is gateway and topology.vtis[0].peer is peer

