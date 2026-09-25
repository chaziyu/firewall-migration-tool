import json
from copy import deepcopy
from types import SimpleNamespace

from fwmigrate.conversion.fortigate_to_palo_alto import (
    PANMigrationDecision,
    PANMigrationDecisionSet,
    PANDecisionReviewState,
    build_recommendations,
    make_decision_key,
)
from fwmigrate.conversion.fortigate_to_palo_alto.interface_candidates import viable_candidate
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.fortigate.model.dhcp import FGDHCPIPRange, FGDHCPReservedAddress, FGDHCPServer
from fwmigrate.vendors.fortigate.model.external_resource import FGExternalResource
from fwmigrate.vendors.fortigate.model.ips import FGIPSSensor, FGIPSSensorEntry
from fwmigrate.vendors.fortigate.model.sdwan import FGSDWAN, FGSDWANHealthCheck, FGSDWANMember
from fwmigrate.vendors.fortigate.model.user import FGLocalUser
from fwmigrate.vendors.fortigate.model.vpn import FGIPsecPhase1, FGIPsecPhase2
from fwmigrate.vendors.fortigate.model.vpn_ssl import FGSSLVPNPortal


def test_recommendations_are_immutable_source_safe_and_feature_scoped():
    config = FGConfig(
        dhcp_servers=[FGDHCPServer(id=1, interface="port3", default_gateway="10.0.0.1", ip_ranges=[FGDHCPIPRange(start_ip="10.0.0.10", end_ip="10.0.0.20")], reserved_addresses=[FGDHCPReservedAddress(ip="10.0.0.11", mac="aa:bb")])],
        local_users=[FGLocalUser(name="alice", password_configured=True)],
        ipsec_phase1=[FGIPsecPhase1(name="vpn-a", interface="port1", psk_configured=True, proposal=["aes256-sha256"])],
        ipsec_phase2=[FGIPsecPhase2(name="vpn-a-p2", phase1name="vpn-a", src_start_ip="10.1.0.1", src_end_ip="10.1.0.10", dst_subnet="10.2.0.0/24")],
        ips_sensors=[FGIPSSensor(name="ips-a", entries=[FGIPSSensorEntry(cve=["CVE-1"], action="drop")])],
        sdwans=[FGSDWAN(members=[FGSDWANMember(seq_num=1, interface="port1")], health_checks=[FGSDWANHealthCheck(name="hc", server="198.51.100.1")])],
        ssl_vpn_portals=[FGSSLVPNPortal(name="employees", split_tunneling="enable")],
        external_resources=[FGExternalResource(name="feed", resource="https://example.test/feed", type="category", refresh_rate=60)],
    )
    before = deepcopy(config.model_dump())
    decisions = PANMigrationDecisionSet((PANMigrationDecision("root", "interface", "port3", "target_interface"),))
    recommendations = build_recommendations(config, SimpleNamespace(), decisions)

    assert isinstance(recommendations, tuple)
    assert {item.family for item in recommendations} == {"DHCP", "VPN", "Users/Admin", "Security", "SD-WAN", "SSL VPN", "External Resource"}
    serialized = json.dumps([item.to_dict() for item in recommendations])
    assert "aa:bb" not in serialized
    assert "CVE-1" not in serialized
    assert "https://example.test/feed" in serialized
    assert config.model_dump() == before
    assert all("confirmed" not in item.to_dict() and "planner_value" not in item.to_dict() for item in recommendations)


def test_target_candidate_evidence_requires_strong_noncontradicting_facts():
    source = SimpleNamespace(name="vlan100", alias="Users", description=None, type="vlan", vlanid=100, ip="10.0.0.1/24")
    target = SimpleNamespace(name="ethernet1/1.100", comment="Users", interface_family="vlan", tag="100", parent="ethernet1/1", ipv4_addresses=["10.0.0.2/24"])
    topology = SimpleNamespace(parent="ethernet1/1")
    valid, strong, supporting, contradictions = viable_candidate(source, target, topology, "ethernet1/1")
    assert valid
    assert "same subnet + VLAN + confirmed parent" in strong
    assert "VLAN 100" in supporting
    assert not contradictions

    mismatch = SimpleNamespace(**{**target.__dict__, "tag": "200"})
    assert viable_candidate(source, mismatch, topology, "ethernet1/1")[0] is False
