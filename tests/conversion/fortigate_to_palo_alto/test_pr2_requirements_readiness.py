from fwmigrate.conversion.fortigate_to_palo_alto import (
    PANDecisionMode, PANMigrationDecision, PANMigrationDecisionSet,
    PANRecommendationReadiness, build_recommendations,
)
from fwmigrate.conversion.fortigate_to_palo_alto.recommendations import decision_value
from fwmigrate.conversion.fortigate_to_palo_alto.requirements import build_mapping_requirements
from fwmigrate.vendors.fortigate.model.dhcp import FGDHCPServer
from fwmigrate.vendors.fortigate.model.sdwan import FGSDWAN, FGSDWANMember
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.fortigate.model.vpn import FGIPsecPhase1
from fwmigrate.vendors.fortigate.model.vpn_ssl import FGSSLVPNAuthenticationRule, FGSSLVPNSettings


def _config():
    return FGConfig(
        dhcp_servers=[FGDHCPServer(id=1, interface="port1")],
        ipsec_phase1=[FGIPsecPhase1(name="vpn-a", interface="port1")],
        sdwans=[FGSDWAN(members=[FGSDWANMember(seq_num=1, interface="port1")])],
        ssl_vpn_settings=[FGSSLVPNSettings(
            source_interface=["port1"],
            authentication_rules=[FGSSLVPNAuthenticationRule(id=1, source_interface=["port2"])],
        )],
    )


def test_pending_mapping_rows_remain_unresolved_and_recommendations_expose_readiness():
    source = _config()
    requirements = build_mapping_requirements(source, object())
    decisions = PANMigrationDecisionSet(tuple(
        PANMigrationDecision(item["source_vdom"], item["kind"], item["source_name"], field)
        for item in requirements["interfaces"]
        for field in item["requires"]
    ))
    recommendations = build_recommendations(source, object(), decisions)
    by_kind = {(item.source_kind, item.source_name): item for item in recommendations}

    dhcp = by_kind[("dhcp_server", "1")]
    assert dhcp.confidence.value == "HIGH"
    assert dhcp.readiness is PANRecommendationReadiness.REQUIRES_DECISION
    assert "Target interface mapping required" in dhcp.blockers
    assert dhcp.required_decision_keys

    vpn = by_kind[("ipsec_phase1", "vpn-a")]
    assert "Target interface mapping required" in vpn.blockers
    assert vpn.readiness is PANRecommendationReadiness.MANUAL_DESIGN

    sdwan = by_kind[("sdwan_member", "1")]
    assert "Target interface mapping required" in sdwan.blockers
    assert sdwan.readiness is PANRecommendationReadiness.REQUIRES_DECISION

    ssl_vpn = by_kind[("ssl_vpn_settings", "settings-root-0")]
    assert len(ssl_vpn.required_decision_keys) == 2
    assert "Target interface mapping required for port1" in ssl_vpn.blockers
    assert "Target interface mapping required for port2" in ssl_vpn.blockers
    assert ssl_vpn.readiness is PANRecommendationReadiness.MANUAL_DESIGN
    assert ssl_vpn.to_dict()["readiness"] == "MANUAL_DESIGN"


def test_confirmed_interface_value_resolves_mapping_blockers():
    source = _config()
    requirements = build_mapping_requirements(source, object())
    pending = PANMigrationDecisionSet(tuple(
        PANMigrationDecision(item["source_vdom"], item["kind"], item["source_name"], field)
        for item in requirements["interfaces"]
        for field in item["requires"]
    ))
    confirmed = PANMigrationDecisionSet(tuple(
        decision.confirm("ethernet1/1" if decision.source_name == "port1" else "ethernet1/2")
        for decision in pending.decisions
    ))
    recommendations = build_recommendations(source, object(), confirmed)
    by_kind = {(item.source_kind, item.source_name): item for item in recommendations}

    assert "Target interface mapping required" not in by_kind[("dhcp_server", "1")].blockers
    assert "Target interface mapping required" not in by_kind[("ipsec_phase1", "vpn-a")].blockers
    assert "Target interface mapping required" not in by_kind[("sdwan_member", "1")].blockers
    assert not any("Target interface mapping required for" in blocker for blocker in by_kind[("ssl_vpn_settings", "settings-root-0")].blockers)
    assert by_kind[("ssl_vpn_settings", "settings-root-0")].readiness is PANRecommendationReadiness.MANUAL_DESIGN


def test_decision_value_requires_a_supported_nonempty_auto_or_confirmed_value():
    pending = PANMigrationDecision("root", "interface", "port1", "target_interface")
    confirmed_empty = pending.confirm()
    unsupported_confirmed = PANMigrationDecision(
        "root", "interface", "port1", "target_interface", value="ethernet1/1",
        mode=PANDecisionMode.UNSUPPORTED,
    ).confirm()
    decisions = PANMigrationDecisionSet((pending,))
    assert decision_value(decisions, pending.key) is None
    assert decision_value(PANMigrationDecisionSet((confirmed_empty,)), pending.key) is None
    assert decision_value(PANMigrationDecisionSet((unsupported_confirmed,)), pending.key) is None
    auto = PANMigrationDecision(
        "root", "interface", "port1", "target_interface", value="ethernet1/1", mode=PANDecisionMode.AUTO,
    )
    assert decision_value(PANMigrationDecisionSet((auto,)), auto.key) == "ethernet1/1"
