import pytest
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.model import FGConfig, FGPolicy
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer
from fwmigrate.generators.palo_alto.transformer import IRToPANOSTransformer
from fwmigrate.generators.palo_alto.xml_generator import PANOSXMLGenerator
from fwmigrate.ir.core import ServiceProtocol, AddressType, PolicyAction
from fwmigrate.core.constants import IR_KEYWORD_ANY

SAMPLE_FGT_CONFIG = """
config system global
    set hostname "FGT-TEST-ALIGN"
end

config system zone
    edit "Azure-GSAP"
        set interface "AzVPN-JPNWest1" "AzVPN-JPNEast1"
    next
end

config system interface
    edit "internal1"
        set vdom "root"
        set ip 172.18.56.1 255.255.255.128
        set alias "Internal_LAN"
    next
    edit "internal3"
        set vdom "root"
        set ip 192.168.50.1 255.255.255.252
        set alias "Polycom LAN"
    next
    edit "wan2"
        set vdom "root"
        set ip 203.115.250.139 255.255.255.248
        set role wan
    next
    edit "AzVPN-JPNWest1"
        set vdom "root"
        set type tunnel
    next
    edit "AzVPN-JPNEast1"
        set vdom "root"
        set type tunnel
    next
end

config firewall wildcard-fqdn custom
    edit "google-play"
        set wildcard-fqdn "*play.google.com"
    next
    edit "box"
        set wildcard-fqdn "*.box.com"
    next
end

config firewall service custom
    edit "ALL_ICMP"
        set protocol ICMP
    next
    edit "SAP Remote Port"
        set tcp-portrange 3299:0-65335
    next
    edit "TCP_8081-8089"
        set tcp-portrange 8081-8089
    next
    edit "WebProxyAll"
        set tcp-portrange 0-65535:0-65535
    next
end

config firewall service group
    edit "SAP_Group"
        set member "ALL_ICMP" "SAP Remote Port"
    next
end

config firewall policy
    edit 10
        set name "LAN_to_Azure"
        set srcintf "internal1"
        set dstintf "Azure-GSAP"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL_ICMP" "SAP Remote Port"
    next
    edit 40
        set name "Bad-IP-NTT"
        set srcintf "internal1"
        set dstintf "wan2"
        set srcaddr "Emotet-03Oct2022"
        set dstaddr "Bad-IP" "Emotet1" "Emotet2" "Emotet3" "Emotet4" "Botnet-28Nov"
        set action deny
        set schedule "always"
        set service "ALL"
    next
end
"""

def test_system_zone_and_interface_inference():
    fg = parse_fortigate_config(SAMPLE_FGT_CONFIG)
    assert len(fg.system_zones) == 1
    assert fg.system_zones[0].name == "Azure-GSAP"
    assert "AzVPN-JPNWest1" in fg.system_zones[0].interface

    transformer = FGToIRTransformer(fg)
    ir = transformer.transform()

    # Verify zones in IR
    zone_names = {z.name: z.interfaces for z in ir.zones}
    assert "Azure-GSAP" in zone_names
    assert "AzVPN-JPNWest1" in zone_names["Azure-GSAP"]
    assert "AzVPN-JPNEast1" in zone_names["Azure-GSAP"]

    # Verify internal1 and internal3 inferred as trust
    assert "trust" in zone_names
    assert "internal1" in zone_names["trust"]
    assert "internal3" in zone_names["trust"]

    # Verify wan2 is in untrust
    assert "untrust" in zone_names
    assert "wan2" in zone_names["untrust"]

    # Verify policy 10 resolved to_zone as Azure-GSAP
    pol_lan_az = next(p for p in ir.policies if p.name == "LAN_to_Azure")
    assert pol_lan_az.from_zone == ["trust"]
    assert pol_lan_az.to_zone == ["Azure-GSAP"]


def test_service_port_range_and_wildcard_fqdn():
    fg = parse_fortigate_config(SAMPLE_FGT_CONFIG)
    transformer = FGToIRTransformer(fg)
    ir = transformer.transform()

    # Verify port range cleaning
    sap_svc = next(s for s in ir.services if s.name == "SAP Remote Port")
    assert sap_svc.ports[0].port == "3299"
    assert sap_svc.ports[0].protocol == ServiceProtocol.TCP

    web_proxy = next(s for s in ir.services if s.name == "WebProxyAll")
    assert web_proxy.ports[0].port == "1-65535"

    range_svc = next(s for s in ir.services if s.name == "TCP_8081-8089")
    assert range_svc.ports[0].port == "8081-8089"

    # Verify wildcard FQDN normalization
    google_play = next(a for a in ir.addresses if a.name == "google-play")
    assert google_play.value == "*.play.google.com"

    box = next(a for a in ir.addresses if a.name == "box")
    assert box.value == "*.box.com"


def test_panos_xml_no_empty_protocol_and_icmp_mapping():
    fg = parse_fortigate_config(SAMPLE_FGT_CONFIG)
    transformer = FGToIRTransformer(fg)
    ir = transformer.transform()

    pan_transformer = IRToPANOSTransformer(ir)
    pan_config = pan_transformer.transform()

    # Verify ALL_ICMP is not in custom service objects
    service_names = [s.name for s in pan_config.vsys.services]
    assert "ALL_ICMP" not in service_names
    assert "SAP Remote Port" in service_names

    # Verify SAP_Group only contains valid TCP/UDP services
    sap_grp = next(g for g in pan_config.vsys.service_groups if g.name == "SAP_Group")
    assert "ALL_ICMP" not in sap_grp.members
    assert "SAP Remote Port" in sap_grp.members

    # Verify policy 10 has application icmp and service "SAP Remote Port"
    pan_rule = next(r for r in pan_config.vsys.security_rules if r.name == "LAN_to_Azure")
    assert "icmp" in pan_rule.application
    assert "SAP Remote Port" in pan_rule.service

    # Generate XML and verify no empty <protocol/>
    generator = PANOSXMLGenerator()
    artifacts = generator.generate(ir)
    xml_content = artifacts[0].content

    assert "<protocol/>" not in xml_content
    assert "<port>3299</port>" in xml_content
    assert "<entry name=\"Azure-GSAP\">" in xml_content


from fwmigrate.core.optimizer import RuleOptimizer

def test_policy_anomaly_audit():
    fg = parse_fortigate_config(SAMPLE_FGT_CONFIG)
    transformer = FGToIRTransformer(fg)
    ir = transformer.transform()
    
    # Run the new generic optimizer that fixes this
    optimizer = RuleOptimizer(ir)
    optimizer.fix_outbound_threat_source_anomalies()

    # Verify audit entry for rule anomaly was generated by the optimizer
    audit_msgs = [e.message for e in ir.audit_entries if e.category == "Policy Optimization"]
    assert any("Automatically fixed source field anomaly in outbound block rule 'Bad-IP-NTT'" in m for m in audit_msgs)


def _transform_single_policy(policy: FGPolicy):
    return FGToIRTransformer(FGConfig(policies=[policy])).transform()


def test_policy_preserves_nat_and_ip_pool_source_fields():
    ir = _transform_single_policy(FGPolicy(
        id=25,
        name="Users_to_Internet",
        srcintf=["LAN"],
        dstintf=["WAN"],
        srcaddr=["USER_NETWORK"],
        dstaddr=["all"],
        service=["ALL"],
        action="accept",
        logtraffic="all",
        nat="enable",
        ippool="enable",
        poolname=["PUBLIC_POOL"],
    ))

    policy = ir.policies[0]
    assert policy.source_rule_id == "25"
    assert policy.source_from_interfaces == ["LAN"]
    assert policy.source_to_interfaces == ["WAN"]
    assert policy.source_log_setting == "all"
    assert policy.nat_enabled is True
    assert policy.nat_pool_enabled is True
    assert policy.nat_pool_names == ["PUBLIC_POOL"]
    assert policy.source == ["USER_NETWORK"]
    assert policy.destination == [IR_KEYWORD_ANY]
    assert policy.action == PolicyAction.ALLOW
    assert ir.nat_rules == []


def test_policy_preserves_nat_enabled_without_ip_pool():
    ir = _transform_single_policy(FGPolicy(
        id=26,
        srcintf=["LAN"],
        dstintf=["WAN"],
        srcaddr=["all"],
        dstaddr=["all"],
        service=["ALL"],
        nat="enable",
    ))

    policy = ir.policies[0]
    assert policy.nat_enabled is True
    assert policy.nat_pool_enabled is False
    assert policy.nat_pool_names == []
    assert ir.nat_rules == []


def test_policy_preserves_nat_disabled():
    ir = _transform_single_policy(FGPolicy(
        id=27,
        srcintf=["LAN"],
        dstintf=["WAN"],
        srcaddr=["all"],
        dstaddr=["all"],
        service=["ALL"],
    ))

    policy = ir.policies[0]
    assert policy.nat_enabled is False
    assert policy.nat_pool_enabled is False
    assert policy.nat_pool_names == []
    assert ir.nat_rules == []
