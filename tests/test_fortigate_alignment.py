import pytest
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.model import FGConfig, FGPolicy
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer
from fwmigrate.generators.palo_alto.transformer import IRToPANOSTransformer
from fwmigrate.generators.palo_alto.xml_generator import PANOSXMLGenerator
from fwmigrate.ir.core import (
    ServiceProtocol,
    AddressType,
    PolicyAction,
    MigrationConfidence,
)
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

def test_system_zone_is_preserved_without_interface_inference():
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

    assert "trust" not in zone_names
    assert "untrust" not in zone_names
    interfaces = {interface.name: interface for interface in ir.interfaces}
    assert interfaces["internal1"].zone is None
    assert interfaces["internal3"].zone is None
    assert interfaces["wan2"].zone is None
    assert interfaces["wan2"].role == "wan"

    # Verify policy 10 resolved to_zone as Azure-GSAP
    pol_lan_az = next(p for p in ir.policies if p.name == "LAN_to_Azure")
    assert pol_lan_az.from_zone == []
    assert pol_lan_az.to_zone == ["Azure-GSAP"]


@pytest.mark.parametrize(
    "interface_name",
    ["wan1", "port1", "internal1", "LAN", "internet", "unifi_port1", "dmz-port"],
)
def test_interface_names_do_not_imply_canonical_zones(interface_name):
    fg = parse_fortigate_config(f"""
config system interface
    edit "{interface_name}"
        set role wan
    next
end
""")
    ir = FGToIRTransformer(fg).transform()

    assert ir.interfaces[0].zone is None
    assert ir.interfaces[0].role == "wan"
    assert ir.zones == []


def test_explicit_system_sdwan_and_caller_zone_mappings_are_preserved():
    fg = parse_fortigate_config("""
config system interface
    edit "port2"
        set role lan
    next
    edit "wan1"
        set role wan
    next
    edit "port3"
        set role dmz
    next
end
config system zone
    edit "LAN_ZONE"
        set interface "port2"
    next
end
config system sdwan
    config zone
        edit "ISP_ZONE"
        next
    end
    config members
        edit 1
            set interface "wan1"
            set zone "ISP_ZONE"
        next
    end
end
""")
    ir = FGToIRTransformer(fg, zone_mapping={"port3": "External"}).transform()
    interfaces = {interface.name: interface for interface in ir.interfaces}
    zones = {zone.name: zone.interfaces for zone in ir.zones}

    assert interfaces["port2"].zone == "LAN_ZONE"
    assert interfaces["wan1"].zone == "ISP_ZONE"
    assert interfaces["port3"].zone == "External"
    assert zones == {
        "LAN_ZONE": ["port2"],
        "ISP_ZONE": ["wan1"],
        "External": ["port3"],
    }


def test_policy_zone_resolution_preserves_mixed_source_references():
    fg = parse_fortigate_config("""
config system interface
    edit "port1"
    next
    edit "port2"
    next
end
config system zone
    edit "LAN_ZONE"
        set interface "port2"
    next
end
config firewall policy
    edit 10
        set srcintf "port1" "port1" "LAN_ZONE"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
    next
end
""")
    ir = FGToIRTransformer(fg).transform()
    policy = ir.policies[0]

    assert policy.source_from_interfaces == ["port1", "port1", "LAN_ZONE"]
    assert policy.source_to_interfaces == ["port1"]
    assert policy.from_zone == ["LAN_ZONE"]
    assert policy.to_zone == []
    zone_audits = [
        entry for entry in ir.audit_entries
        if entry.category == "Policy Zone Resolution"
    ]
    assert [entry.id for entry in zone_audits] == [
        "policy:10:source:port1",
        "policy:10:destination:port1",
    ]
    assert all(entry.confidence == MigrationConfidence.MANUAL for entry in zone_audits)


def test_service_port_range_and_wildcard_fqdn():
    fg = parse_fortigate_config(SAMPLE_FGT_CONFIG)
    transformer = FGToIRTransformer(fg)
    ir = transformer.transform()

    # Destination and source port constraints remain distinct.
    sap_svc = next(s for s in ir.services if s.name == "SAP Remote Port")
    assert sap_svc.ports[0].port == "3299"
    assert sap_svc.ports[0].source_port == "0-65335"
    assert sap_svc.ports[0].raw_source_value == "3299:0-65335"
    assert sap_svc.ports[0].protocol == ServiceProtocol.TCP

    web_proxy = next(s for s in ir.services if s.name == "WebProxyAll")
    assert web_proxy.ports[0].port == "0-65535"
    assert web_proxy.ports[0].source_port == "0-65535"

    range_svc = next(s for s in ir.services if s.name == "TCP_8081-8089")
    assert range_svc.ports[0].port == "8081-8089"

    # Source IR preserves FortiGate wildcard syntax exactly.
    google_play = next(a for a in ir.addresses if a.name == "google-play")
    assert google_play.value == "*play.google.com"

    box = next(a for a in ir.addresses if a.name == "box")
    assert box.value == "*.box.com"

    # PAN-OS-specific formatting is applied only in target transformation.
    pan_config = IRToPANOSTransformer(ir).transform()
    pan_google_play = next(
        item
        for item in pan_config.vsys.addresses
        if item.name == "google-play"
    )
    assert pan_google_play.fqdn == "*.play.google.com"
    assert google_play.value == "*play.google.com"


def test_panos_xml_no_empty_protocol_and_icmp_mapping():
    fg = parse_fortigate_config(SAMPLE_FGT_CONFIG)
    transformer = FGToIRTransformer(
        fg,
        zone_mapping={
            "internal1": "trust",
            "wan2": "untrust",
        },
    )
    ir = transformer.transform()

    pan_transformer = IRToPANOSTransformer(ir)
    pan_config = pan_transformer.transform()

    # Verify ALL_ICMP is not in custom service objects
    service_names = [s.name for s in pan_config.vsys.services]
    assert "ALL_ICMP" not in service_names
    assert "SAP Remote Port" not in service_names

    # The group is withheld because none of its members can be represented
    # without losing ICMP or source-port semantics.
    assert "SAP_Group" not in [
        group.name for group in pan_config.vsys.service_groups
    ]

    # Verify policy 10 has application icmp and service "SAP Remote Port"
    pan_rule = next(r for r in pan_config.vsys.security_rules if r.name == "LAN_to_Azure")
    assert "icmp" in pan_rule.application
    assert "SAP Remote Port" in pan_rule.service

    # Generate XML and verify no empty <protocol/>
    generator = PANOSXMLGenerator()
    artifacts = generator.generate(ir)
    xml_content = artifacts[0].content

    assert "<protocol/>" not in xml_content
    assert "<port>3299</port>" not in xml_content
    assert "<entry name=\"Azure-GSAP\">" in xml_content
    assert any(
        entry.id == "SAP Remote Port"
        and entry.confidence.value == "manual"
        for entry in ir.audit_entries
    )


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

def test_policy_preserves_ssl_profile_with_utm_enabled():
    ir = _transform_single_policy(
        FGPolicy(
            id=103,
            srcaddr=["all"],
            dstaddr=["all"],
            service=["ALL"],
            action="accept",
            utm_status="enable",
            ssl_ssh_profile="deep-inspection",
            ips_sensor="default",
        )
    )

    policy = ir.policies[0]

    assert policy.ssl_ssh_profile == "deep-inspection"
    assert policy.ips_sensor == "default"

def test_policy_preserves_source_values_beside_normalized_values():
    ir = _transform_single_policy(FGPolicy(
        id=24,
        srcaddr=["all"],
        dstaddr=["all"],
        service=["ALL"],
        action="accept",
        schedule="always",
    ))

    policy = ir.policies[0]
    assert policy.source_address_references == ["all"]
    assert policy.destination_address_references == ["all"]
    assert policy.source_service_references == ["ALL"]
    assert policy.source_action == "accept"
    assert policy.source_schedule == "always"

    assert policy.source == [IR_KEYWORD_ANY]
    assert policy.destination == [IR_KEYWORD_ANY]
    assert policy.service == [IR_KEYWORD_ANY]
    assert policy.action == PolicyAction.ALLOW
    assert policy.schedule is None
    assert ir.nat_rules == []
    assert not any(
        entry.confidence == MigrationConfidence.MANUAL
        for entry in ir.audit_entries
    )


def test_policy_preserves_nat_and_ip_pool_source_fields():
    ir = _transform_single_policy(FGPolicy(
        id=25,
        uuid="0819b852-ebb4-51eb-210e-517744c1e41b",
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
    assert policy.source_uuid == "0819b852-ebb4-51eb-210e-517744c1e41b"
    assert policy.source_from_interfaces == ["LAN"]
    assert policy.source_to_interfaces == ["WAN"]
    assert policy.source_log_setting == "all"
    assert policy.nat_enabled is True
    assert policy.nat_pool_enabled is True
    assert policy.nat_pool_names == ["PUBLIC_POOL"]
    assert policy.source == ["USER_NETWORK"]
    assert policy.destination == [IR_KEYWORD_ANY]
    assert policy.action == PolicyAction.ALLOW
    assert len(ir.nat_rules) == 1
    assert ir.nat_rules[0].source_pool_references == ["PUBLIC_POOL"]
    assert ir.nat_rules[0].requires_manual_review is True


def test_policy_preserves_identity_selectors_without_normalization():
    ir = _transform_single_policy(FGPolicy(
        id=100,
        name="Identity_Test",
        srcintf=["LAN"],
        dstintf=["WAN"],
        srcaddr=["all"],
        dstaddr=["all"],
        groups=["SSLVPN Users", "Domain_Users"],
        users=["alice", "bob.smith"],
        service=["ALL"],
        action="accept",
    ))

    policy = ir.policies[0]
    assert policy.source_user_groups == ["SSLVPN Users", "Domain_Users"]
    assert policy.source_users == ["alice", "bob.smith"]


def test_policy_preserves_inspection_ztna_and_extra_source_settings():
    ir = _transform_single_policy(FGPolicy(
        id=102,
        inspection_mode="proxy",
        ztna_status="enable",
        ztna_ems_tag=["TAG_A", "TAG_B"],
        extra_settings={
            "timeout_send_rst": "enable",
            "port_preserve": "disable",
        },
    ))

    policy = ir.policies[0]
    assert policy.source_inspection_mode == "proxy"
    assert policy.source_ztna_status == "enable"
    assert policy.source_ztna_ems_tags == ["TAG_A", "TAG_B"]
    assert policy.source_extra_settings == {
        "timeout_send_rst": "enable",
        "port_preserve": "disable",
    }


def test_policy_identity_selector_defaults_are_empty_lists():
    source_policy = FGPolicy(id=101)
    ir_policy = _transform_single_policy(source_policy).policies[0]

    assert source_policy.groups == []
    assert source_policy.users == []
    assert ir_policy.source_user_groups == []
    assert ir_policy.source_users == []


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
    assert policy.source_uuid is None
    assert policy.nat_enabled is True
    assert policy.nat_pool_enabled is False
    assert policy.nat_pool_names == []
    assert len(ir.nat_rules) == 1
    assert ir.nat_rules[0].source_translation_mode.value == "interface-address"


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


def test_fortigate_policy_security_profiles_preserve_explicit_values_without_invented_defaults():
    # Case 1: Partial UTM - only IPS and SSL-SSH specified
    config_partial = """
config firewall policy
    edit 10
        set name "Partial_UTM"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set utm-status enable
        set ips-sensor "default"
        set ssl-ssh-profile "certificate-inspection"
    next
end
"""
    fg_partial = parse_fortigate_config(config_partial)
    ir_partial = FGToIRTransformer(fg_partial).transform()

    pol_partial = ir_partial.policies[0]
    assert pol_partial.antivirus is None
    assert pol_partial.ips_sensor == "default"
    assert pol_partial.webfilter is None
    assert pol_partial.application_list is None
    assert pol_partial.ssl_ssh_profile == "certificate-inspection"
    assert pol_partial.security_profile_group == "SPG_IPS_default"

    assert len(ir_partial.security_profile_groups) == 1
    spg_partial = ir_partial.security_profile_groups[0]
    assert spg_partial.name == "SPG_IPS_default"
    assert spg_partial.antivirus is None
    assert spg_partial.vulnerability == "default"
    assert spg_partial.anti_spyware is None
    assert spg_partial.url_filtering is None
    assert spg_partial.file_blocking is None
    assert spg_partial.wildfire is None
    assert spg_partial.ssl_decryption == "certificate-inspection"

    # Case 2: Explicit AV="default" is preserved, not invented
    config_explicit_av = """
config firewall policy
    edit 20
        set name "Explicit_AV_UTM"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set utm-status enable
        set av-profile "default"
    next
end
"""
    fg_av = parse_fortigate_config(config_explicit_av)
    ir_av = FGToIRTransformer(fg_av).transform()

    pol_av = ir_av.policies[0]
    assert pol_av.antivirus == "default"
    assert pol_av.ips_sensor is None
    assert pol_av.webfilter is None
    assert pol_av.application_list is None
    assert pol_av.ssl_ssh_profile is None
    assert pol_av.security_profile_group == "SPG_AV_default"

    assert len(ir_av.security_profile_groups) == 1
    spg_av = ir_av.security_profile_groups[0]
    assert spg_av.name == "SPG_AV_default"
    assert spg_av.antivirus == "default"
    assert spg_av.vulnerability is None
    assert spg_av.anti_spyware is None
    assert spg_av.url_filtering is None
    assert spg_av.file_blocking is None
    assert spg_av.wildfire is None
    assert spg_av.ssl_decryption is None
