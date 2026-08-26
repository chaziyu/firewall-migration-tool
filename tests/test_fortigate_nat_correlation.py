from fwmigrate.generators.palo_alto.transformer import IRToPANOSTransformer
from fwmigrate.generators.palo_alto.terraform_generator import PANOSTerraformGenerator
from fwmigrate.generators.palo_alto.xml_generator import PANOSXMLGenerator
from fwmigrate.ir.enums import MigrationConfidence, NATTranslationMode, NATType
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer


POLICY_BASE = """
        set srcintf "LAN"
        set dstintf "WAN"
        set srcaddr "LAN_NET"
        set dstaddr "all"
        set service "ALL"
        set action accept
"""

INTERFACES = """
config system interface
    edit "LAN"
        set role lan
        set ip 10.0.0.1 255.255.255.0
    next
    edit "WAN"
        set role wan
        set ip 203.0.113.10 255.255.255.0
    next
end
config system zone
    edit "LAN"
        set interface "LAN"
    next
    edit "WAN"
        set interface "WAN"
    next
end
"""


def _transform(config: str):
    return FGToIRTransformer(parse_fortigate_config(INTERFACES + config)).transform()


def _transform_raw(config: str):
    return FGToIRTransformer(parse_fortigate_config(config)).transform()


def _main_tf(ir):
    return next(
        artifact.content
        for artifact in PANOSTerraformGenerator().generate(ir)
        if artifact.filename == "main.tf"
    )


def test_interface_address_snat_is_correlated_to_policy():
    ir = _transform(f"""
config firewall policy
    edit 10
{POLICY_BASE}
        set nat enable
    next
end
""")

    assert len(ir.nat_rules) == 1
    rule = ir.nat_rules[0]
    assert rule.type == NATType.SOURCE
    assert rule.source_policy_reference == "10"
    assert rule.source_translation_mode == NATTranslationMode.INTERFACE_ADDRESS
    assert rule.source_from_interfaces == ["LAN"]
    assert rule.source_to_interfaces == ["WAN"]
    assert rule.source == ["LAN_NET"]
    assert rule.source_pool_references == []
    assert rule.translated_sources == ["203.0.113.10"]
    assert rule.requires_manual_review is False
    xml = PANOSXMLGenerator().generate(ir)[0].content
    assert "<interface-address>" in xml
    assert "<interface>WAN</interface>" in xml
    hcl = _main_tf(ir)
    assert "original_packet {" in hcl
    assert "translated_packet {" in hcl
    assert "interface_address {" in hcl
    assert 'interface = "WAN"' in hcl


def test_nat_with_unzoned_interfaces_preserves_evidence_and_requires_review():
    ir = _transform_raw("""
config system interface
    edit "port1"
        set ip 10.0.0.1 255.255.255.0
    next
    edit "port2"
        set ip 203.0.113.10 255.255.255.0
    next
end
config firewall policy
    edit 11
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "LAN_NET"
        set dstaddr "all"
        set service "ALL"
        set action accept
        set nat enable
    next
end
""")

    rule = ir.nat_rules[0]
    assert rule.source_from_interfaces == ["port1"]
    assert rule.source_to_interfaces == ["port2"]
    assert rule.from_zone == []
    assert rule.to_zone == []
    assert rule.requires_manual_review is True
    assert any(
        "unresolved canonical zones" in entry.message
        for entry in ir.audit_entries
    )
    assert "original_packet {" not in _main_tf(ir)
    assert any(
        entry.category == "PAN-OS Terraform NAT"
        and "withheld" in entry.message
        for entry in ir.audit_entries
    )


def test_interface_address_snat_preserves_host_ip_not_network_or_cidr():
    ir = _transform_raw("""
config system interface
    edit "port10"
        set ip 192.168.42.30 255.255.255.0
    next
end
config system zone
    edit "LAN_ZONE"
        set interface "LAN"
    next
    edit "WAN_ZONE"
        set interface "port10"
    next
end
config firewall policy
    edit 11
        set srcintf "LAN"
        set dstintf "port10"
        set srcaddr "LAN_NET"
        set dstaddr "all"
        set service "ALL"
        set action accept
        set nat enable
    next
end
""")

    rule = ir.nat_rules[0]
    assert rule.translated_sources == ["192.168.42.30"]
    assert rule.translated_source == "192.168.42.30"
    assert rule.requires_manual_review is False


def test_dynamic_interface_address_snat_is_unresolved():
    for mode in ("pppoe", "dhcp"):
        ir = _transform_raw(f"""
config system interface
    edit "wan1"
        set mode {mode}
        set ip 198.51.100.99 255.255.255.0
    next
end
config firewall policy
    edit 12
        set srcintf "LAN"
        set dstintf "wan1"
        set srcaddr "LAN_NET"
        set dstaddr "all"
        set service "ALL"
        set action accept
        set nat enable
    next
end
""")

        rule = ir.nat_rules[0]
        assert rule.translated_sources == []
        assert rule.requires_manual_review is True
        assert any(
            mode in entry.message and "dynamic interface address" in entry.message
            for entry in ir.audit_entries
        )


def test_sdwan_zone_interface_address_snat_does_not_select_a_member():
    ir = _transform_raw("""
config system interface
    edit "wan1"
        set ip 203.0.113.10 255.255.255.0
    next
    edit "wan2"
        set ip 198.51.100.10 255.255.255.0
    next
end
config system sdwan
    set status enable
    config zone
        edit "Internet-Zone"
        next
    end
    config members
        edit 1
            set interface "wan1"
            set zone "Internet-Zone"
        next
        edit 2
            set interface "wan2"
            set zone "Internet-Zone"
        next
    end
end
config firewall policy
    edit 13
        set srcintf "LAN"
        set dstintf "Internet-Zone"
        set srcaddr "LAN_NET"
        set dstaddr "all"
        set service "ALL"
        set action accept
        set nat enable
    next
end
""")

    rule = ir.nat_rules[0]
    assert rule.source_to_interfaces == ["Internet-Zone"]
    assert rule.translated_sources == []
    assert rule.requires_manual_review is True
    assert any("runtime-selected SD-WAN member" in entry.message for entry in ir.audit_entries)


def test_ambiguous_interface_address_snat_is_unresolved():
    cases = (
        ('set dstintf "wan1" "wan2"', "multiple possible outgoing interfaces"),
        ('set dstintf "any"', "does not identify an egress interface"),
        ('set dstintf "missing"', "was not found"),
    )
    for dstintf, expected_reason in cases:
        ir = _transform_raw(f"""
config system interface
    edit "wan1"
        set ip 203.0.113.10 255.255.255.0
    next
    edit "wan2"
        set ip 198.51.100.10 255.255.255.0
    next
end
config firewall policy
    edit 14
        set srcintf "LAN"
        {dstintf}
        set srcaddr "LAN_NET"
        set dstaddr "all"
        set service "ALL"
        set action accept
        set nat enable
    next
end
""")

        rule = ir.nat_rules[0]
        assert rule.translated_sources == []
        assert rule.requires_manual_review is True
        assert any(expected_reason in entry.message for entry in ir.audit_entries)


def test_missing_or_unconfigured_static_interface_ip_is_unresolved():
    for ip_setting in ("", "set ip 0.0.0.0 0.0.0.0"):
        ir = _transform_raw(f"""
config system interface
    edit "wan1"
        {ip_setting}
    next
end
config firewall policy
    edit 15
        set srcintf "LAN"
        set dstintf "wan1"
        set srcaddr "LAN_NET"
        set dstaddr "all"
        set service "ALL"
        set action accept
        set nat enable
    next
end
""")

        rule = ir.nat_rules[0]
        assert rule.translated_sources == []
        assert rule.requires_manual_review is True
        assert any("has no usable static primary IP" in entry.message for entry in ir.audit_entries)


def test_ip_pool_snat_is_correlated_and_inventory_remains():
    ir = _transform(f"""
config firewall ippool
    edit "PUBLIC_POOL"
        set startip 203.0.113.10
        set endip 203.0.113.20
    next
end
config firewall policy
    edit 20
{POLICY_BASE}
        set nat enable
        set ippool enable
        set poolname "PUBLIC_POOL"
    next
end
""")

    assert len(ir.ip_pools) == 1
    assert ir.ip_pools[0].name == "PUBLIC_POOL"
    assert len(ir.nat_rules) == 1
    rule = ir.nat_rules[0]
    assert rule.source_policy_reference == "20"
    assert rule.source_translation_mode == NATTranslationMode.POOL
    assert rule.source_pool_references == ["PUBLIC_POOL"]
    assert rule.source_pool_type == "overload"
    assert rule.translated_sources == ["203.0.113.10-203.0.113.20"]
    xml = PANOSXMLGenerator().generate(ir)[0].content
    assert "<translated-address>" in xml
    assert "<member>203.0.113.10-203.0.113.20</member>" in xml
    hcl = _main_tf(ir)
    assert 'translated_addresses = ["203.0.113.10-203.0.113.20"]' in hcl


def test_unreferenced_ip_pool_does_not_create_nat_rule():
    ir = _transform("""
config firewall ippool
    edit "UNUSED_POOL"
        set startip 203.0.113.10
        set endip 203.0.113.20
    next
end
""")

    assert [pool.name for pool in ir.ip_pools] == ["UNUSED_POOL"]
    assert ir.nat_rules == []


def test_direct_vip_dnat_uses_policy_match_and_vip_translation():
    ir = _transform("""
config firewall vip
    edit "VIP_WEB"
        set extip 198.51.100.10
        set mappedip "10.0.0.10"
        set extintf "WAN"
    next
end
config firewall policy
    edit 30
        set uuid "policy-30-uuid"
        set srcintf "WAN"
        set dstintf "LAN"
        set srcaddr "all"
        set dstaddr "VIP_WEB"
        set service "HTTPS"
        set action accept
    next
end
""")

    assert len(ir.virtual_ips) == 1
    assert len(ir.nat_rules) == 1
    rule = ir.nat_rules[0]
    assert rule.type == NATType.DESTINATION
    assert rule.source_policy_reference == "30"
    assert rule.source_policy_uuid == "policy-30-uuid"
    assert rule.source_vip_reference == "VIP_WEB"
    assert rule.destination == ["198.51.100.10"]
    assert rule.translated_destinations == ["10.0.0.10"]


def test_unreferenced_vip_does_not_create_nat_rule():
    ir = _transform("""
config firewall vip
    edit "UNUSED_VIP"
        set extip 198.51.100.10
        set mappedip "10.0.0.10"
    next
end
""")

    assert [vip.name for vip in ir.virtual_ips] == ["UNUSED_VIP"]
    assert ir.nat_rules == []


def test_vip_group_expands_deterministically_and_preserves_group_reference():
    ir = _transform("""
config firewall vip
    edit "VIP_A"
        set extip 198.51.100.10
        set mappedip "10.0.0.10"
    next
    edit "VIP_B"
        set extip 198.51.100.11
        set mappedip "10.0.0.11"
    next
end
config firewall vipgrp
    edit "VIP_GROUP"
        set interface "any"
        set member "VIP_A" "VIP_B"
    next
end
config firewall policy
    edit 40
        set srcintf "WAN"
        set dstintf "LAN"
        set srcaddr "all"
        set dstaddr "VIP_GROUP"
        set service "ALL"
        set action accept
    next
end
""")

    assert [rule.name for rule in ir.nat_rules] == ["DNAT-P40-VIP_A", "DNAT-P40-VIP_B"]
    assert [rule.source_vip_reference for rule in ir.nat_rules] == ["VIP_A", "VIP_B"]
    assert all(rule.source_vip_group_reference == "VIP_GROUP" for rule in ir.nat_rules)
    assert all(rule.source_policy_reference == "40" for rule in ir.nat_rules)


def test_vip_port_forward_preserves_original_and_translated_ports():
    ir = _transform("""
config firewall vip
    edit "VIP_PAT"
        set extip 198.51.100.10
        set mappedip "10.0.0.10"
        set portforward enable
        set protocol tcp
        set extport 8443
        set mappedport 443
    next
end
config firewall policy
    edit 50
        set srcintf "WAN"
        set dstintf "LAN"
        set srcaddr "all"
        set dstaddr "VIP_PAT"
        set service "ALL"
        set action accept
    next
end
""")

    rule = ir.nat_rules[0]
    assert rule.destination_protocol == "tcp"
    assert rule.original_destination_port == "8443"
    assert rule.translated_port == "443"
    assert any(service.name == "svc_nat_tcp_8443" for service in ir.services)
    xml = PANOSXMLGenerator().generate(ir)[0].content
    assert "<service>svc_nat_tcp_8443</service>" in xml
    assert "<translated-port>443</translated-port>" in xml
    hcl = _main_tf(ir)
    assert 'service               = "svc_nat_tcp_8443"' in hcl
    assert "static_translation {" in hcl
    assert "port    = 443" in hcl


def test_disabled_policy_stays_disabled_in_ir_and_panos_xml():
    ir = _transform(f"""
config firewall policy
    edit 60
{POLICY_BASE}
        set status disable
        set nat enable
    next
end
""")

    assert ir.nat_rules[0].enabled is False
    assert ir.nat_rules[0].translated_sources == ["203.0.113.10"]
    xml = PANOSXMLGenerator().generate(ir)[0].content
    assert '<entry name="SNAT-P60">' in xml
    assert "<disabled>yes</disabled>" in xml
    assert "disabled    = true" in _main_tf(ir)


def test_multiple_services_survive_ir_and_split_into_panos_rules():
    ir = _transform("""
config firewall policy
    edit 70
        set srcintf "LAN"
        set dstintf "WAN"
        set srcaddr "LAN_NET"
        set dstaddr "all"
        set service "HTTPS" "port_8081"
        set action accept
        set nat enable
    next
end
""")

    assert ir.nat_rules[0].services == ["HTTPS", "port_8081"]
    pan = IRToPANOSTransformer(ir).transform()
    assert [rule.service for rule in pan.vsys.nat_rules] == ["HTTPS", "port_8081"]
    assert [rule.name for rule in pan.vsys.nat_rules] == [
        "SNAT-P70-HTTPS", "SNAT-P70-port_8081",
    ]
    hcl = _main_tf(ir)
    assert 'name = "SNAT-P70-HTTPS"' in hcl
    assert 'name = "SNAT-P70-port_8081"' in hcl


def test_snat_and_vip_create_one_twice_nat_rule():
    ir = _transform("""
config firewall vip
    edit "VIP_WEB"
        set extip 198.51.100.10
        set mappedip "10.0.0.10"
        set extintf "WAN"
    next
end
config firewall policy
    edit 80
        set srcintf "WAN"
        set dstintf "LAN"
        set srcaddr "all"
        set dstaddr "VIP_WEB"
        set service "HTTPS"
        set action accept
        set nat enable
    next
end
""")

    assert len(ir.nat_rules) == 1
    rule = ir.nat_rules[0]
    assert rule.type == NATType.TWICE
    assert rule.source_translation_mode == NATTranslationMode.INTERFACE_ADDRESS
    assert rule.translated_destinations == ["10.0.0.10"]
    xml = PANOSXMLGenerator().generate(ir)[0].content
    assert xml.count("<entry name=\"TWICE-P80-VIP_WEB\">") == 1
    assert "<source-translation>" in xml
    assert "<destination-translation>" in xml
    hcl = _main_tf(ir)
    assert hcl.count('name = "TWICE-P80-VIP_WEB"') == 1
    assert "interface_address {" in hcl
    assert "static_translation {" in hcl


def test_missing_pool_never_falls_back_and_is_withheld_from_target():
    ir = _transform(f"""
config firewall policy
    edit 90
{POLICY_BASE}
        set nat enable
        set ippool enable
        set poolname "MISSING_POOL"
    next
end
""")

    rule = ir.nat_rules[0]
    assert rule.source_translation_mode == NATTranslationMode.POOL
    assert rule.source_pool_references == ["MISSING_POOL"]
    assert rule.translated_sources == []
    assert rule.requires_manual_review is True
    assert any(
        entry.confidence == MigrationConfidence.MANUAL and "missing IP pool" in entry.message
        for entry in ir.audit_entries
    )
    assert IRToPANOSTransformer(ir).transform().vsys.nat_rules == []
    assert 'resource "panos_nat_rule_group"' not in _main_tf(ir)


def test_internet_service_nat_preserves_reference_without_any_fallback():
    ir = _transform("""
config firewall policy
    edit 100
        set srcintf "LAN"
        set dstintf "WAN"
        set srcaddr "LAN_NET"
        set internet-service enable
        set internet-service-name "Microsoft-Office365"
        set action accept
        set nat enable
    next
end
""")

    rule = ir.nat_rules[0]
    assert rule.internet_services == ["Microsoft-Office365"]
    assert rule.destination == []
    assert rule.services == []
    assert rule.requires_manual_review is True


def test_mixed_vip_and_ordinary_destinations_partition_snat_match():
    ir = _transform("""
config firewall vip
    edit "VIP_WEB"
        set extip 198.51.100.10
        set mappedip "10.0.0.10"
    next
end
config firewall policy
    edit 110
        set srcintf "LAN"
        set dstintf "WAN"
        set srcaddr "LAN_NET"
        set dstaddr "VIP_WEB" "ORDINARY_SERVER"
        set service "HTTPS"
        set action accept
        set nat enable
    next
end
""")

    assert [rule.type for rule in ir.nat_rules] == [NATType.TWICE, NATType.SOURCE]
    assert ir.nat_rules[0].destination == ["198.51.100.10"]
    assert ir.nat_rules[1].destination == ["ORDINARY_SERVER"]
