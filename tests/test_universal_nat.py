import pytest
from fwmigrate.core.models import (
    IRNatRule,
    IRNatType,
    IRSecurityRule,
    IRServiceObject,
    ServiceProtocol
)
from fwmigrate.parsers.fortigate.transformer import extract_nat_and_security
from fwmigrate.generators.palo_alto.xml_generator import generate_panos_dnat_xml
from fwmigrate.generators.palo_alto.terraform_generator import (
    generate_panos_nat_rule_hcl,
    generate_panos_nat_rule_group_hcl
)


def test_ir_schema_models():
    """Test instantiation and defaults of universal decoupled NAT and Security models."""
    sec = IRSecurityRule(
        name="sec_test",
        from_zones=["trust"],
        to_zones=["untrust"],
        sources=["10.0.0.1/32"],
        destinations=["198.51.100.10/32"],
        services=["svc_tcp_8080"],
        action="allow"
    )
    assert sec.name == "sec_test"
    assert sec.services == ["svc_tcp_8080"]

    nat = IRNatRule(
        name="dnat_test",
        nat_type=IRNatType.DNAT_STATIC,
        from_zones=["untrust"],
        to_zones=["untrust"],
        sources=["any"],
        destinations=["198.51.100.10"],
        service="svc_tcp_8080",
        translated_destinations=["10.1.1.50"],
        translated_port="80"
    )
    assert nat.nat_type == IRNatType.DNAT_STATIC
    assert nat.translated_port == "80"


def test_fortigate_decoupling_snat_and_pat():
    """Test policy with both SNAT and PAT port-forwarded VIP."""
    policy = {
        "name": "Web_Publish_Policy",
        "srcintf": ["untrust"],
        "dstintf": ["dmz"],
        "srcaddr": ["any"],
        "dstaddr": ["VIP_WEB_8080"],
        "service": ["ALL"],
        "action": "accept",
        "nat": "enable",
        "poolname": ["PUBLIC_SNAT_POOL"]
    }

    vip_inventory = {
        "VIP_WEB_8080": {
            "extip": "198.51.100.25",
            "mappedip": "10.240.10.100",
            "mapped_interface": "dmz",
            "portforward": "enable",
            "protocol": "tcp",
            "extport": "8080",
            "mappedport": "80",
            "extintf": "port1"
        }
    }

    service_inventory = {}
    sec_rule, nat_rules, gen_services = extract_nat_and_security(
        policy, vip_inventory, service_inventory
    )

    # 1. Security Rule assertions
    assert sec_rule.name == "Web_Publish_Policy"
    assert sec_rule.action == "accept"
    assert sec_rule.to_zones == ["dmz"]
    assert sec_rule.destinations == ["VIP_WEB_8080"]
    # Strict service binding: Must not be ALL/any; must be the PAT service
    assert sec_rule.services == ["svc_tcp_8080"]

    # 2. Service Object generation
    assert len(gen_services) == 1
    assert gen_services[0].name == "svc_tcp_8080"
    assert gen_services[0].protocol == ServiceProtocol.TCP
    assert gen_services[0].port == "8080"
    assert "svc_tcp_8080" in service_inventory

    # 3. NAT rules: One SNAT and One DNAT
    assert len(nat_rules) == 2

    snat = next(r for r in nat_rules if r.nat_type == IRNatType.SNAT_DIPP)
    assert snat.name == "SNAT_Web_Publish_Policy"
    assert snat.translated_sources == ["PUBLIC_SNAT_POOL"]

    dnat = next(r for r in nat_rules if r.nat_type == IRNatType.DNAT_STATIC)
    assert dnat.name == "DNAT_VIP_WEB_8080"
    assert dnat.from_zones == ["untrust"]
    assert dnat.to_zones == ["untrust"]  # Pre-NAT zone
    assert dnat.destinations == ["198.51.100.25"]
    assert dnat.translated_destinations == ["10.240.10.100"]
    assert dnat.translated_port == "80"
    assert dnat.service == "svc_tcp_8080"


def test_fortigate_multi_vip_zone_aggregation():
    """Test policy with multiple VIPs mapping to different destination zones (Fixing Zone Overwrite Flaw)."""
    policy = {
        "name": "Multi_VIP_Policy",
        "srcintf": ["untrust"],
        "dstintf": ["any"],
        "srcaddr": ["any"],
        "dstaddr": ["VIP_DMZ", "VIP_INTERNAL"],
        "service": ["HTTP", "HTTPS"],
        "action": "accept"
    }

    vip_inventory = {
        "VIP_DMZ": {
            "extip": "198.51.100.1",
            "mappedip": "10.1.1.1",
            "mapped_interface": "dmz_zone",
            "extintf": "port1"
        },
        "VIP_INTERNAL": {
            "extip": "198.51.100.2",
            "mappedip": "10.2.2.2",
            "mapped_interface": "trust_zone",
            "extintf": "port1"
        }
    }

    sec_rule, nat_rules, gen_services = extract_nat_and_security(policy, vip_inventory)

    # Must contain both post-NAT zones without dropping either
    assert "dmz_zone" in sec_rule.to_zones
    assert "trust_zone" in sec_rule.to_zones
    assert len(sec_rule.to_zones) == 2
    assert len(nat_rules) == 2


def test_fortigate_bidirectional_snat_extraction():
    """Test static 1-to-1 VIP with extintf='any' generating bi-directional SNAT."""
    policy = {
        "name": "Server_Static_1to1",
        "srcintf": ["untrust"],
        "dstintf": ["trust"],
        "srcaddr": ["any"],
        "dstaddr": ["VIP_STATIC_MAIL"],
        "service": ["ALL"],
        "action": "accept"
    }

    vip_inventory = {
        "VIP_STATIC_MAIL": {
            "extip": "198.51.100.50",
            "mappedip": "10.0.0.50",
            "mapped_interface": "trust",
            "extintf": "any"  # triggers bi-directional SNAT check
        }
    }

    sec_rule, nat_rules, _ = extract_nat_and_security(policy, vip_inventory)

    assert len(nat_rules) == 2
    dnat = next(r for r in nat_rules if r.nat_type == IRNatType.DNAT_STATIC)
    bi_snat = next(r for r in nat_rules if r.nat_type == IRNatType.SNAT_STATIC)

    assert dnat.destinations == ["198.51.100.50"]
    assert dnat.translated_destinations == ["10.0.0.50"]

    assert bi_snat.name == "SNAT_Outbound_VIP_STATIC_MAIL"
    assert bi_snat.sources == ["10.0.0.50"]
    assert bi_snat.translated_sources == ["198.51.100.50"]
    assert bi_snat.from_zones == ["trust"]
    assert bi_snat.to_zones == ["untrust"]


def test_panos_xml_and_terraform_generation():
    """Test PAN-OS XML and Terraform HCL generation for DNAT with PAT."""
    dnat_rule = IRNatRule(
        name="DNAT_Web_Server",
        nat_type=IRNatType.DNAT_STATIC,
        from_zones=["untrust"],
        to_zones=["untrust"],
        sources=["any"],
        destinations=["198.51.100.10"],
        service="svc_tcp_8080",
        translated_destinations=["10.10.10.100"],
        translated_port="80"
    )

    snat_rule = IRNatRule(
        name="SNAT_Outbound",
        nat_type=IRNatType.SNAT_DIPP,
        from_zones=["trust"],
        to_zones=["untrust"],
        sources=["10.10.10.0/24"],
        destinations=["any"],
        service="any",
        translated_sources=["203.0.113.5"]
    )

    # XML generation check
    xml_out = generate_panos_dnat_xml(dnat_rule)
    assert '<entry name="DNAT_Web_Server">' in xml_out
    assert "<to><member>untrust</member></to>" in xml_out
    assert "<from><member>untrust</member></from>" in xml_out
    assert "<destination><member>198.51.100.10</member></destination>" in xml_out
    assert "<service>svc_tcp_8080</service>" in xml_out
    assert "<translated-address>10.10.10.100</translated-address>" in xml_out
    assert "<translated-port>80</translated-port>" in xml_out

    # Standalone Terraform HCL generation check
    hcl_single = generate_panos_nat_rule_hcl(dnat_rule)
    assert 'resource "panos_nat_rule" "dnat_web_server"' in hcl_single
    assert 'destination_zone      = "untrust"' in hcl_single
    assert 'destination_addresses = ["198.51.100.10"]' in hcl_single
    assert 'service               = "svc_tcp_8080"' in hcl_single
    assert 'address = "10.10.10.100"' in hcl_single
    assert 'port    = "80"' in hcl_single

    # Group Terraform HCL generation check
    hcl_group = generate_panos_nat_rule_group_hcl([dnat_rule, snat_rule])
    assert 'resource "panos_nat_rule_group" "nat_policies"' in hcl_group
    assert 'name                  = "DNAT_Web_Server"' in hcl_group
    assert 'name                  = "SNAT_Outbound"' in hcl_group
    assert 'translated_addresses = ["203.0.113.5"]' in hcl_group
