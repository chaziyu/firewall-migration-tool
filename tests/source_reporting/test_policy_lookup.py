"""Tests for Phase 3 5-tuple Policy Match Simulator (FortiGate & Palo Alto)."""

from __future__ import annotations

from fwmigrate.source_reporting.policy_lookup import (
    evaluate_fortigate_policy_lookup,
    evaluate_paloalto_policy_lookup,
)
from fwmigrate.vendors.fortigate.extraction.extractor import extract_fortigate_config
from fwmigrate.vendors.fortigate.parser import parse_fortigate_config
from fwmigrate.vendors.palo_alto.source_builder import build_panos_config

_FG_POLICY_CONF = """#config-version=FGT60F-7.4.9-FW-build2829-250101:opmode=0:vdom=0:user=admin
config firewall address
    edit "LAN_NET"
        set subnet 10.10.0.0 255.255.255.0
    next
    edit "WEB_VIP_BACK"
        set subnet 172.16.10.20 255.255.255.255
    next
    edit "ADMIN_HOST"
        set type iprange
        set start-ip 10.10.0.50
        set end-ip 10.10.0.55
    next
end
config firewall addrgrp
    edit "GRP_WEB"
        set member "LAN_NET"
    next
end
config firewall service custom
    edit "CUSTOM_APP"
        set tcp-portrange 8443:1024-65535
    next
end
config firewall service group
    edit "GRP_SVC"
        set member "HTTPS" "CUSTOM_APP"
    next
end
config firewall vip
    edit "VIP_WEB"
        set extip 203.0.113.10
        set extintf "wan1"
        set mappedip "172.16.10.20"
    next
end
config firewall policy
    edit 1
        set name "DISABLED_ALLOW"
        set srcintf "port1"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
        set status disable
    next
    edit 2
        set name "ALLOW_CUSTOM_HTTPS"
        set srcintf "port1"
        set dstintf "wan1"
        set srcaddr "GRP_WEB"
        set dstaddr "all"
        set service "GRP_SVC"
        set action accept
        set nat enable
    next
    edit 3
        set name "SHADOWED_ANY"
        set srcintf "port1"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action deny
    next
    edit 4
        set name "INBOUND_VIP"
        set srcintf "wan1"
        set dstintf "dmz"
        set srcaddr "all"
        set dstaddr "VIP_WEB"
        set service "HTTPS"
        set action accept
    next
    edit 5
        set name "NEGATED_SRC"
        set srcintf "port2"
        set dstintf "wan1"
        set srcaddr "ADMIN_HOST"
        set srcaddr-negate enable
        set dstaddr "all"
        set service "ALL"
        set action accept
    next
end
"""

_PA_POLICY_XML = """<config version="11.1.0">
  <devices><entry name="fw"><vsys><entry name="vsys1">
    <address>
      <entry name="NET_TRUST"><ip-netmask>10.20.0.0/24</ip-netmask></entry>
      <entry name="SRV_RANGE"><ip-range>172.16.5.10-172.16.5.20</ip-range></entry>
    </address>
    <address-group>
      <entry name="GRP_TRUST"><static><member>NET_TRUST</member></static></entry>
    </address-group>
    <service>
      <entry name="SVC_8443"><protocol><tcp><port>8443</port></tcp></protocol></entry>
    </service>
    <service-group>
      <entry name="GRP_SVC"><members><member>SVC_8443</member></members></entry>
    </service-group>
    <rulebase>
      <security><rules>
        <entry name="Disabled_Rule">
          <from><member>trust</member></from><to><member>untrust</member></to>
          <source><member>any</member></source><destination><member>any</member></destination>
          <service><member>any</member></service><action>deny</action><disabled>yes</disabled>
        </entry>
        <entry name="Allow_Trust_App">
          <from><member>trust</member></from><to><member>untrust</member></to>
          <source><member>GRP_TRUST</member></source><destination><member>SRV_RANGE</member></destination>
          <source-user><member>any</member></source-user>
          <application><member>ssl</member></application>
          <service><member>GRP_SVC</member></service><action>allow</action>
        </entry>
        <entry name="Shadowed_Broad">
          <from><member>trust</member></from><to><member>untrust</member></to>
          <source><member>any</member></source><destination><member>any</member></destination>
          <service><member>any</member></service><action>deny</action>
        </entry>
      </rules></security>
      <default-security-rules><rules>
        <entry name="intrazone-default"><action>allow</action></entry>
      </rules></default-security-rules>
      <nat><rules>
        <entry name="OUTBOUND_SNAT">
          <from><member>trust</member></from><to><member>untrust</member></to>
          <source><member>NET_TRUST</member></source><destination><member>any</member></destination>
          <service>any</service>
          <source-translation><dynamic-ip-and-port><interface-address><interface>ethernet1/1</interface></interface-address></dynamic-ip-and-port></source-translation>
        </entry>
      </rules></nat>
    </rulebase>
  </entry></vsys></entry></devices>
</config>"""


def test_fortigate_policy_lookup_groups_vip_negate_shadowed_and_implicit_deny():
    cfg = extract_fortigate_config(parse_fortigate_config(_FG_POLICY_CONF)).config

    res = evaluate_fortigate_policy_lookup(
        cfg,
        src_iface="port1",
        dst_iface="wan1",
        src_addr="10.10.0.15",
        dst_addr="8.8.8.8",
        protocol="tcp/8443",
    )
    assert res["matched"] is True
    assert res["action"] == "ACCEPT"
    assert res["match"]["id"] == "2"
    assert len(res["shadowed"]) == 1
    assert res["shadowed"][0]["id"] == "3"

    vip_res = evaluate_fortigate_policy_lookup(
        cfg,
        src_iface="wan1",
        dst_iface="dmz",
        src_addr="198.51.100.5",
        dst_addr="203.0.113.10",
        protocol="443",
    )
    assert vip_res["matched"] is True
    assert vip_res["match"]["id"] == "4"

    neg_miss = evaluate_fortigate_policy_lookup(
        cfg,
        src_iface="port2",
        dst_iface="wan1",
        src_addr="10.10.0.52",
        dst_addr="8.8.8.8",
        protocol="tcp/80",
    )
    assert neg_miss["matched"] is False
    assert neg_miss["action"] == "DENY"

    neg_hit = evaluate_fortigate_policy_lookup(
        cfg,
        src_iface="port2",
        dst_iface="wan1",
        src_addr="10.10.0.99",
        dst_addr="8.8.8.8",
        protocol="tcp/80",
    )
    assert neg_hit["matched"] is True
    assert neg_hit["match"]["id"] == "5"


def test_paloalto_policy_lookup_security_nat_shadowed_and_intrazone_default():
    cfg = build_panos_config(_PA_POLICY_XML)

    sec_res = evaluate_paloalto_policy_lookup(
        cfg,
        policy_type="security",
        src_zone="trust",
        dst_zone="untrust",
        src_addr="10.20.0.44",
        dst_addr="172.16.5.15",
        protocol="tcp",
        dst_port="8443",
    )
    assert sec_res["matched"] is True
    assert sec_res["action"] == "ALLOW"
    assert sec_res["match"]["name"] == "Allow_Trust_App"
    assert [s["name"] for s in sec_res["shadowed"]] == ["Shadowed_Broad"]

    nat_res = evaluate_paloalto_policy_lookup(
        cfg,
        policy_type="nat",
        src_zone="trust",
        dst_zone="untrust",
        src_addr="10.20.0.44",
        dst_addr="8.8.8.8",
        protocol="tcp",
        dst_port="443",
    )
    assert nat_res["matched"] is True
    assert nat_res["match"]["name"] == "OUTBOUND_SNAT"
    assert "ethernet1/1" in nat_res["match"]["src_translation"]

    intra = evaluate_paloalto_policy_lookup(
        cfg,
        policy_type="security",
        src_zone="trust",
        dst_zone="trust",
        src_addr="10.20.0.10",
        dst_addr="10.20.0.20",
        protocol="tcp",
        dst_port="22",
    )
    assert intra["matched"] is False
    assert intra["action"] == "ALLOW"
    assert "intrazone-default" in intra["reason"]

    inter_deny = evaluate_paloalto_policy_lookup(
        cfg,
        policy_type="security",
        src_zone="dmz",
        dst_zone="untrust",
        src_addr="192.168.1.10",
        dst_addr="8.8.8.8",
        protocol="tcp",
        dst_port="443",
    )
    assert inter_deny["matched"] is False
    assert inter_deny["action"] == "DENY"
