"""Tests for Phase 3 End-to-End Packet Flow Simulator ('Trace Packet')."""

from __future__ import annotations

from fwmigrate.source_reporting.packet_trace import (
    trace_fortigate_packet,
    trace_paloalto_packet,
)
from fwmigrate.vendors.fortigate.extraction.extractor import extract_fortigate_config
from fwmigrate.vendors.fortigate.parser import parse_fortigate_config
from fwmigrate.vendors.palo_alto.source_builder import build_panos_config

_FG_TRACE_CONF = """#config-version=FGT60F-7.4.9-FW-build2829-250101:opmode=0:vdom=0:user=admin
config system interface
    edit "internal"
        set vdom "root"
        set ip 10.10.10.1 255.255.255.0
        set allowaccess https ssh ping
    next
    edit "dmz"
        set vdom "root"
        set ip 172.16.10.1 255.255.255.0
    next
    edit "wan1"
        set vdom "root"
        set ip 198.51.100.2 255.255.255.248
    next
end
config system zone
    edit "Z_LAN"
        set interface "internal"
    next
end
config router static
    edit 1
        set dst 0.0.0.0 0.0.0.0
        set gateway 198.51.100.1
        set device "wan1"
    next
end
config firewall vip
    edit "VIP_DMZ"
        set extip 198.51.100.5
        set extintf "wan1"
        set mappedip "172.16.10.50"
    next
end
config firewall policy
    edit 10
        set name "LAN_TO_INET"
        set srcintf "Z_LAN"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set service "HTTPS"
        set action accept
        set nat enable
    next
    edit 20
        set name "WAN_TO_VIP"
        set srcintf "wan1"
        set dstintf "dmz"
        set srcaddr "all"
        set dstaddr "VIP_DMZ"
        set service "HTTPS"
        set action accept
    next
end
"""

_PA_TRACE_XML = """<config version="11.1.0">
  <devices><entry name="fw">
    <deviceconfig><system><ip-address>10.255.0.10</ip-address></system></deviceconfig>
    <network>
      <interface><ethernet>
        <entry name="ethernet1/1"><link-state>up</link-state><layer3><ip><entry name="198.51.100.2/29"/></ip></layer3></entry>
        <entry name="ethernet1/2"><link-state>up</link-state><layer3><ip><entry name="10.10.0.1/24"/></ip></layer3></entry>
      </ethernet></interface>
      <virtual-router><entry name="default">
        <interface><member>ethernet1/1</member><member>ethernet1/2</member></interface>
        <routing-table><ip><static-route>
          <entry name="def"><destination>0.0.0.0/0</destination><interface>ethernet1/1</interface><nexthop><ip-address>198.51.100.1</ip-address></nexthop></entry>
        </static-route></ip></routing-table>
      </entry></virtual-router>
    </network>
    <vsys><entry name="vsys1">
      <zone>
        <entry name="untrust"><network><layer3><member>ethernet1/1</member></layer3></network></entry>
        <entry name="trust"><network><layer3><member>ethernet1/2</member></layer3></network></entry>
      </zone>
      <rulebase>
        <security><rules>
          <entry name="Allow_HTTPS">
            <from><member>trust</member></from><to><member>untrust</member></to>
            <source><member>any</member></source><destination><member>any</member></destination>
            <service><member>service-https</member></service><action>allow</action>
          </entry>
        </rules></security>
        <nat><rules>
          <entry name="Outbound_NAT">
            <from><member>trust</member></from><to><member>untrust</member></to>
            <source><member>any</member></source><destination><member>any</member></destination>
            <service>any</service>
            <source-translation><dynamic-ip-and-port><interface-address><interface>ethernet1/1</interface></interface-address></dynamic-ip-and-port></source-translation>
          </entry>
        </rules></nat>
      </rulebase>
    </entry></vsys>
  </entry></devices>
</config>"""


def test_fortigate_packet_trace_allow_dnat_local_in_l2_and_deny():
    cfg = extract_fortigate_config(parse_fortigate_config(_FG_TRACE_CONF)).config

    allow = trace_fortigate_packet(cfg, src_ip="10.10.10.25", dst_ip="8.8.8.8", dst_port="443", protocol="tcp")
    assert allow["valid"] is True
    assert allow["verdict"] == "ALLOW"
    assert allow["ingress"] == "internal"
    assert allow["egress"] == "wan1"
    assert "SNAT Enabled" in allow["nat"]
    assert "Symmetric" in allow["return_path"]

    dnat = trace_fortigate_packet(cfg, src_ip="203.0.113.5", dst_ip="198.51.100.5", dst_port="443", protocol="tcp")
    assert dnat["verdict"] == "ALLOW"
    assert dnat["egress"] == "dmz"
    assert "DNAT (VIP_WEB" not in dnat["nat"]
    assert "DNAT (VIP_DMZ)" in dnat["nat"]

    local_in = trace_fortigate_packet(cfg, src_ip="10.10.10.25", dst_ip="10.10.10.1", dst_port="443", protocol="tcp")
    assert local_in["verdict"] == "LOCAL-IN"

    l2 = trace_fortigate_packet(cfg, src_ip="10.10.10.25", dst_ip="10.10.10.30", dst_port="443", protocol="tcp")
    assert l2["verdict"] == "L2 DIRECT"

    deny = trace_fortigate_packet(cfg, src_ip="10.10.10.25", dst_ip="8.8.8.8", dst_port="22", protocol="tcp")
    assert deny["verdict"] == "DENY"


def test_paloalto_packet_trace_allow_local_in_l2_and_drop():
    cfg = build_panos_config(_PA_TRACE_XML)

    allow = trace_paloalto_packet(cfg, src_ip="10.10.0.50", dst_ip="8.8.8.8", dst_port="443", protocol="tcp")
    assert allow["valid"] is True
    assert allow["verdict"] == "ALLOW"
    assert "trust" in allow["ingress"]
    assert "untrust" in allow["egress"]
    assert "Outbound_NAT" in allow["nat"]
    assert "Symmetric" in allow["return_path"]

    local_in = trace_paloalto_packet(cfg, src_ip="10.10.0.50", dst_ip="10.255.0.10", dst_port="443", protocol="tcp")
    assert local_in["verdict"] == "LOCAL-IN"

    l2 = trace_paloalto_packet(cfg, src_ip="10.10.0.50", dst_ip="10.10.0.60", dst_port="443", protocol="tcp")
    assert l2["verdict"] == "L2 DIRECT"

    deny = trace_paloalto_packet(cfg, src_ip="10.10.0.50", dst_ip="8.8.8.8", dst_port="80", protocol="tcp")
    assert deny["verdict"] == "DENY"
