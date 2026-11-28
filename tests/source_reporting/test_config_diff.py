"""Tests for Phase 3 Firewall-Aware Structural Config Diff."""

from __future__ import annotations

from fwmigrate.source_reporting.config_diff import (
    diff_fortigate_configs,
    diff_paloalto_configs,
)
from fwmigrate.vendors.fortigate.extraction.extractor import extract_fortigate_config
from fwmigrate.vendors.fortigate.parser import parse_fortigate_config
from fwmigrate.vendors.palo_alto.source_builder import build_panos_config

_FG_BASE = """#config-version=FGT60F-7.4.9-FW-build2829-250101:opmode=0:vdom=0:user=admin
config system interface
    edit "internal"
        set vdom "root"
        set ip 10.10.0.1 255.255.255.0
    next
end
config router static
    edit 1
        set dst 0.0.0.0 0.0.0.0
        set gateway 1.1.1.1
        set device "internal"
    next
end
config firewall vip
    edit "VIP_1"
        set extip 2.2.2.2
        set mappedip "10.10.0.50"
    next
end
config vpn ipsec phase1-interface
    edit "VPN_A"
        set interface "internal"
        set ike-version 2
        set proposal aes256-sha256
        set dhgrp 14
        set remote-gw 9.9.9.9
        set psksecret ENC SUPER_SECRET_DO_NOT_LEAK
    next
end
config firewall policy
    edit 1
        set name "Allow_Web"
        set srcintf "internal"
        set dstintf "internal"
        set srcaddr "all"
        set dstaddr "all"
        set service "HTTPS"
        set action accept
    next
    edit 2
        set name "Old_Rule"
        set srcintf "internal"
        set dstintf "internal"
        set srcaddr "all"
        set dstaddr "all"
        set service "HTTP"
        set action deny
    next
end
"""

_FG_CHANGED = """#config-version=FGT60F-7.4.9-FW-build2829-250101:opmode=0:vdom=0:user=admin
config system interface
    edit "internal"
        set vdom "root"
        set ip 10.10.0.1 255.255.255.0
        set allowaccess https
    next
end
config router static
    edit 1
        set dst 0.0.0.0 0.0.0.0
        set gateway 1.1.1.2
        set device "internal"
    next
end
config firewall vip
    edit "VIP_1"
        set extip 2.2.2.2
        set mappedip "10.10.0.50"
    next
end
config vpn ipsec phase1-interface
    edit "VPN_A"
        set interface "internal"
        set ike-version 2
        set proposal aes256-sha256
        set dhgrp 14
        set remote-gw 9.9.9.10
        set psksecret ENC NEW_SECRET_DO_NOT_LEAK
    next
end
config firewall policy
    edit 1
        set name "Allow_Web"
        set srcintf "internal"
        set dstintf "internal"
        set srcaddr "all"
        set dstaddr "all"
        set service "HTTPS"
        set action accept
    next
    edit 3
        set name "New_Rule"
        set srcintf "internal"
        set dstintf "internal"
        set srcaddr "all"
        set dstaddr "all"
        set service "SSH"
        set action accept
    next
end
"""

_PA_BASE = """<config version="11.1.0">
  <devices><entry name="fw">
    <network>
      <interface><ethernet><entry name="ethernet1/1"><layer3><ip><entry name="10.0.0.1/24"/></ip></layer3></entry></ethernet></interface>
      <virtual-router><entry name="default"><routing-table><ip><static-route><entry name="def"><destination>0.0.0.0/0</destination><interface>ethernet1/1</interface><nexthop><ip-address>10.0.0.254</ip-address></nexthop></entry></static-route></ip></routing-table></entry></virtual-router>
      <ike><gateway><entry name="GW1"><local-address><interface>ethernet1/1</interface></local-address><peer-address><ip>8.8.4.4</ip></peer-address><authentication><pre-shared-key><key>PA_SECRET_1</key></pre-shared-key></authentication></entry></gateway></ike>
      <tunnel><ipsec><entry name="TUN1"><auto-key><ike-gateway><entry name="GW1"/></ike-gateway></auto-key><tunnel-interface>tunnel.1</tunnel-interface></entry></ipsec></tunnel>
    </network>
    <vsys><entry name="vsys1"><rulebase>
      <security><rules><entry name="R1"><from><member>trust</member></from><to><member>untrust</member></to><action>allow</action></entry></rules></security>
    </rulebase></entry></vsys>
  </entry></devices>
</config>"""

_PA_CHANGED = """<config version="11.1.0">
  <devices><entry name="fw">
    <network>
      <interface><ethernet><entry name="ethernet1/1"><layer3><ip><entry name="10.0.0.2/24"/></ip></layer3></entry></ethernet></interface>
      <virtual-router><entry name="default"><routing-table><ip><static-route><entry name="def"><destination>0.0.0.0/0</destination><interface>ethernet1/1</interface><nexthop><ip-address>10.0.0.253</ip-address></nexthop></entry></static-route></ip></routing-table></entry></virtual-router>
      <ike><gateway><entry name="GW1"><local-address><interface>ethernet1/1</interface></local-address><peer-address><ip>8.8.8.8</ip></peer-address><authentication><pre-shared-key><key>PA_SECRET_2</key></pre-shared-key></authentication></entry></gateway></ike>
      <tunnel><ipsec><entry name="TUN1"><auto-key><ike-gateway><entry name="GW1"/></ike-gateway></auto-key><tunnel-interface>tunnel.1</tunnel-interface></entry></ipsec></tunnel>
    </network>
    <vsys><entry name="vsys1"><rulebase>
      <security><rules>
        <entry name="R1"><from><member>trust</member></from><to><member>untrust</member></to><action>deny</action></entry>
        <entry name="R2"><from><member>trust</member></from><to><member>dmz</member></to><action>allow</action></entry>
      </rules></security>
    </rulebase></entry></vsys>
  </entry></devices>
</config>"""


def test_fortigate_config_diff_domains_and_secret_redaction():
    before = extract_fortigate_config(parse_fortigate_config(_FG_BASE)).config
    after = extract_fortigate_config(parse_fortigate_config(_FG_CHANGED)).config

    same = diff_fortigate_configs(before, before)
    assert same["has_diff"] is False
    assert same["summary"]["total"] == 0

    diff = diff_fortigate_configs(before, after, before_name="before.conf", after_name="after.conf")
    assert diff["has_diff"] is True
    assert diff["summary"] == {"added": 1, "modified": 3, "removed": 1, "total": 5}
    domains = {d["name"]: d["rows"] for d in diff["domains"]}
    assert set(domains) == {"Firewall Policies", "Static Routes", "IPSec VPN Tunnels", "Interfaces & Zones"}

    serialized = str(diff)
    assert "SUPER_SECRET_DO_NOT_LEAK" not in serialized
    assert "NEW_SECRET_DO_NOT_LEAK" not in serialized
    assert "psk" not in serialized.lower()


def test_paloalto_config_diff_domains_and_secret_redaction():
    before = build_panos_config(_PA_BASE)
    after = build_panos_config(_PA_CHANGED)

    same = diff_paloalto_configs(before, before)
    assert same["has_diff"] is False

    diff = diff_paloalto_configs(before, after, before_name="a.xml", after_name="b.xml")
    assert diff["has_diff"] is True
    assert diff["summary"] == {"added": 1, "modified": 4, "removed": 0, "total": 5}

    serialized = str(diff)
    assert "PA_SECRET_1" not in serialized
    assert "PA_SECRET_2" not in serialized
    assert "pre_shared_key" not in serialized.lower()
