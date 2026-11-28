"""Tests for Phase 3 Longest-Prefix-Match (LPM) Route Lookup."""

from __future__ import annotations

from fwmigrate.source_reporting.route_lookup import (
    lookup_fortigate_route,
    lookup_paloalto_route,
)
from fwmigrate.vendors.fortigate.extraction.extractor import extract_fortigate_config
from fwmigrate.vendors.fortigate.parser import parse_fortigate_config
from fwmigrate.vendors.palo_alto.source_builder import build_panos_config

_FG_ROUTE_CONF = """#config-version=FGT60F-7.4.9-FW-build2829-250101:opmode=0:vdom=0:user=admin
config system interface
    edit "internal"
        set vdom "root"
        set ip 10.10.10.1 255.255.255.0
    next
    edit "down_if"
        set vdom "root"
        set status down
        set ip 10.10.10.1 255.255.255.128
    next
    edit "wan1"
        set vdom "root"
        set ip 198.51.100.2 255.255.255.248
    next
end
config router static
    edit 1
        set dst 0.0.0.0 0.0.0.0
        set gateway 198.51.100.1
        set device "wan1"
        set distance 10
        set priority 0
    next
    edit 2
        set dst 10.20.0.0 255.255.0.0
        set gateway 10.10.10.254
        set device "internal"
        set distance 10
        set priority 5
    next
    edit 3
        set dst 10.20.0.0 255.255.0.0
        set gateway 10.10.10.253
        set device "internal"
        set distance 5
        set priority 10
    next
    edit 4
        set dst 10.20.5.0 255.255.255.0
        set status disable
        set gateway 10.10.10.250
        set device "internal"
    next
end
config router policy
    edit 1
        set input-device "internal"
        set src "10.10.10.0/24"
        set gateway 198.51.100.1
        set output-device "wan1"
    next
end
"""

_PA_ROUTE_XML = """<config version="11.1.0">
  <devices><entry name="fw">
    <network>
      <interface><ethernet>
        <entry name="ethernet1/1"><link-state>up</link-state><layer3><ip><entry name="198.51.100.2/29"/></ip></layer3></entry>
        <entry name="ethernet1/2"><link-state>up</link-state><layer3><ip><entry name="10.10.0.1/24"/></ip></layer3></entry>
        <entry name="ethernet1/3"><link-state>down</link-state><layer3><ip><entry name="10.10.0.1/25"/></ip></layer3></entry>
      </ethernet></interface>
      <virtual-router>
        <entry name="vr-main">
          <interface><member>ethernet1/1</member><member>ethernet1/2</member></interface>
          <admin-dists><static>10</static></admin-dists>
          <routing-table><ip><static-route>
            <entry name="default"><destination>0.0.0.0/0</destination><interface>ethernet1/1</interface><nexthop><ip-address>198.51.100.1</ip-address></nexthop><metric>10</metric></entry>
            <entry name="corp_a"><destination>10.50.0.0/16</destination><interface>ethernet1/2</interface><nexthop><ip-address>10.10.0.254</ip-address></nexthop><metric>20</metric></entry>
            <entry name="corp_b"><destination>10.50.0.0/16</destination><interface>ethernet1/2</interface><nexthop><ip-address>10.10.0.253</ip-address></nexthop><metric>5</metric></entry>
          </static-route></ip></routing-table>
        </entry>
      </virtual-router>
    </network>
  </entry></devices>
</config>"""


def test_fortigate_lpm_route_lookup_and_tie_breakers():
    cfg = extract_fortigate_config(parse_fortigate_config(_FG_ROUTE_CONF)).config

    bad = lookup_fortigate_route(cfg, "not-an-ip")
    assert bad["valid"] is False

    connected = lookup_fortigate_route(cfg, "10.10.10.55")
    assert connected["valid"] is True
    assert connected["winner"]["type"] == "Connected"
    assert connected["winner"]["interface"] == "internal"
    assert connected["active_policy_routes"] == 1

    # Equal /16 prefix: lower distance (5 vs 10) wins, disabled /24 excluded
    tie = lookup_fortigate_route(cfg, "10.20.5.9")
    assert tie["winner"]["destination"] == "10.20.0.0/16"
    assert tie["winner"]["gateway"] == "10.10.10.253"
    assert tie["winner"]["distance"] == 5
    assert len(tie["candidates"]) == 3  # 2 static /16 + 1 default 0/0


def test_paloalto_lpm_route_lookup_connected_and_metric_tie_breaker():
    cfg = build_panos_config(_PA_ROUTE_XML)

    bad = lookup_paloalto_route(cfg, "999.1.1.1")
    assert bad["valid"] is False

    conn = lookup_paloalto_route(cfg, "10.10.0.25")
    assert conn["valid"] is True
    assert conn["winner"]["type"] == "Connected"
    assert conn["winner"]["interface"] == "ethernet1/2"
    assert conn["virtual_routers"] == ["vr-main"]

    tie = lookup_paloalto_route(cfg, "10.50.1.2")
    assert tie["winner"]["route_name"] == "corp_b"
    assert tie["winner"]["metric"] == 5
    assert "10.10.0.253" in tie["winner"]["next_hop"]
