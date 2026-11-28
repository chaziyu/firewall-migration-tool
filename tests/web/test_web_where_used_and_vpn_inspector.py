"""Tests for Global IP/Object Where-Used search and Site-to-Site VPN 4-layer Inspector."""

from __future__ import annotations

import json

from fwmigrate.source_reporting import source_reporters
from fwmigrate.vendors.fortigate.vpn_inspector import build_fortigate_vpn_inspector
from fwmigrate.vendors.fortigate.where_used import search_fortigate_where_used
from fwmigrate.vendors.palo_alto.vpn_inspector import build_paloalto_vpn_inspector
from fwmigrate.vendors.palo_alto.where_used import search_paloalto_where_used
from fwmigrate.web import create_app


_FG_SAMPLE = """config system interface
    edit "wan1"
        set vdom "root"
        set ip 203.0.113.10 255.255.255.0
        set role wan
        set status up
    next
    edit "port2"
        set vdom "root"
        set ip 10.10.1.1 255.255.255.0
        set role lan
        set status up
    next
    edit "vpn-hq"
        set vdom "root"
        set type tunnel
        set interface "wan1"
        set status up
    next
    edit "vpn-legacy"
        set vdom "root"
        set type tunnel
        set interface "wan1"
        set status disable
    next
end
config system zone
    edit "VPN-ZONE"
        set interface "vpn-hq"
    next
end
config firewall address
    edit "LAN_HOST_5"
        set subnet 10.10.1.5 255.255.255.255
    next
    edit "LAN_RANGE"
        set type iprange
        set start-ip 10.10.1.10
        set end-ip 10.10.1.20
    next
    edit "REMOTE_NET"
        set subnet 172.16.50.0 255.255.255.0
    next
end
config firewall addrgrp
    edit "GRP_LVL1"
        set member "LAN_HOST_5"
    next
    edit "GRP_LVL2"
        set member "GRP_LVL1"
    next
    edit "GRP_CYCLE_A"
        set member "GRP_CYCLE_B" "LAN_RANGE"
    next
    edit "GRP_CYCLE_B"
        set member "GRP_CYCLE_A"
    next
end
config firewall vip
    edit "VIP_WEB"
        set extip 203.0.113.50
        set mappedip "10.10.1.5"
        set extintf "wan1"
    next
end
config firewall ippool
    edit "SNAT_POOL"
        set startip 10.10.1.100
        set endip 10.10.1.110
    next
end
config vpn ipsec phase1-interface
    edit "vpn-hq"
        set interface "wan1"
        set ike-version 2
        set peertype any
        set proposal aes256-sha256
        set dhgrp 14
        set remote-gw 198.51.100.1
        set psksecret ENC SUPER_SECRET_FG_PSK
    next
    edit "vpn-legacy"
        set interface "wan1"
        set ike-version 1
        set proposal 3des-md5
        set dhgrp 2
        set remote-gw 198.51.100.2
        set psksecret ENC LEGACY_SECRET_FG_PSK
    next
end
config vpn ipsec phase2-interface
    edit "vpn-hq-p2"
        set phase1name "vpn-hq"
        set proposal aes256-sha256
        set dhgrp 14
        set src-subnet 10.10.1.0 255.255.255.0
        set dst-subnet 172.16.50.0 255.255.255.0
    next
end
config router static
    edit 1
        set dst 172.16.50.0 255.255.255.0
        set device "vpn-hq"
    next
    edit 2
        set dst 10.20.0.0 255.255.0.0
        set gateway 10.10.1.254
        set device "port2"
    next
end
config firewall policy
    edit 10
        set name "Allow-LAN-to-HQ"
        set srcintf "port2"
        set dstintf "VPN-ZONE"
        set srcaddr "GRP_LVL2"
        set dstaddr "REMOTE_NET"
        set action accept
        set schedule "always"
        set service "ALL"
        set nat enable
    next
end
"""


_PA_SAMPLE = """<config version="10.2.0">
  <devices>
    <entry name="localhost.localdomain">
      <network>
        <interface>
          <ethernet>
            <entry name="ethernet1/1">
              <layer3><ip><entry name="203.0.113.10/24"/></ip></layer3>
            </entry>
          </ethernet>
          <tunnel>
            <units>
              <entry name="tunnel.1">
                <ip><entry name="169.254.1.1/30"/></ip>
              </entry>
              <entry name="tunnel.2"/>
            </units>
          </tunnel>
        </interface>
        <ike>
          <crypto-profiles>
            <ike-crypto-profiles>
              <entry name="STRONG-IKE">
                <encryption><member>aes-256-cbc</member></encryption>
                <hash><member>sha256</member></hash>
                <dh-group><member>group14</member></dh-group>
              </entry>
              <entry name="WEAK-IKE">
                <encryption><member>3des</member></encryption>
                <hash><member>sha1</member></hash>
                <dh-group><member>group2</member></dh-group>
              </entry>
            </ike-crypto-profiles>
            <ipsec-crypto-profiles>
              <entry name="STRONG-IPSEC">
                <esp><encryption><member>aes-256-gcm</member></encryption><authentication><member>sha256</member></authentication></esp>
                <dh-group>group14</dh-group>
              </entry>
              <entry name="WEAK-IPSEC">
                <esp><encryption><member>des</member></encryption><authentication><member>md5</member></authentication></esp>
                <dh-group>group5</dh-group>
              </entry>
            </ipsec-crypto-profiles>
          </crypto-profiles>
          <gateway>
            <entry name="gw-hq">
              <protocol><ikev2><ike-crypto-profile>STRONG-IKE</ike-crypto-profile></ikev2><version>ikev2</version></protocol>
              <authentication><pre-shared-key><key>PA_SECRET_ONE</key></pre-shared-key></authentication>
              <local-address><interface>ethernet1/1</interface></local-address>
              <peer-address><ip>198.51.100.10</ip></peer-address>
            </entry>
            <entry name="gw-legacy">
              <protocol><ikev1><ike-crypto-profile>WEAK-IKE</ike-crypto-profile></ikev1><version>ikev1</version></protocol>
              <authentication><pre-shared-key><key>PA_SECRET_TWO</key></pre-shared-key></authentication>
              <local-address><interface>ethernet1/1</interface></local-address>
              <peer-address><ip>198.51.100.20</ip></peer-address>
            </entry>
          </gateway>
        </ike>
        <tunnel>
          <ipsec>
            <entry name="vpn-pa-hq">
              <auto-key>
                <ike-gateway><entry name="gw-hq"/></ike-gateway>
                <ipsec-crypto-profile>STRONG-IPSEC</ipsec-crypto-profile>
                <proxy-id>
                  <entry name="proxy-1">
                    <local>10.10.1.0/24</local>
                    <remote>172.16.60.0/24</remote>
                  </entry>
                </proxy-id>
              </auto-key>
              <tunnel-interface>tunnel.1</tunnel-interface>
            </entry>
            <entry name="vpn-pa-legacy">
              <disabled>yes</disabled>
              <auto-key>
                <ike-gateway><entry name="gw-legacy"/></ike-gateway>
                <ipsec-crypto-profile>WEAK-IPSEC</ipsec-crypto-profile>
              </auto-key>
              <tunnel-interface>tunnel.2</tunnel-interface>
            </entry>
          </ipsec>
        </tunnel>
        <virtual-router>
          <entry name="default">
            <interface><member>ethernet1/1</member><member>tunnel.1</member></interface>
            <routing-table><ip><static-route>
              <entry name="to-hq">
                <destination>172.16.60.0/24</destination>
                <interface>tunnel.1</interface>
              </entry>
            </static-route></ip></routing-table>
          </entry>
        </virtual-router>
      </network>
      <vsys>
        <entry name="vsys1">
          <import><network><interface><member>ethernet1/1</member><member>tunnel.1</member><member>tunnel.2</member></interface></network></import>
          <zone>
            <entry name="trust"><network><layer3><member>ethernet1/1</member></layer3></network></entry>
            <entry name="vpn-z"><network><layer3><member>tunnel.1</member></layer3></network></entry>
          </zone>
          <address>
            <entry name="PA_LAN_NET"><ip-netmask>10.10.1.0/24</ip-netmask></entry>
            <entry name="PA_RANGE"><ip-range>10.10.1.50-10.10.1.60</ip-range></entry>
          </address>
          <address-group>
            <entry name="PA_GRP_1"><static><member>PA_LAN_NET</member></static></entry>
            <entry name="PA_GRP_2"><static><member>PA_GRP_1</member></static></entry>
          </address-group>
          <rulebase>
            <security><rules>
              <entry name="allow-vpn-hq">
                <from><member>trust</member></from>
                <to><member>vpn-z</member></to>
                <source><member>PA_GRP_2</member></source>
                <destination><member>any</member></destination>
                <application><member>any</member></application>
                <service><member>application-default</member></service>
                <action>allow</action>
              </entry>
            </rules></security>
            <nat><rules>
              <entry name="accidental-vpn-snat">
                <from><member>trust</member></from>
                <to><member>vpn-z</member></to>
                <source><member>PA_GRP_2</member></source>
                <destination><member>any</member></destination>
                <source-translation><dynamic-ip-and-port><interface-address><interface>tunnel.1</interface></interface-address></dynamic-ip-and-port></source-translation>
              </entry>
            </rules></nat>
          </rulebase>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>"""


def test_fortigate_where_used_recursive_groups_and_endpoints():
    reporter = source_reporters.get("fortigate")
    analysis = reporter.analyze_source(_FG_SAMPLE)

    # IPv4 inside subnet, mapped VIP, recursive nested group (GRP_LVL1 -> GRP_LVL2)
    res_ip = search_fortigate_where_used(analysis.extracted.config, "10.10.1.5")
    assert res_ip["query_type"] == "ip"
    assert {"LAN_HOST_5", "GRP_LVL1", "GRP_LVL2", "VIP_WEB"}.issubset(set(res_ip["resolved_objects"]))
    cats = {c["key"]: c["rows"] for c in res_ip["categories"]}
    assert any(r["name"] == "VIP_WEB" for r in cats["nat_vip_pools"])
    assert any(r["name"] == "Allow-LAN-to-HQ" for r in cats["policies"])
    assert any(r["name"] == "vpn-hq-p2" for r in cats["vpn_and_interfaces"])

    # CIDR query hitting range + cycle-safe groups + IP pool + route
    res_cidr = search_fortigate_where_used(analysis.extracted.config, "10.10.1.0/24")
    assert res_cidr["query_type"] == "cidr"
    assert {"LAN_RANGE", "GRP_CYCLE_A", "GRP_CYCLE_B", "SNAT_POOL"}.issubset(set(res_cidr["resolved_objects"]))
    cats_cidr = {c["key"]: c["rows"] for c in res_cidr["categories"]}
    assert any(r["kind"] == "IP Pool" and r["name"] == "SNAT_POOL" for r in cats_cidr["nat_vip_pools"])
    assert any(r["kind"] == "Interface" and r["name"] == "port2" for r in cats_cidr["vpn_and_interfaces"])

    # Object name query
    res_name = search_fortigate_where_used(analysis.extracted.config, "LAN_HOST_5")
    assert res_name["query_type"] == "name"
    assert "GRP_LVL2" in res_name["resolved_objects"]

    # HTTP endpoint POST /api/fg/where-used and POST /api/source/where-used
    client = create_app({"TESTING": True}).test_client()
    resp = client.post(
        "/api/fg/where-used",
        json={"source": {"vendor": "fortigate", "source_text": _FG_SAMPLE}, "query": "10.10.1.5"},
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["success"] is True
    assert body["vendor"] == "fortigate"
    assert body["total_matches"] >= 4
    assert "SUPER_SECRET_FG_PSK" not in json.dumps(body)


def test_paloalto_where_used_and_http_endpoint():
    reporter = source_reporters.get("palo_alto")
    analysis = reporter.analyze_source(_PA_SAMPLE)

    res = search_paloalto_where_used(analysis.config, "10.10.1.5")
    assert res["query_type"] == "ip"
    assert {"PA_LAN_NET", "PA_GRP_1", "PA_GRP_2"}.issubset(set(res["resolved_objects"]))
    cats = {c["key"]: c["rows"] for c in res["categories"]}
    assert any(r["name"] == "allow-vpn-hq" for r in cats["policies"])
    assert any(r["name"] == "accidental-vpn-snat" for r in cats["nat_vip_pools"])
    assert any(r["name"] == "vpn-pa-hq" for r in cats["vpn_and_interfaces"])

    client = create_app({"TESTING": True}).test_client()
    resp = client.post(
        "/api/pa/where-used",
        json={"source": {"vendor": "palo_alto", "source_text": _PA_SAMPLE}, "query": "10.10.1.55"},
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["success"] is True
    assert body["vendor"] == "palo_alto"
    assert "PA_RANGE" in body["resolved_objects"]
    assert "PA_SECRET_ONE" not in json.dumps(body)

    bad = client.post(
        "/api/source/where-used",
        json={"source_vendor": "fortigate", "source": {"vendor": "fortigate", "source_text": _FG_SAMPLE}, "query": "   "},
    )
    assert bad.status_code == 400


def test_fortigate_vpn_inspector_stitches_4_layers_and_checks():
    reporter = source_reporters.get("fortigate")
    analysis = reporter.analyze_source(_FG_SAMPLE)
    rows = {row["name"]: row for row in build_fortigate_vpn_inspector(analysis.extracted.config, analysis.derived)}
    assert set(rows) == {"vpn-hq", "vpn-legacy"}
    assert "SUPER_SECRET_FG_PSK" not in json.dumps(rows)

    hq = rows["vpn-hq"]
    assert hq["health"] == "warning"
    assert hq["zones"] == ["VPN-ZONE"]
    assert hq["phase2_count"] == 1
    assert hq["route_count"] == 1
    assert hq["policy_count"] == 1
    assert any(f["code"] == "ACCIDENTAL_NAT" for f in hq["findings"])
    assert not any(f["code"] == "WEAK_CRYPTO" for f in hq["findings"])

    legacy = rows["vpn-legacy"]
    assert legacy["health"] == "disabled"
    codes = {f["code"] for f in legacy["findings"]}
    assert {"TUNNEL_DISABLED", "MISSING_PHASE2", "MISSING_STATIC_ROUTE", "MISSING_ALLOW_POLICY", "LEGACY_IKEV1", "WEAK_CRYPTO"} <= codes


def test_paloalto_vpn_inspector_stitches_4_layers_and_checks():
    reporter = source_reporters.get("palo_alto")
    analysis = reporter.analyze_source(_PA_SAMPLE)
    rows = {row["name"]: row for row in build_paloalto_vpn_inspector(analysis.config, analysis.derived)}
    assert set(rows) == {"vpn-pa-hq", "vpn-pa-legacy"}
    assert "PA_SECRET_ONE" not in json.dumps(rows)
    assert "PA_SECRET_TWO" not in json.dumps(rows)

    hq = rows["vpn-pa-hq"]
    assert hq["health"] == "warning"
    assert hq["zones"] == ["vpn-z"]
    assert hq["virtual_router"] == "default"
    assert hq["phase2_count"] == 1
    assert hq["route_count"] == 1
    assert hq["policy_count"] == 1
    assert any(f["code"] == "ACCIDENTAL_NAT" for f in hq["findings"])
    assert not any(f["code"] == "WEAK_CRYPTO" for f in hq["findings"])

    legacy = rows["vpn-pa-legacy"]
    assert legacy["health"] == "disabled"
    codes = {f["code"] for f in legacy["findings"]}
    assert {"TUNNEL_DISABLED", "MISSING_PHASE2", "MISSING_TUNNEL_BINDING", "MISSING_STATIC_ROUTE", "MISSING_ALLOW_POLICY", "LEGACY_IKEV1", "WEAK_CRYPTO"} <= codes
