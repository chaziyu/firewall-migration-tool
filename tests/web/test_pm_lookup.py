"""Tests for Phase 2 Preventive Maintenance (PM) Lookup and Excel export."""

from __future__ import annotations

from datetime import date
import io

from openpyxl import load_workbook

from fwmigrate.source_reporting.pm_checklist import (
    evaluate_fortigate_pm_checklist,
    evaluate_paloalto_pm_checklist,
    export_pm_checklist_excel,
)
from fwmigrate.vendors.fortigate.derived import build_derived_views as build_fg_derived
from fwmigrate.vendors.fortigate.extraction.extractor import extract_fortigate_config
from fwmigrate.vendors.fortigate.parser import parse_fortigate_config
from fwmigrate.vendors.palo_alto.native import build_derived_views as build_pa_derived
from fwmigrate.vendors.palo_alto.source_builder import build_panos_config
from fwmigrate.web import create_app


_FG_PM_PASS_CONF = """#config-version=FGT60F-7.4.9-FW-build2829-250101:opmode=0:vdom=0:user=admin
#serial_number=FGT60FTK20000001
config system global
    set hostname "FG-PM-EDGE"
    set timezone 57
    set admin-sport 8443
    set admin-ssh-port 2222
end
config system ntp
    set ntpsync enable
    config ntpserver
        edit 1
            set server "time.cloudflare.com"
        next
    end
end
config system ha
    set mode a-p
    set group-name "PROD-HA"
    set priority 200
    set hbdev "port7" 50
end
config system interface
    edit "internal"
        set vdom "root"
        set ip 10.10.0.1 255.255.255.0
        set allowaccess https ssh ping
    next
    edit "vlan10"
        set vdom "root"
        set type vlan
        set interface "internal"
        set vlanid 10
        set ip 10.10.10.1 255.255.255.0
    next
    edit "wan1"
        set vdom "root"
        set role wan
        set ip 1.1.1.2 255.255.255.0
    next
end
config router static
    edit 1
        set dst 0.0.0.0 0.0.0.0
        set gateway 1.1.1.1
        set device "wan1"
    next
end
config log setting
    set fwpolicy-implicit-log enable
end
config log disk setting
    set status enable
end
config log fortianalyzer2 setting
    set status enable
    set server "10.10.0.50"
end
config log syslogd setting
    set status enable
    set server "10.10.0.51"
end
config vpn ipsec phase1-interface
    edit "hq-vpn"
        set interface "wan1"
        set ike-version 2
        set proposal aes256-sha256
        set dhgrp 14
        set remote-gw 9.9.9.9
        set psksecret ENC TEST_SECRET
    next
end
config vpn ipsec phase2-interface
    edit "hq-vpn-p2"
        set phase1name "hq-vpn"
        set proposal aes256-sha256
        set dhgrp 14
    next
end
config firewall policy
    edit 1
        set name "VPN_IN"
        set srcintf "hq-vpn"
        set dstintf "internal"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set schedule "always"
        set action accept
    next
end
"""

_FG_PM_WARN_CONF = """#config-version=FGT60E-6.4.14-FW-build2093-230801:opmode=0:vdom=0:user=admin
config system global
    set hostname "FG-PM-WARN"
    set timezone 04
end
config system ntp
    set ntpsync disable
end
config system interface
    edit "wan1"
        set vdom "root"
        set ip 1.1.1.2 255.255.255.0
        set allowaccess http https ssh
    next
end
config router static
    edit 1
        set dst 0.0.0.0 0.0.0.0
        set gateway 1.1.1.1
        set device "wan1"
    next
end
"""

_PA_PM_PASS_XML = """<config version="11.1.0" detail-version="11.1.4">
  <shared>
    <log-settings />
    <server-profile>
      <syslog><entry name="sys1"><server><entry name="s1"><server>10.0.0.5</server></entry></server></entry></syslog>
    </server-profile>
  </shared>
  <devices><entry name="fw">
    <deviceconfig>
      <system>
        <hostname>PA-PM-PASS</hostname>
        <ip-address>10.0.0.10</ip-address>
        <netmask>255.255.255.0</netmask>
        <timezone>Asia/Singapore</timezone>
        <service><disable-http>yes</disable-http><disable-https>no</disable-https><disable-ssh>no</disable-ssh></service>
        <permitted-ip><entry name="10.0.0.0/24"/></permitted-ip>
        <ntp-servers>
          <primary-ntp-server><ntp-server-address>10.0.0.2</ntp-server-address></primary-ntp-server>
          <secondary-ntp-server><ntp-server-address>10.0.0.3</ntp-server-address></secondary-ntp-server>
        </ntp-servers>
      </system>
      <high-availability>
        <enabled>yes</enabled>
        <group>
          <group-id>10</group-id>
          <peer-ip>169.254.1.2</peer-ip>
          <mode><active-active/></mode>
        </group>
        <interface><ha1><port>ha1-a</port><ip-address>169.254.1.1</ip-address></ha1></interface>
      </high-availability>
    </deviceconfig>
    <network>
      <interface><ethernet>
        <entry name="ethernet1/1"><link-state>up</link-state><layer3><ip><entry name="1.1.1.2/24"/></ip></layer3></entry>
        <entry name="ethernet1/2"><link-state>down</link-state><layer3><ip><entry name="10.1.1.1/24"/></ip></layer3></entry>
      </ethernet></interface>
      <virtual-router><entry name="default"><interface><member>ethernet1/1</member></interface><routing-table><ip><static-route><entry name="def"><destination>0.0.0.0/0</destination><interface>ethernet1/1</interface><nexthop><ip-address>1.1.1.1</ip-address></nexthop></entry></static-route></ip></routing-table></entry></virtual-router>
    </network>
    <vsys><entry name="vsys1">
      <zone><entry name="untrust"><network><layer3><member>ethernet1/1</member></layer3></network></entry></zone>
      <log-settings><profiles><entry name="fwd-prof"/></profiles></log-settings>
    </entry></vsys>
  </entry></devices>
</config>"""


def test_fortigate_pm_checklist_all_15_checks_and_statuses():
    extracted = extract_fortigate_config(parse_fortigate_config(_FG_PM_PASS_CONF))
    derived = build_fg_derived(extracted.config, source_metadata=extracted.source_metadata)
    res = evaluate_fortigate_pm_checklist(
        extracted.config,
        derived,
        metadata=extracted.source_metadata,
        today=date(2026, 6, 1),
    )
    assert res["vendor"] == "fortigate"
    assert res["hostname"] == "FG-PM-EDGE"
    assert res["summary"]["total"] == 15
    by_no = {r["no"]: r for r in res["rows"]}
    assert set(by_no) == {
        "1.1", "1.4", "3.1", "3.2", "3.3", "4.1", "5.1",
        "6.2", "6.3", "6.5", "6.6", "6.7", "6.8", "6.9", "6.10",
    }
    assert by_no["6.5"]["status"] == "Pass"
    assert "time.cloudflare.com" in by_no["6.5"]["finding"]
    assert by_no["6.7"]["status"] == "Pass"
    assert "PROD-HA" in by_no["6.7"]["finding"]
    assert by_no["6.9"]["status"] == "Pass"
    assert "FortiAnalyzer 2 (10.10.0.50)" in by_no["6.9"]["finding"]
    assert "Syslog (10.10.0.51)" in by_no["6.9"]["finding"]
    assert by_no["4.1"]["status"] == "Warn"  # VPN configured, missing static route to hq-vpn

    warn_ext = extract_fortigate_config(parse_fortigate_config(_FG_PM_WARN_CONF))
    warn_res = evaluate_fortigate_pm_checklist(
        warn_ext.config,
        build_fg_derived(warn_ext.config, source_metadata=warn_ext.source_metadata),
        metadata=warn_ext.source_metadata,
        today=date(2026, 6, 1),
    )
    warn_by_no = {r["no"]: r for r in warn_res["rows"]}
    assert warn_by_no["3.1"]["status"] == "Fail"
    assert warn_by_no["6.2"]["status"] == "Fail"
    assert warn_by_no["6.3"]["status"] == "Fail"
    assert warn_by_no["6.5"]["status"] == "Warn"
    assert warn_by_no["6.7"]["status"] == "Info"
    assert warn_by_no["6.9"]["status"] == "Warn"


def test_paloalto_pm_checklist_all_10_checks_and_90_day_filter():
    pa_cfg = build_panos_config(_PA_PM_PASS_XML)
    res = evaluate_paloalto_pm_checklist(pa_cfg, build_pa_derived(pa_cfg), today=date(2026, 6, 1))
    assert res["vendor"] == "palo_alto"
    assert res["hostname"] == "PA-PM-PASS"
    assert res["summary"]["total"] == 10
    by_no = {r["no"]: r for r in res["rows"]}
    assert set(by_no) == {"1.1", "1.4", "4.2", "4.3", "4.4", "4.5", "4.6", "4.7", "4.8", "4.9"}
    assert by_no["4.2"]["status"] == "Pass"
    assert by_no["4.3"]["status"] == "Pass"
    assert by_no["4.5"]["status"] == "Pass"
    assert "10.0.0.2, 10.0.0.3" in by_no["4.5"]["finding"]
    assert by_no["4.7"]["status"] == "Pass"
    assert "Active-Active, Group 10, Peer 169.254.1.2, HA1 ha1-a" in by_no["4.7"]["finding"]
    assert by_no["4.8"]["status"] == "Pass"
    assert "2026/03/03 00:00:00" in by_no["4.8"]["guidance"]


def test_pm_checklist_excel_export_and_routes():
    client = create_app({"TESTING": True, "WEB_MODE": "public"}).test_client()
    fg_payload = {
        "source_vendor": "fortigate",
        "source": {"vendor": "fortigate", "source_text": _FG_PM_PASS_CONF, "source_name": "fg.conf"},
    }
    pa_payload = {
        "source_vendor": "palo_alto",
        "source": {"vendor": "palo_alto", "source_text": _PA_PM_PASS_XML, "source_name": "pa.xml"},
    }

    fg_resp = client.post("/api/source/pm-lookup", json=fg_payload)
    assert fg_resp.status_code == 200
    fg_data = fg_resp.get_json()
    assert fg_data["success"] is True
    assert fg_data["summary"]["total"] == 15

    pa_resp = client.post("/api/source/pm-lookup", json=pa_payload)
    assert pa_resp.status_code == 200
    assert pa_resp.get_json()["summary"]["total"] == 10

    bad_resp = client.post(
        "/api/source/pm-lookup",
        json={"source_vendor": "cisco_asa", "source": {"vendor": "cisco_asa", "source_text": ""}},
    )
    assert bad_resp.status_code == 400

    export_resp = client.post("/api/source/pm-lookup/export", json=fg_payload)
    assert export_resp.status_code == 200
    assert "spreadsheetml" in export_resp.headers.get("Content-Type", "")
    assert "fortigate_pm_lookup.xlsx" in export_resp.headers.get("Content-Disposition", "")

    wb = load_workbook(io.BytesIO(export_resp.data))
    assert wb.sheetnames == ["PM Lookup"]
    ws = wb["PM Lookup"]
    assert ws["A5"].value == "No."
    assert ws["F5"].value == "Recommendation / Follow-up"
    assert ws["A6"].value == "1.1"
    assert ws["C20"].value == "Backup Configurations"

    # Formula neutralization check on direct Excel builder
    formula_bytes = export_pm_checklist_excel(
        {
            "vendor": "fortigate",
            "vendor_label": "FortiGate",
            "hostname": "=CMD|calc",
            "subtitle": "sub",
            "summary": {"pass": 1, "warn": 0, "fail": 0, "info": 0, "total": 1},
            "rows": [
                {
                    "no": "1.1",
                    "category": "Cat",
                    "task": "+Task",
                    "status": "Pass",
                    "finding": "@finding",
                    "guidance": "-guide",
                }
            ],
        }
    )
    f_wb = load_workbook(io.BytesIO(formula_bytes))
    f_ws = f_wb["PM Lookup"]
    assert str(f_ws["B2"].value).startswith("'")
    assert str(f_ws["C6"].value).startswith("'")
    assert str(f_ws["E6"].value).startswith("'")
    assert str(f_ws["F6"].value).startswith("'")
