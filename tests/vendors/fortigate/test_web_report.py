from __future__ import annotations

import json
import unittest
from copy import deepcopy

from fwmigrate.vendors.fortigate.derived import build_derived_views
from fwmigrate.vendors.fortigate.model.address import FGAddress, FGAddressGroup
from fwmigrate.vendors.fortigate.model.interface import FGInterface
from fwmigrate.vendors.fortigate.model.policy import FGPolicy
from fwmigrate.vendors.fortigate.model.route_static import FGStaticRoute
from fwmigrate.vendors.fortigate.model.service import FGService
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.fortigate.model.vpn import FGIPsecPhase1, FGIPsecPhase2
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter
from fwmigrate.vendors.fortigate.validation.validator import validate_config
from fwmigrate.vendors.fortigate.web_report import build_web_report


def test_report_keeps_policy_inspection_authentication_and_absent_lists():
    source = '''config firewall policy
 edit 1
  set name inspected
  set logtraffic all
  set comments "review comment"
  set groups "staff"
  set utm-status enable
  set ips-sensor "sensor"
  set ssl-ssh-profile "inspection"
  set srcaddr-negate disable
  set poolname "pool"
  set custom-review "safe evidence"
 next
 edit 2
  set srcaddr all
  unset srcaddr
 next
end
'''
    reporter = FortiGateSourceReporter()
    analysis = reporter.analyze_source(source)
    before = deepcopy(analysis.extracted.config.model_dump())
    rows = reporter.build_preview(analysis)["sections"]["policies"]
    row = rows[0]
    assert {key: row[key] for key in ("logtraffic", "comments", "groups", "utm_status", "ips_sensor",
                                     "ssl_ssh_profile", "srcaddr_negate", "poolname")} == {
        "logtraffic": "all", "comments": "review comment", "groups": ["staff"], "utm_status": "enable",
        "ips_sensor": "sensor", "ssl_ssh_profile": "inspection", "srcaddr_negate": "disable", "poolname": ["pool"]}
    assert row["additional_settings"]["custom_review"] == "safe evidence"
    assert "logtraffic" in row["explicit_fields"]
    assert row["source_addresses"] is None and row["services"] is None
    assert rows[1]["source_addresses"] is None
    assert analysis.extracted.config.model_dump() == before
    config = FGConfig(policies=[FGPolicy(policy_id=0, srcaddr=[], service=[])])
    derived = build_derived_views(config)
    empty = build_web_report(config, derived, validate_config(config, derived=derived), top_level_sections=1)
    assert empty["sections"]["policies"][0]["source_addresses"] == []
    assert empty["sections"]["policies"][0]["services"] == []


def test_report_exposes_nested_typed_families_and_redacts_nested_evidence():
    from fwmigrate.vendors.fortigate.model.admin import FGAdminProfile, FGAdminSystemPermission
    from fwmigrate.vendors.fortigate.model.dhcp import FGDHCPServer, FGDHCPIPRange
    from fwmigrate.vendors.fortigate.model.ips import FGIPSSensor, FGIPSSensorEntry
    from fwmigrate.vendors.fortigate.model.sdwan import FGSDWAN, FGSDWANMember
    from fwmigrate.vendors.fortigate.model.user import FGUserGroup, FGUserGroupMatch
    from fwmigrate.vendors.fortigate.model.vip import FGVIP, FGVIPRealServer
    from fwmigrate.vendors.fortigate.model.vpn_ssl import FGSSLVPNSettings, FGSSLVPNAuthenticationRule

    config = FGConfig(
        user_groups=[FGUserGroup(name="staff", vdom="branch", matches=[FGUserGroupMatch(id=1, group_name="remote")])],
        admin_profiles=[FGAdminProfile(name="operator", cli_vdom="branch", scope="vdom",
            system_permission=FGAdminSystemPermission(raw_extra={"password": "NESTED_SECRET", "safe": "retained"}))],
        ips_sensors=[FGIPSSensor(name="sensor", entries=[FGIPSSensorEntry(id=2, action="block")])],
        sdwans=[FGSDWAN(vdom="branch", members=[FGSDWANMember(seq_num=1, cost=0)])],
        vips=[FGVIP(name="vip", realservers=[FGVIPRealServer(id=1, ip="192.0.2.10")])],
        dhcp_servers=[FGDHCPServer(id=1, ip_ranges=[FGDHCPIPRange(id=1, start_ip="192.0.2.20", end_ip="192.0.2.30")])],
        ssl_vpn_settings=[FGSSLVPNSettings(authentication_rules=[FGSSLVPNAuthenticationRule(id=1, groups=["staff"])])],
    )
    derived = build_derived_views(config)
    before = deepcopy(config.model_dump())
    report = build_web_report(config, derived, validate_config(config, derived=derived), top_level_sections=1)
    sections = report["sections"]
    assert sections["user_groups"][0]["matches"][0]["group_name"] == "remote"
    assert sections["admin_profiles"][0]["vdom"] == "branch"
    assert sections["admin_profiles"][0]["profile_scope"] == "vdom"
    assert sections["admin_profiles"][0]["system_permission"]["additional_settings"]["safe"] == "retained"
    assert sections["ips_sensors"][0]["entries"][0]["action"] == "block"
    assert sections["sdwan"][0]["members"][0]["cost"] == 0
    assert sections["vips"][0]["realservers"][0]["ip"] == "192.0.2.10"
    assert sections["dhcp_servers"][0]["ip_ranges"][0]["start_ip"] == "192.0.2.20"
    assert sections["ssl_vpn_settings"][0]["authentication_rules"][0]["groups"] == ["staff"]
    assert "NESTED_SECRET" not in json.dumps(report)
    assert "raw_extra" not in json.dumps(report)
    assert config.model_dump() == before


def test_preview_retains_complete_scoped_inventory_commands_and_coverage():
    from collections import Counter
    from dataclasses import replace
    from fwmigrate.vendors.fortigate.extraction.result import ExtractionResult

    source = '''config global
 config system dns
  set primary 192.0.2.53
 end
 config system ntp
  set ntpsync enable
  config ntpserver
   edit 1
    set server ntp.example.test
   next
  end
 end
end
config vdom
 edit branch
  config firewall address
   edit same
    set subnet 192.0.2.0 255.255.255.0
    unset comment
   next
  end
  config unsupported-empty
  end
  config unsupported-setting
   set password TEST_SECRET
   set useful retained
   set custom-control retained
  end
 next
end
'''
    reporter = FortiGateSourceReporter()
    analysis = reporter.analyze_source(source)
    before = deepcopy(analysis.extracted.config.model_dump())
    report = reporter.build_preview(analysis)
    records = report["sections"]["source_inventory"]
    assert len(records) == report["summary"]["records"] == len(analysis.extracted.source_objects)
    counts = Counter(row["extraction_status"] for row in records)
    assert counts["SOURCE_ONLY"] == report["summary"]["source_only_count"]
    assert counts["EMPTY_SECTION"] == report["summary"]["empty_section_count"] == 1
    assert report["summary"]["model_gap_count"] == 0
    dns = next(row for row in records if row["source_path"] == "system dns")
    assert dns["cli_scope"] == "global" and dns["values"]["primary"] == "192.0.2.53"
    server = next(row for row in records if row["source_path"] == "system ntp ntpserver")
    assert server["name"] == "1" and server["values"]["server"] == "ntp.example.test"
    address = next(row for row in records if row["source_path"] == "firewall address")
    assert address["vdom"] == "branch" and "comment" in address["unset_fields"]
    assert any(command["operation"] == "unset" and command["field"] == "comment" for command in address["commands"])
    assert address["start_line_number"] < address["end_line_number"]
    assert "TEST_SECRET" not in json.dumps(report)
    source_record = next(record for record in analysis.extracted.source_objects if record.source_path == "unsupported-setting")
    assert next(row for row in records if row["source_path"] == "unsupported-setting")["values"] == source_record.values
    assert analysis.extracted.config.model_dump() == before
    missing_model = ExtractionResult(config=FGConfig(), source_objects=analysis.extracted.source_objects)
    gaps = reporter.build_preview(replace(analysis, extracted=missing_model))
    assert gaps["summary"]["model_gap_count"] == 1
    assert next(row for row in gaps["sections"]["extraction_coverage"]
                if row["source_path"] == "firewall address")["status"] == "MODEL_GAP"


class WebReportTest(unittest.TestCase):
    def setUp(self) -> None:
        self.secret = "do-not-serialize-this-psk"
        self.config = FGConfig(
            interfaces=[
                FGInterface(
                    name="agg1",
                    type="aggregate",
                    members=["port1"],
                ),
                FGInterface(
                    name="port1",
                    ip="192.0.2.1 255.255.255.0",
                    raw_extra={"psksecret": self.secret},
                )
            ],
            addresses=[FGAddress(name="server", subnet="10.0.0.0 255.255.255.0")],
            address_groups=[FGAddressGroup(name="broken", members=["missing"])],
            services=[FGService(name="WEB", tcp_portrange="80 443")],
            policies=[
                FGPolicy(
                    policy_id=1,
                    name="A" * 34,
                    srcintf=["port1"],
                    dstintf=["port1"],
                    srcaddr=["all"],
                    dstaddr=["server"],
                    service=["WEB"],
                    schedule="always",
                    action="accept",
                    nat="enable",
                )
            ],
            static_routes=[FGStaticRoute(seq_num=1, dst="0.0.0.0 0.0.0.0")],
            ipsec_phase1=[
                FGIPsecPhase1(
                    name="tunnel",
                    interface="port1",
                    remote_gw="198.51.100.1",
                    ike_version="2",
                )
            ],
            ipsec_phase2=[
                FGIPsecPhase2(
                    name="selectors",
                    phase1name="tunnel",
                    src_subnet="192.0.2.0 255.255.255.0",
                    dst_addr_type="name",
                    dst_name="server",
                )
            ],
        )
        self.derived = build_derived_views(self.config)
        self.validation = validate_config(self.config, derived=self.derived)
        self.report = build_web_report(
            self.config,
            self.derived,
            self.validation,
            top_level_sections=8,
        )

    def test_summary_and_explicit_source_fields(self):
        self.assertEqual("fortigate", self.report["vendor"])
        summary = self.report["summary"]
        self.assertEqual(8, summary["top_level_sections"])
        self.assertEqual(2, summary["objects"]["interfaces"])
        self.assertEqual(["root"], summary["vdoms"])
        self.assertEqual(summary["vdoms"], summary["scopes"])
        self.assertIsInstance(summary["objects"], dict)
        self.assertIn("severity_counts", summary["validation"])

        interface = next(
            row
            for row in self.report["sections"]["interfaces"]
            if row["name"] == "port1"
        )
        self.assertEqual("port1", interface["name"])
        self.assertEqual(["port1"], interface["physical_interfaces"])
        self.assertIsNone(interface["type"])
        self.assertIsNone(self.report["sections"]["routes"][0]["distance"])

    def test_interface_topology_nests_vpn_under_interface(self):
        rows = self.report["sections"]["interface_topology"]
        self.assertEqual(["agg1", "port1", "tunnel"], [row["name"] for row in rows])
        self.assertEqual("aggregate", rows[0]["kind"])
        self.assertEqual("physical", rows[1]["kind"])
        self.assertEqual("vpn", rows[2]["kind"])
        self.assertEqual("port1", rows[2]["parent"])
        self.assertTrue(rows[2]["display_name"].lstrip().startswith("└─ ◈"))

    def test_genuine_derived_values_are_used(self):
        services = self.report["sections"]["services"]
        self.assertEqual(["80", "443"], [item["port"] for item in services])
        self.assertTrue(all(item["generated"] for item in services))

        policy = self.report["sections"]["policies"][0]
        self.assertEqual("A" * 34, policy["name"])
        self.assertEqual(["all"], policy["source_addresses"])
        self.assertEqual(["server"], policy["destination_addresses"])
        self.assertEqual("always", policy["schedule"])
        self.assertEqual("192.0.2.1", self.report["sections"]["nat"][0]["translated_addresses"][0])

        phase2 = self.report["sections"]["vpn_phase2"][0]
        self.assertEqual("192.0.2.0-192.0.2.255", phase2["source_range"])
        self.assertEqual("10.0.0.0-10.0.0.255", phase2["destination_range"])

    def test_policy_report_keeps_ipv4_and_ipv6_addresses_separate(self):
        self.config.policies.extend(
            [
                FGPolicy(
                    policy_id=2,
                    srcaddr=["SRC-V4"],
                    srcaddr6=["SRC-V6"],
                    dstaddr=["DST-V4"],
                    dstaddr6=["DST-V6"],
                    srcaddr6_negate="enable",
                    dstaddr6_negate="disable",
                ),
                FGPolicy(
                    policy_id=3,
                    srcaddr6=["ONLY-SRC-V6"],
                    dstaddr6=["ONLY-DST-V6"],
                ),
            ]
        )
        derived = build_derived_views(self.config)
        report = build_web_report(
            self.config,
            derived,
            validate_config(self.config, derived=derived),
            top_level_sections=8,
        )
        by_id = {row["policy_id"]: row for row in report["sections"]["policies"]}
        self.assertEqual(["SRC-V4"], by_id[2]["source_addresses"])
        self.assertEqual(["SRC-V6"], by_id[2]["source_addresses_ipv6"])
        self.assertEqual(["DST-V4"], by_id[2]["destination_addresses"])
        self.assertEqual(["DST-V6"], by_id[2]["destination_addresses_ipv6"])
        self.assertEqual("enable", by_id[2]["source_address_negate_ipv6"])
        self.assertEqual("disable", by_id[2]["destination_address_negate_ipv6"])
        self.assertIsNone(self.config.policies[-1].srcaddr)
        self.assertIsNone(self.config.policies[-1].dstaddr)
        self.assertIsNone(by_id[3]["source_addresses"])
        self.assertEqual(["ONLY-SRC-V6"], by_id[3]["source_addresses_ipv6"])
        self.assertIsNone(by_id[3]["destination_addresses"])
        self.assertEqual(["ONLY-DST-V6"], by_id[3]["destination_addresses_ipv6"])

    def test_validation_and_broken_references_are_serialized(self):
        broken = self.report["sections"]["unresolved_references"]
        self.assertEqual("missing", broken[0]["reference"])
        self.assertTrue(self.report["sections"]["validation"])
        self.assertEqual(
            len(self.validation.issues),
            self.report["summary"]["validation"]["issue_count"],
        )
        self.assertEqual(1, len(self.report["sections"]["routes"]))
        self.assertEqual(1, len(self.report["sections"]["vpn_tunnels"]))
        self.assertEqual(1, len(self.report["sections"]["vpn_phase2"]))
        self.assertEqual(1, len(broken))
        self.assertNotIn("unsupported_count", self.report["summary"])
        self.assertIsNone(self.report["sections"]["routes"][0]["distance"])

    def test_raw_extra_and_secrets_are_not_serialized(self):
        serialized = json.dumps(self.report)
        self.assertNotIn("raw_extra", serialized)
        self.assertNotIn(self.secret, serialized)

    def test_missing_source_sections_preserve_values_scope_and_redaction(self):
        source = '''config vdom
 edit branch
  config firewall vip
   edit public
    set extip 198.51.100.10
    set extintf wan1
    set mappedip 10.0.0.10
    set portforward enable
    set extport 443
    set mappedport 8443
    set password synthetic-secret
   next
  end
  config firewall vip6
   edit public
    set extip 2001:db8::10
    set mappedip 2001:db8:1::10
   next
  end
  config firewall vipgrp
   edit public-group
    set member public
   next
  end
  config firewall ippool
   edit snat
    set startip 198.51.100.20
    set endip 198.51.100.21
    set arp-reply disable
   next
  end
  config firewall ippool6
   edit snat
    set startip 2001:db8::20
    set endip 2001:db8::21
   next
  end
  config firewall wildcard-fqdn custom
   edit wildcard
    set wildcard-fqdn *.example.test
   next
  end
  config user local
   edit alice
    set type password
    set status disable
    set passwd synthetic-secret
   next
  end
  config system dhcp server
   edit 1
    set interface lan
    set default-gateway 10.0.0.1
    set netmask 255.255.255.0
    set lease-time 0
   next
  end
  config vpn ssl web portal
   edit remote
    set tunnel-mode disable
    set ip-pools SSLVPN_TUNNEL_ADDR1
   next
  end
 next
end
config system admin
 edit operator
  set vdom branch
  set accprofile read-only
  set trusthost1 192.0.2.0 255.255.255.0
  set password synthetic-secret
 next
end
'''
        reporter = FortiGateSourceReporter()
        analysis = reporter.analyze_source(source)
        before = deepcopy(analysis)
        report = reporter.build_preview(analysis)
        sections = report["sections"]
        self.assertEqual(["ipv4", "ipv6"], [row["address_family"] for row in sections["vips"]])
        self.assertEqual("8443", sections["vips"][0]["mappedport"])
        self.assertEqual(["10.0.0.10"], sections["vips"][0]["mappedip"])
        self.assertEqual(["public"], sections["vip_groups"][0]["members"])
        self.assertEqual(["ipv4", "ipv6"], [row["address_family"] for row in sections["ip_pools"]])
        self.assertIsNone(sections["ip_pools"][0]["type"])
        self.assertEqual("disable", sections["ip_pools"][0]["arp_reply"])
        self.assertEqual("*.example.test", sections["wildcard_fqdns"][0]["wildcard_fqdn"])
        self.assertEqual("disable", sections["local_users"][0]["status"])
        self.assertEqual(0, sections["dhcp_servers"][0]["lease_time"])
        self.assertEqual("disable", sections["ssl_vpn_portals"][0]["tunnel_mode"])
        self.assertEqual(["SSLVPN_TUNNEL_ADDR1"], sections["ssl_vpn_portals"][0]["ip_pools"])
        self.assertEqual(["branch"], sections["administrators"][0]["vdoms"])
        self.assertEqual(["192.0.2.0 255.255.255.0"], sections["administrators"][0]["trusthosts"])
        self.assertEqual("branch", sections["vips"][0]["vdom"])
        self.assertIn("branch", report["summary"]["scopes"])
        self.assertEqual(2, report["summary"]["objects"]["vips"])
        self.assertEqual(1, report["summary"]["objects"]["local_users"])
        serialized = json.dumps(report)
        self.assertNotIn("synthetic-secret", serialized)
        self.assertNotIn("raw_extra", serialized)
        self.assertEqual(before, analysis)

    def test_missing_sections_keep_empty_inventory_without_inventing_values(self):
        report = FortiGateSourceReporter().build_preview(FortiGateSourceReporter().analyze_source('''config vpn ssl web portal
 edit absent
 next
 edit empty
  set ip-pools
 next
end'''))
        self.assertIsNone(report["sections"]["ssl_vpn_portals"][0]["ip_pools"])
        self.assertEqual([], report["sections"]["ssl_vpn_portals"][1]["ip_pools"])
        self.assertEqual([], report["sections"]["vips"])
        self.assertEqual([], report["sections"]["local_users"])

    def test_invalid_interface_address_is_reported_directly_without_repair(self):
        for value in ("ource static any any destination static", "192.0.2.1 255.0.255.0", "2001:db8::1/64", ""):
            with self.subTest(value=value):
                config = FGConfig(interfaces=[FGInterface(name="wan1", ip=value)])
                before = config.model_dump()
                result = validate_config(config)
                findings = [issue for issue in result.issues if issue.domain == "interface" and issue.field == "ip"]
                self.assertEqual(1, len(findings))
                self.assertEqual("error", findings[0].severity.value)
                self.assertEqual("wan1", findings[0].object_name)
                self.assertEqual(before, config.model_dump())
        for value in (None, "192.0.2.1 255.255.255.0", "192.0.2.1/24", "0.0.0.0 0.0.0.0"):
            with self.subTest(value=value):
                config = FGConfig(interfaces=[FGInterface(name="wan1", ip=value)])
                self.assertFalse([issue for issue in validate_config(config).issues if issue.domain == "interface" and issue.field == "ip"])

    def test_extended_fortigate_sections_and_fields_preserve_source_data_without_secret_leaks(self):
        source = '''#config-version=FGT60F-7.2.8-FW-build1639-240415:opmode=0:vdom=0:user=admin
#conf_file_ver=123456
#buildno=1639
#global_vdom=1
config system global
 set hostname fg-edge-01
 set timezone 04
 set admin-sport 8443
 set revision-backup-on-logout enable
end
config system ha
 set mode a-p
 set group-id 10
 set group-name ha-cluster
 set priority 200
 set password SUPER_SECRET_HA_PWD
 set monitor port1 port2
end
config system snmp community
 edit 1
  set name SUPER_SECRET_COMMUNITY
  set query-v2c-status enable
  config hosts
   edit 1
    set ip 192.0.2.50 255.255.255.255
   next
  end
 next
end
config system interface
 edit "port1"
  set ip 192.0.2.1 255.255.255.0
  set mtu 1500
  set distance 5
  set priority 10
  set snmp-index 1
  set lacp-mode active
  set management-ip 192.0.2.2 255.255.255.0
 next
end
config router bgp
 set as 65100
 set router-id 192.0.2.1
 config neighbor
  edit "192.0.2.254"
   set remote-as 65200
   set password SUPER_SECRET_BGP_PWD
  next
 end
end
config router policy
 edit 1
  set input-device "port1"
  set src "10.0.0.0/8"
  set gateway 192.0.2.254
  set output-device "port2"
 next
end
config firewall proxy-policy
 edit 1
  set proxy explicit-web
  set srcintf "port1"
  set dstintf "port2"
  set srcaddr "all"
  set dstaddr "all"
  set service "webproxy"
  set action accept
 next
end
config firewall shaper traffic-shaper
 edit "VoIP-Guarantee"
  set guaranteed-bandwidth 1000
  set maximum-bandwidth 5000
 next
end
config firewall ldb-monitor
 edit "http-check"
  set type http
  set port 8080
  set interval 10
 next
end
config firewall vip
 edit "vs-web"
  set type server-load-balance
  set extip 198.51.100.20
  set extintf "port1"
  set server-type http
  set ldb-method round-robin
  config realservers
   edit 1
    set ip 10.10.10.10
    set port 80
   next
  end
 next
end
config antivirus profile
 edit "av-strict"
  set feature-set proxy
  config http
   set av-scan block
  end
 next
end
config webfilter profile
 edit "wf-corp"
  set feature-set flow
  config web
   set urlfilter-table 1
  end
 next
end
config firewall ssl-ssh-profile
 edit "deep-inspect"
  config https
   set ports 443
   set status deep-inspection
  end
 next
end
config user ldap
 edit "corp-ad"
  set server 10.0.0.10
  set port 636
  set cnid "sAMAccountName"
  set dn "dc=example,dc=com"
  set password SUPER_SECRET_LDAP_PWD
 next
end
config user fortitoken
 edit "FTKMOB123456"
  set status active
  set seed SUPER_SECRET_TOKEN_SEED
 next
end
config wireless-controller vap
 edit "corp-wifi"
  set ssid "CorpWiFi"
  set security wpa2-only-personal
  set passphrase SUPER_SECRET_WIFI_PSK
 next
end
config log syslogd setting
 set status enable
 set server 192.0.2.200
 set port 514
end
config system admin
 edit "secadmin"
  set accprofile "super_admin"
  set vdom "root"
  set password SUPER_SECRET_ADMIN_PWD
  set force-password-change enable
  set ssh-public-key1 "ssh-rsa AAAA"
 next
end
'''
        reporter = FortiGateSourceReporter()
        analysis = reporter.analyze_source(source)
        report = reporter.build_preview(analysis)
        sections = report["sections"]
        summary = report["summary"]

        self.assertEqual("FGT60F", summary["source_metadata"]["hardware_model"])
        self.assertEqual("7.2.8", summary["source_metadata"]["fortios_version"])
        self.assertEqual("build1639", summary["source_metadata"]["firmware_build"])

        port1 = next(row for row in sections["interfaces"] if row["name"] == "port1")
        self.assertEqual(1500, port1["mtu"])
        self.assertEqual(5, port1["distance"])
        self.assertEqual(10, port1["priority"])
        self.assertEqual(1, port1["snmp_index"])
        self.assertEqual("active", port1["lacp_mode"])
        self.assertEqual("192.0.2.2 255.255.255.0", port1["management_ip"])

        self.assertEqual("fg-edge-01", sections["system_global"][0]["hostname"])
        self.assertEqual("a-p", sections["ha_config"][0]["mode"])
        self.assertTrue(sections["ha_config"][0]["password_configured"])
        self.assertTrue(sections["snmp_communities"][0]["community_configured"])
        self.assertIsNone(sections["snmp_communities"][0]["name"])
        self.assertEqual(65100, sections["router_bgp"][0]["bgp_as"])
        self.assertTrue(sections["router_bgp"][0]["neighbors"][0]["password_configured"])
        self.assertEqual(["port1"], sections["policy_routes"][0]["input_device"])
        self.assertEqual("explicit-web", sections["proxy_policies"][0]["proxy"])
        self.assertEqual(1000, sections["traffic_shapers"][0]["guaranteed_bandwidth"])
        self.assertEqual("http", sections["ldb_monitors"][0]["type"])
        self.assertEqual("vs-web", sections["virtual_servers"][0]["name"])
        self.assertEqual("block", sections["antivirus_profiles"][0]["protocols"][0]["av_scan"])
        self.assertEqual(1, sections["webfilter_profiles"][0]["urlfilter_table"])
        self.assertEqual("deep-inspection", sections["ssl_ssh_profiles"][0]["protocols"][0]["status"])
        self.assertTrue(sections["ldap_servers"][0]["password_configured"])
        self.assertEqual("FTKMOB123456", sections["fortitokens"][0]["serial_number"])
        self.assertTrue(sections["fortitokens"][0]["seed_configured"])
        self.assertTrue(sections["wireless_vaps"][0]["passphrase_configured"])
        self.assertEqual("192.0.2.200", sections["syslog_settings"][0]["server"])
        self.assertEqual("enable", sections["administrators"][0]["additional_settings"]["force_password_change"])
        self.assertTrue(sections["administrators"][0]["password_configured"])
        self.assertTrue(sections["administrators"][0]["ssh_key_configured"])

        serialized = json.dumps(report)
        self.assertNotIn("SUPER_SECRET_", serialized)
        self.assertNotIn("raw_extra", serialized)

    def test_guest_users_switch_policies_references_and_excel_sheets(self):
        import io
        from openpyxl import load_workbook
        from fwmigrate.vendors.fortigate.export.excel import export_excel

        source = '''
config system interface
 edit "port1"
  set vdom "root"
 next
end
config user guest
 edit "1"
  set user-id "visitor1"
  set sponsor "alice"
  set password SUPER_SECRET_GUEST_PWD
 next
end
config switch-controller port-policy
 edit "corp-port"
  set fortilink "fortilink"
  set qos-policy "qos1"
  set vlan-policy "vlan1"
 next
end
config switch-controller lldp-profile
 edit "lldp1"
  set med-tlvs inventory-management network-policy
 next
end
config switch-controller qos qos-policy
 edit "qos1"
  set default-cos 3
 next
end
config switch-controller vlan-policy
 edit "vlan1"
  set vlan "corp-vlan"
 next
end
config firewall ssl-ssh-profile
 edit "custom-ssl"
 next
end
config firewall proxy-policy
 edit 10
  set proxy explicit-web
  set srcintf "port1"
  set dstintf "port1"
  set srcaddr "all"
  set dstaddr "all"
  set service "ALL"
  set schedule "always"
  set ssl-ssh-profile "missing-ssl"
 next
end
'''
        reporter = FortiGateSourceReporter()
        analysis = reporter.analyze_source(source)
        report = reporter.build_preview(analysis)
        sections = report["sections"]

        self.assertEqual("visitor1", sections["guest_users"][0]["user_id"])
        self.assertTrue(sections["guest_users"][0]["password_configured"])
        self.assertNotIn("SUPER_SECRET_GUEST_PWD", json.dumps(report))
        self.assertEqual("corp-port", sections["switch_port_policies"][0]["name"])
        self.assertEqual("lldp1", sections["switch_lldp_profiles"][0]["name"])
        self.assertEqual(3, sections["switch_qos_policies"][0]["default_cos"])
        self.assertEqual("corp-vlan", sections["switch_vlan_policies"][0]["vlan"])
        self.assertTrue(any(
            item["source_kind"] == "proxy_policy" and item["reference"] == "missing-ssl"
            for item in sections["unresolved_references"]
        ))

        buf = io.BytesIO()
        export_excel(
            extracted=analysis.extracted,
            derived=analysis.derived,
            validation=analysis.validation,
            output=buf,
            source_name="test.conf",
        )
        buf.seek(0)
        wb = load_workbook(buf, read_only=True)
        for sheet_name in (
            "Guest Users", "Managed FortiAPs", "WiFi SSIDs", "FortiAP Profiles",
            "WIDS Profiles", "Managed Switches", "Switch Port Policies", "NAC Policies",
            "Proxy Policies", "SSL-SSH Profiles",
        ):
            self.assertIn(sheet_name, wb.sheetnames)
        wb.close()

    def test_wifi_switch_all_seven_sections_in_web_report_excel_and_chat_summary(self):
        import io
        from openpyxl import load_workbook
        from fwmigrate.vendors.fortigate.export.excel import export_excel
        from fwmigrate.web_support.chat_service import build_config_summary

        source = '''
config wireless-controller wtp-profile
 edit "FAP221E-prof"
  set comment "Campus AP"
  config platform
   set type 221E
  end
 next
end
config wireless-controller wtp
 edit "FAP221E-default"
  set admin enable
  set wtp-profile "FAP221E-prof"
  set location "Bldg 1"
 next
end
config wireless-controller vap
 edit "guest-wifi"
  set ssid "Guest"
  set status disable
  set schedule "always"
  set local-bridging enable
  set security wpa2-only-personal
  set passphrase SUPER_SECRET_GUEST_PSK
 next
end
config wireless-controller wids-profile
 edit "wids-default"
  set ap-scan enable
  set comment "Monitor rogues"
 next
end
config switch-controller managed-switch
 edit "FS124F-01"
  set name "Access-SW1"
  set switch-group "Edge"
  set status enable
  set platform FS-124F
  set firmware-provision-version "7.4.2"
 next
end
config switch-controller port-policy
 edit "nac-port"
  set user-group "employees"
  set guest-vlan "guest"
  set guest-auth-delay 30
  set mac-auth-bypass enable
  set eap-passthru enable
  set radius-timeout-overwrite disable
 next
end
config user nac-policy
 edit "iot-devices"
  set hw-vendor "Axis"
  set assign-vlan 150
  set matched-devices 4
  set status enable
 next
end
'''
        reporter = FortiGateSourceReporter()
        analysis = reporter.analyze_source(source)
        report = reporter.build_preview(analysis)
        sections = report["sections"]

        self.assertEqual("221E", sections["wtp_profiles"][0]["platform"])
        self.assertEqual("Bldg 1", sections["wireless_wtps"][0]["location"])
        self.assertEqual("always", sections["wireless_vaps"][0]["schedule"])
        self.assertTrue(sections["wireless_vaps"][0]["passphrase_configured"])
        self.assertEqual("enable", sections["wids_profiles"][0]["ap_scan"])
        self.assertEqual("Edge", sections["managed_switches"][0]["switch_group"])
        self.assertEqual("7.4.2", sections["managed_switches"][0]["firmware_provision_version"])
        self.assertEqual(["employees"], sections["switch_port_policies"][0]["user_group"])
        self.assertEqual("150", sections["nac_policies"][0]["assign_vlan"])
        self.assertEqual(4, sections["nac_policies"][0]["matched_devices"])
        self.assertNotIn("SUPER_SECRET_GUEST_PSK", json.dumps(report))

        summary_text = build_config_summary(vendor="fortigate", filename="fg.conf", preview=report)
        for key in (
            "[wireless_wtps]", "[wireless_vaps]", "[wtp_profiles]",
            "[wids_profiles]", "[managed_switches]", "[switch_port_policies]", "[nac_policies]",
        ):
            self.assertIn(key, summary_text)
        self.assertNotIn("SUPER_SECRET_GUEST_PSK", summary_text)

        buf = io.BytesIO()
        export_excel(
            extracted=analysis.extracted,
            derived=analysis.derived,
            validation=analysis.validation,
            output=buf,
            source_name="wifi.conf",
        )
        buf.seek(0)
        wb = load_workbook(buf, data_only=True)
        self.assertEqual("221E", wb["FortiAP Profiles"]["B4"].value)
        self.assertEqual("enable", wb["WIDS Profiles"]["B4"].value)
        self.assertEqual("150", wb["NAC Policies"]["F4"].value)
        self.assertEqual("Edge", wb["Managed Switches"]["C4"].value)
        wb.close()

    def test_sdwan_web_report_excel_and_chat_summary(self):
        import io
        from openpyxl import load_workbook
        from fwmigrate.vendors.fortigate.export.excel import export_excel
        from fwmigrate.web_support.chat_service import build_config_summary

        source = '''
config system interface
 edit "wan1"
  set vdom "root"
  set ip 192.0.2.2 255.255.255.0
 next
end
config system sdwan
 set status enable
 config zone
  edit "virtual-wan-link"
  next
 end
 config members
  edit 1
   set interface "wan1"
   set gateway 192.0.2.1
   set status enable
  next
 end
 config health-check
  edit "PingCheck"
   set server "8.8.8.8"
   set protocol ping
   set members 1
   config sla
    edit 1
     set latency-threshold 300
     set jitter-threshold 25
     set packetloss-threshold 2
    next
   end
  next
 end
 config service
  edit 1
   set name "VideoConferencing"
   set mode priority
   set link-cost-factor bibandwidth
   set protocol 6
   set start-port 443
   set end-port 443
   set health-check "PingCheck"
   set priority-members 1
   set status enable
  next
 end
end
'''
        reporter = FortiGateSourceReporter()
        analysis = reporter.analyze_source(source)
        report = reporter.build_preview(analysis)
        sdwan = report["sections"]["sdwan"][0]

        self.assertEqual("enable", sdwan["status"])
        self.assertEqual(300, sdwan["health_checks"][0]["sla"][0]["latency_threshold"])
        self.assertEqual("bibandwidth", sdwan["services"][0]["link_cost_factor"])
        self.assertEqual(443, sdwan["services"][0]["start_port"])

        summary_text = build_config_summary(vendor="fortigate", filename="fg.conf", preview=report)
        self.assertIn("[sdwan]", summary_text)

        buf = io.BytesIO()
        export_excel(
            extracted=analysis.extracted,
            derived=analysis.derived,
            validation=analysis.validation,
            output=buf,
            source_name="sdwan.conf",
        )
        buf.seek(0)
        wb = load_workbook(buf, data_only=True)
        self.assertEqual(300, wb["SD-WAN Health Checks"]["I4"].value)
        self.assertEqual("bibandwidth", wb["SD-WAN Rules"]["E4"].value)
        self.assertEqual(6, wb["SD-WAN Rules"]["H4"].value)
        wb.close()


if __name__ == "__main__":
    unittest.main()

