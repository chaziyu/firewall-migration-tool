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


if __name__ == "__main__":
    unittest.main()

