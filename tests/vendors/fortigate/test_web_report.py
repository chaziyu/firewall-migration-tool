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
        self.assertEqual([], by_id[3]["source_addresses"])
        self.assertEqual(["ONLY-SRC-V6"], by_id[3]["source_addresses_ipv6"])
        self.assertEqual([], by_id[3]["destination_addresses"])
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

