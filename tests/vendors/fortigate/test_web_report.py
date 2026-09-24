from __future__ import annotations

import json
import unittest

from fwmigrate.vendors.fortigate.derived import build_derived_views
from fwmigrate.vendors.fortigate.model.address import FGAddress, FGAddressGroup
from fwmigrate.vendors.fortigate.model.interface import FGInterface
from fwmigrate.vendors.fortigate.model.policy import FGPolicy
from fwmigrate.vendors.fortigate.model.route_static import FGStaticRoute
from fwmigrate.vendors.fortigate.model.service import FGService
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.fortigate.model.vpn import FGIPsecPhase1, FGIPsecPhase2
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


if __name__ == "__main__":
    unittest.main()

