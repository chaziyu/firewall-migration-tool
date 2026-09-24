import unittest

from fwmigrate.vendors.fortigate.derived import build_derived_views
from fwmigrate.vendors.fortigate.model.external_resource import FGExternalResource
from fwmigrate.vendors.fortigate.model.interface import FGInterface
from fwmigrate.vendors.fortigate.model.policy import FGPolicy
from fwmigrate.vendors.fortigate.model.service import FGService
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.fortigate.model.vip import FGVIP, FGVIPRealServer
from fwmigrate.vendors.fortigate.model.vpn import FGIPsecPhase2
from fwmigrate.vendors.fortigate.transform.nat import transform_nat
from fwmigrate.vendors.fortigate.transform.vpn import normalize_vpn_phase2
from fwmigrate.vendors.fortigate.transform.services import transform_services
from fwmigrate.vendors.fortigate.validation.validator import validate_config


class Phase2SemanticTest(unittest.TestCase):
    def test_ip_selector_is_a_single_host(self):
        result = normalize_vpn_phase2(
            FGConfig(
                ipsec_phase2=[
                    FGIPsecPhase2(
                        name="single-host",
                        src_addr_type="ip",
                        src_start_ip="192.168.167.71",
                        dst_addr_type="ip",
                        dst_start_ip="192.168.99.35",
                    )
                ]
            )
        )

        self.assertEqual(result.issues, [])
        self.assertEqual(result.phase2[0].source_range, "192.168.167.71-192.168.167.71")
        self.assertEqual(result.phase2[0].destination_range, "192.168.99.35-192.168.99.35")

    def test_range_selector_still_requires_two_endpoints(self):
        result = normalize_vpn_phase2(
            FGConfig(
                ipsec_phase2=[
                    FGIPsecPhase2(
                        name="incomplete-range",
                        src_addr_type="range",
                        src_start_ip="192.0.2.1",
                    )
                ]
            )
        )

        self.assertEqual(result.phase2[0].source_range, None)
        self.assertEqual(result.issues[0].message, "Selector has only one range endpoint.")

    def test_missing_selector_type_keeps_conservative_range_behavior(self):
        result = normalize_vpn_phase2(
            FGConfig(
                ipsec_phase2=[
                    FGIPsecPhase2(
                        name="unknown-selector",
                        src_start_ip="192.0.2.1",
                    )
                ]
            )
        )

        self.assertEqual(result.phase2[0].source_range, None)
        self.assertEqual(result.issues[0].message, "Selector has only one range endpoint.")

    def test_service_generated_state_is_explicit(self):
        result = transform_services(
            FGConfig(
                services=[
                    FGService(
                        name="multi",
                        tcp_portrange="80",
                        udp_portrange="53",
                    ),
                    FGService(
                        name="single",
                        protocol="TCP",
                        tcp_portrange="443",
                    ),
                ]
            )
        )

        self.assertEqual(
            [item.generated for item in result.services],
            [True, True, False],
        )

    def test_ambiguous_interface_nat_has_no_address(self):
        config = FGConfig(
            interfaces=[
                FGInterface(name="port1", ip="192.0.2.1/24"),
                FGInterface(name="port2", ip="192.0.2.2/24"),
            ],
            policies=[
                FGPolicy(
                    policy_id=1,
                    nat="enable",
                    dstintf=["port1", "port2"],
                )
            ],
        )

        result = transform_nat(config)[0]

        self.assertEqual(result.egress_interfaces, ("port1", "port2"))
        self.assertEqual(result.translated_addresses, ())
        self.assertTrue(result.issues)

    def test_broken_references_are_derived_once(self):
        derived = build_derived_views(
            FGConfig(
                policies=[FGPolicy(policy_id=2, srcaddr=["missing"])]
            )
        )

        self.assertEqual(len(derived.broken_references), 1)
        self.assertEqual(derived.broken_references[0].reference, "missing")

    def test_external_address_resolves_policy_addresses(self):
        config = FGConfig(
            external_resources=[
                FGExternalResource(name="torip", type="address")
            ],
            policies=[
                FGPolicy(
                    policy_id=1470,
                    name="in168blacklist",
                    srcaddr=["torip"],
                    dstaddr=["torip"],
                )
            ],
        )

        derived = build_derived_views(config)
        validation = validate_config(config, derived=derived)

        self.assertFalse(derived.broken_references)
        self.assertFalse(
            any(issue.field in {"srcaddr", "dstaddr"} for issue in validation.issues)
        )

    def test_non_address_external_resource_does_not_resolve(self):
        derived = build_derived_views(
            FGConfig(
                external_resources=[
                    FGExternalResource(name="torip", type="domain")
                ],
                policies=[FGPolicy(srcaddr=["torip"])],
            )
        )

        self.assertEqual(
            [broken.reference for broken in derived.broken_references],
            ["torip"],
        )

    def test_external_address_reference_is_vdom_scoped(self):
        derived = build_derived_views(
            FGConfig(
                external_resources=[
                    FGExternalResource(name="torip", type="address", vdom="vdom-a")
                ],
                policies=[FGPolicy(vdom="root", srcaddr=["torip"])],
            )
        )

        self.assertEqual(
            [broken.reference for broken in derived.broken_references],
            ["torip"],
        )

    def test_load_balancing_vip_with_one_usable_backend_is_valid(self):
        result = validate_config(
            FGConfig(
                vips=[
                    FGVIP(
                        name="vip",
                        type="load-balance",
                        realservers=[FGVIPRealServer(ip="192.0.2.10")],
                    )
                ]
            )
        )

        self.assertFalse(
            any(issue.domain == "vip" for issue in result.issues)
        )


if __name__ == "__main__":
    unittest.main()

