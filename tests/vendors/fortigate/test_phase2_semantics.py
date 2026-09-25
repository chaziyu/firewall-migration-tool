import unittest

from fwmigrate.vendors.fortigate.derived import build_derived_views
from fwmigrate.vendors.fortigate.model.address import FGAddress, FGAddressGroup
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
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter
from fwmigrate.vendors.fortigate.export.excel import _nat_type


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

    def test_named_selector_wins_over_stale_subnet(self):
        config = FGConfig(
            addresses=[
                FGAddress(name="peer", subnet="192.0.2.0 255.255.255.0"),
                FGAddress(name="peer2", subnet="203.0.113.0 255.255.255.0"),
            ],
            ipsec_phase2=[FGIPsecPhase2(
                name="named", src_addr_type="name", src_name="peer",
                src_subnet="198.51.100.0 255.255.255.0",
                dst_addr_type="name", dst_name="peer2",
                dst_subnet="198.51.100.0 255.255.255.0",
            ), FGIPsecPhase2(
                name="subnet", src_addr_type="subnet",
                src_subnet="203.0.113.0 255.255.255.0", src_name="stale-name",
            )],
        )

        result = normalize_vpn_phase2(config)

        self.assertEqual(result.phase2[0].source_range, "192.0.2.0-192.0.2.255")
        self.assertEqual(result.phase2[0].destination_range, "203.0.113.0-203.0.113.255")
        self.assertEqual(result.phase2[1].source_range, "203.0.113.0-203.0.113.255")
        self.assertTrue(any("ignored because 'name' is selected" in issue.message for issue in result.issues))
        self.assertTrue(any("ignored because 'subnet' is selected" in issue.message for issue in result.issues))

    def test_named_address_group_is_recognized_but_not_flattened(self):
        result = normalize_vpn_phase2(FGConfig(
            address_groups=[FGAddressGroup(name="peers", members=["peer1", "peer2"])],
            ipsec_phase2=[FGIPsecPhase2(name="group", src_addr_type="name", src_name="peers")],
        ))

        self.assertIsNone(result.phase2[0].source_range)
        self.assertTrue(any("valid selector reference" in issue.message for issue in result.issues))

    def test_ipv6_named_selector_does_not_leak_into_ipv4(self):
        result = normalize_vpn_phase2(FGConfig(
            addresses=[FGAddress(name="peer6", address_family="ipv6", ip6="2001:db8::1/128")],
            ipsec_phase2=[FGIPsecPhase2(name="v6", src_addr_type="name6", src_name6="peer6")],
        ))

        self.assertIsNone(result.phase2[0].source_range)
        self.assertEqual(result.phase2[0].source_range6, "2001:db8::1-2001:db8::1")

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

    def test_explicit_service_protocol_controls_active_fields(self):
        result = transform_services(FGConfig(services=[
            FGService(name="ip50", protocol="IP", protocol_number=50, tcp_portrange="443"),
            FGService(name="icmp", protocol="ICMP", icmptype=8, udp_portrange="53"),
            FGService(name="tcp", protocol="TCP", tcp_portrange="443", udp_portrange="53", protocol_number=6),
        ]))

        self.assertEqual(
            [(item.protocol, item.protocol_number, item.port) for item in result.services],
            [("ip", 50, None), ("icmp", None, None), ("tcp", None, "443")],
        )
        self.assertEqual(len(result.issues), 4)

    def test_cli_source_extracts_nat64_and_selector_driven_semantics(self):
        source = '''
config firewall address
    edit "peer"
        set subnet 192.0.2.0 255.255.255.0
    next
end
config firewall ippool
    edit "POOL64"
        set type overload
        set startip 198.51.100.10
        set endip 198.51.100.20
        set nat64 enable
    next
end
config firewall policy
    edit 64
        set nat64 enable
        set ippool enable
        set poolname "POOL64"
    next
end
config firewall service custom
    edit "proto50"
        set protocol IP
        set protocol-number 50
        set tcp-portrange 443
    next
end
config vpn ipsec phase2-interface
    edit "named-peer"
        set src-addr-type name
        set src-name "peer"
        set src-subnet 198.51.100.0 255.255.255.0
    next
end
'''
        analysis = FortiGateSourceReporter().analyze_source(source)
        policy = analysis.extracted.config.policies[0]
        service = analysis.derived.services.services[0]
        phase2 = analysis.derived.vpn.phase2[0]

        self.assertEqual(policy.nat, None)
        self.assertEqual(policy.nat64, "enable")
        self.assertIn("nat64", policy.explicit_fields)
        self.assertNotIn("nat64", policy.raw_extra)
        self.assertEqual(analysis.derived.nat[0].translation_type, "nat64_ip_pool")
        self.assertEqual(service.protocol_number, 50)
        self.assertEqual(service.port, None)
        self.assertEqual(phase2.source_range, "192.0.2.0-192.0.2.255")
        self.assertTrue(any(issue.domain == "service" for issue in analysis.validation.issues))
        self.assertTrue(any(issue.domain == "vpn_phase2" for issue in analysis.validation.issues))
        self.assertEqual(_nat_type("nat64_ip_pool"), "NAT64 IP Pool")

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

