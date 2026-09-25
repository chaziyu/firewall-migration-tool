from fwmigrate.vendors.fortigate.config import ExtractionConfig
from fwmigrate.vendors.fortigate.derived import build_derived_views
from fwmigrate.vendors.fortigate.export import export_excel
from fwmigrate.vendors.fortigate.extraction.coverage import typed_source_paths
from fwmigrate.vendors.fortigate.extraction.extractor import extract_fortigate_config
from fwmigrate.vendors.fortigate.parser import parse_fortigate_config
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter
from fwmigrate.vendors.fortigate.section_registry import registered_sections
from fwmigrate.vendors.fortigate.validation.validator import validate_config
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


def test_policy_based_ipsec_has_separate_source_and_derived_state():
    source = """config vpn ipsec phase1
    edit policy-vpn
        set interface wan1
        set remote-gw 192.0.2.1
        set proposal aes256-sha256
        set psksecret do-not-retain-this
        set authpasswd also-do-not-retain
        unset authpasswd
    next
end
config firewall policy
    edit 9
        set action ipsec
        set vpntunnel policy-vpn
    next
end
config vpn ipsec phase2
    edit policy-child
        set phase1name policy-vpn
        set proposal aes256-sha256
        set pfs enable
        set src-addr-type subnet
        set src-subnet 10.1.0.0 255.255.255.0
        set dst-addr-type subnet
        set dst-subnet 10.2.0.0 255.255.255.0
        set protocol 6
        set src-port 443
    next
end
"""
    reporter = FortiGateSourceReporter()
    analysis = reporter.analyze_source(source)
    assert analysis.extracted.config.ipsec_phase1 == []
    assert analysis.extracted.config.ipsec_phase2 == []
    phase1 = analysis.extracted.config.ipsec_policy_phase1[0]
    assert phase1.interface == "wan1"
    assert phase1.psk_configured
    assert not phase1.auth_password_configured
    assert "vpn ipsec phase1" in typed_source_paths()
    assert not analysis.derived.topology.vpns
    assert not analysis.derived.broken_references
    policy_phase2 = analysis.extracted.config.ipsec_policy_phase2[0]
    assert policy_phase2.protocol == 6
    assert policy_phase2.src_port == 443
    normalized = analysis.derived.vpn.phase2[0]
    assert normalized.vpn_type == "policy-based"
    assert normalized.source_range == "10.1.0.0-10.1.0.255"


def test_cli_phase2_named_selector_uses_the_matching_address():
    analysis = FortiGateSourceReporter().analyze_source('''config firewall address
    edit "peer"
        set subnet 192.0.2.0 255.255.255.0
    next
end
config vpn ipsec phase2-interface
    edit "named-peer"
        set src-addr-type name
        set src-name "peer"
        set src-subnet 198.51.100.0 255.255.255.0
    next
end
''')
    source = analysis.extracted.config.ipsec_phase2[0]
    derived = analysis.derived.vpn.phase2[0]

    assert source.src_addr_type == "name"
    assert source.src_name == "peer"
    assert derived.source_range == "192.0.2.0-192.0.2.255"
