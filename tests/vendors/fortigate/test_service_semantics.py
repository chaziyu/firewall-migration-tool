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

    def test_web_proxy_selector_does_not_mark_ports_inactive(self):
        result = transform_services(FGConfig(services=[
            FGService(
                name="webproxy",
                protocol="ALL",
                proxy="enable",
                tcp_portrange="0-65535:0-65535",
            ),
        ]))

        self.assertFalse(result.issues)
        self.assertEqual(
            [(item.source_name, item.protocol) for item in result.services],
            [("webproxy", "all")],
        )

    def test_cli_source_preserves_protocol_number_and_ignores_inactive_ports(self):
        analysis = FortiGateSourceReporter().analyze_source('''config firewall service custom
    edit "proto50"
        set protocol IP
        set protocol-number 50
        set tcp-portrange 443
    next
end
''')
        source = analysis.extracted.config.services[0]
        derived = analysis.derived.services.services[0]

        self.assertEqual((source.protocol, source.protocol_number), ("IP", 50))
        self.assertEqual((derived.protocol_number, derived.port), (50, None))
