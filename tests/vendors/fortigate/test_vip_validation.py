import unittest

from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.fortigate.model.vip import FGVIP, FGVIPRealServer
from fwmigrate.vendors.fortigate.validation.models import ValidationSeverity
from fwmigrate.vendors.fortigate.validation.validator import validate_config


class VIPValidationTest(unittest.TestCase):
    def _issues(self, vip):
        return validate_config(FGConfig(vips=[vip])).issues

    def test_one_backend_with_ip_has_no_warning(self):
        self.assertFalse(self._issues(
            FGVIP(
                name="mwg",
                type="server-load-balance",
                realservers=[FGVIPRealServer(ip="192.168.169.131")],
            )
        ))

    def test_one_backend_with_address_has_no_warning(self):
        self.assertFalse(self._issues(
            FGVIP(
                name="qradartest",
                type="server-load-balance",
                realservers=[FGVIPRealServer(address="backend-address")],
            )
        ))

    def test_two_backends_have_no_warning(self):
        self.assertFalse(self._issues(
            FGVIP(
                name="vip",
                type="load-balance",
                realservers=[
                    FGVIPRealServer(ip="192.0.2.10"),
                    FGVIPRealServer(ip="192.0.2.11"),
                ],
            )
        ))

    def test_zero_backends_warns(self):
        issues = self._issues(FGVIP(name="vip", type="server-load-balance"))

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].severity, ValidationSeverity.WARNING)
        self.assertEqual(issues[0].domain, "vip")
        self.assertEqual(issues[0].field, "realservers")
        self.assertEqual(
            issues[0].message,
            "Load-balancing VIP has no configured real-server backend with an IP or address.",
        )

    def test_backend_without_ip_or_address_warns(self):
        issues = self._issues(
            FGVIP(
                name="vip",
                type="server-load-balance",
                realservers=[FGVIPRealServer(port=443)],
            )
        )

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].field, "realservers")

    def test_static_nat_vip_is_not_checked(self):
        self.assertFalse(self._issues(FGVIP(name="vip", type="static-nat")))


if __name__ == "__main__":
    unittest.main()

