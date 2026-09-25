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
import unittest

from fwmigrate.vendors.fortigate.model.interface import FGInterface
from fwmigrate.vendors.fortigate.model.ippool import FGIPPool
from fwmigrate.vendors.fortigate.model.policy import FGPolicy
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.fortigate.transform.nat import transform_nat


class NatSemanticsTest(unittest.TestCase):
    def _nat(self, interface: FGInterface):
        return transform_nat(
            FGConfig(
                interfaces=[interface],
                policies=[
                    FGPolicy(
                        policy_id=1,
                        nat="enable",
                        dstintf=[interface.name],
                    )
                ],
            )
        )[0]

    def _policy_nat(self, policy: FGPolicy, *, interfaces=(), ip_pools=()):
        return transform_nat(
            FGConfig(
                interfaces=list(interfaces),
                ip_pools=list(ip_pools),
                policies=[policy],
            )
        )[0]

    def test_static_and_cidr_addresses(self):
        for value in ("103.230.127.102 255.255.255.0", "103.230.127.102/24"):
            result = self._nat(FGInterface(name="wan1", ip=value))
            self.assertEqual(result.translated_addresses, ("103.230.127.102",))
            self.assertEqual(result.issues, ())

    def test_missing_address_has_specific_issue(self):
        result = self._nat(FGInterface(name="wan1"))
        self.assertEqual(result.translated_addresses, ())
        self.assertIn("no explicitly configured IPv4 address", result.issues[0])

    def test_dynamic_modes_have_specific_issues(self):
        for mode in ("dhcp", "pppoe"):
            result = self._nat(FGInterface(name="wan1", mode=mode))
            self.assertEqual(result.translated_addresses, ())
            self.assertIn(f"dynamic addressing mode '{mode}'", result.issues[0])

    def test_any_interface_address_nat_is_runtime_dependent(self):
        result = self._policy_nat(
            FGPolicy(policy_id=1, nat="enable", dstintf=["any"])
        )
        self.assertEqual(result.translation_type, "interface_address")
        self.assertEqual(result.translated_addresses, ())
        self.assertEqual(
            result.issues,
            (
                "Outgoing interface 'any' is non-specific; interface-address "
                "SNAT depends on the runtime egress path and cannot be "
                "derived deterministically.",
            ),
        )

    def test_any_interface_casing_has_same_semantics(self):
        result = self._policy_nat(
            FGPolicy(policy_id=1, nat="enable", dstintf=["ANY"])
        )
        self.assertEqual(result.translated_addresses, ())
        self.assertIn("is non-specific", result.issues[0])
        self.assertNotIn("dynamic", result.issues[0])

    def test_specific_interface_has_no_non_specific_warning(self):
        result = self._nat(FGInterface(name="wan1", ip="192.0.2.1 255.255.255.0"))
        self.assertFalse(any("non-specific" in issue for issue in result.issues))

    def test_ip_pool_nat_does_not_use_interface_address_warning(self):
        result = self._policy_nat(
            FGPolicy(
                policy_id=1,
                nat="enable",
                dstintf=["any"],
                ippool="enable",
                poolname=["POOL1"],
            ),
            ip_pools=[FGIPPool(name="POOL1", startip="198.51.100.10", endip="198.51.100.10")],
        )
        self.assertEqual(result.translation_type, "ip_pool")
        self.assertEqual(result.translated_addresses, ("198.51.100.10",))
        self.assertFalse(any("non-specific" in issue for issue in result.issues))

    def test_nat64_uses_its_pool_without_ordinary_nat(self):
        result = self._policy_nat(
            FGPolicy(policy_id=1, nat64="enable", poolname=["POOL64"]),
            ip_pools=[FGIPPool(name="POOL64", startip="198.51.100.10", endip="198.51.100.20")],
        )

        self.assertEqual(result.translation_type, "nat64_ip_pool")
        self.assertEqual(result.translated_addresses, ("198.51.100.10-198.51.100.20",))

    def test_explicit_nat_and_nat64_are_derived_separately(self):
        rows = transform_nat(FGConfig(
            ip_pools=[FGIPPool(name="POOL1", startip="198.51.100.10", endip="198.51.100.10")],
            policies=[FGPolicy(nat="enable", nat64="enable", ippool="enable", poolname=["POOL1"])],
        ))

        self.assertEqual(
            [row.translation_type for row in rows],
            ["ip_pool", "nat64_ip_pool"],
        )

    def test_nat64_without_pool_keeps_a_review_row(self):
        result = self._policy_nat(FGPolicy(policy_id=1, nat64="enable"))

        self.assertEqual(result.translation_type, "nat64_ip_pool")
        self.assertEqual(result.translated_addresses, ())
        self.assertTrue(any("No deterministic NAT64" in issue for issue in result.issues))

    def test_incomplete_pool_endpoints_are_not_translations(self):
        for pool in (
            FGIPPool(name="POOL1", startip="198.51.100.10"),
            FGIPPool(name="POOL1", endip="198.51.100.20"),
        ):
            with self.subTest(pool=pool):
                result = self._policy_nat(
                    FGPolicy(nat="enable", ippool="enable", poolname=["POOL1"]),
                    ip_pools=[pool],
                )
                self.assertEqual(result.translated_addresses, ())
                self.assertTrue(any("only one explicitly configured" in issue for issue in result.issues))

    def test_nat64_pool_explicitly_disabling_nat64_is_reviewed(self):
        result = self._policy_nat(
            FGPolicy(nat64="enable", poolname=["POOL1"]),
            ip_pools=[FGIPPool(name="POOL1", startip="198.51.100.10", endip="198.51.100.10", nat64="disable")],
        )
        self.assertEqual(result.translated_addresses, ("198.51.100.10",))
        self.assertTrue(any("explicitly disables NAT64" in issue for issue in result.issues))

    def test_unknown_interface_keeps_existing_warning(self):
        result = self._policy_nat(
            FGPolicy(policy_id=1, nat="enable", dstintf=["missing"])
        )
        self.assertIn("Outgoing interface/zone 'missing' was not found.", result.issues)

    def test_malformed_address_is_previewed_without_repair(self):
        source = "source static any any destination static " + "103.230.127.102 " * 40
        result = self._nat(FGInterface(name="wan1", ip=source))
        message = result.issues[0]
        self.assertEqual(result.translated_addresses, ())
        self.assertIn("explicit 'ip' value that could not be parsed", message)
        self.assertIn("...", message)
        self.assertNotIn(source, message)
        self.assertNotIn("103.230.127.102 " * 10, message)


if __name__ == "__main__":
    unittest.main()



class Phase2SemanticTest(unittest.TestCase):








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

    def test_cli_nat64_pool_source_reaches_derived_translation(self):
        analysis = FortiGateSourceReporter().analyze_source('''config firewall ippool
    edit "POOL64"
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
''')
        policy = analysis.extracted.config.policies[0]

        self.assertIsNone(policy.nat)
        self.assertEqual(policy.nat64, "enable")
        self.assertIn("nat64", policy.explicit_fields)
        self.assertEqual(analysis.derived.nat[0].translation_type, "nat64_ip_pool")
