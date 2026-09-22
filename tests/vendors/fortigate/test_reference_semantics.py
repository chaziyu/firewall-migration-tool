import unittest

from fwmigrate.vendors.fortigate.derived import build_derived_views
from fwmigrate.vendors.fortigate.model.address import FGAddress, FGAddressGroup
from fwmigrate.vendors.fortigate.model.interface import FGInterface
from fwmigrate.vendors.fortigate.model.policy import FGPolicy
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.fortigate.model.vpn import FGIPsecPhase1
from fwmigrate.vendors.fortigate.relationships.references import (
    ReferenceKind,
    build_reference_index,
    collect_broken_references,
)
from fwmigrate.vendors.fortigate.validation.validator import validate_config


class ReferenceSemanticsTest(unittest.TestCase):
    def test_duplicate_interfaces_are_reported_without_merging(self):
        first = FGInterface(name="INFUAT-BIBDUAT", raw_extra={"snmp-index": 34})
        second = FGInterface(name="INFUAT-BIBDUAT", raw_extra={"snmp-index": 11})
        config = FGConfig(interfaces=[first, second])

        derived = build_derived_views(config)
        result = validate_config(config, derived=derived)
        duplicates = [issue for issue in result.issues if issue.domain == "interface"]

        self.assertEqual(1, len(duplicates))
        self.assertEqual("error", duplicates[0].severity.value)
        self.assertIn("source identity is ambiguous", duplicates[0].message)
        self.assertEqual(2, len(config.interfaces))
        self.assertIs(first, derived.references.get(ReferenceKind.INTERFACE, vdom="root", name=first.name))

    def test_same_name_different_object_types_is_not_duplicate(self):
        config = FGConfig(
            interfaces=[FGInterface(name="VPN1")],
            ipsec_phase1=[FGIPsecPhase1(name="VPN1")],
        )

        self.assertFalse(build_reference_index(config).duplicates)

    def test_ipv4_and_ipv6_namespaces_are_independent(self):
        config = FGConfig(
            addresses=[
                FGAddress(name="all"),
                FGAddress(name="dup"),
                FGAddress(name="dup"),
                FGAddress(name="all", address_family="ipv6"),
                FGAddress(name="dup", address_family="ipv6"),
                FGAddress(name="dup", address_family="ipv6"),
            ],
            address_groups=[
                FGAddressGroup(name="shared"),
                FGAddressGroup(name="shared", address_family="ipv6"),
            ],
        )
        index = build_reference_index(config)

        self.assertIsNotNone(index.get(ReferenceKind.ADDRESS, vdom="root", name="all"))
        self.assertIsNotNone(index.get(ReferenceKind.ADDRESS6, vdom="root", name="all"))
        self.assertEqual(1, sum(item.kind == ReferenceKind.ADDRESS for item in index.duplicates))
        self.assertEqual(1, sum(item.kind == ReferenceKind.ADDRESS6 for item in index.duplicates))
        self.assertFalse(any(item.name == "shared" for item in index.duplicates))

    def test_policy_address_references_use_the_matching_family(self):
        config = FGConfig(
            addresses=[
                FGAddress(name="v4"),
                FGAddress(name="v6", address_family="ipv6"),
            ],
            policies=[
                FGPolicy(
                    policy_id=1,
                    srcaddr=["v4"],
                    srcaddr6=["v6"],
                ),
                FGPolicy(
                    policy_id=2,
                    srcaddr=["v6"],
                    srcaddr6=["v4"],
                ),
            ],
        )

        broken = collect_broken_references(config)
        self.assertEqual({"srcaddr", "srcaddr6"}, {item.source_field for item in broken})
        self.assertEqual({"v6", "v4"}, {item.reference for item in broken})

    def test_route_based_phase1_is_valid_for_policy_interfaces_only(self):
        config = FGConfig(
            interfaces=[FGInterface(name="wan1")],
            ipsec_phase1=[FGIPsecPhase1(name="Euronet-P1", interface="wan1")],
            policies=[FGPolicy(policy_id=1, srcintf=["Euronet-P1"], dstintf=["Euronet-P1"])],
        )

        self.assertFalse(collect_broken_references(config))

    def test_phase1_attachment_still_requires_a_physical_interface(self):
        config = FGConfig(
            ipsec_phase1=[FGIPsecPhase1(name="VPN1", interface="missing-wan")],
        )

        broken = collect_broken_references(config)
        self.assertEqual("interface", broken[0].source_field)
        self.assertEqual("missing-wan", broken[0].reference)

    def test_predefined_address_references_remain_family_aware(self):
        config = FGConfig(
            policies=[FGPolicy(policy_id=1, srcaddr=["all"], srcaddr6=["all6"])],
        )

        self.assertFalse(collect_broken_references(config))


if __name__ == "__main__":
    unittest.main()

