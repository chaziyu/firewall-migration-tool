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

from fwmigrate.vendors.fortigate.derived import build_derived_views
from fwmigrate.vendors.fortigate.model.address import FGAddress, FGAddressGroup
from fwmigrate.vendors.fortigate.model.admin import FGAdministrator, FGAdminProfile
from fwmigrate.vendors.fortigate.model.dhcp import FGDHCPServer
from fwmigrate.vendors.fortigate.model.interface import FGInterface
from fwmigrate.vendors.fortigate.model.policy import FGPolicy
from fwmigrate.vendors.fortigate.model.route_static import FGStaticRoute
from fwmigrate.vendors.fortigate.model.sdwan import FGSDWAN, FGSDWANZone
from fwmigrate.vendors.fortigate.model.service import FGService, FGServiceGroup
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.fortigate.model.vip import FGVIP, FGVIPGroup, FGVIPRealServer
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

    def test_admin_profiles_are_indexed_and_accprofile_is_validated(self):
        config = FGConfig(
            administrators=[
                FGAdministrator(name="admin", accprofile="missing"),
                FGAdministrator(name="operator", accprofile="read_only"),
                FGAdministrator(name="super", accprofile="super_admin"),
            ],
            admin_profiles=[FGAdminProfile(name="read_only")],
        )
        broken = collect_broken_references(config)
        self.assertEqual([("administrator", "accprofile", "missing")], [
            (item.source_kind, item.source_field, item.reference) for item in broken
        ])
        duplicates = build_reference_index(FGConfig(admin_profiles=[
            FGAdminProfile(name="duplicate"), FGAdminProfile(name="duplicate")
        ])).duplicates
        self.assertEqual([ReferenceKind.ADMIN_PROFILE], [item.kind for item in duplicates])

    def test_route_and_dhcp_bindings_validate_only_typed_references(self):
        config = FGConfig(
            interfaces=[FGInterface(name="wan1")],
            ipsec_phase1=[FGIPsecPhase1(name="tunnel1")],
            addresses=[FGAddress(name="address1")],
            address_groups=[FGAddressGroup(name="group1")],
            sdwans=[FGSDWAN(zones=[FGSDWANZone(name="virtual-wan-link")])],
            static_routes=[
                FGStaticRoute(seq_num=1, dst="192.0.2.0/24", dstaddr="missing-address", device="missing-device", sdwan_zone=["missing-zone"]),
                FGStaticRoute(seq_num=2, dstaddr="address1", device="tunnel1", sdwan_zone=["virtual-wan-link"]),
                FGStaticRoute(seq_num=3, address_family="ipv6", dstaddr="missing-v6", device="wan1"),
            ],
            dhcp_servers=[
                FGDHCPServer(id=1, interface="missing-interface"),
                FGDHCPServer(id=2, interface="wan1"),
            ],
        )
        broken = collect_broken_references(config)
        found = {(item.source_kind, item.source_field, item.reference): item for item in broken}
        self.assertEqual({
            ("static_route", "dstaddr", "missing-address"),
            ("static_route", "device", "missing-device"),
            ("static_route", "sdwan_zone", "missing-zone"),
            ("static_route6", "dstaddr", "missing-v6"),
            ("dhcp_server", "interface", "missing-interface"),
        }, set(found))
        self.assertEqual(
            (ReferenceKind.ADDRESS, ReferenceKind.ADDRESS_GROUP),
            found[("static_route", "dstaddr", "missing-address")].expected_kinds,
        )
        self.assertEqual(
            (ReferenceKind.INTERFACE, ReferenceKind.IPSEC_PHASE1),
            found[("static_route", "device", "missing-device")].expected_kinds,
        )
        self.assertEqual((ReferenceKind.ADDRESS6, ReferenceKind.ADDRESS_GROUP6),
            found[("static_route6", "dstaddr", "missing-v6")].expected_kinds)

    def test_vip_references_and_group_interface_are_checked(self):
        config = FGConfig(
            interfaces=[FGInterface(name="wan1")],
            addresses=[FGAddress(name="public"), FGAddress(name="backend")],
            services=[FGService(name="https")],
            service_groups=[FGServiceGroup(name="web")],
            vips=[
                FGVIP(name="good", extintf="wan1", extaddr=["public"], mapped_addr="backend", service=["web"], realservers=[FGVIPRealServer(id=1, address="backend")]),
                FGVIP(name="bad", extintf="missing-interface", extaddr=["missing-external"], mapped_addr="missing-mapped", service=["missing-service"], realservers=[FGVIPRealServer(id=7, address="missing-backend")]),
            ],
            vip_groups=[
                FGVIPGroup(name="good-group", interface="wan1"),
                FGVIPGroup(name="bad-group", interface="missing-group-interface"),
            ],
        )
        broken = collect_broken_references(config)
        self.assertEqual({
            ("vip", "bad", "extintf", "missing-interface"),
            ("vip", "bad", "extaddr", "missing-external"),
            ("vip", "bad", "mapped_addr", "missing-mapped"),
            ("vip", "bad", "service", "missing-service"),
            ("vip", "bad", "realservers[7].address", "missing-backend"),
            ("vip_group", "bad-group", "interface", "missing-group-interface"),
        }, {(item.source_kind, item.source_name, item.source_field, item.reference) for item in broken})
        self.assertEqual((ReferenceKind.ADDRESS,), next(
            item.expected_kinds for item in broken if item.source_field == "extaddr"
        ))


if __name__ == "__main__":
    unittest.main()



class Phase2SemanticTest(unittest.TestCase):








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
