import pytest

from fwmigrate.builtin_plugins import register_builtin_plugins
from fwmigrate.core.registry import PluginRegistry
from tests.fixture_paths import VENDOR_FIXTURES


EXPECTED_COLLECTION_COUNTS = {
    "fortigate": (0, 3, 4, 1, 3, 1, 3, 1, 1, 2, 1),
    "palo_alto": (2, 2, 4, 1, 2, 1, 1, 0, 0, 1, 0),
    "cisco_asa": (0, 3, 4, 1, 2, 1, 3, 0, 0, 2, 2),
    "cisco_ftd": (0, 2, 3, 0, 1, 0, 0, 0, 0, 2, 0),
    "checkpoint": (0, 0, 3, 1, 1, 0, 2, 0, 0, 1, 0),
    "juniper_srx": (3, 0, 3, 1, 1, 1, 2, 0, 0, 0, 1),
}
COLLECTIONS = (
    "zones",
    "interfaces",
    "addresses",
    "address_groups",
    "services",
    "service_groups",
    "policies",
    "ip_pools",
    "virtual_ips",
    "nat_rules",
    "routes",
)
EXPECTED_REPRESENTATIVE_OBJECTS = {
    "fortigate": ("HOST_10.1.1.100", "Allow_Corporate_To_Internet", "SNAT-P1"),
    "palo_alto": ("Server_Web", "Allow_LAN_To_Web", "SNAT_Outbound"),
    "cisco_asa": ("Web_Server_01", "inside_in_41__inside_in", "nat_manual_48"),
    "cisco_ftd": ("InsideHost", None, "Static Source"),
    "checkpoint": ("Host_ERP_Database", "Allow_Corporate_To_ERP", "NAT_Corporate_Outbound"),
    "juniper_srx": ("srv-web-01", "Allow_Branch_To_Internet", None),
}


@pytest.fixture(scope="module", autouse=True)
def _register_plugins():
    register_builtin_plugins()


@pytest.mark.parametrize("source_vendor", VENDOR_FIXTURES)
def test_current_ir_counts_and_representative_semantics(source_vendor):
    extraction = PluginRegistry.get_parser(source_vendor).extract(
        VENDOR_FIXTURES[source_vendor].read_text(encoding="utf-8")
    )
    ir = extraction.canonical_ir

    assert ir.metadata.source_vendor == source_vendor
    assert tuple(len(getattr(ir, name)) for name in COLLECTIONS) == (
        EXPECTED_COLLECTION_COUNTS[source_vendor]
    )

    address, policy, nat_rule = EXPECTED_REPRESENTATIVE_OBJECTS[source_vendor]
    assert ir.addresses[0].name == address
    assert (ir.policies[0].name if ir.policies else None) == policy
    assert (ir.nat_rules[0].name if ir.nat_rules else None) == nat_rule


def test_representative_policy_nat_and_route_meaning_is_stable():
    fortigate = PluginRegistry.get_parser("fortigate").extract(
        VENDOR_FIXTURES["fortigate"].read_text(encoding="utf-8")
    ).canonical_ir
    assert fortigate.policies[0].source == ["NET_192.168.1.0_24"]
    assert fortigate.policies[0].destination == ["<IR_ANY>"]
    assert fortigate.policies[0].action.value == "allow"
    assert fortigate.nat_rules[0].translated_sources == ["203.0.113.2"]
    assert fortigate.routes[0].destination == "0.0.0.0/0"
    assert fortigate.routes[0].next_hop == "203.0.113.1"

    ftd = PluginRegistry.get_parser("cisco_ftd").extract(
        VENDOR_FIXTURES["cisco_ftd"].read_text(encoding="utf-8")
    ).canonical_ir
    assert ftd.nat_rules[0].source == ["InsideHost"]
    assert ftd.nat_rules[0].translated_sources == ["PublicHost"]
