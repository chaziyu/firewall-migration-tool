from types import SimpleNamespace

from fwmigrate.conversion.fortigate_to_palo_alto.decisions import (
    PANDecisionReviewState, PANMigrationDecision, PANMigrationDecisionSet,
)
from fwmigrate.conversion.fortigate_to_palo_alto.models import (
    PANMigrationPlan, PANMigrationStatus, PlannedAddress, PlannedNATRule,
)
from fwmigrate.conversion.fortigate_to_palo_alto.renderer import PANSetRenderer
from fwmigrate.conversion.fortigate_to_palo_alto.target_object_reuse import (
    _plan_target_nat_collisions, classify_target_object_reuse, mark_target_name_collisions,
)
from fwmigrate.conversion.fortigate_to_palo_alto.target_validation import PANTargetFinding
from fwmigrate.vendors.fortigate.model.address import FGAddress
from fwmigrate.vendors.fortigate.model.route_static import FGStaticRoute
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.palo_alto.model.address import PANAddress
from fwmigrate.vendors.palo_alto.source_model import PANScope
from fwmigrate.vendors.palo_alto.model.routing import PANStaticRoute, PANVirtualRouter
from fwmigrate.vendors.palo_alto.model.nat import PANNATRule


def _target(address):
    return SimpleNamespace(config=SimpleNamespace(
        addresses=[address], address_groups=[], services=[], service_groups=[], schedules=[],
        scopes=[address.scope]), derived=SimpleNamespace(reference_index=None, scope_hierarchy=None))


def test_same_name_address_reuse_requires_exact_explicit_semantics():
    source = FGConfig(addresses=[FGAddress(name="lan-net", subnet="192.0.2.0/24")])
    scope = PANScope(kind="vsys", name="vsys1", vsys="vsys1", device_name="dev")
    target_address = PANAddress(name="lan-net", source_path="/config/devices/entry/vsys/entry/address/entry",
        scope=scope, ip_netmask="192.0.2.0/24", explicit_fields={"ip_netmask"})
    decisions = PANMigrationDecisionSet((PANMigrationDecision("root", "vdom", "root", "vsys", value="vsys1",
        review_state=PANDecisionReviewState.CONFIRMED),))
    reuse = classify_target_object_reuse(source, SimpleNamespace(services=None), decisions,
        _target(target_address), "dev")
    assert reuse[0]["status"] == "EXACT_MATCH"

    target_address.ip_netmask = "198.51.100.0/24"
    conflict = classify_target_object_reuse(source, SimpleNamespace(services=None), decisions,
        _target(target_address), "dev")
    assert conflict[0]["status"] == "NAME_CONFLICT"


def test_missing_target_explicit_field_is_not_treated_as_exact():
    source = FGConfig(addresses=[FGAddress(name="lan-net", subnet="192.0.2.0/24")])
    scope = PANScope(kind="vsys", name="vsys1", vsys="vsys1", device_name="dev")
    target_address = PANAddress(name="lan-net", source_path="/config/devices/entry/vsys/entry/address/entry",
        scope=scope, ip_netmask="192.0.2.0/24", explicit_fields=set())
    decisions = PANMigrationDecisionSet((PANMigrationDecision("root", "vdom", "root", "vsys", value="vsys1",
        review_state=PANDecisionReviewState.CONFIRMED),))
    result = classify_target_object_reuse(source, SimpleNamespace(services=None), decisions,
        _target(target_address), "dev")
    assert result[0]["status"] != "EXACT_MATCH"


def test_same_name_semantic_conflict_is_not_rendered():
    plan = PANMigrationPlan(addresses=(PlannedAddress(source_vdom="root", source_name="lan-net",
        target_vsys="vsys1", target_name="lan-net", status=PANMigrationStatus.SUPPORTED,
        address_type="ip-netmask", value="192.0.2.0/24"),))
    blocked = mark_target_name_collisions(plan, ({"family": "address", "source_vdom": "root",
        "source_name": "lan-net", "target_name": "lan-net", "status": "NAME_CONFLICT"},))
    assert blocked.addresses[0].status == PANMigrationStatus.MANUAL_REVIEW
    assert PANSetRenderer().render(blocked).commands == ()


def test_target_validation_error_blocks_rendering_only_in_affected_vdom():
    plan = PANMigrationPlan(addresses=(
        PlannedAddress(source_vdom="root", source_name="root-net", target_vsys="vsys1",
            target_name="root-net", status=PANMigrationStatus.SUPPORTED,
            address_type="ip-netmask", value="192.0.2.0/24"),
        PlannedAddress(source_vdom="blue", source_name="blue-net", target_vsys="vsys2",
            target_name="blue-net", status=PANMigrationStatus.SUPPORTED,
            address_type="ip-netmask", value="198.51.100.0/24"),
    ))
    finding = PANTargetFinding('["root","vdom","root","vsys"]', "TARGET_VSYS_CONFLICT", "error", "missing")
    blocked = mark_target_name_collisions(plan, (), (finding,))
    assert blocked.addresses[0].status == PANMigrationStatus.MANUAL_REVIEW
    assert blocked.addresses[1].status == PANMigrationStatus.SUPPORTED


def test_existing_route_destination_requires_exact_route_semantics_for_reuse():
    source = FGConfig(static_routes=[FGStaticRoute(seq_num=10, vdom="root", dst="192.0.2.0/24",
        gateway="192.0.2.1", distance=10)])
    scope = PANScope(kind="device", name="dev", device_name="dev")
    existing = PANStaticRoute(name="10", source_path="/router/vr/static-route/entry", scope=scope,
        destination="192.0.2.0/24", nexthop_type="ip-address", nexthop_ip_address="192.0.2.1",
        admin_distance="10", explicit_fields={"destination", "nexthop_type", "nexthop_ip_address", "admin_distance"})
    target = SimpleNamespace(config=SimpleNamespace(virtual_routers=[PANVirtualRouter(name="vr-main",
        source_path="/router", scope=scope, static_routes=[existing])], interfaces=[], interface_units=[],
        zones=[], addresses=[], address_groups=[], services=[], service_groups=[], schedules=[]),
        derived=SimpleNamespace(reference_index=None, scope_hierarchy=None))
    decisions = PANMigrationDecisionSet((
        PANMigrationDecision("root", "vdom", "root", "vsys", value="vsys1", review_state=PANDecisionReviewState.CONFIRMED),
        PANMigrationDecision("root", "vdom", "root", "virtual_router", value="vr-main", review_state=PANDecisionReviewState.CONFIRMED),
    ))
    collision = classify_target_object_reuse(source, SimpleNamespace(services=None), decisions, target, "dev")
    route = next(item for item in collision if item["family"] == "static_route")
    assert route["status"] == "EXACT_MATCH"
    existing.nexthop_ip_address = "198.51.100.1"
    collision = classify_target_object_reuse(source, SimpleNamespace(services=None), decisions, target, "dev")
    route = next(item for item in collision if item["family"] == "static_route")
    assert route["status"] == "NAME_CONFLICT"


def test_nat_overlap_is_reported_and_not_auto_reused():
    scope = PANScope(kind="vsys", name="vsys1", vsys="vsys1", device_name="dev")
    planned = PlannedNATRule(source_vdom="root", source_name="nat1", target_name="nat1",
        target_vsys="vsys1", status=PANMigrationStatus.SUPPORTED, from_zones=("TRUST",),
        to_zones=("UNTRUST",), source_addresses=("lan-net",), destination_addresses=("web-net",), service="https")
    target_rule = PANNATRule(name="existing-nat", source_path="/nat/rule", scope=scope,
        from_zones=["TRUST"], to_zones=["UNTRUST"], source=["lan-net"], destination=["web-net"],
        service="https", explicit_fields={"from_zones", "to_zones", "source", "destination", "service"})
    target = SimpleNamespace(config=SimpleNamespace(nat_rules=[target_rule]))
    collision = _plan_target_nat_collisions((planned,), target, "dev")
    assert collision[0]["status"] == "AMBIGUOUS"
