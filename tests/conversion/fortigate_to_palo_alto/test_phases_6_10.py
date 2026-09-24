from types import SimpleNamespace

from fwmigrate.conversion.fortigate_to_palo_alto import (
    FortiGateToPaloAltoPlanner,
    PANMigrationOptions,
    PANMigrationStatus,
)
from fwmigrate.vendors.fortigate.model.policy import FGPolicy
from fwmigrate.vendors.fortigate.model.route_static import FGStaticRoute
from fwmigrate.vendors.fortigate.model.schedule import (
    FGOneTimeSchedule,
    FGRecurringSchedule,
)
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.fortigate.model.zone import FGZone
from fwmigrate.vendors.fortigate.transform.services import (
    NormalizedService,
    NormalizedServiceGroup,
    ServiceTransformResult,
)


def _options():
    return PANMigrationOptions(
        vdoms={"root": {"vsys": "vsys1", "virtual_router": "default"}},
        interfaces={"root": {
            "lan": {"target_interface": "ethernet1/1", "target_zone": "trust"},
            "wan": {"target_interface": "ethernet1/2", "target_zone": "untrust"},
        }},
    )


def test_services_use_derived_expansion_and_flag_non_tcp_udp():
    derived = SimpleNamespace(services=ServiceTransformResult(
        services=[
            NormalizedService(name="https", vdom="root", protocol="tcp", port="443"),
            NormalizedService(name="icmp", vdom="root", protocol="icmp"),
        ],
        groups=[NormalizedServiceGroup(name="web", vdom="root", members=("https",))],
    ))
    plan = FortiGateToPaloAltoPlanner().plan(FGConfig(), derived, options=_options())

    assert plan.services[0].destination_port == "443"
    assert plan.services[1].status is PANMigrationStatus.UNSUPPORTED
    assert plan.service_groups[0].members == ("https",)


def test_schedules_and_schedule_groups_preserve_source_semantics():
    source = FGConfig(
        recurring_schedules=[FGRecurringSchedule(name="work", days=["monday"], start="09:00", end="17:00")],
        one_time_schedules=[FGOneTimeSchedule(name="once", start="2026/01/01 09:00", end="2026/01/01 17:00")],
    )
    plan = FortiGateToPaloAltoPlanner().plan(source, SimpleNamespace(), options=_options())

    assert [item.schedule_type for item in plan.schedules] == ["recurring", "one-time"]


def test_topology_requires_every_zone_member_mapping():
    source = FGConfig(policies=[FGPolicy(srcintf=["lan-zone"])], zones=[FGZone(name="lan-zone", members=["lan", "missing"])])
    derived = SimpleNamespace(topology=SimpleNamespace(interfaces=()))
    plan = FortiGateToPaloAltoPlanner().plan(source, derived, options=_options())

    assert plan.zones[0].status is PANMigrationStatus.MANUAL_REVIEW
    assert plan.zones[0].interfaces == ("ethernet1/1",)


def test_routes_use_explicit_virtual_router_and_interface_mapping():
    source = FGConfig(static_routes=[FGStaticRoute(seq_num=10, dst="0.0.0.0/0", device="wan", gateway="192.0.2.1", distance=10)])
    plan = FortiGateToPaloAltoPlanner().plan(source, SimpleNamespace(), options=_options())

    route = plan.static_routes[0]
    assert route.virtual_router == "default"
    assert route.interface == "ethernet1/2"
    assert route.status is PANMigrationStatus.SUPPORTED


def test_policy_order_and_zone_action_mapping_are_preserved():
    source = FGConfig(policies=[
        FGPolicy(policy_id=20, name="second", srcintf=["lan"], dstintf=["wan"], action="deny"),
        FGPolicy(policy_id=30, name="third", srcintf=["lan"], dstintf=["wan"], action="accept"),
    ])
    plan = FortiGateToPaloAltoPlanner().plan(source, SimpleNamespace(), options=_options())

    assert [rule.source_policy_id for rule in plan.security_rules] == [20, 30]
    assert [rule.action for rule in plan.security_rules] == ["deny", "allow"]
