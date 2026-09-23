from fwmigrate.conversion.fortigate_to_palo_alto import (
    FortiGateToPaloAltoPlanner,
    PANMigrationOptions,
    PANMigrationStatus,
)
from fwmigrate.vendors.fortigate.model.address import FGAddress, FGAddressGroup
from fwmigrate.vendors.fortigate.model.source import FGConfig


def test_address_representations_and_static_group_are_preserved():
    source = FGConfig(
        addresses=[
            FGAddress(name="net", vdom="root", subnet="10.0.0.0 255.255.255.0"),
            FGAddress(name="range", vdom="root", start_ip="10.0.0.1", end_ip="10.0.0.9"),
            FGAddress(name="fqdn", vdom="root", fqdn="example.com"),
            FGAddress(name="wildcard", vdom="root", wildcard="10.0.0.0/255.255.0.0"),
        ],
        address_groups=[FGAddressGroup(name="servers", vdom="root", members=["net", "fqdn"])],
    )
    plan = FortiGateToPaloAltoPlanner().plan(
        source,
        object(),
        options=PANMigrationOptions(vdoms={"root": {"vsys": "vsys1"}}),
    )

    assert [(item.address_type, item.value) for item in plan.addresses] == [
        ("ip-netmask", "10.0.0.0 255.255.255.0"),
        ("ip-range", "10.0.0.1-10.0.0.9"),
        ("fqdn", "example.com"),
        ("ip-wildcard", "10.0.0.0/255.255.0.0"),
    ]
    assert plan.address_groups[0].members == ("net", "fqdn")
    assert all(item.status is PANMigrationStatus.SUPPORTED for item in plan.addresses)


def test_missing_vsys_mapping_is_reviewable_and_does_not_invent_target_scope():
    source = FGConfig(addresses=[FGAddress(name="net", subnet="10.0.0.0 255.255.255.0")])

    plan = FortiGateToPaloAltoPlanner().plan(source, object())

    assert plan.addresses[0].status is PANMigrationStatus.MANUAL_REVIEW
    assert plan.issues[0].code == "missing_vsys_mapping"
