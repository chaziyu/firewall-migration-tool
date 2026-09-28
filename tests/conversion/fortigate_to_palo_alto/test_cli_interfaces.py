from fwmigrate.conversion.fortigate_to_palo_alto.models import (
    PANMigrationPlan,
    PANMigrationStatus,
    PlannedInterface,
)
from fwmigrate.conversion.fortigate_to_palo_alto.renderer import PANSetRenderer


def test_physical_interface_renders_device_import_and_router_membership_in_order():
    plan = PANMigrationPlan(interfaces=(
        PlannedInterface(
            source_vdom="root",
            source_kind="interface",
            source_object_type="interface",
            source_name="port1",
            target_vsys="vsys1",
            target_name="ethernet1/1",
            status=PANMigrationStatus.SUPPORTED,
            interface_family="ethernet",
            ipv4_addresses=("192.0.2.1/24",),
            virtual_router="vr-main",
        ),
    ))

    assert PANSetRenderer().render(plan).commands == (
        "set network interface ethernet ethernet1/1 layer3",
        "set network interface ethernet ethernet1/1 layer3 ip 192.0.2.1/24",
        "set system setting target-vsys vsys1",
        "set import network interface [ ethernet1/1 ]",
        "set system target-vsys none",
        "set network virtual-router vr-main interface [ ethernet1/1 ]",
    )


def test_vlan_subinterface_renders_under_explicit_mapped_parent():
    plan = PANMigrationPlan(interfaces=(
        PlannedInterface(
            source_vdom="root",
            source_kind="interface",
            source_object_type="interface",
            source_name="vlan100",
            target_vsys="vsys1",
            target_name="ethernet1/1.100",
            status=PANMigrationStatus.SUPPORTED,
            interface_family="ethernet",
            parent="ethernet1/1",
            tag=100,
            ipv4_addresses=("10.0.0.1/24",),
            virtual_router="vr-main",
        ),
    ))

    assert PANSetRenderer().render(plan).commands == (
        "set network interface ethernet ethernet1/1 layer3 units ethernet1/1.100",
        "set network interface ethernet ethernet1/1 layer3 units ethernet1/1.100 tag 100",
        "set network interface ethernet ethernet1/1 layer3 units ethernet1/1.100 ip 10.0.0.1/24",
        "set system setting target-vsys vsys1",
        "set import network interface [ ethernet1/1.100 ]",
        "set system target-vsys none",
        "set network virtual-router vr-main interface [ ethernet1/1.100 ]",
    )
