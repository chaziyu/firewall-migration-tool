from fwmigrate.conversion.fortigate_to_palo_alto.models import (
    PANMigrationPlan,
    PANMigrationStatus,
    PlannedInterface,
)
from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer
from dataclasses import replace
import pytest


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
        "set vsys vsys1 import network interface [ ethernet1/1 ]",
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
        "set vsys vsys1 import network interface [ ethernet1/1.100 ]",
        "set network virtual-router vr-main interface [ ethernet1/1.100 ]",
    )


def loopback(**changes):
    return PlannedInterface(source_vdom='root', source_kind='interface', source_object_type='interface',
        source_name='lo', target_vsys='vsys1', target_name='loopback.1', status=PANMigrationStatus.SUPPORTED,
        interface_family='loopback', ipv4_addresses=('192.0.2.1/32',), virtual_router='vr-main', **changes)


def test_loopback_uses_verified_pan_os_11_1_units_path():
    assert PANSetRenderer().render(PANMigrationPlan(interfaces=(loopback(),))).commands == (
        'set network interface loopback units loopback.1',
        'set network interface loopback units loopback.1 ip 192.0.2.1/32',
        'set vsys vsys1 import network interface [ loopback.1 ]',
        'set network virtual-router vr-main interface [ loopback.1 ]',
    )


@pytest.mark.parametrize('changes', [dict(target_name='loopback.0'), dict(target_vsys=None),
    dict(virtual_router=None), dict(ipv4_addresses=('invalid/32',)), dict(ipv4_addresses=('192.0.2.1/24',)), dict(parent='ethernet1/1', tag=10)])
def test_invalid_loopback_plan_never_renders(changes):
    assert PANSetRenderer().render(PANMigrationPlan(interfaces=(replace(loopback(), **changes),))).commands == ()


def test_duplicate_loopbacks_are_blocked_across_vsys():
    items = (loopback(), replace(loopback(), source_vdom='other', target_vsys='vsys2'))
    assert PANSetRenderer().render(PANMigrationPlan(interfaces=items)).commands == ()
