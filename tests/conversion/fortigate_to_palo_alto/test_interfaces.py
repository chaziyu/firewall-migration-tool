from fwmigrate.conversion.fortigate_to_palo_alto.planning.interfaces import plan_interfaces
from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationStatus
from fwmigrate.conversion.fortigate_to_palo_alto.options import PANMigrationOptions
from fwmigrate.vendors.fortigate.model.interface import FGInterface
from fwmigrate.vendors.fortigate.model.source import FGConfig


def _options(interfaces):
    return PANMigrationOptions(
        vdoms={"root": {"vsys": "vsys1", "virtual_router": "vr-main"}},
        interfaces={"root": interfaces},
    )


def test_static_ethernet_mapping_becomes_executable_interface():
    source = FGConfig(interfaces=[
        FGInterface(name="port1", ip="192.0.2.1 255.255.255.0"),
    ])

    planned = plan_interfaces(
        source,
        _options({"port1": {"target_interface": "ethernet1/1"}}),
    )

    assert len(planned) == 1
    item = planned[0]
    assert item.status is PANMigrationStatus.SUPPORTED
    assert item.target_name == "ethernet1/1"
    assert item.target_vsys == "vsys1"
    assert item.virtual_router == "vr-main"
    assert item.parent is None
    assert item.ipv4_addresses == ("192.0.2.1/24",)


def test_vlan_mapping_requires_explicit_parent_and_vlan_id():
    source = FGConfig(interfaces=[
        FGInterface(name="port1"),
        FGInterface(name="vlan100", type="vlan", interface="port1", vlanid=100, ip="10.0.0.1/24"),
    ])
    planned = plan_interfaces(
        source,
        _options({
            "port1": {"target_interface": "ethernet1/1"},
            "vlan100": {"target_interface": "ethernet1/1.100"},
        }),
    )
    by_name = {item.source_name: item for item in planned}

    assert by_name["port1"].status is PANMigrationStatus.SUPPORTED
    assert by_name["vlan100"].status is PANMigrationStatus.SUPPORTED
    assert by_name["vlan100"].parent == "ethernet1/1"
    assert by_name["vlan100"].tag == 100
    assert by_name["vlan100"].ipv4_addresses == ("10.0.0.1/24",)


def test_dynamic_or_unknown_interface_semantics_fail_closed():
    source = FGConfig(interfaces=[
        FGInterface(name="wan", mode="dhcp"),
        FGInterface(name="agg1", type="aggregate", members=["port1", "port2"]),
    ])
    planned = plan_interfaces(
        source,
        _options({
            "wan": {"target_interface": "ethernet1/1"},
            "agg1": {"target_interface": "ae1"},
        }),
    )
    by_name = {item.source_name: item for item in planned}

    assert by_name["wan"].status is PANMigrationStatus.MANUAL_REVIEW
    assert any("dynamic interface mode" in warning for warning in by_name["wan"].warnings)
    assert by_name["agg1"].status is PANMigrationStatus.MANUAL_REVIEW
    assert any("unsupported FortiGate interface type" in warning for warning in by_name["agg1"].warnings)


def test_interface_planning_never_infers_missing_ownership():
    source = FGConfig(interfaces=[FGInterface(name="port1", ip="192.0.2.1/24")])
    planned = plan_interfaces(
        source,
        PANMigrationOptions(interfaces={"root": {
            "port1": {"target_interface": "ethernet1/1"},
        }}),
    )

    assert planned[0].status is PANMigrationStatus.MANUAL_REVIEW
    assert any("vsys mapping" in warning.lower() for warning in planned[0].warnings)
    assert any("virtual-router mapping" in warning.lower() for warning in planned[0].warnings)
