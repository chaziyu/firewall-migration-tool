from fwmigrate.conversion.fortigate_to_palo_alto.planning.interfaces import plan_interfaces
from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationStatus
from fwmigrate.conversion.fortigate_to_palo_alto.options import PANMigrationOptions
from fwmigrate.vendors.fortigate.model.interface import FGInterface
from fwmigrate.vendors.fortigate.model.source import FGConfig
import pytest


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
    assert any("explicit supported lacp-mode" in warning for warning in by_name["agg1"].warnings)


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


@pytest.mark.parametrize('extra', [{}, {'allowaccess': ['ping']}, {'raw_extra': {'mtu': 1400}}, {'mode': 'dhcp'}])
def test_loopback_planning_preserves_only_the_supported_explicit_subset(extra):
    config = FGConfig(interfaces=[FGInterface(name='lo', type='loopback', ip='192.0.2.1/32', **extra)])
    item, = plan_interfaces(config, _options({'lo': {'target_interface': 'loopback.1'}}))
    assert item.interface_family == 'loopback'
    assert item.ipv4_addresses == ('192.0.2.1/32',)
    assert (item.status is PANMigrationStatus.SUPPORTED) == (not extra)


@pytest.mark.parametrize('name', ['loopback.0', 'loopback.10000', 'ethernet1/1', 'loopback.x'])
def test_loopback_identifier_is_validated(name):
    config = FGConfig(interfaces=[FGInterface(name='lo', type='loopback')])
    item, = plan_interfaces(config, _options({'lo': {'target_interface': name}}))
    assert item.status is PANMigrationStatus.MANUAL_REVIEW


def test_loopback_bare_address_does_not_infer_a_host_mask():
    config = FGConfig(interfaces=[FGInterface(name='lo', type='loopback', ip='192.0.2.1')])
    item, = plan_interfaces(config, _options({'lo': {'target_interface': 'loopback.1'}}))
    assert item.status is PANMigrationStatus.MANUAL_REVIEW
    assert not item.ipv4_addresses
