from fwmigrate.conversion.fortigate_to_palo_alto import (
    FortiGateToPaloAltoPlanner,
    PANMigrationOptions,
    PANMigrationStatus,
)
from fwmigrate.vendors.fortigate.model.address import FGAddress, FGAddressGroup
from fwmigrate.vendors.fortigate.model.source import FGConfig
import pytest


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
        ("ip-netmask", "10.0.0.0/24"),
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


@pytest.mark.parametrize('fields,kind,value,supported', [
    ({'type': 'fqdn', 'fqdn': 'example.org', 'subnet': '192.0.2.0/24'}, 'fqdn', 'example.org', True),
    ({'type': 'ipmask', 'fqdn': 'example.org', 'subnet': '192.0.2.0/24'}, 'ip-netmask', '192.0.2.0/24', True),
    ({'fqdn': 'example.org', 'subnet': '192.0.2.0/24'}, None, None, False),
    ({'type': 'fqdn', 'subnet': '192.0.2.0/24'}, None, None, False),
    ({'type': 'future', 'subnet': '192.0.2.0/24'}, None, None, False),
    ({'type': 'fqdn', 'fqdn': 'example.org', 'raw_extra': {'future-match': 'enable'}}, 'fqdn', 'example.org', False),
    ({'fqdn': 'example.org', 'raw_extra': {'color': '2', 'uuid': 'metadata'}}, 'fqdn', 'example.org', True),
])
def test_address_type_selects_active_value_without_mutating_source(fields, kind, value, supported):
    source = FGConfig(addresses=[FGAddress(name='host', **fields)])
    before = source.model_dump()
    plan = FortiGateToPaloAltoPlanner().plan(source, object(),
        options=PANMigrationOptions(vdoms={'root': {'vsys': 'vsys1'}}))
    item = plan.addresses[0]
    assert (item.address_type, item.value) == (kind, value)
    assert (item.status is PANMigrationStatus.SUPPORTED) == supported
    assert source.model_dump() == before


@pytest.mark.parametrize('fields', [{'type': 'folder'}, {'raw_extra': {'future-control': 'enable'}},
                                   {'allow_routing': 'enable'}])
def test_static_group_rejects_unrepresented_settings(fields):
    source = FGConfig(address_groups=[FGAddressGroup(name='group', members=['host'], **fields)])
    plan = FortiGateToPaloAltoPlanner().plan(source, object(),
        options=PANMigrationOptions(vdoms={'root': {'vsys': 'vsys1'}}))
    assert plan.address_groups[0].status is not PANMigrationStatus.SUPPORTED
